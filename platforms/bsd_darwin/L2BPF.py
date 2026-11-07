# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
BPF device backend for FreeBSD, OpenBSD, NetBSD, DragonflyBSD and macOS.
"""

import errno
import fcntl
import os
import select
import struct
import time
from typing import List, Optional

from LightPacket.Config import config
from LightPacket.LightPacketUnix import get_default_interface_bsd
from LightPacket.Logger.LightLogger import Logger, ErrorCode
from LightPacket.bpf import (
    get_bpf_bytes,
    get_bpf_device_struct,
    free_filter,
)

from LightPacket.platforms.bsd_darwin.bpf_constants import (
    BIOCGBLEN,
    BIOCSBLEN,
    BIOCSETF,
    BIOCPROMISC,
    BIOCSETIF,
    BIOCIMMEDIATE,
    BIOCSHDRCMPLT,
    FMT_IFREQ,
    FMT_BPF_HDR,
)

Logger = Logger()

# sizeof(bpf_int32) — the alignment unit used by BPF_WORDALIGN.
_BPF_ALIGNMENT = 4


def _wordalign(x: int) -> int:
    """Match the kernel's BPF_WORDALIGN macro."""
    return (x + (_BPF_ALIGNMENT - 1)) & ~(_BPF_ALIGNMENT - 1)


def _default_iface() -> Optional[str]:
    if getattr(config.network, "INTERFACE", None):
        return config.network.INTERFACE
    try:
        return get_default_interface_bsd()["name"]
    except Exception:
        return None


class L2BPF:
    """BPF device socket. One frame per os.write(), N frames per os.read()."""

    _MAX_DEVICES = 256  # upper bound on /dev/bpfN iteration

    def __init__(
        self,
        iface=None,
        bpf_device=None,
        nonstop=None,
        snaplen=None,
    ):
        self.iface = iface or _default_iface()
        if not self.iface:
            raise RuntimeError("No network interface found")

        self.snaplen = snaplen if snaplen is not None else config.network.SNAPLEN
        self.nonstop = (
            nonstop
            if nonstop is not None
            else getattr(config.network, "NON_STOP", False)
        )
        self.fd: Optional[int] = None
        self.buflen: int = 0
        self.closed: bool = False
        self._filter: Optional[str] = None

        self.fd = self._open_device(bpf_device)
        try:
            self._configure(self.iface)
        except Exception:
            self.close()
            raise


    def _open_device(self, preferred: Optional[str]) -> int:
        if preferred:
            try:
                return os.open(preferred, os.O_RDWR)
            except OSError as e:
                raise RuntimeError(f"Failed to open {preferred}: {e}")

        try:
            return os.open("/dev/bpf", os.O_RDWR)
        except OSError:
            pass

        last_err: Optional[OSError] = None
        for i in range(self._MAX_DEVICES):
            try:
                return os.open(f"/dev/bpf{i}", os.O_RDWR)
            except OSError as e:
                if e.errno in (errno.ENOENT, errno.EBUSY):
                    last_err = e
                    continue
                raise RuntimeError(f"Failed to open /dev/bpf{i}: {e}")
        raise RuntimeError(
            "No BPF device available "
            f"(all /dev/bpf* busy or missing; last: {last_err})"
        )

    def _configure(self, iface: str) -> None:
        # 1. Buffer length. The kernel rounds it up; store what it returned.
        try:
            req = struct.pack("@I", self.snaplen)
            self.buflen = struct.unpack(
                "@I", fcntl.ioctl(self.fd, BIOCSBLEN, req)
            )[0]
        except OSError:
            self.buflen = struct.unpack(
                "@I", fcntl.ioctl(self.fd, BIOCGBLEN, b"\0" * 4)
            )[0]

        # 2. Bind to interface. Required before any read/write succeeds.
        fcntl.ioctl(
            self.fd,
            BIOCSETIF,
            struct.pack(FMT_IFREQ, iface.encode("ascii")[:16]),
        )

        # 3. Immediate mode: read() returns as soon as one packet is buffered.
        fcntl.ioctl(self.fd, BIOCIMMEDIATE, struct.pack("@I", 1))

        # 4. Promiscuous mode (best effort; needs privilege on some systems).
        if getattr(config.network, "PROMISC", False):
            try:
                fcntl.ioctl(self.fd, BIOCPROMISC)
            except OSError:
                pass

        # 5. We build the link-layer header ourselves when sending.
        try:
            fcntl.ioctl(self.fd, BIOCSHDRCMPLT, struct.pack("@I", 1))
        except OSError:
            pass  # not supported everywhere

        # 6. Non-blocking so select() + os.read() behave predictably.
        flags = fcntl.fcntl(self.fd, fcntl.F_GETFL)
        fcntl.fcntl(self.fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)


    def set_filter(self, filter_str: str) -> bool:
        """Compile a cBPF filter string via libpcap and attach it (BIOCSETF)."""
        if self.closed or self.fd is None:
            return False

        try:
            _fp_ctypes, bp = get_bpf_bytes(filter_str, self.iface)
        except Exception as e:
            Logger.error(
                error_code=ErrorCode.CANNOT_COMPILE_BPF,
                message=f"Cannot compile filter: {e}",
            )
            return False

        if bp is None:
            Logger.error(
                error_code=ErrorCode.CANNOT_COMPILE_BPF,
                message="Cannot compile filter, make sure libpcap is installed",
            )
            return False

        try:
            self._attach_fprog(get_bpf_device_struct(bp))
            self._filter = filter_str
            return True
        except (OSError, ValueError) as e:
            Logger.error(
                error_code=ErrorCode.CANNOT_COMPILE_BPF,
                message=f"Cannot attach filter: {e}",
            )
            return False
        finally:
            try:
                free_filter(bp)
            except Exception:
                pass

    def set_filter_fprog(self, fprog: bytes) -> bool:
        """Attach a pre-built BSD struct bpf_program, already packed as bytes."""
        if self.closed or self.fd is None:
            return False
        try:
            self._attach_fprog(fprog)
            return True
        except (OSError, ValueError) as e:
            Logger.error(
                error_code=ErrorCode.CANNOT_COMPILE_BPF,
                message=f"Cannot attach fprog: {e}",
            )
            return False

    def _attach_fprog(self, fprog) -> None:
        if isinstance(fprog, (bytes, bytearray)):
            fp_bytes = bytes(fprog)
        else:
            try:
                fp_bytes = bytes(memoryview(fprog))
            except TypeError as e:
                raise ValueError(
                    f"fprog must be bytes or a ctypes struct: {e}"
                )
        expected = struct.calcsize("@IP")
        if len(fp_bytes) != expected:
            raise ValueError(
                f"fprog must be {expected} bytes (struct bpf_program), "
                f"got {len(fp_bytes)}"
            )
        fcntl.ioctl(self.fd, BIOCSETF, fp_bytes)


    def sendl2(self, packet) -> int:
        """Write one raw Layer 2 frame."""
        if self.closed or self.fd is None:
            raise RuntimeError("Socket closed")
        if hasattr(packet, "build") and callable(packet.build):
            packet = packet.build()
        if not isinstance(packet, (bytes, bytearray)):
            raise TypeError(
                f"packet must be bytes, got {type(packet).__name__}"
            )
        return os.write(self.fd, bytes(packet))

    def recvl2(self, count: int = 1, timeout: float = 1.0) -> List[bytes]:
        """Receive up to `count` frames, waiting up to `timeout` seconds."""
        if self.closed or self.fd is None:
            raise RuntimeError("Socket closed")

        packets: List[bytes] = []
        deadline = time.monotonic() + max(timeout, 0.0)

        while True:
            if count > 0 and len(packets) >= count:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            try:
                ready, _, _ = select.select([self.fd], [], [], remaining)
            except (OSError, ValueError):
                break
            if not ready:
                break

            try:
                buf = os.read(self.fd, self.buflen)
            except BlockingIOError:
                continue
            except OSError as e:
                if e.errno in (errno.EINTR, errno.EAGAIN):
                    continue
                raise
            if not buf:
                continue

            for frame in self._parse_buffer(buf):
                packets.append(frame)
                if count > 0 and len(packets) >= count:
                    return packets

        return packets

    def iterl2(self):
        """Generator: yield frames until the device is closed."""
        while not self.closed:
            for frame in self.recvl2(count=1, timeout=1.0):
                yield frame


    def _parse_buffer(self, buf: bytes):
        """
        Walk the chain of bpf_hdr records in a buffer returned by read(2).
        Yields raw frame bytes (header stripped). Stops silently on truncation.

        Layout per record:
            struct bpf_hdr { timeval bh_tstamp; u_int bh_caplen;
                             u_int bh_datalen; u_short bh_hdrlen; }
            <caplen bytes of frame>
            <padding to BPF_WORDALIGN>
        """
        hdr_size = struct.calcsize(FMT_BPF_HDR)
        offset = 0
        n = len(buf)

        while offset + hdr_size <= n:
            try:
                _tv_sec, _tv_usec, caplen, _datalen, hdrlen = struct.unpack_from(
                    FMT_BPF_HDR, buf, offset
                )
            except struct.error:
                return

            if hdrlen < hdr_size or hdrlen > (n - offset):
                return
            pkt_start = offset + hdrlen
            pkt_end = pkt_start + caplen
            if pkt_end > n:
                return

            if caplen > 0:
                yield buf[pkt_start:pkt_end]

            offset = _wordalign(pkt_end)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        fd, self.fd = self.fd, None
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass