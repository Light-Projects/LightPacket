# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Pure Python implementation of PCAPNG reader and writer.
Equivalent to lib/pcapng.c, lib/pcapng.h, and lib/pcapng_format.h.
"""

import struct
from dataclasses import dataclass
from typing import List, Optional, Iterator, BinaryIO, Union

# Block Types
BLOCK_TYPE_SHB = 0x0A0D0D0A
BLOCK_TYPE_IDB = 0x00000001
BLOCK_TYPE_EPB = 0x00000006
BLOCK_TYPE_SPB = 0x00000003

BYTE_ORDER_MAGIC = 0x1A2B3C4D

PCAPNG_VERSION_MAJOR = 1
PCAPNG_VERSION_MINOR = 0

OPT_ENDOFOPT = 0x0000
OPT_IF_NAME = 0x0002

# Status codes
PCAPNG_OK = 0
PCAPNG_ERR_IO = -1
PCAPNG_ERR_FORMAT = -2
PCAPNG_ERR_EOF = -3
PCAPNG_ERR_NOMEM = -4
PCAPNG_ERR_UNSUPPORTED = -5
PCAPNG_ERR_INVAL = -6

_STATUS_MESSAGES = {
    PCAPNG_OK: "success",
    PCAPNG_ERR_IO: "I/O error",
    PCAPNG_ERR_FORMAT: "malformed pcapng data",
    PCAPNG_ERR_EOF: "end of file",
    PCAPNG_ERR_NOMEM: "out of memory",
    PCAPNG_ERR_UNSUPPORTED: "unsupported feature",
    PCAPNG_ERR_INVAL: "invalid argument",
}


def pcapng_strerror(status: int) -> str:
    return _STATUS_MESSAGES.get(status, "unknown error")


class PcapngError(Exception):
    """Exception raised by PCAPNG operations."""

    def __init__(self, status: int, context: str = ""):
        self.status = status
        message = pcapng_strerror(status)
        if context:
            message = f"{context}: {message}"
        super().__init__(message)


def _check(status: int, context: str = "") -> int:
    if status < 0:
        raise PcapngError(status, context)
    return status


@dataclass
class Packet:
    interface_id: int
    timestamp_usecs: int
    captured_len: int
    original_len: int
    data: bytes

    @property
    def is_truncated(self) -> bool:
        return self.captured_len < self.original_len


@dataclass
class Interface:
    link_type: int
    snaplen: int
    name: str


def _align4(n: int) -> int:
    return (n + 3) & ~3


class PyPcapngWriter:
    """Pure Python PCAPNG Writer."""

    def __init__(self, filename_or_fp: Union[str, BinaryIO], write_essentials=True):
        self.filename_or_fp = filename_or_fp
        self._fp: Optional[BinaryIO] = None
        self._should_close = False
        self.next_if_id: int = 0
        self._closed: bool = False

        if isinstance(self.filename_or_fp, str):
            try:
                self._fp = open(self.filename_or_fp, "wb")
                self._should_close = True
            except OSError as e:
                raise PcapngError(PCAPNG_ERR_IO, f"failed to open '{self.filename_or_fp}' for writing: {e}")
        else:
            self._fp = self.filename_or_fp
            self._should_close = False

        if write_essentials == True:
            self._write_shb()

    def _write_shb(self):
        body = struct.pack("<IHHq", BYTE_ORDER_MAGIC, PCAPNG_VERSION_MAJOR, PCAPNG_VERSION_MINOR, -1)
        total_len = 4 + 4 + len(body) + 4
        self._fp.write(struct.pack("<II", BLOCK_TYPE_SHB, total_len))
        self._fp.write(body)
        self._fp.write(struct.pack("<I", total_len))

    def add_interface(self, link_type: int, snaplen: int = 0, name: Optional[str] = None) -> int:
        self._check_open()
        body = struct.pack("<HHI", link_type, 0, snaplen)

        options = b""
        if name:
            name_bytes = name.encode("utf-8")
            if len(name_bytes) > 0xFFFF:
                name_bytes = name_bytes[:0xFFFF]
            name_len = len(name_bytes)
            padded_len = _align4(name_len)
            pad_bytes = padded_len - name_len

            options = (
                struct.pack("<HH", OPT_IF_NAME, name_len)
                + name_bytes
                + (b"\x00" * pad_bytes)
                + struct.pack("<HH", OPT_ENDOFOPT, 0)
            )

        total_len = 4 + 4 + len(body) + len(options) + 4
        self._fp.write(struct.pack("<II", BLOCK_TYPE_IDB, total_len))
        self._fp.write(body)
        if options:
            self._fp.write(options)
        self._fp.write(struct.pack("<I", total_len))

        if_id = self.next_if_id
        self.next_if_id += 1
        return if_id

    def write_packet(self, interface_id: int, ts_usecs: int, data: Union[bytes, bytearray]) -> None:
        self._check_open()
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError(f"data must be bytes-like, got {type(data).__name__}")
        if interface_id >= self.next_if_id:
            raise PcapngError(PCAPNG_ERR_INVAL, f"unknown interface_id {interface_id}")

        raw = bytes(data)
        length = len(raw)
        padded_len = _align4(length)
        pad_bytes = padded_len - length

        ts_high = (ts_usecs >> 32) & 0xFFFFFFFF
        ts_low = ts_usecs & 0xFFFFFFFF

        hdr = struct.pack("<IIIII", interface_id, ts_high, ts_low, length, length)
        total_len = 4 + 4 + len(hdr) + padded_len + 4

        self._fp.write(struct.pack("<II", BLOCK_TYPE_EPB, total_len))
        self._fp.write(hdr)
        if length > 0:
            self._fp.write(raw)
        if pad_bytes > 0:
            self._fp.write(b"\x00" * pad_bytes)
        self._fp.write(struct.pack("<I", total_len))

    def write_simple_packet(self, data: Union[bytes, bytearray]) -> None:
        self._check_open()
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError(f"data must be bytes-like, got {type(data).__name__}")

        if self.next_if_id == 0:
            raise PcapngError(PCAPNG_ERR_INVAL, "Must add at least one interface before writing an SPB")

        raw = bytes(data)
        length = len(raw)

        padded_len = _align4(length)
        pad_bytes = padded_len - length

        total_len = 4 + 4 + 4 + padded_len + 4

        self._fp.write(struct.pack("<II", BLOCK_TYPE_SPB, total_len))
        self._fp.write(struct.pack("<I", length))

        if length > 0:
            self._fp.write(raw)

        if pad_bytes > 0:
            self._fp.write(b"\x00" * pad_bytes)

        self._fp.write(struct.pack("<I", total_len))

    def _check_open(self):
        if self._closed or self._fp is None:
            raise ValueError("I/O operation on closed PcapngWriter")

    def close(self):
        if not self._closed:
            self._closed = True
            if self._should_close and self._fp is not None:
                self._fp.close()
            self._fp = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


class PyPcapngReader:
    """Pure Python PCAPNG Reader."""

    def __init__(self, filename_or_fp: Union[str, BinaryIO], read_essentials=True):
        self.filename_or_fp = filename_or_fp
        self._fp: Optional[BinaryIO] = None
        self._should_close = False
        self._closed: bool = False
        self.endian: str = "<"
        self._interfaces: List[Interface] = []

        if isinstance(self.filename_or_fp, str):
            try:
                self._fp = open(self.filename_or_fp, "rb")
                self._should_close = True
            except OSError as e:
                raise PcapngError(PCAPNG_ERR_IO, f"failed to open '{self.filename_or_fp}' for reading: {e}")
        else:
            self._fp = self.filename_or_fp
            self._should_close = False

        if read_essentials == True:
            self._read_shb()
            self._prescan_interfaces()

    @property
    def interfaces(self) -> List[Interface]:
        self._check_open()
        return list(self._interfaces)

    def _peek_block_header(self) -> bytes:
        """Return the next 8 bytes (block type + total length) without advancing."""
        pos = self._fp.tell()
        raw = self._fp.read(8)
        self._fp.seek(pos)
        return raw

    def _read_shb(self):
        raw = self._fp.read(8)
        if len(raw) < 8:
            raise PcapngError(PCAPNG_ERR_FORMAT, "file too small for SHB")

        block_type, total_len = struct.unpack("<II", raw)
        if block_type != BLOCK_TYPE_SHB:
            raise PcapngError(PCAPNG_ERR_FORMAT, f"not a pcapng file, invalid SHB block type: {hex(block_type)}")

        body_raw = self._fp.read(16)
        if len(body_raw) < 16:
            raise PcapngError(PCAPNG_ERR_FORMAT, "truncated SHB body")

        magic_raw = struct.unpack("<I", body_raw[:4])[0]
        if magic_raw == BYTE_ORDER_MAGIC:
            self.endian = "<"
        elif struct.unpack(">I", body_raw[:4])[0] == BYTE_ORDER_MAGIC:
            self.endian = ">"
            total_len = struct.unpack(">I", raw[4:8])[0]
        else:
            raise PcapngError(PCAPNG_ERR_FORMAT, f"invalid byte order magic: {hex(magic_raw)}")

        # Skip remaining bytes of SHB before trailing length
        consumed = 4 + 4 + 16
        remaining = total_len - consumed - 4
        if remaining > 0:
            self._fp.seek(remaining, 1)

        trailing_raw = self._fp.read(4)
        if len(trailing_raw) < 4:
            raise PcapngError(PCAPNG_ERR_FORMAT, "truncated SHB trailing length")
        trailing_len = struct.unpack(f"{self.endian}I", trailing_raw)[0]
        if trailing_len != total_len:
            raise PcapngError(PCAPNG_ERR_FORMAT, "SHB trailing length mismatch")

    def _prescan_interfaces(self):
        """Pre-scan consecutive IDBs at the start of the file."""
        while True:
            pos = self._fp.tell()
            raw = self._fp.read(8)
            if len(raw) < 8:
                self._fp.seek(pos)
                break

            b_type, t_len = struct.unpack(f"{self.endian}II", raw)
            if b_type != BLOCK_TYPE_IDB:
                self._fp.seek(pos)
                break

            self._fp.seek(pos)
            self._parse_idb()

    def _parse_idb(self):
        raw_hdr = self._fp.read(8)
        b_type, total_len = struct.unpack(f"{self.endian}II", raw_hdr)
        body_len = total_len - 12
        if body_len < 8:
            raise PcapngError(PCAPNG_ERR_FORMAT, "IDB body too short")

        idb_body = self._fp.read(8)
        link_type, reserved, snaplen = struct.unpack(f"{self.endian}HHI", idb_body)

        options_len = body_len - 8
        name = ""
        if options_len > 0:
            options_raw = self._fp.read(options_len)
            offset = 0
            while offset + 4 <= len(options_raw):
                opt_code, opt_len = struct.unpack(f"{self.endian}HH", options_raw[offset : offset + 4])
                offset += 4
                padded = _align4(opt_len)
                if opt_code == OPT_ENDOFOPT:
                    break
                elif opt_code == OPT_IF_NAME:
                    val = options_raw[offset : offset + opt_len]
                    name = val.decode("utf-8", errors="replace")
                offset += padded

        trailing_raw = self._fp.read(4)
        trailing_len = struct.unpack(f"{self.endian}I", trailing_raw)[0]
        if trailing_len != total_len:
            raise PcapngError(PCAPNG_ERR_FORMAT, "IDB trailing length mismatch")

        self._interfaces.append(Interface(link_type=link_type, snaplen=snaplen, name=name))

    def read_packet(self) -> Optional[Packet]:
        self._check_open()
        while True:
            raw = self._fp.read(8)
            if not raw or len(raw) < 8:
                return None

            b_type, total_len = struct.unpack(f"{self.endian}II", raw)
            if total_len < 12:
                raise PcapngError(PCAPNG_ERR_FORMAT, f"invalid block total_len {total_len}")

            body_len = total_len - 12

            if b_type == BLOCK_TYPE_EPB:
                if body_len < 20:
                    raise PcapngError(PCAPNG_ERR_FORMAT, "EPB body too short")

                epb_hdr = self._fp.read(20)
                if_id, ts_h, ts_l, cap_len, orig_len = struct.unpack(f"{self.endian}IIIII", epb_hdr)
                ts_usecs = (ts_h << 32) | ts_l

                data = self._fp.read(cap_len)
                pad = _align4(cap_len) - cap_len
                if pad > 0:
                    self._fp.seek(pad, 1)

                options_len = body_len - 20 - _align4(cap_len)
                if options_len > 0:
                    self._fp.seek(options_len, 1)

                trailing_raw = self._fp.read(4)
                trailing_len = struct.unpack(f"{self.endian}I", trailing_raw)[0]
                if trailing_len != total_len:
                    raise PcapngError(PCAPNG_ERR_FORMAT, "EPB trailing length mismatch")

                return Packet(
                    interface_id=if_id,
                    timestamp_usecs=ts_usecs,
                    captured_len=cap_len,
                    original_len=orig_len,
                    data=data,
                )


            elif b_type == BLOCK_TYPE_SPB:
                if body_len < 4:
                    raise PcapngError(PCAPNG_ERR_FORMAT, "SPB body too short")

                spb_hdr = self._fp.read(4)

                if len(spb_hdr) < 4:
                    raise PcapngError(PCAPNG_ERR_FORMAT, "truncated SPB header")

                orig_len = struct.unpack(f"{self.endian}I", spb_hdr)[0]
                data_padded_len = body_len - 4
                cap_len = min(orig_len, data_padded_len)

                if cap_len < 0:
                    raise PcapngError(PCAPNG_ERR_FORMAT, "invalid SPB packet length calculation")

                data = self._fp.read(cap_len)

                if len(data) < cap_len:
                    raise PcapngError(PCAPNG_ERR_FORMAT, "truncated SPB packet data")

                pad = data_padded_len - cap_len

                if pad > 0:
                    self._fp.seek(pad, 1)

                trailing_raw = self._fp.read(4)

                if len(trailing_raw) < 4:
                    raise PcapngError(PCAPNG_ERR_FORMAT, "truncated SPB trailing length")

                trailing_len = struct.unpack(f"{self.endian}I", trailing_raw)[0]
                if trailing_len != total_len:
                    raise PcapngError(PCAPNG_ERR_FORMAT, "SPB trailing length mismatch")


                return Packet(
                    interface_id=0,
                    timestamp_usecs=0,
                    captured_len=cap_len,
                    original_len=orig_len,
                    data=data,
                )

            elif b_type == BLOCK_TYPE_IDB:
                # Rewind 8 bytes to parse IDB with self._parse_idb
                self._fp.seek(-8, 1)
                self._parse_idb()
                continue
            else:
                # Skip other blocks
                if body_len > 0:
                    self._fp.seek(body_len, 1)
                trailing_raw = self._fp.read(4)
                if len(trailing_raw) < 4:
                    raise PcapngError(PCAPNG_ERR_FORMAT, "truncated trailing length")
                continue

    def _check_open(self):
        if self._closed or self._fp is None:
            raise ValueError("I/O operation on closed PcapngReader")

    def close(self):
        if not self._closed:
            self._closed = True
            if self._should_close and self._fp is not None:
                self._fp.close()
            self._fp = None

    def __iter__(self) -> Iterator[Packet]:
        return self

    def __next__(self) -> Packet:
        pkt = self.read_packet()
        if pkt is None:
            raise StopIteration
        return pkt

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
