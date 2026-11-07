# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
BPF device constants and struct definitions for FreeBSD, NetBSD,
OpenBSD, and Darwin.
"""

import ctypes
import struct
from LightPacket.os_consts import FREEBSD, NETBSD


# ---------------------------------------------------------------------------
# ioctl constants (identical across all four targets)
# ---------------------------------------------------------------------------

BIOCGBLEN      = 0x40044266
BIOCSBLEN      = 0xc0044266
BIOCSETF       = 0x80104267
BIOCFLUSH      = 0x20004268
BIOCPROMISC    = 0x20004269
BIOCGDLT       = 0x4004426a
BIOCGETIF      = 0x4020426b
BIOCSETIF      = 0x8020426c
BIOCSRTIMEOUT  = 0x8010426d
BIOCGRTIMEOUT  = 0x4010426e
BIOCGSTATS     = 0x4008426f
BIOCIMMEDIATE  = 0x80044270
BIOCVERSION    = 0x40044271
BIOCGRSIG      = 0x40044272
BIOCSRSIG      = 0x80044273
BIOCSHDRCMPLT  = 0x80044275
BIOCGHDRCMPLT  = 0x40044276
BIOCSDLT       = 0x80044278
BIOCGDLTLIST   = 0xc0104279
BIOCGDIRECTION = 0x4004427b
BIOCSDIRECTION = 0x8004427c
BIOCSSEESENT   = 0x8004427d

# FreeBSD-only: timestamp format control
BIOCSTSTAMP    = 0x80044284
BIOCGTSTAMP    = 0x40044285

BPF_T_MICROTIME            = 0x0000
BPF_T_NANOTIME             = 0x0001
BPF_T_MICROTIME_FAST       = 0x0100
BPF_T_NANOTIME_FAST        = 0x0101
BPF_T_MICROTIME_MONOTONIC  = 0x0200
BPF_T_NANOTIME_MONOTONIC   = 0x0201

# ---------------------------------------------------------------------------
# Alignment
# ---------------------------------------------------------------------------

if FREEBSD or NETBSD:
    BPF_ALIGNMENT = ctypes.sizeof(ctypes.c_long)
else:
    BPF_ALIGNMENT = ctypes.sizeof(ctypes.c_int32)

# ---------------------------------------------------------------------------
# Struct definitions
# ---------------------------------------------------------------------------

class bpf_timeval(ctypes.Structure):
    """
    Timestamp prefix of bpf_hdr.

    On FreeBSD with BPF_T_NANOTIME set, the kernel writes:
        { time_t tv_sec; long tv_nsec; }
    On NetBSD, the standard struct timeval is used with 64-bit time_t:
        { time_t tv_sec; suseconds_t tv_usec; }
    On Darwin/OpenBSD, both fields are 32-bit:
        { int32_t tv_sec; int32_t tv_usec; }

    """
    if FREEBSD:
        _fields_ = [
            ("tv_sec",  ctypes.c_ulong),
            ("tv_nsec", ctypes.c_ulong),
        ]
    elif NETBSD:
        _fields_ = [
            ("tv_sec",  ctypes.c_ulong),
            ("tv_usec", ctypes.c_ulong),
        ]
    else:  # Darwin, OpenBSD, and (for testability) Linux fallback
        _fields_ = [
            ("tv_sec",  ctypes.c_uint32),
            ("tv_usec", ctypes.c_uint32),
        ]


class bpf_hdr(ctypes.Structure):
    """
    BPF packet header, prepended to each captured frame.

    Layout (all supported platforms):
        struct bpf_timespec bh_tstamp;
        bpf_u_int32         bh_caplen;
        bpf_u_int32         bh_datalen;
        u_short             bh_hdrlen;

    """
    _fields_ = [
        ("bh_tstamp", bpf_timeval),
        ("bh_caplen", ctypes.c_uint32),
        ("bh_datalen", ctypes.c_uint32),
        ("bh_hdrlen",  ctypes.c_uint16),
    ]



BPF_HDR_SIZE = ctypes.sizeof(bpf_hdr)

FMT_IFREQ       = "@16s16x"
FMT_BPF_STAT    = "@II"
FMT_BPF_VERSION = "@HH"
FMT_BPF_INSN    = "@HBBI"

# ---------------------------------------------------------------------------
# FreeBSD timestamp configuration
# ---------------------------------------------------------------------------

def configure_timestamp(fd):
    if not FREEBSD:
        return
    try:
        import fcntl
        fcntl.ioctl(fd, BIOCSTSTAMP, struct.pack("@I", BPF_T_NANOTIME))
    except OSError:
        # If this fails, the header will use the default timeval format.
        # On amd64 that's still 16 bytes so layout is identical. On i386
        # it's 8 bytes and bpf_hdr is smaller — you'd see misparsed
        # fields. Log and continue; the caller can decide what to do.
        pass


def parse_bpf_buffer(buf):
    """
    Walk the chain of bpf_hdr records in a buffer returned by read(2).

    Yields raw frame bytes (header stripped). Stops silently on
    truncation or corruption.

    Uses ctypes for correct alignment and platform-specific layout.
    Trusts the runtime bh_hdrlen field, which is BPF_WORDALIGN'd by
    the kernel.
    """

    offset = 0
    n = len(buf)
    min_hdr = BPF_HDR_SIZE

    while offset + min_hdr <= n:
        try:
            hdr = bpf_hdr.from_buffer_copy(buf[offset:offset + min_hdr])
        except (ValueError, TypeError):
            return

        if hdr.bh_hdrlen < min_hdr or hdr.bh_hdrlen > (n - offset):
            return

        pkt_start = offset + hdr.bh_hdrlen
        pkt_end = pkt_start + hdr.bh_caplen
        if pkt_end > n:
            return

        if hdr.bh_caplen > 0:
            yield buf[pkt_start:pkt_end]

        offset = (pkt_end + (BPF_ALIGNMENT - 1)) & ~(BPF_ALIGNMENT - 1)