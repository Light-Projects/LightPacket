# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Pure Python implementation of LBN (Light Binary Notation) format.
Equivalent to lib/lbn.c, lib/lbn.h, and specifications in LBN.md.
"""

import struct
import time
import zlib
from typing import List, Optional, Union, Sequence

LBN_MAGIC = b"LBN\x01"
LBN_MAGIC_OLD = b"LBN\x00"

LBN_VERSION = 1
LBN_FLAG_NONE = 0x00
LBN_FLAG_COMPRESSED = 0x01

HEADER_STRUCT = struct.Struct("<IIIII")


def lbn_checksum(version: int, created: int, count: int, flags: int) -> int:
    """Calculate CRC-32 over header fields (version, created, count, flags)."""
    buf = struct.pack("<IIII", version, created, count, flags)
    return zlib.crc32(buf) & 0xFFFFFFFF


def lbn_save(
    filename: str,
    packets: Sequence[Union[bytes, bytearray]],
    count: Optional[int] = None,
    compress: int = 0,
) -> int:
    """
    Pure Python implementation of lbn_save (LBN 1.1).
    Returns 0 on success, -1 on failure.
    """
    try:
        if count is None:
            count = len(packets)
        flags = LBN_FLAG_COMPRESSED if compress else LBN_FLAG_NONE
        created = int(time.time())
        chksum = lbn_checksum(LBN_VERSION, created, count, flags)

        with open(filename, "wb") as f:
            f.write(LBN_MAGIC)
            f.write(HEADER_STRUCT.pack(LBN_VERSION, created, count, flags, chksum))

            for i in range(count):
                pkt = packets[i]
                if hasattr(pkt, "build") and callable(pkt.build):
                    raw = bytes(pkt.build())
                else:
                    raw = bytes(pkt)

                orig_len = len(raw)
                ts = float(time.time())
                f.write(struct.pack("<d", ts))

                if compress:
                    out_data = zlib.compress(raw, level=6)
                    out_len = len(out_data)
                else:
                    out_data = raw
                    out_len = orig_len

                f.write(struct.pack("<II", out_len, orig_len))
                f.write(out_data)
        return 0
    except Exception:
        return -1


def lbn_save_v1_0(
    filename: str,
    packets: Sequence[Union[bytes, bytearray]],
    count: Optional[int] = None,
    compress: int = 0,
) -> int:
    """
    Pure Python implementation of lbn_save_v1_0 (legacy LBN 1.0).
    Returns 0 on success, -1 on failure.
    """
    try:
        if count is None:
            count = len(packets)
        flags = LBN_FLAG_COMPRESSED if compress else LBN_FLAG_NONE
        created = int(time.time())
        chksum = lbn_checksum(LBN_VERSION, created, count, flags)

        with open(filename, "wb") as f:
            f.write(LBN_MAGIC_OLD)
            f.write(HEADER_STRUCT.pack(LBN_VERSION, created, count, flags, chksum))

            for i in range(count):
                pkt = packets[i]
                if hasattr(pkt, "build") and callable(pkt.build):
                    raw = bytes(pkt.build())
                else:
                    raw = bytes(pkt)

                orig_len = len(raw)
                ts = float(time.time())
                f.write(struct.pack("<d", ts))

                if compress:
                    out_data = zlib.compress(raw, level=6)
                    out_len = len(out_data)
                else:
                    out_data = raw
                    out_len = orig_len

                f.write(struct.pack("<I", out_len))
                f.write(out_data)
        return 0
    except Exception:
        return -1


def lbn_load(filename: str) -> Optional[List[bytes]]:
    """
    Pure Python implementation of lbn_load.
    Returns list of packet bytes on success, or None on failure.
    """
    try:
        with open(filename, "rb") as f:
            magic = f.read(4)
            if magic == LBN_MAGIC:
                old = False
            elif magic == LBN_MAGIC_OLD:
                old = True
            else:
                return None

            hdr_raw = f.read(20)
            if len(hdr_raw) < 20:
                return None

            version, created, count, flags, stored_crc = HEADER_STRUCT.unpack(hdr_raw)
            calc_crc = lbn_checksum(version, created, count, flags)
            if calc_crc != stored_crc:
                return None

            compressed = bool(flags & LBN_FLAG_COMPRESSED)
            packets: List[bytes] = []

            for _ in range(count):
                ts_raw = f.read(8)
                if len(ts_raw) < 8:
                    break

                if not old:
                    len_buf = f.read(8)
                    if len(len_buf) < 8:
                        break
                    out_len, orig_len = struct.unpack("<II", len_buf)
                else:
                    len_buf = f.read(4)
                    if len(len_buf) < 4:
                        break
                    out_len = struct.unpack("<I", len_buf)[0]
                    orig_len = out_len * 4

                data = f.read(out_len)
                if len(data) < out_len:
                    break

                if compressed:
                    decomp = zlib.decompress(data)
                    if not old and orig_len > 0 and len(decomp) != orig_len:
                        break
                    packets.append(decomp)
                else:
                    packets.append(data)

            return packets
    except Exception:
        return None
