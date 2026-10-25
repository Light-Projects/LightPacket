# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Pure Python implementation of the PCAP file reader.
Equivalent to lib/pcap_reader.c and lib/pcap_reader.h.
"""

import struct
from typing import List, Dict, Any, Tuple, Optional, BinaryIO

PCAP_MAGIC_USEC = 0xA1B2C3D4
PCAP_MAGIC_NSEC = 0xA1B23C4D
PCAP_MAGIC_USEC_SWAPPED = 0xD4C3B2A1
PCAP_MAGIC_NSEC_SWAPPED = 0x4D3CB2A1

GLOBAL_HEADER_SIZE = 24
PACKET_HEADER_SIZE = 16


class PcapReader:
    """Pure Python PCAP format reader."""

    def __init__(self, filename_or_fp):
        self.filename_or_fp = filename_or_fp
        self._fp: Optional[BinaryIO] = None
        self._should_close = False
        self.endian: str = "<"
        self.magic: int = 0
        self.global_header: Dict[str, Any] = {}

    def open(self):
        if isinstance(self.filename_or_fp, str):
            self._fp = open(self.filename_or_fp, "rb")
            self._should_close = True
        else:
            self._fp = self.filename_or_fp
            self._should_close = False

        self._read_global_header()
        return self

    def _read_global_header(self):
        raw_header = self._fp.read(GLOBAL_HEADER_SIZE)
        if len(raw_header) < GLOBAL_HEADER_SIZE:
            raise ValueError(f"Truncated PCAP header: expected {GLOBAL_HEADER_SIZE} bytes, got {len(raw_header)}")

        magic_raw = struct.unpack("<I", raw_header[:4])[0]
        if magic_raw in (PCAP_MAGIC_USEC, PCAP_MAGIC_NSEC):
            self.endian = "<"
            self.magic = magic_raw
        elif magic_raw in (PCAP_MAGIC_USEC_SWAPPED, PCAP_MAGIC_NSEC_SWAPPED):
            self.endian = ">"
            self.magic = struct.unpack(">I", raw_header[:4])[0]
        else:
            raise ValueError(f"Invalid PCAP magic number: {hex(magic_raw)}")

        magic, v_maj, v_min, thiszone, sigfigs, snaplen, network = struct.unpack(
            f"{self.endian}IHHiIII", raw_header
        )
        self.global_header = {
            "magic": hex(magic),
            "version_major": v_maj,
            "version_minor": v_min,
            "thiszone": thiszone,
            "sigfigs": sigfigs,
            "snaplen": snaplen,
            "network": network,
        }

    def read_packet(self) -> Optional[Dict[str, Any]]:
        raw_hdr = self._fp.read(PACKET_HEADER_SIZE)
        if not raw_hdr:
            return None
        if len(raw_hdr) < PACKET_HEADER_SIZE:
            return None

        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            f"{self.endian}IIII", raw_hdr
        )
        data = self._fp.read(incl_len)
        if len(data) < incl_len:
            return None

        return {
            "ts_sec": ts_sec,
            "ts_usec": ts_usec,
            "incl_len": incl_len,
            "orig_len": orig_len,
            "data": data,
        }

    def read_all(self) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        packets = []
        while True:
            pkt = self.read_packet()
            if pkt is None:
                break
            packets.append(pkt)
        return [self.global_header], packets

    def close(self):
        if self._should_close and self._fp is not None:
            self._fp.close()
            self._fp = None

    def __enter__(self):
        return self.open()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def read_pcap_file(filename: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Read all packets from a PCAP file.
    Returns (header_list, packets_list).
    """
    try:
        with PcapReader(filename) as reader:
            return reader.read_all()
    except Exception:
        return [], []
