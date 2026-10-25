# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Pure Python implementation of the PCAP file writer.
Equivalent to lib/pcap_writer.c and lib/pcap_writer.h.
"""

import struct
import time
from typing import List, Union, BinaryIO, Optional

PCAP_MAGIC_USEC = 0xA1B2C3D4
PCAP_MAGIC_NSEC = 0xA1B23C4D

PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_SNAPLEN = 65535

PCAP_LINKTYPE_ETHERNET = 1
PCAP_LINKTYPE_PPP = 9
PCAP_LINKTYPE_RAW = 101
PCAP_LINKTYPE_IEEE802_11 = 105

GLOBAL_HEADER_STRUCT = struct.Struct("<IHHiIII")
PACKET_HEADER_STRUCT = struct.Struct("<IIII")


class PcapWriter:
    """Pure Python PCAP format writer."""

    def __init__(self, filename_or_fp: Union[str, BinaryIO], linktype: int = PCAP_LINKTYPE_ETHERNET, snaplen: int = PCAP_SNAPLEN):
        self.filename_or_fp = filename_or_fp
        self.linktype = linktype
        self.snaplen = snaplen
        self._fp: Optional[BinaryIO] = None
        self._should_close = False
        self._header_written = False
        self._packets_written = 0

    def open(self):
        if isinstance(self.filename_or_fp, str):
            self._fp = open(self.filename_or_fp, "wb")
            self._should_close = True
        else:
            self._fp = self.filename_or_fp
            self._should_close = False

        self._write_global_header()
        return self

    def _write_global_header(self):
        if not self._header_written and self._fp is not None:
            header_bytes = GLOBAL_HEADER_STRUCT.pack(
                PCAP_MAGIC_NSEC,
                PCAP_VERSION_MAJOR,
                PCAP_VERSION_MINOR,
                0,
                0,
                self.snaplen,
                self.linktype,
            )
            self._fp.write(header_bytes)
            self._header_written = True

    def write_packet(self, data: Union[bytes, bytearray], ts_sec: Optional[int] = None, ts_usec: int = 0):
        if self._fp is None:
            raise RuntimeError("PcapWriter is not open or already closed")
        if not self._header_written:
            self._write_global_header()

        raw = bytes(data)
        orig_len = len(raw)
        captured = min(orig_len, self.snaplen)

        if ts_sec is None:
            ts_sec = int(time.time())

        hdr_bytes = PACKET_HEADER_STRUCT.pack(ts_sec, ts_usec, captured, orig_len)
        self._fp.write(hdr_bytes)
        if captured > 0:
            self._fp.write(raw[:captured])
        self._packets_written += 1

    def write_packets(self, packets: List[Union[bytes, bytearray]]):
        for pkt in packets:
            print(type(pkt))
            self.write_packet(pkt)

    def close(self):
        if self._should_close and self._fp is not None:
            self._fp.close()
            self._fp = None

    def __enter__(self):
        return self.open()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __len__(self):
        return self._packets_written


def create_pcap_file(filename: str, packetarr, totalpackets: int, linktype: int = 1) -> int:
    """
    Pure Python implementation of create_pcap_file matching the C function signature.
    Returns 0 on success, non-zero on error.
    """
    if filename is None or totalpackets < 0:
        return 1
    if totalpackets > 0 and packetarr is None:
        return 1

    try:
        with PcapWriter(filename, linktype=linktype) as writer:
            for i in range(totalpackets):
                # Handle packetarr whether it's a list of bytes or ctypes structures
                item = packetarr[i]
                if hasattr(item, "payload") and hasattr(item, "data_length"):
                    length = item.data_length
                    raw = bytes(item.payload[:length]) if length > 0 else b""
                else:
                    raw = bytes(item)
                writer.write_packet(raw)
        return 0
    except Exception:
        return 1
