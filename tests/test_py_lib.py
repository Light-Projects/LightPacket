# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Unit tests for pure Python implementation of lib/ (PCAP, PCAPNG, LBN).
Exercises pure Python serialization, parsing, error handling, and streams.
"""

import os
import struct
import time
import pytest

from LightPacket.lib.py_pcap_reader import (
    PcapReader,
    read_pcap_file,
    PCAP_MAGIC_USEC,
    PCAP_MAGIC_NSEC,
    PCAP_MAGIC_USEC_SWAPPED,
    PCAP_MAGIC_NSEC_SWAPPED,
)
from LightPacket.lib.py_pcap_writer import (
    PcapWriter,
    create_pcap_file,
    PCAP_LINKTYPE_ETHERNET,
    PCAP_LINKTYPE_PPP,
    PCAP_LINKTYPE_RAW,
    PCAP_LINKTYPE_IEEE802_11,
)
from LightPacket.lib.py_pcapng import (
    PyPcapngWriter,
    PyPcapngReader,
    Packet,
    Interface,
    PcapngError,
    BLOCK_TYPE_SHB,
    BYTE_ORDER_MAGIC,
)
from LightPacket.lib.py_lbn import (
    lbn_save,
    lbn_save_v1_0,
    lbn_load,
    lbn_checksum,
    LBN_MAGIC,
    LBN_MAGIC_OLD,
)

# Also test high-level Saving modules in pure-Python mode

# ==============================================================================
# PCAP Pure Python Tests
# ==============================================================================

def test_pcap_pure_python_roundtrip(tmp_path):
    pcap_path = str(tmp_path / "test.pcap")
    pkts = [b"\x01\x02\x03\x04", b"\xaa\xbb\xcc\xdd\xee", b"hello world packet!"]

    # Write using PcapWriter
    with PcapWriter(pcap_path, linktype=PCAP_LINKTYPE_ETHERNET) as writer:
        for p in pkts:
            writer.write_packet(p, ts_sec=1600000000, ts_usec=500)

    # Read back using PcapReader
    with PcapReader(pcap_path) as reader:
        header, read_pkts = reader.read_all()

    assert len(header) == 1
    assert header[0]["network"] == PCAP_LINKTYPE_ETHERNET
    assert header[0]["version_major"] == 2
    assert header[0]["version_minor"] == 4
    assert len(read_pkts) == 3
    assert [p["data"] for p in read_pkts] == pkts
    assert read_pkts[0]["ts_sec"] == 1600000000
    assert read_pkts[0]["ts_usec"] == 500


def test_pcap_different_linktypes(tmp_path):
    for lt in (PCAP_LINKTYPE_PPP, PCAP_LINKTYPE_RAW, PCAP_LINKTYPE_IEEE802_11):
        path = str(tmp_path / f"test_{lt}.pcap")
        with PcapWriter(path, linktype=lt) as writer:
            writer.write_packet(b"\xde\xad\xbe\xef")

        with PcapReader(path) as reader:
            header, pkts = reader.read_all()
        assert header[0]["network"] == lt
        assert len(pkts) == 1
        assert pkts[0]["data"] == b"\xde\xad\xbe\xef"


def test_pcap_empty_file(tmp_path):
    path = str(tmp_path / "empty.pcap")
    with PcapWriter(path) as writer:
        pass  # write only global header

    with PcapReader(path) as reader:
        header, pkts = reader.read_all()
    assert len(header) == 1
    assert pkts == []


def test_pcap_swapped_endian_reading(tmp_path):
    path = str(tmp_path / "swapped.pcap")
    # Manually construct big-endian global header and packet header
    ghdr = struct.pack(">IHHiIII", PCAP_MAGIC_USEC, 2, 4, 0, 0, 65535, 1)
    phdr = struct.pack(">IIII", 1000, 20, 4, 4)
    data = b"\x11\x22\x33\x44"

    with open(path, "wb") as f:
        f.write(ghdr + phdr + data)

    with PcapReader(path) as reader:
        header, pkts = reader.read_all()
    assert reader.endian == ">"
    assert len(pkts) == 1
    assert pkts[0]["ts_sec"] == 1000
    assert pkts[0]["ts_usec"] == 20
    assert pkts[0]["data"] == data


def test_pcap_saving_high_level_streams(tmp_path):
    path = str(tmp_path / "stream.pcap")
    with PcapWriter(path, linktype=PCAP_LINKTYPE_ETHERNET) as stream:
        stream.write_packets([b"pkt1", b"pkt2"])
        stream.write_packet(b"pkt3")
        assert len(stream) == 3


# ==============================================================================
# PCAPNG Pure Python Tests
# ==============================================================================

def test_pcapng_pure_python_roundtrip(tmp_path):
    path = str(tmp_path / "test.pcapng")
    writer = PyPcapngWriter(path)
    if0 = writer.add_interface(link_type=1, snaplen=65535, name="eth0")
    if1 = writer.add_interface(link_type=105, snaplen=2048, name="wlan0")
    assert if0 == 0
    assert if1 == 1

    writer.write_packet(if0, 1000000, b"packet on eth0")
    writer.write_packet(if1, 2000000, b"packet on wlan0 - longer payload")
    writer.close()

    reader = PyPcapngReader(path)
    ifaces = reader.interfaces
    assert len(ifaces) == 2
    assert ifaces[0].name == "eth0"
    assert ifaces[0].link_type == 1
    assert ifaces[1].name == "wlan0"
    assert ifaces[1].link_type == 105

    pkts = list(reader)
    assert len(pkts) == 2
    assert pkts[0].interface_id == 0
    assert pkts[0].timestamp_usecs == 1000000
    assert pkts[0].data == b"packet on eth0"
    assert not pkts[0].is_truncated

    assert pkts[1].interface_id == 1
    assert pkts[1].timestamp_usecs == 2000000
    assert pkts[1].data == b"packet on wlan0 - longer payload"
    reader.close()


def test_pcapng_saving_high_level(tmp_path):
    path = str(tmp_path / "high_level.pcapng")
    with PyPcapngWriter(path) as writer:
        if_id = writer.add_interface(link_type=1, name="lo")
        writer.write_packet(if_id, 5000, b"\x00\x01\x02")

    with PyPcapngReader(path) as reader:
        assert len(reader.interfaces) == 1
        assert reader.interfaces[0].name == "lo"
        pkt = reader.read_packet()
        assert pkt.data == b"\x00\x01\x02"
        assert reader.read_packet() is None


def test_pcapng_invalid_interface_raises(tmp_path):
    path = str(tmp_path / "err.pcapng")
    with PyPcapngWriter(path) as writer:
        with pytest.raises(PcapngError):
            writer.write_packet(99, 1000, b"fail")


def test_pcapng_invalid_type_raises(tmp_path):
    path = str(tmp_path / "err2.pcapng")
    with PyPcapngWriter(path) as writer:
        idx = writer.add_interface(link_type=1)
        with pytest.raises(TypeError):
            writer.write_packet(idx, 1000, "not bytes")


# ==============================================================================
# LBN Pure Python Tests
# ==============================================================================

def test_lbn_v1_1_uncompressed_roundtrip(tmp_path):
    path = str(tmp_path / "test_v1_1.lbn")
    packets = [b"frame 1", b"frame 2 with more data", b"x"]

    rc = lbn_save(path, packets, compress=0)
    assert rc == 0

    loaded = lbn_load(path)
    assert loaded == packets


def test_lbn_v1_1_compressed_roundtrip(tmp_path):
    path = str(tmp_path / "test_v1_1_comp.lbn")
    # Repetitive data compresses well
    packets = [b"A" * 1000, b"B" * 2000, b"C" * 500]

    rc = lbn_save(path, packets, compress=1)
    assert rc == 0

    # Verify compression occurred on disk
    assert os.path.getsize(path) < 3500

    loaded = lbn_load(path)
    assert loaded == packets


def test_lbn_v1_0_roundtrip(tmp_path):
    path = str(tmp_path / "test_v1_0.lbn")
    packets = [b"legacy pkt 1", b"legacy pkt 2"]

    rc = lbn_save_v1_0(path, packets, compress=0)
    assert rc == 0

    loaded = lbn_load(path)
    assert loaded == packets


def test_lbn_checksum_corruption_detection(tmp_path):
    path = str(tmp_path / "corrupt.lbn")
    lbn_save(path, [b"secret payload"], compress=0)

    # Corrupt 1 byte in the 20-byte header (e.g. byte offset 8 in header = byte 12 in file)
    with open(path, "r+b") as f:
        f.seek(12)
        val = f.read(1)[0]
        f.seek(12)
        f.write(bytes([val ^ 0xFF]))

    # Must fail checksum verification and return None
    assert lbn_load(path) is None


def test_lbn_saving_high_level(tmp_path):
    path = str(tmp_path / "stream.lbn")
    ok = lbn_save(path, [b"packet-a", b"packet-b"], 2, compress=1)
    assert ok == 0

    result = lbn_load(path)
    assert result == [b"packet-a", b"packet-b"]

