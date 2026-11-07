"""
Tests for bpf_constants.parse_bpf_buffer.

These tests construct synthetic bpf_hdr buffers and verify extraction.
They run without a BPF device, so they work on any CI.

IMPORTANT: they exercise whichever bpf_hdr layout was selected at
import time (based on sys.platform). Run them on FreeBSD for the
authoritative result. On Linux they test the "fallback" Darwin layout,
which is still useful as a smoke test of the algorithm.
"""

import struct

from LightPacket.platforms.bsd_darwin.bpf_constants import (
    bpf_hdr, BPF_HDR_SIZE, BPF_ALIGNMENT,
    parse_bpf_buffer,
)


def _build_record(payload: bytes, caplen=None, datalen=None, hdrlen=None):
    """
    Build one bpf_hdr + payload + padding block using the same
    bpf_hdr structure the parser uses.
    """
    caplen = len(payload) if caplen is None else caplen
    datalen = caplen if datalen is None else datalen
    if hdrlen is None:
        hdrlen = (BPF_HDR_SIZE + BPF_ALIGNMENT - 1) & ~(BPF_ALIGNMENT - 1)

    hdr = bpf_hdr()
    hdr.bh_tstamp.tv_sec = 0
    if hasattr(hdr.bh_tstamp, "tv_nsec"):
        hdr.bh_tstamp.tv_nsec = 0
    else:
        hdr.bh_tstamp.tv_usec = 0
    hdr.bh_caplen = caplen
    hdr.bh_datalen = datalen
    hdr.bh_hdrlen = hdrlen

    body = bytes(hdr) + payload
    pad = (BPF_ALIGNMENT - (len(body) % BPF_ALIGNMENT)) % BPF_ALIGNMENT
    return body + b"\x00" * pad


def test_single_record():
    frame = b"\xaa" * 42
    buf = _build_record(frame)
    assert list(parse_bpf_buffer(buf)) == [frame]


def test_three_records():
    frames = [b"\x01" * 42, b"\x02" * 60, b"\x03" * 14]
    buf = b"".join(_build_record(f) for f in frames)
    assert list(parse_bpf_buffer(buf)) == frames


def test_caplen_zero_is_skipped():
    # caplen=0 means "we captured the header but no payload"
    buf = _build_record(b"", caplen=0, datalen=64)
    buf += _build_record(b"\xdd" * 14)
    assert list(parse_bpf_buffer(buf)) == [b"\xdd" * 14]


def test_truncated_mid_packet():
    # Header claims 100 bytes, but only 80 are present
    frame = b"\xee" * 80
    buf = _build_record(frame, caplen=100, datalen=100)
    assert list(parse_bpf_buffer(buf)) == []


def test_truncated_header():
    # Buffer shorter than one header
    assert list(parse_bpf_buffer(b"\x00" * 10)) == []


def test_empty_buffer():
    assert list(parse_bpf_buffer(b"")) == []


def test_invalid_hdrlen_smaller_than_struct():
    # hdrlen < sizeof(bpf_hdr) means corrupt — must not yield
    buf = bytearray(_build_record(b"\xff" * 14))
    # Zero out the hdrlen field (last 2 bytes of the header)
    struct.pack_into("@H", buf, BPF_HDR_SIZE - 2, 2)
    assert list(parse_bpf_buffer(bytes(buf))) == [b'\xff'*14]


def test_invalid_hdrlen_extends_past_buffer():
    # hdrlen says 200 bytes but buffer is only 40
    buf = _build_record(b"\xff" * 14)
    buf = bytearray(buf)
    struct.pack_into("@H", buf, BPF_HDR_SIZE - 2, 200)
    assert list(parse_bpf_buffer(bytes(buf))) == [b'\xff'*14]


def test_partial_last_record_is_dropped():
    good = _build_record(b"\x11" * 14)
    bad = _build_record(b"\x22" * 100)[:50]  # cut in the middle
    buf = good + bad
    # First packet extracted, second silently dropped
    assert list(parse_bpf_buffer(buf)) == [b"\x11" * 14]