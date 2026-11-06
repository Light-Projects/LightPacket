# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
BPF Device Constants for macOS, FreeBSD, NetBSD, OpenBSD, and AIX Unix.
Derived directly from the standard kernel file: <net/bpf.h>
"""

from LightPacket.os_consts import IS_64BITS

BIOCGBLEN      = 0x40044266  # Get buffer length for reads (u_int)
BIOCSBLEN      = 0xc0044266  # Set buffer length for reads (u_int)
BIOCSETF       = 0x80104267  # Set packet filter engine program (struct bpf_program)
BIOCFLUSH      = 0x20004268  # Flush incoming packet buffer (None)
BIOCPROMISC    = 0x20004269  # Force interface into promiscuous mode (None)
BIOCGDLT       = 0x4004426a  # Get link-layer type e.g. DLT_EN10MB (u_int)
BIOCGETIF      = 0x4020426b  # Get bound interface name (struct ifreq)
BIOCSETIF      = 0x8020426c  # Bind BPF descriptor to interface (struct ifreq)
BIOCSRTIMEOUT  = 0x8010426d  # Set read timeout limit (struct timeval)
BIOCGRTIMEOUT  = 0x4010426e  # Get read timeout limit (struct timeval)
BIOCGSTATS     = 0x4008426f  # Get performance packet stats (struct bpf_stat)
BIOCIMMEDIATE  = 0x80044270  # Toggle immediate data arrival flag (u_int)
BIOCVERSION    = 0x40044271  # Get BPF translation kernel version (struct bpf_version)
BIOCGRSIG      = 0x40044272  # Get incoming signal (u_int)
BIOCSRSIG      = 0x80044273  # Set incoming signal (u_int)

# Platform-Specific Extensions (Primarily macOS & modern FreeBSD)

BIOCSHDRCMPLT  = 0x80044275  # Set status of link header auto-fill (u_int)
BIOCGHDRCMPLT  = 0x40044276  # Get status of link header auto-fill (u_int)
BIOCSDLT       = 0x80044278  # Change default link-layer type (u_int)
BIOCGDLTLIST   = 0xc0104279  # Retrieve array of supported data-links (struct bpf_dltlist)
BIOCGDIRECTION = 0x4004427b  # Get frame direction filtering status (u_int)
BIOCSDIRECTION = 0x8004427c  # Set frame direction filtering status (u_int)
BIOCSSEESENT   = 0x8004427d  # Toggle capture of self-transmitted packets (u_int)


# struct ifreq (Used by BIOCSETIF / BIOCGETIF)
# Layout: 16 bytes for interface name string, 16 bytes empty buffer space padding.
FMT_IFREQ = "@16s16x"  # Total: 32 bytes

# struct bpf_stat (Used by BIOCGSTATS)
# Layout: Two 4-byte unsigned integers (bs_recv: received, bs_drop: overflow dropped)
FMT_BPF_STAT = "@II"  # Total: 8 bytes

# struct bpf_version (Used by BIOCVERSION)
# Layout: Two 2-byte unsigned short integers (major version, minor version)
FMT_BPF_VERSION = "@HH"  # Total: 4 bytes

# struct timeval (Used by BIOCSRTIMEOUT / BIOCGRTIMEOUT)
# Layout: Two 8-byte long integers (tv_sec: seconds, tv_usec: microseconds (nanoseconds in some platforms) )
# NOTE: On prehistoric 32-bit Unix architectures, this changes to "ii" (4-byte integers).

# Layout:
    #   - tv_sec (8-byte long)
    #   - tv_usec (8-byte long)
    #   - bh_caplen (4-byte unsigned int: chunk size inside the buffer payload)
    #   - bh_datalen (4-byte unsigned int: actual wire packet size)
    #   - bh_hdrlen (2-byte unsigned short: total header size including alignment bytes)
    #   - Explicit padding to alignment boundaries

if IS_64BITS:
    FMT_TIMEVAL = "@ll"  # Total: 16 bytes
    FMT_BPF_HDR = "@llIIH"  # Total Base: 26 bytes (kernel pads this out contextually)
else:
    FMT_TIMEVAL = "@ii"  # Total: 16 bytes
    FMT_BPF_HDR = "@iiIIH"  # Total Base: 26 bytes (kernel pads this out contextually)

# Individual raw assembly statement structure inside a filter chain

FMT_BPF_INSN = "@HBBI"  # Total: 8 bytes per instruction
# Layout breakdown:
#   - code: 2 bytes (unsigned short)
#   - jt:   1 byte  (unsigned char jump-if-true offset)
#   - jf:   1 byte  (unsigned char jump-if-false offset)
#   - k:    4 bytes (unsigned int generic value/offset field)
