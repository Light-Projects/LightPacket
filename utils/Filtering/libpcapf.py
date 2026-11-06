# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import os
import sys
import ctypes as ct

if sys.platform.startswith('win'):
    npcap_folder = os.path.join(os.environ['WINDIR'], 'System32', 'Npcap')
    if os.path.exists(npcap_folder):
        os.environ['PATH'] = npcap_folder + os.pathsep + os.environ['PATH']

    try:
        pcap = ct.CDLL('wpcap.dll')
    except OSError as e:
        raise OSError(
            "Could not load 'wpcap.dll'. Please ensure Npcap is installed "
            "and that its installation directory is in your system PATH."
        ) from e
else:
    from ctypes.util import find_library
    libpcap_path = find_library("pcap")
    if not libpcap_path:
        raise OSError("Could not find libpcap library.")
    pcap = ct.CDLL(libpcap_path)


class bpf_program(ct.Structure):
    _fields_ = [
        ('bf_len', ct.c_uint),
        ('bf_insns', ct.c_void_p),
    ]

pcap.pcap_compile.argtypes = [
    ct.c_void_p,                # pcap_t *p
    ct.POINTER(bpf_program),    # struct bpf_program *fp
    ct.c_char_p,                # const char *str
    ct.c_int,                   # int optimize
    ct.c_uint32                 # bpf_u_int32 netmask
]
pcap.pcap_compile.restype = ct.c_int

# The core low-level filter function
pcap.bpf_filter.argtypes = [
    ct.c_void_p,                # const struct bpf_insn *pc
    ct.POINTER(ct.c_ubyte),     # const u_char *p
    ct.c_uint,                  # u_int wirelen
    ct.c_uint                   # u_int buflen
]
pcap.bpf_filter.restype = ct.c_uint

# Helper functions
pcap.pcap_open_dead.argtypes = [ct.c_int, ct.c_int]
pcap.pcap_open_dead.restype = ct.c_void_p
pcap.pcap_close.argtypes = [ct.c_void_p]
pcap.pcap_freecode.argtypes = [ct.POINTER(bpf_program)]

def open_handler(filter_str ,linktype=1):
    dead_handle = pcap.pcap_open_dead(linktype, 65535)
    if not dead_handle:
        raise RuntimeError("Failed to create dead pcap handle.")

    filter_program = bpf_program()

    if pcap.pcap_compile(dead_handle, ct.byref(filter_program), filter_str.encode(), 1, 0xFFFFFFFF) < 0:
        pcap.pcap_close(dead_handle)
        raise RuntimeError("Failed to compile filter string.")

    pcap.pcap_close(dead_handle)
    return filter_program

def packet_matches(raw_packet_bytes, fstr, linktype=1):
    """
    Returns True if the raw packet bytes match the compiled BPF filter.
    """
    pkt_len = len(raw_packet_bytes)
    if pkt_len == 0:
        return False

    pkt_buffer = (ct.c_ubyte * pkt_len).from_buffer_copy(raw_packet_bytes)

    filter_program = open_handler(filter_str=fstr, linktype=linktype)
    result = pcap.bpf_filter(
        filter_program.bf_insns, # Pointer to instructions
        pkt_buffer,                    # Packet bytes
        pkt_len,                       # wirelen
        pkt_len                        # buflen
    )

    pcap.pcap_freecode(ct.byref(filter_program))
    return result != 0
