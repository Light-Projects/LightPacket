# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
OSs Consts (Borrowed from Scapy)
"""

from sys import byteorder, maxsize, platform

__all__ = [
    "LINUX",
    "OPENBSD",
    "FREEBSD",
    "NETBSD",
    "DARWIN",
    "SOLARIS",
    "WINDOWS",
    "IS_64BITS",
    "LITTLE_ENDIAN",
]

LINUX    = platform.startswith("linux")
OPENBSD  = platform.startswith("openbsd")
FREEBSD  = platform.startswith("freebsd")
NETBSD   = platform.startswith("netbsd")
DARWIN   = platform.startswith("darwin")
SOLARIS  = platform.startswith("sunos")
WINDOWS  = platform.startswith("win32")

IS_64BITS = maxsize > 2**32
LITTLE_ENDIAN = byteorder == 'little'
