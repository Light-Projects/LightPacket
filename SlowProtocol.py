# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import struct
from LightPacket.BaseLayer import BaseLayer
from LightPacket.Logger.LightLogger import Logger, ErrorCode
from LightPacket.Decoration.Colors import BOLD, RESET, CYAN, BLUE, PURPLE

LLogger = Logger()

"""
SlowProtocol Layer Creation (class SlowProtocol)
"""

class SlowProtocol(BaseLayer):
    def __init__(self, subtype=0x01):
        super().__init__()
        self.subtype = subtype

    def build(self):
        return struct.pack("!B", self.subtype) + self.get_payload_bytes()

    def __len__(self):
        return 1 + (len(self.payload) if self.payload else 0)

    def __repr__(self):
        return (
            f"<SlowProtocol subtype={hex(self.subtype)} >")

    def copy(self) -> 'SlowProtocol':
        new_layer = SlowProtocol(
            subtype=self.subtype
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        return [
            f"subtype={self.subtype}"
        ]

"""
SlowProtocol Parser (separate from the builder)
"""

class SlowProtocolParser:

    @staticmethod
    def load_as_slowprotocol_layer(raw_packet,Alr=0,verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        if len(raw_packet[0]) < 1:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,message="SlowProtocol required header is 1 bytes")


        SSHEADER = raw_packet[0][:1]

        subtype = struct.unpack('!B', SSHEADER)

        payload = raw_packet[0][1:]
        Lenght = len(SSHEADER)
        Total = len(payload) + Lenght

        if verbose:
            print(f"\n{BOLD}SLOW-PROTOCOL LAYER : {RESET}Len({PURPLE}{Lenght}{RESET}) Total Len({PURPLE}{Total}{RESET}) >")
            print(f'   {BLUE}SUBTYPE:{CYAN} {hex(subtype)}{RESET}')

        ss = SlowProtocol(
            subtype=subtype
        )

        if len(payload) > 0:
            from LightPacket.Raw import RawParser
            prelayer = RawParser.load_as_Raw_layer(payload,verbose=verbose)

            return ss / prelayer
        return ss

