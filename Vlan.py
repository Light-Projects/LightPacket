# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import struct
from LightPacket.BaseLayer import BaseLayer
from LightPacket.Logger.LightLogger import Logger, ErrorCode
from LightPacket.Decoration.Colors import BOLD, RESET, CYAN, BLUE, PURPLE, YELLOW

LLogger = Logger()

"""
VLAN Layer Creation (class VLAN)
"""

class VLAN(BaseLayer):

    def __init__(self, tpid=0x8100, priority=0, dei=0, vlan_id=1):

        super().__init__()
        self.tpid = tpid
        self.priority = priority & 0x07
        self.dei = dei & 0x01
        self.vlan_id = vlan_id & 0x0FFF

    def build(self) -> bytes:
        self.check_layers()
        tci = (self.priority << 13) | (self.dei << 12) | self.vlan_id
        result = struct.pack('!HH', self.tpid, tci)

        if self.payload:
            return result + self.payload.build()
        return result

    def check_layers(self) -> int:
        layer = self.payload.__class__.__name__

        if layer == 'VLAN':
            self.tpid = 0x88A8
            numofvlan,self.nxl = self.payload.num()
        else:
            numofvlan = 0
            self.nxl = layer

        return numofvlan

    def num(self):
        return 1 + self.check_layers(),self.nxl

    def __len__(self):
        return 4 + (len(self.payload) if self.payload else 0)

    def __repr__(self):
        return (
            f"<VLAN tpid={hex(self.tpid)}, "
            f"priority={self.priority}, "
            f"dei={self.dei}, "
            f"vlan_id={self.vlan_id}>"
        )

    def copy(self) -> 'VLAN':
        new_layer = VLAN(
            tpid=self.tpid,
            priority=self.priority,
            dei=self.dei,
            vlan_id=self.vlan_id
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        return [
            f"tpid={hex(self.tpid)}",
            f"priority={self.priority}",
            f"dei={self.dei}",
            f"vlan_id={self.vlan_id}"
        ]

"""
VLAN Parser (separate from the builder)
"""

class VLANParser:

    @staticmethod
    def load_as_vlan_layer(raw_packet, Alr=0, verbose=False):

        if type(raw_packet) is not list:
            raw_packet = [raw_packet]

        if len(raw_packet[0]) < 4:
            LLogger.error(
                error_code=ErrorCode.INVALID_DATA_LENGTH,
                message="VLAN required header is 4 bytes"
            )
            return None

        vlan_header = raw_packet[0][:4]
        payload = raw_packet[0][4:]

        tpid, tci = struct.unpack('!HH', vlan_header)

        priority = (tci >> 13) & 0x07
        dei = (tci >> 12) & 0x01
        vlan_id = tci & 0x0FFF

        length = len(vlan_header)
        vlan = VLAN(
            tpid=tpid,
            priority=priority,
            dei=dei,
            vlan_id=vlan_id
        )

        if verbose:
            print(f"\n{BOLD}VLAN LAYER : {RESET}Len({PURPLE}{length}{RESET}) >")
            print(f'   {BLUE}TPID:{CYAN} {hex(tpid)}')
            print(f'   {BLUE}Priority:{CYAN} {priority}')
            print(f'   {BLUE}DEI:{CYAN} {dei}')
            print(f'   {BLUE}VLAN ID:{CYAN} {vlan_id}{RESET}')

        if len(payload) > 0 and tpid == 0x88A8:
            prelayer = VLANParser.load_as_vlan_layer(payload,verbose=verbose)
            return vlan / prelayer

        return vlan


def vlannum(raw_packet):
    count = 0
    offset = 0

    while offset + 4 <= len(raw_packet):
        try:
            tpid = struct.unpack('!H', raw_packet[offset:offset + 2])[0]
            if tpid in [0x8100, 0x88A8, 0x9100, 0x9200]:
                count += 1
                offset += 4
            else:
                break
        except:
            break

    return count


"""
VXLAN Layer Creation (class VXLAN)

Payload: inner Ethernet frame (per RFC 7348 there is no other allowed payload).
Dispatched from UDP destination port 4789.
"""

VXLAN_I_FLAG        = 0x08
VXLAN_VNI_MAX       = 0xFFFFFF
VXLAN_VNI_RESERVED  = 0xFFFFFF
VXLAN_HEADER_LEN    = 8
VXLAN_UDP_PORT      = 4789


class VXLAN(BaseLayer):
    def __init__(self, vni=0, flags=VXLAN_I_FLAG, reserved1=0, reserved2=0):
        super().__init__()
        self.vni = vni
        self.flags = flags & VXLAN_I_FLAG
        self.reserved1 = reserved1
        self.reserved2 = reserved2

    @property
    def i_flag(self) -> bool:
        return bool(self.flags & VXLAN_I_FLAG)

    def build(self):
        first_word = (self.flags << 24) | (self.reserved1 & 0xFFFFFF)
        second_word = (self.vni << 8) | (self.reserved2 & 0xFF)
        header = struct.pack("!II", first_word, second_word)
        return header + self.get_payload_bytes()

    def __len__(self):
        return VXLAN_HEADER_LEN + (len(self.payload) if self.payload else 0)

    def __repr__(self):
        return (
            f"<VXLAN vni={self.vni} flags={hex(self.flags)} "
            f"i={self.i_flag} >"
        )

    def copy(self) -> 'VXLAN':
        new_layer = VXLAN(vni=self.vni, flags=self.flags, reserved1=self.reserved1, reserved2=self.reserved2)
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        return [
            f"flags={hex(self.flags)} (i={self.i_flag})",
            f"vni={self.vni}", f"reserved1={self.reserved1}",
            f"reserved2={self.reserved2}"
        ]


"""
VXLAN Parser (separate from the builder)
"""

class VXLANParser:

    @staticmethod
    def load_as_vxlan_layer(raw_packet, Alr=0, verbose=False ,p=False):
        if not isinstance(raw_packet, list):
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and not isinstance(raw_packet[0], (bytes, bytearray)):
                raw_packet[0] = raw_packet[0].build()

        raw = raw_packet[0]
        if len(raw) < VXLAN_HEADER_LEN:
            LLogger.error(
                error_code=ErrorCode.INVALID_DATA_LENGTH,
                message=f"VXLAN header requires {VXLAN_HEADER_LEN} bytes, got {len(raw)}"
            )
            return None

        first_word, second_word = struct.unpack("!II", raw[:VXLAN_HEADER_LEN])

        flags     = (first_word >> 24) & 0xFF
        reserved1 =  first_word        & 0xFFFFFF
        vni       = (second_word >> 8) & VXLAN_VNI_MAX
        reserved2 =  second_word       & 0xFF

        i_flag = bool(flags & VXLAN_I_FLAG)

        if verbose:
            print(f"\n{BOLD}VXLAN LAYER : {RESET}Len({PURPLE}{VXLAN_HEADER_LEN}{RESET})")
            print(f'   {BLUE}FLAGS: {CYAN}0x{flags:02x}{RESET} (I={YELLOW}{i_flag}{RESET})')
            print(f'   {BLUE}VNI:   {CYAN}{vni}{RESET}')
            print(f'   {BLUE}RESERVED1:  {CYAN}{reserved1}{RESET}')
            print(f'   {BLUE}RESERVED2:  {CYAN}{reserved2}{RESET}')

        vxlan = VXLAN(vni=vni, flags=flags, reserved1=reserved1, reserved2=reserved2)

        payload = raw[VXLAN_HEADER_LEN:]
        if len(payload) > 0:
            from LightPacket.EthernetII import EthernetParser
            from LightPacket.Raw import RawParser
            prelayer = EthernetParser.load_as_ethernet_layer(payload, verbose=verbose, p=p)
            if prelayer is None:
                prelayer = RawParser.load_as_Raw_layer(payload, verbose=verbose)
            return vxlan / prelayer

        return vxlan