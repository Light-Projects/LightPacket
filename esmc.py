# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import struct
from LightPacket.BaseLayer import BaseLayer
from LightPacket.Logger.LightLogger import Logger, ErrorCode
from LightPacket.Decoration.Colors import BOLD, RESET, CYAN, BLUE, PURPLE

LLogger = Logger()

"""
ESMC Layer Creation (class ESMC)
"""

class ESMC(BaseLayer):
    def __init__(self, oui=b'\x00\x19\xA7', subtype=0x01, version=1,
                 event=1, reserved1=0, reserved2=b'\x00\x00\x00'):
        super().__init__()
        self.subtype = subtype
        self.oui = oui
        self.version = version
        self.event = event
        self.reserved1 = reserved1
        self.reserved2 = reserved2

    def build(self):
        flags = ((self.version & 0xF) << 4) | \
                ((self.event & 0x1) << 3) | \
                (self.reserved1 & 0x7)
        header = struct.pack("!3sHB3s", self.oui, self.subtype,
                             flags, self.reserved2)
        return header + self.get_payload_bytes()

    def __len__(self):
        return 9 + (len(self.payload) if self.payload else 0)

    def __repr__(self):
        return (
            f"<ESMC subtype={hex(self.subtype)} oui={self.oui} version={self.version} "
            f" event={self.event} >")

    def copy(self) -> 'ESMC':
        new_layer = ESMC(
            subtype=self.subtype, oui=self.oui, version=self.version, event=self.event,
            reserved1=self.reserved1, reserved2=self.reserved2
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        return [
            f"subtype={self.subtype}", f"oui={self.oui}", f"version={self.version}", f"event={self.event}",
            f"reserved1={self.reserved1}", f"reserved2={self.reserved2}"
        ]

"""
ESMC Parser (separate from the builder)
"""

class ESMCParser:

    @staticmethod
    def load_as_esmc_layer(raw_packet,Alr=0,verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        if len(raw_packet[0]) < 9:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,message="ESMC required header is 9 bytes")

        ESMCHEADER = raw_packet[0][:9]

        oui, subtype, flags, reserved2 = struct.unpack('!3sHB3s', ESMCHEADER)

        version = (flags >> 4) & 0xF
        event = (flags >> 3) & 0x1
        reserved1 = flags & 0x7

        payload = raw_packet[0][9:]
        Lenght = len(ESMCHEADER)
        Total = len(payload) + Lenght

        if verbose:
            print(f"\n{BOLD}ESMC LAYER : {RESET}Len({PURPLE}{Lenght}{RESET}) Total Len({PURPLE}{Total}{RESET}) >")
            print(f'   {BLUE}SUBTYPE:{CYAN} {subtype}{RESET}')
            print(f'   {BLUE}EVENT:{CYAN} {event}{RESET}')
            print(f'   {BLUE}OUI:{CYAN} {oui}{RESET}')
            print(f'   {BLUE}VERSION:{CYAN} {version}{RESET}')
            print(f'   {BLUE}RESERVED1:{CYAN} {reserved1}{RESET}')
            print(f'   {BLUE}RESERVED2:{CYAN} {reserved2}{RESET}')

        esmc = ESMC(
            subtype=subtype,
            oui=oui,
            version=version,
            event=event,
            reserved1=reserved1,
            reserved2=reserved2
        )

        if len(payload) > 0:
            if payload[0] == 1:
                return esmc / QLTLVParser.load_as_qltlv_layer(payload,verbose=verbose)

            from LightPacket.Raw import RawParser
            prelayer = RawParser.load_as_Raw_layer(payload,verbose=verbose)

            return esmc / prelayer
        return esmc

"""
QLTLV Layer Creation (class QLTLV)
"""

class QLTLV(BaseLayer):
    def __init__(self, type_ = 1 ,length = 4, unused=0, ssmcode=0):
        super().__init__()
        self.type = type_
        self.length = length
        self.unused = unused
        self.ssmcode = ssmcode

    def build(self):
        flags = ((self.unused & 0xF) << 4) | \
                (self.ssmcode & 0x7)
        header = struct.pack("!BHB", self.type, self.length,
                             flags)
        return header + self.get_payload_bytes()

    def __len__(self):
        return 4 + (len(self.payload) if self.payload else 0)

    def __repr__(self):
        return (
            f"<QLTLV type_={self.type} length={self.length} unused={self.unused} "
            f" ssmcode={self.ssmcode} >")

    def copy(self) -> 'QLTLV':
        new_layer = QLTLV(
            type_=self.type,length=self.length,unused=self.unused,ssmcode=self.ssmcode
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        return [
            f"type_={self.type}", f"length={self.length}", f"unused={self.unused}", f"ssmcode={self.ssmcode}",
        ]

"""
QLTLV Parser (separate from the builder)
"""

class QLTLVParser:

    @staticmethod
    def load_as_qltlv_layer(raw_packet,Alr=0,verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        if len(raw_packet[0]) < 4:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,message="QLTLV required header is 4 bytes")

        ESMCHEADER = raw_packet[0][:4]

        type_, length, flags = struct.unpack('!BHB', ESMCHEADER)

        unused = (flags >> 4) & 0xF
        ssmcode = flags & 0x7

        payload = raw_packet[0][4:]
        Lenght = len(ESMCHEADER)
        Total = len(payload) + Lenght

        if verbose:
            print(f"\n{BOLD}QLTLV LAYER : {RESET}Len({PURPLE}{Lenght}{RESET}) Total Len({PURPLE}{Total}{RESET}) >")
            print(f'   {BLUE}TYPE:{CYAN} {type_}{RESET}')
            print(f'   {BLUE}LENGTH:{CYAN} {length}{RESET}')
            print(f'   {BLUE}UNUSED:{CYAN} {unused}{RESET}')
            print(f'   {BLUE}SSMCODE:{CYAN} {ssmcode}{RESET}')

        qltlv = QLTLV(
            type_=type_,
            length=length,
            unused=unused,
            ssmcode=ssmcode
        )

        if len(payload) > 0:
            if payload[0] == 2:
                return qltlv / EQLTLVParser.load_as_eqltlv_layer(payload,verbose=verbose)

            from LightPacket.Raw import RawParser
            prelayer = RawParser.load_as_Raw_layer(payload,verbose=verbose)

            return qltlv / prelayer
        return qltlv

EQLTLV_TYPE   = 0x02
EQLTLV_LENGTH = 20
EQLTLV_SIZE   = 20

class EQLTLV(BaseLayer):
    def __init__(self, type_ = 2, length = EQLTLV_LENGTH, enhanced_ssm_code=0,
                 clock_identity=b"\x00" * 8,
                 cl_mixed_chain=0, cl_partial_chain=0,
                 cascaded_eEECs=0, cascaded_EECs=0,
                 reserved=b"\x00" * 5):
        super().__init__()
        self.type = type_
        self.length = length
        self.enhanced_ssm_code = enhanced_ssm_code
        self.clock_identity    = clock_identity
        self.cl_mixed_chain    = cl_mixed_chain & 0x1
        self.cl_partial_chain  = cl_partial_chain & 0x1
        self.cascaded_eEECs    = cascaded_eEECs
        self.cascaded_EECs     = cascaded_EECs
        self.reserved          = reserved

    def build(self):
        flag = ((self.cl_mixed_chain   & 0x1) << 0) | \
               ((self.cl_partial_chain & 0x1) << 1)
        header = struct.pack(
            "!BH B 8s B BB 5s",
            self.type, self.length, self.enhanced_ssm_code,
            self.clock_identity, flag,
            self.cascaded_eEECs, self.cascaded_EECs,
            self.reserved,
        )
        return header + self.get_payload_bytes()

    def __len__(self):
        return EQLTLV_SIZE + (len(self.payload) if self.payload else 0)

    def __repr__(self):
        return (
            f"<EQLTLV type_={self.type} length={self.length} enhanced_ssm_code={self.enhanced_ssm_code} "
            f" clock_identity={self.clock_identity} >")

    def copy(self) -> 'EQLTLV':
        new_layer = EQLTLV(
            type_=self.type,length=self.length,enhanced_ssm_code=self.enhanced_ssm_code,clock_identity=self.clock_identity,
            cl_mixed_chain=self.cl_mixed_chain,cl_partial_chain=self.cl_partial_chain,cascaded_EECs=self.cascaded_EECs,
            cascaded_eEECs=self.cascaded_eEECs,reserved=self.reserved,
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self):
        return [
            f"type=0x{self.type:02x}",
            f"length=0x{self.length:04x}",
            f"enhanced_ssm_code=0x{self.enhanced_ssm_code:02x}",
            f"clock_identity={self.clock_identity.hex(':')}",
            f"cl_mixed_chain={self.cl_mixed_chain}",
            f"cl_partial_chain={self.cl_partial_chain}",
            f"cascaded_eEECs={self.cascaded_eEECs}",
            f"cascaded_EECs={self.cascaded_EECs}",
        ]

class EQLTLVParser:
    @staticmethod
    def load_as_eqltlv_layer(raw, verbose=False):
        if len(raw) < EQLTLV_SIZE:
            LLogger.error(ErrorCode.INVALID_DATA_LENGTH,
                          f"EQLTLV requires {EQLTLV_SIZE} bytes, got {len(raw)}")
            return None

        (type_, length, essm, clock_id, flag,
         c_eEEC, c_EEC, reserved) = struct.unpack("!BH B 8s B BB 5s", raw[:EQLTLV_SIZE])

        if length != EQLTLV_LENGTH:
            LLogger.error(ErrorCode.INVALID_DATA_LENGTH,
                          f"EQLTLV length must be 20, got {length}")
            return None

        payload = raw[EQLTLV_SIZE:]
        Lenght = length
        Total = len(payload) + Lenght

        if verbose:
            print(f"\n{BOLD}EQLTLV LAYER : {RESET}Len({PURPLE}{Lenght}{RESET}) Total Len({PURPLE}{Total}{RESET}) >")
            print(f'   {BLUE}TYPE:{CYAN} {type_}{RESET}')
            print(f'   {BLUE}LENGTH:{CYAN} {length}{RESET}')
            print(f'   {BLUE}E-SSM-CODE:{CYAN} {essm}{RESET}')
            print(f'   {BLUE}CLOCK:{CYAN} {clock_id}{RESET}')
            print(f'   {BLUE}CL-MIXED:{CYAN} {(flag >> 0) & 0x1}{RESET}')
            print(f'   {BLUE}CL-PARTIAL:{CYAN} {(flag >> 1) & 0x1}{RESET}')
            print(f'   {BLUE}eEECs:{CYAN} {c_eEEC}{RESET}')
            print(f'   {BLUE}EECs:{CYAN} {c_EEC}{RESET}')
            print(f'   {BLUE}RESERVED:{CYAN} {reserved}{RESET}')

        eqltlv = EQLTLV(
            type_=type_,
            length=length,
            enhanced_ssm_code=essm,
            clock_identity=clock_id,
            cl_mixed_chain=(flag >> 0) & 0x1,
            cl_partial_chain=(flag >> 1) & 0x1,
            cascaded_eEECs=c_eEEC,
            cascaded_EECs=c_EEC,
            reserved=reserved,
        )


        if len(payload) > 0:
            from LightPacket.Raw import RawParser
            return eqltlv / RawParser.load_as_Raw_layer(payload, verbose=verbose)
        return eqltlv


