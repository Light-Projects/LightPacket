# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.


from LightPacket.LightBPF.CompilerSet.Compiler import BpfCompiler
from LightPacket.LightBPF.CompilerSet.Emulator import BpfEmulator

def packet_matches(raw_packet_bytes, fstr, linktype=1):
    instructions = BpfCompiler.compile_str(fstr, linktype=linktype)
    match_len = BpfEmulator.execute(instructions, raw_packet_bytes)

    return match_len != 0

