# Copyright 2015 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# Modified by:
#     - @Young-Lord <ly-niko@qq.com>

from typing import List, Tuple
from . import util

# Code for parsing the various Dalvik opcode formats
INSTRUCTION_FORMAT = util.keysToRanges(
    {
        0x00: "10x",
        0x01: "12x",
        0x02: "22x",
        0x03: "32x",
        0x04: "12x",
        0x05: "22x",
        0x06: "32x",
        0x07: "12x",
        0x08: "22x",
        0x09: "32x",
        0x0A: "11x",
        0x0B: "11x",
        0x0C: "11x",
        0x0D: "11x",
        0x0E: "10x",
        0x0F: "11x",
        0x10: "11x",
        0x11: "11x",
        0x12: "11n",
        0x13: "21s",
        0x14: "31i",
        0x15: "21h",
        0x16: "21s",
        0x17: "31i",
        0x18: "51l",
        0x19: "21h",
        0x1A: "21c",
        0x1B: "31c",
        0x1C: "21c",
        0x1D: "11x",
        0x1E: "11x",
        0x1F: "21c",
        0x20: "22c",
        0x21: "12x",
        0x22: "21c",
        0x23: "22c",
        0x24: "35c",
        0x25: "3rc",
        0x26: "31t",
        0x27: "11x",
        0x28: "10t",
        0x29: "20t",
        0x2A: "30t",
        0x2B: "31t",
        0x2C: "31t",
        0x2D: "23x",
        0x32: "22t",
        0x38: "21t",
        0x3E: "10x",
        0x44: "23x",
        0x52: "22c",
        0x60: "21c",
        0x6E: "35c",
        0x73: "10x",
        0x74: "3rc",
        0x79: "10x",
        0x7B: "12x",
        0x90: "23x",
        0xB0: "12x",
        0xD0: "22s",
        0xD8: "22b",
        0xE3: "10x",
    },
    256,
)


# parsing funcs
def p00op(w):
    return []


def pBAop(w):
    return [(w >> 8) & 0xF, w >> 12]


def pAAop(w):
    return [w >> 8]


def p00opAAAA(w, w2):
    return [w2]


def pAAopBBBB(w, w2):
    return [w >> 8, w2]


def pAAopCCBB(w, w2):
    return [w >> 8, w2 & 0xFF, w2 >> 8]


def pBAopCCCC(w, w2):
    return [(w >> 8) & 0xF, w >> 12, w2]


def p00opAAAAAAAA(w, w2, w3):
    return [w2 ^ (w3 << 16)]


def p00opAAAABBBB(w, w2, w3):
    return [w2, w3]


def pAAopBBBBBBBB(w, w2, w3):
    return [w >> 8, w2 ^ (w3 << 16)]


def pAGopBBBBFEDC(w, w2, w3):
    a = w >> 12
    c, d, e, f = (w3) & 0xF, (w3 >> 4) & 0xF, (w3 >> 8) & 0xF, (w3 >> 12) & 0xF
    g = (w >> 8) & 0xF
    return [w2, [c, d, e, f, g][:a]]


def pAAopBBBBCCCC(w, w2, w3):
    a = w >> 8
    return [w2, range(w3, w3 + a)]


def pAAopBBBBBBBBBBBBBBBB(w, w2, w3, w4, w5):
    b = w2 ^ (w3 << 16) ^ (w4 << 32) ^ (w5 << 48)
    return [w >> 8, b]


_FUNC = {
    "10x": p00op,
    "12x": pBAop,
    "11n": pBAop,
    "11x": pAAop,
    "10t": pAAop,
    "20t": p00opAAAA,
    "22x": pAAopBBBB,
    "21t": pAAopBBBB,
    "21s": pAAopBBBB,
    "21h": pAAopBBBB,
    "21c": pAAopBBBB,
    "23x": pAAopCCBB,
    "22b": pAAopCCBB,
    "22t": pBAopCCCC,
    "22s": pBAopCCCC,
    "22c": pBAopCCCC,
    "30t": p00opAAAAAAAA,
    "32x": p00opAAAABBBB,
    "31i": pAAopBBBBBBBB,
    "31t": pAAopBBBBBBBB,
    "31c": pAAopBBBBBBBB,
    "35c": pAGopBBBBFEDC,
    "3rc": pAAopBBBBCCCC,
    "51l": pAAopBBBBBBBBBBBBBBBB,
}


def sign(x: int, bits: int) -> int:
    if x >= (1 << (bits - 1)):
        x -= 1 << bits
    return x


def decode(shorts: List[int], pos: int, opcode: int) -> Tuple[int, List[int]]:
    fmt = INSTRUCTION_FORMAT[opcode]
    size = int(fmt[0])
    results: List[int] = _FUNC[fmt](*shorts[pos : pos + size])
    # Check if we need to sign extend
    if fmt[2] == "n":
        results[-1] = sign(results[-1], 4)
    elif fmt[2] == "b" or (fmt[2] == "t" and size == 1):
        results[-1] = sign(results[-1], 8)
    elif fmt[2] == "s" or (fmt[2] == "t" and size == 2):
        results[-1] = sign(results[-1], 16)
    elif fmt[2] == "t" and size == 3:
        results[-1] = sign(results[-1], 32)

    # Hats depend on actual size expected, so we rely on opcode as a hack
    if fmt[2] == "h":
        assert opcode == 0x15 or opcode == 0x19
        results[-1] = results[-1] << (16 if opcode == 0x15 else 48)

    # Convert code offsets to actual code position
    if fmt[2] == "t":
        results[-1] += pos
    return pos + size, results
