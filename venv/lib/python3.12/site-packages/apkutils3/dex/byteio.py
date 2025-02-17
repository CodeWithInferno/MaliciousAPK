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

import struct

from .util import signExtend


class Reader:

    def __init__(self, data: bytes, pos: int=0):
        self.data = data
        self.pos = pos

    def read(self, size: int) -> bytes:
        if not 0 <= size <= len(self.data) - self.pos:
            raise IndexError
        result = self.data[self.pos: self.pos + size]
        self.pos += size
        return result

    def _unpack(self, fmt_str: str):
        fmt = struct.Struct(fmt_str)
        return fmt.unpack_from(self.read(fmt.size))[0]

    def u8(self) -> int:
        '''
        1bytes, FF
        '''
        return self.read(1)[0]

    def u16(self) -> int:
        '''
        2bytes FF FF
        '''
        return self._unpack('<H')

    def u32(self) -> int:
        '''
        4bytes FF FF FF FF
        '''
        return self._unpack('<I')

    def u64(self) -> int:
        '''
        8bytes FF FF FF FF FF FF FF FF 
        '''
        return self._unpack('<Q')

    def _leb128(self, signed: bool=False):
        result = 0
        size = 0
        while self.data[self.pos] >> 7:
            result ^= (self.data[self.pos] & 0x7f) << size
            size += 7
            self.pos += 1
        result ^= (self.data[self.pos] & 0x7f) << size
        size += 7
        self.pos += 1

        if signed:
            result = signExtend(result, size)
        return result

    def uleb128(self):
        return self._leb128()

    def sleb128(self):
        return self._leb128(signed=True)

    # Maintain strings in binary encoding instead of attempting to decode them
    # since the output will be using the same encoding anyway
    def readCStr(self) -> bytes:
        oldpos, self.pos = self.pos, self.data.find(b'\0', self.pos)
        return self.data[oldpos:self.pos]


class Writer:

    def __init__(self):
        self.buf = bytearray()

    def write(self, s: bytes) -> None:
        self.buf += s

    def _pack(self, fmt: str, arg):
        return self.write(struct.pack(fmt, arg))

    def u8(self, x) -> None:
        return self.write(bytes([x]))

    def u16(self, x) -> None:
        return self._pack('>H', x)

    def u32(self, x) -> None:
        return self._pack('>I', x)

    def u64(self, x) -> None:
        return self._pack('>Q', x)

    def toBytes(self) -> bytes:
        return bytes(self.buf)
