# The MIT License (MIT)

# Copyright (c) 2021 Tom J. Sun
# Copyright (c) 2015 Sokolov Yura
# Copyright (c) 2013 Fritz Grimpen

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
# coding: utf-8

from .data import DataItem


class InvalidCborError(Exception):
    pass


class _Break(InvalidCborError):
    def __init__(self):
        InvalidCborError.__init__(self, "Invalid BREAK code occurred")


class Decoder:
    def __init__(self, _input):
        self._jump_table = [
            lambda *args: self.decode_integer(*args, sign=False),
            lambda *args: self.decode_integer(*args, sign=True),
            self.decode_bytestring,
            self.decode_textstring,
            self.decode_list,
            self.decode_dict,
            self.decode_tagging,
            self.decode_other,
        ]
        self.input = _input

    def decode(self):
        mtype, ainfo = self._decode_ibyte()
        try:
            decoder = self._jump_table[mtype]
        except KeyError as e:
            raise InvalidCborError("Invalid major type {}".format(mtype)) from e
        return decoder(mtype, ainfo)

    def decode_integer(self, mtype, ainfo, sign=False):
        res = self._decode_length(ainfo)
        if sign is True:
            return -1 - res
        return res

    def _decode_indefinite_string(self, expected_mtype):
        res = bytearray()
        while True:
            mtype_, ainfo_ = self._decode_ibyte()
            if (mtype_, ainfo_) == (7, 31):  # BREAK
                break
            if mtype_ != expected_mtype:
                pass
            res.extend(self.decode_bytestring(mtype_, ainfo_))
        return res

    def decode_bytestring(self, _mtype, ainfo):
        length = self._decode_length(ainfo)
        if length is None:
            return bytes(self._decode_indefinite_string(2))
        return self._read(length)

    def decode_textstring(self, _mtype, ainfo):
        length = self._decode_length(ainfo)
        if length is None:
            return self._decode_indefinite_string(3).decode("utf-8")
        return self._read(length).decode("utf-8")

    def decode_list(self, mtype, ainfo):
        length = self._decode_length(ainfo)
        if length is None:
            res = []
            while True:
                try:
                    res.append(self.decode())
                except _Break:
                    break
            return res
        res = [None for _ in range(length)]
        for n in range(length):
            res[n] = self.decode()
        return res

    def decode_dict(self, mtype, ainfo):
        length = self._decode_length(ainfo)
        if length is None:
            res = {}
            try:
                while True:
                    key = self.decode()
                    value = self.decode()
                    res[key] = value
            except _Break:
                pass
            return res
        res = {}
        for _ in range(length):
            key, value = self.decode(), self.decode()
            res[key] = value
        return res

    def decode_tagging(self, mtype, ainfo):
        length = self._decode_length(ainfo)
        return DataItem(length, self.decode())

    def decode_half_float(self, mtype, ainfo):
        import struct

        half = struct.unpack(">H", self._read(2))[0]
        valu = (half & 0x7FFF) << 13 | (half & 0x8000) << 16
        if (half & 0x7C00) != 0x7C00:
            import math

            return math.ldexp(struct.unpack("!f", struct.pack("!I", valu))[0], 112)
        return struct.unpack("!f", struct.pack("!I", valu | 0x7F800000))[0]

    def decode_single_float(self, mtype, ainfo):
        import struct

        return struct.unpack(">f", self._read(4))[0]

    def decode_double_float(self, mtype, ainfo):
        import struct

        return struct.unpack(">d", self._read(8))[0]

    def decode_other(self, mtype, ainfo):
        if ainfo == 20:
            return False
        if ainfo == 21:
            return True
        if ainfo == 22:
            return None
        if ainfo == 23:
            from .data import Undefined

            return Undefined
        if ainfo == 25:
            return self.decode_half_float(mtype, ainfo)
        if ainfo == 26:
            return self.decode_single_float(mtype, ainfo)
        if ainfo == 27:
            return self.decode_double_float(mtype, ainfo)
        raise _Break()

    def _decode_ibyte(self):
        byte = self._read(1)[0]
        if isinstance(byte, str):
            byte = ord(byte)
        return (byte & 0b11100000) >> 5, byte & 0b00011111

    def _decode_length(self, ainfo):
        if ainfo < 24:
            return ainfo
        if ainfo == 24:
            return from_bytes(self._read(1))
        if ainfo == 25:
            return from_bytes(self._read(2))
        if ainfo == 26:
            return from_bytes(self._read(4))
        if ainfo == 27:
            return from_bytes(self._read(8))
        if ainfo == 31:
            return None
        raise InvalidCborError("Invalid additional information {}".format(ainfo))

    def _read(self, n):
        m = self.input.read(n)
        if len(m) != n:
            raise InvalidCborError(
                "Expected {} bytes, got {} bytes instead".format(n, len(m))
            )
        return m


__all__ = ("InvalidCborError", "Decoder")


def from_bytes(val):
    return int.from_bytes(val, "big")
