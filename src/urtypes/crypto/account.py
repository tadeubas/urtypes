# The MIT License (MIT)

# Copyright (c) 2021 Tom J. Sun

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

from ..registry import RegistryType, RegistryItem

CRYPTO_ACCOUNT = RegistryType("crypto-account", 311)


class Account(RegistryItem):
    def __init__(self, master_fingerprint, output_descriptors):
        self.master_fingerprint = master_fingerprint
        self.output_descriptors = output_descriptors

    @classmethod
    def registry_type(cls):
        return CRYPTO_ACCOUNT

    def to_data_item(self):
        _map = {}
        if self.master_fingerprint is not None:
            _map[1] = int.from_bytes(self.master_fingerprint, "big")
        if self.output_descriptors is not None:
            _map[2] = [
                descriptor.to_data_item() for descriptor in self.output_descriptors
            ]
        return _map

    @classmethod
    def from_data_item(cls, item):
        _map = cls.mapping(item)
        master_fingerprint = _map[1].to_bytes(4, "big") if 1 in _map else None

        from .output import Output

        outputs = (
            [Output.from_data_item(item) for item in _map[2]] if 2 in _map else None
        )
        return cls(master_fingerprint, outputs)
