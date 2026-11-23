"""Conservative QPACK expansion preflight before entering the native decoder.

The mirror keeps bounded entry-length metadata, not header values. Unsupported
or unverifiable blocks stop analysis instead of being decompressed speculatively.
"""

from hpack.huffman_table import decode_huffman
from .decode_errors import DecodeError
from .qpack_static import STATIC_LENGTHS
from .qpack_budget import TABLE_CAPACITY
from array import array


class LengthRing:
    """Fixed 8 bytes per slot; absolute indexes cannot alias overwritten slots."""

    def __init__(self, capacity):
        self.slots = max(1, capacity // 32)
        self.data = array("I", [0]) * (2 * self.slots)
        self.inserted = 0

    def __len__(self):
        return min(self.inserted, self.slots)

    def __getitem__(self, index):
        if not max(0, self.inserted-self.slots) <= index < self.inserted:
            raise KeyError(index)
        start = 2 * (index % self.slots)
        return self.data[start], self.data[start+1]

    def append(self, name, value):
        start = 2 * (self.inserted % self.slots)
        self.data[start], self.data[start+1] = name, value
        self.inserted += 1

    def clear(self):
        self.data = array("I")
        self.inserted = 0


class NeedMore(Exception):
    pass


def integer(data, position, prefix):
    if position >= len(data):
        raise NeedMore
    mask = (1 << prefix) - 1
    value = data[position] & mask
    position += 1
    if value < mask:
        return value, position
    shift = 0
    while True:
        if position >= len(data):
            raise NeedMore
        byte = data[position]
        position += 1
        if shift > 56:
            raise DecodeError("limits.qpack_integer")
        value += (byte & 127) << shift
        if not byte & 128:
            return value, position
        shift += 7


class Guard:
    def __init__(self, capacity=4096, maximum=16384, fields=64):
        if not isinstance(capacity, int) or not 0 <= capacity <= TABLE_CAPACITY:
            raise ValueError("unsupported QPACK capacity")
        self.capacity, self.maximum, self.fields = capacity, maximum, fields
        self.entries = LengthRing(capacity)
        self.inserted = 0
        self.buffer = bytearray()

    def string(self, data, position, prefix=7, huffman_bit=128):
        if position >= len(data):
            raise NeedMore
        huffman = bool(data[position] & huffman_bit)
        length, start = integer(data, position, prefix)
        # RFC 7541 Huffman symbols use at least five bits per output octet.
        bound = (length * 8 + 4) // 5 if huffman else length
        if bound > self.maximum:
            raise DecodeError("limits.qpack_literal")
        if start + length > len(data):
            raise NeedMore
        encoded = bytes(data[start : start + length])
        size = len(decode_huffman(encoded)) if huffman else length
        return size, start + length

    def entry(self, absolute):
        try:
            return self.entries[absolute]
        except KeyError:
            raise DecodeError("qpack.invalid_reference")

    def insert(self, name, value):
        if name + value + 32 > self.capacity:
            raise DecodeError("limits.qpack_entry_capacity",
                              requested_bytes=name + value + 32, limit_bytes=self.capacity)
        self.entries.append(name, value)
        self.inserted += 1
        # No dynamic table can retain more than capacity/32 entries. Keeping
        # this metadata superset avoids unsafe eviction based on upper bounds.

    def feed_encoder(self, data):
        if len(self.buffer) + len(data) > self.maximum:
            raise DecodeError("limits.qpack_encoder")
        self.buffer.extend(data)
        position = 0
        while position < len(self.buffer):
            start = position
            byte = self.buffer[position]
            try:
                if byte & 128:
                    index, position = integer(self.buffer, position, 6)
                    if byte & 64:
                        if index >= 99:
                            raise DecodeError("qpack.invalid_reference")
                        name = STATIC_LENGTHS[index][0]
                    else:
                        name = self.entry(self.inserted - index - 1)[0]
                    value, position = self.string(self.buffer, position)
                    action = (name, value)
                elif byte & 64:
                    name, position = self.string(self.buffer, position, 5, 32)
                    value, position = self.string(self.buffer, position)
                    action = (name, value)
                elif byte & 32:
                    capacity, position = integer(self.buffer, position, 5)
                    if capacity > self.capacity:
                        raise DecodeError("limits.qpack_table_capacity",
                                          requested_bytes=capacity, limit_bytes=self.capacity)
                    action = None
                else:
                    index, position = integer(self.buffer, position, 5)
                    action = self.entry(self.inserted - index - 1)
            except NeedMore:
                position = start
                break
            if action is not None:
                self.insert(*action)
        validated = bytes(self.buffer[:position])
        del self.buffer[:position]
        return validated

    def check(self, data):
        if len(data) > self.maximum:
            raise DecodeError("limits.qpack_encoded")
        try:
            encoded, position = integer(data, 0, 8)
            if encoded:
                entries = self.capacity // 32
                if not entries or encoded > 2 * entries:
                    raise DecodeError("qpack.invalid_field")
                maximum = self.inserted + entries
                required = maximum // (2 * entries) * (2 * entries) + encoded - 1
                if required > maximum:
                    required -= 2 * entries
                if required <= 0:
                    raise DecodeError("qpack.invalid_field")
            else:
                required = 0
            if position >= len(data):
                raise NeedMore
            sign = bool(data[position] & 128)
            delta, position = integer(data, position, 7)
            base = required - delta - 1 if sign else required + delta
            if base < 0:
                raise DecodeError("qpack.invalid_field")
            if required > self.inserted:
                return False
            total = count = 0
            while position < len(data):
                byte = data[position]
                if byte & 128:
                    index, position = integer(data, position, 6)
                    if byte & 64:
                        if index >= 99:
                            raise DecodeError("qpack.invalid_reference")
                        name, value = STATIC_LENGTHS[index]
                    else:
                        name, value = self.entry(base - index - 1)
                elif byte & 64:
                    index, position = integer(data, position, 4)
                    if byte & 16:
                        if index >= 99:
                            raise DecodeError("qpack.invalid_reference")
                        name = STATIC_LENGTHS[index][0]
                    else:
                        name = self.entry(base - index - 1)[0]
                    value, position = self.string(data, position)
                elif byte & 32:
                    name, position = self.string(data, position, 3, 8)
                    value, position = self.string(data, position)
                elif byte & 16:
                    index, position = integer(data, position, 4)
                    name, value = self.entry(base + index)
                else:
                    index, position = integer(data, position, 3)
                    name = self.entry(base + index)[0]
                    value, position = self.string(data, position)
                count += 1
                total += name + value + 32
                if count > self.fields or total > self.maximum:
                    raise DecodeError("limits.qpack_decoded")
            return True
        except NeedMore as error:
            raise DecodeError("qpack.truncated") from error
