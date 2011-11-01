# -*- coding: utf-8 -*-
"""
    libfb2.utils
    ~~~~~~~~~~~~

    Various utilities.

    :copyright: (c) Copyright 2011 by Armin Ronacher, Richard Lacharite, Pilate.
    :license: BSD, see LICENSE for more details.
"""
import struct
from array import array
from itertools import imap, count
from contextlib import contextmanager


DICE_HEADER = '\x00\xd1\xce\x00'
HASH_OFFSET = 0x08
HASH_SIZE = 256
MAGIC_OFFSET = 0x0128
MAGIC_SIZE = 257
MAGIC_XOR = 0x7b
DATA_OFFSET = 0x022c


_structcache = {}


class TypeReader(object):
    """A simple type reader that wraps a Python fd"""

    def __init__(self, fp, limit=None):
        self._fp = fp
        self._offset = fp.tell()
        if limit is None:
            fp.seek(0, 2)
            limit = fp.tell()
            fp.seek(self._offset)
        self.limit = limit
        self.pos = 0

    def read_st(self, typecode, arch='<'):
        st = get_cached_struct(arch + typecode)
        data = self.read(st.size)
        return st.unpack(data)

    def read_sst(self, typecode, arch='<'):
        rv = self.read_st(typecode, arch)
        assert len(rv) == 1, 'Expected exactly one item, got %d' % len(rv)
        return rv[0]

    def read_varint(self):
        rv = 0
        for idx in count():
            byte = self.read_byte()
            rv |= (byte & 0x7f) << (7 * idx)
            if not byte >> 7:
                break
        return rv

    def read_byte(self):
        return ord(self.read(1))

    def read_cstring(self):
        rv = []
        while 1:
            c = self.read(1)
            if c == '\x00':
                break
            rv.append(c)
        return ''.join(rv)

    def read_bstring(self):
        rv = self.read(self.read_varint())
        if not rv or rv[-1] != '\x00':
            raise ValueError('missing bstring delimiter')
        return rv[:-1]

    @property
    def eof(self):
        return self.pos >= self.limit

    def read(self, length=None):
        if length is None:
            length = self.limit - self.pos
        else:
            length = min(length, self.limit - self.pos)
        rv = self._fp.read(length)
        if len(rv) != length:
            raise ValueError('Unexpected end of file')
        self.pos += length
        return rv

    def tell(self):
        return self.pos

    def seek(self, delta, how=0):
        return self._fp.seek(delta, how)

    def seek(self, delta, how=0):
        if how == 0:
            target = max(0, min(delta, self.limit))
        elif how == 1:
            target = max(0, min(delta + self.pos, self.limit))
        elif how == 2:
            target = max(0, min(self.limit - delta, self.limit))
        else:
            raise ValueError('Invalid seek method')
        self._fp.seek(self._offset + target, 0)
        self.pos = target

    def close(self):
        self._fp.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        self.close()


class DecryptingTypeReader(TypeReader):
    """Works like the simple TypeReader but supports decryption."""

    def __init__(self, fp):
        header = fp.read(len(DICE_HEADER))
        if header != DICE_HEADER:
            self.hash = None
            self.magic = None
            data_offset = 0
        else:
            data_offset = DATA_OFFSET
            fp.seek(HASH_OFFSET)
            if fp.read(1) != 'x':
                raise SBException('Hash start marker not found')
            self.hash = fp.read(HASH_SIZE)
            if fp.read(1) != 'x':
                raise SBException('Hash end marker not found')

            fp.seek(MAGIC_OFFSET)
            self.magic = map(ord, fp.read(MAGIC_SIZE))
            if len(self.magic) != MAGIC_SIZE:
                raise SBException('Magic incomplete')

        fp.seek(0, 2)
        limit = fp.tell() - data_offset
        fp.seek(data_offset)
        TypeReader.__init__(self, fp, limit)

    def read(self, length=None):
        start_pos = self.pos
        rv = super(DecryptingTypeReader, self).read(length)
        if self.magic is None:
            return rv
        data = array('c', rv)
        for off, b in enumerate(imap(ord, data)):
            i = start_pos + off
            data[off] = chr(b ^ self.magic[i % MAGIC_SIZE] ^ MAGIC_XOR)
        return data.tostring()


def get_cached_struct(typecode):
    if isinstance(typecode, struct.Struct):
        return typecode
    rv = _structcache.get(typecode)
    if rv is None:
        _structcache[typecode] = rv = struct.Struct(typecode)
    return rv


@contextmanager
def open_fp_or_filename(fp_or_filename, mode='rb'):
    if isinstance(fp_or_filename, basestring):
        with open(fp_or_filename, mode) as f:
            yield f
    else:
        yield fp_or_filename
