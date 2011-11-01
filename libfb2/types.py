# -*- coding: utf-8 -*-
"""
    libfb2.types
    ~~~~~~~~~~~~

    Common type wrappers.

    :copyright: (c) Copyright 2011 by Armin Ronacher.
    :license: BSD, see LICENSE for more details.
"""


class PrimitiveWrapper(object):
    __slots__ = ()

    @property
    def primitive(self):
        raise NotImplementedError()

    def __hash__(self):
        return hash(self.primitive)

    def __eq__(self, other):
        if type(self) is not type(other):
            return False
        return self.primitive == other.primitive

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        rv = self.primitive
        if isinstance(rv, basestring):
            rv = repr(rv)
        return '<%s %s>' % (self.__class__.__name__, rv)


class BytesPrimitiveWrapper(PrimitiveWrapper):
    __slots__ = ('bytes',)

    def __init__(self, bytes):
        self.bytes = bytes

    def __len__(self):
        return len(self.bytes)

    def __str__(self):
        return str(self.bytes)

    @property
    def primitive(self):
        return self.bytes


class Blob(BytesPrimitiveWrapper):
    """Represents a blob."""
    __slots__ = ()


class SHA1(BytesPrimitiveWrapper):
    """SHA1 hashes are used for content hashes as it seems."""
    __slots__ = ()

    def __init__(self, bytes):
        self.bytes = bytes

    @property
    def hex(self):
        return self.bytes.encode('hex')

    def __repr__(self):
        return '<SHA1 %s>' % self.hex


class Unknown(BytesPrimitiveWrapper):
    __slots__ = ('code',)

    def __init__(self, code, bytes):
        self.code = code
        self.bytes = bytes
