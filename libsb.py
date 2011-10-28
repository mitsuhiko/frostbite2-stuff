# -*- coding: utf-8 -*-
"""
    libsb
    ~~~~~

    Reads frostbite2 sb and toc files.  Thanks to gibbed for the original
    analysis of the XOR trick for the obfuscation.

    :copyright: (c) Copyright 2011 by Armin Ronacher, Richard Lacharite, Pilate.
    :license: BSD, see LICENSE for more details.
"""
import os
import struct
from StringIO import StringIO
from uuid import UUID
from array import array
from itertools import imap
from datetime import datetime


DICE_HEADER = '\x00\xd1\xce\x00'
HASH_OFFSET = 0x08
HASH_SIZE = 256
MAGIC_OFFSET = 0x0128
MAGIC_SIZE = 257
MAGIC_XOR = 0x7b
DATA_OFFSET = 0x022c
CAS_CAT_HEADER = 'Nyan' * 4


_structcache = {}


def get_cached_struct(typecode):
    if isinstance(typecode, struct.Struct):
        return typecode
    rv = _structcache.get(typecode)
    if rv is None:
        _structcache[typecode] = rv = struct.Struct(typecode)
    return rv


class TOCException(Exception):
    pass


class CASException(Exception):
    pass


class TypeReaderMixin(object):

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
        while 1:
            val = self.read_byte()
            rv = (rv << 7) | (val & 0x7f)
            if not val >> 7:
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
            raise TOCException('missing bstring delimiter')
        return rv[:-1]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


class TOCReader(TypeReaderMixin):
    """Reads a TOC/Superbundle file.  If the file starts with the
    magic DICE header (00D1CE00) it's xor "encrypted" with the key of
    the encryption starting at `MAGIC_OFFSET`.  Otherwise it starts
    reading the data direction from the first byte.
    """

    def __init__(self, fp_or_filename):
        if hasattr(fp_or_filename, 'read'):
            self._fp = fp_or_filename
            self._managed_fp = False
        else:
            self._fp = open(fp_or_filename, 'rb')
            self._managed_fp = True

        def _fail_init(message):
            self.close()
            raise TOCException(message)

        header = self._fp.read(len(DICE_HEADER))
        if header != DICE_HEADER:
            self.hash = None
            self.magic = None
            data_offset = 0
        else:
            data_offset = DATA_OFFSET
            self._fp.seek(HASH_OFFSET)
            if self._fp.read(1) != 'x':
                _fail_init('Hash start marker not found')
            self.hash = self._fp.read(HASH_SIZE)
            if self._fp.read(1) != 'x':
                _fail_init('Hash end marker not found')

            self._fp.seek(MAGIC_OFFSET)
            self.magic = map(ord, self._fp.read(MAGIC_SIZE))
            if len(self.magic) != MAGIC_SIZE:
                _fail_init('Magic incomplete')

        self._fp.seek(0, 2)
        self.end = self._fp.tell() - data_offset
        self._fp.seek(data_offset)
        self.pos = 0

    @property
    def eof(self):
        return self.pos >= self.end

    def read(self, length=None):
        if length is None:
            length = self.end - self.pos
        data = array('c', self._fp.read(length))
        if len(data) != length:
            raise TOCException('Unexpected end of file')
        if self.magic is not None:
            for off, b in enumerate(imap(ord, data)):
                i = self.pos + off
                data[off] = chr(b ^ self.magic[i % MAGIC_SIZE] ^ MAGIC_XOR)
        self.pos += length
        return data.tostring()

    def close(self):
        if self._managed_fp:
            self._fp.close()


class BundleFileStream(TypeReaderMixin):

    def __init__(self, fp, limit):
        self._fp = fp
        self.limit = limit
        self.pos = 0

    def read(self, length=None):
        if length is None:
            length = self.limit - self.pos
        rv = self._fp.read(length)
        if len(rv) != length:
            raise TOCException('Unexpected end of file')
        self.pos += length
        return rv

    def close(self):
        if self._fp is not None:
            self._fp.close()
            self._fp = None


class BundleFile(object):

    def __init__(self, bundle, id, offset, size):
        self.bundle = bundle
        self.id = id
        self.offset = offset
        self.size = size

    def get_raw_contents(self):
        with self.open() as f:
            return f.read()

    def get_parsed_contents(self):
        with self.open() as f:
            parser = TOCParser(f)
            parser.read_object()
            return parser.pop()

    def open(self):
        f = open(self.bundle.basename + '.sb', 'rb')
        f.seek(self.offset)
        return BundleFileStream(f, self.size)

    def __repr__(self):
        return '<BundleFile %r>' % self.id


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
    """Represents a blob.  So far I have not found a file where the blob is
    extra large but just in case the repr compresses it.  This mainly exists
    so that the structure can be reversed without loss of data.
    """
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


class TOCParser(object):
    """Parses TOC/Superbundle files.  Each value read is put on on a stack
    temporarily until something else consumes it.  Even things such as
    dictionary keys end up on there temporarily to aid debugging.
    """

    def __init__(self, reader):
        self.reader = reader
        self.stack = []

    def read_object(self, typecode=None):
        if typecode is None:
            typecode = self.reader.read_byte()
        raw_typecode = typecode
        flags = typecode >> 5
        typecode = typecode & 0x1f

        if typecode == 0:
            self.push(None)
        elif typecode == 1:
            self.read_list()
        elif typecode == 2:
            self.read_dict()
        elif typecode == 5:
            self.push(Unknown(5, self.reader.read(8)))
        elif typecode == 6:
            self.push(bool(self.reader.read_byte()))
        elif typecode == 7:
            self.push(self.reader.read_bstring())
        elif typecode == 8:
            self.push(self.reader.read_sst('l'))
        elif typecode == 9:
            self.push(self.reader.read_sst('q'))
        elif typecode == 15:
            self.push(UUID(bytes=self.reader.read(16)))
        elif typecode == 16:
            self.push(SHA1(self.reader.read(20)))
        elif typecode == 19:
            # XXX: either read_varint is broken or there is some extra
            # information in there for the blobs.  It fails to read one
            # of the beta files.
            size = self.reader.read_varint()
            self.push(Blob(self.reader.read(size)))
        else:
            raise TOCException('Unknown type marker %x (type=%d)' %
                               (raw_typecode, typecode))

    def push(self, obj):
        self.stack.append(obj)

    def pop(self):
        return self.stack.pop()

    def read_list(self):
        rv = []
        self.push(rv)
        size_info = self.reader.read_varint()
        # We don't need the size_info since the collection is delimited

        while 1:
            self.read_object()
            value = self.pop()
            if value is None:
                break
            rv.append(value)

        # at that point, reverse the list
        rv.reverse()

    def read_dict(self):
        rv = {}
        self.push(rv)
        size_info = self.reader.read_varint()
        # We don't need the size_info since the collection is delimited

        while 1:
            typecode = self.reader.read_byte()
            if typecode == 0:
                break
            key = self.reader.read_cstring()
            self.push(key) # for debugging, if it blows up the key is on the stack
            self.read_object(typecode=typecode)
            value = self.pop()
            self.pop()
            rv[key] = value


class BundleReader(object):
    """Gives access to a TOC and SB bundle.  Pass it the basename
    (for instance UI, Weapons etc.) and it will add .toc for the TOC
    and .sb for the actual contents.

    :attr:`files` gives access to all files by id in a sanish way.
    The contents of those files are not yet parsed.
    """

    def __init__(self, basename):
        self.basename = basename
        with TOCReader(basename + '.toc') as reader:
            parser = TOCParser(reader)
            parser.read_object()
            self.root = parser.pop()
            assert not parser.stack, 'Parsing error left stack filled'

    def list_files(self):
        """Lists all files in the bundle."""
        result = []
        for bundle in self.root['bundles']:
            result.append(bundle['id'])
        return result

    def get_file(self, id):
        """Gets a bundle file."""
        # O(n) FTL.  Put them into an index on init?
        for bundle in self.root['bundles']:
            if bundle['id'] == id:
                return BundleFile(self, **bundle)


class CASFileReader(TypeReaderMixin):
    """Reads CAS files."""

    def __init__(self, fp_or_filename):
        if hasattr(fp_or_filename, 'read'):
            self._fp = fp_or_filename
            self._managed_fp = False
        else:
            self._fp = open(fp_or_filename, 'rb')
            self._managed_fp = True

    def read(self, length=None):
        return self._fp.read(length or -1)

    def get_next_file(self):
        header = self.read(4)
        hash = self.read(20).encode('hex')
        data_length = self.read_sst('q')
        return CASFile(hash, self._fp, data_length)

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def close(self):
        if self._managed_fp:
            self._fp.close()


class CASFile(object):

    def __init__(self, hash, fp, size):
        self.hash = hash
        self.fp = fp
        self.offset = fp.tell()
        self.size = size

    def get_raw_contents(self):
        with self.open() as f:
            return f.read()

    def open(self):
        f = os.fdopen(os.dup(self.fp.fileno()))
        f.seek(self.offset)
        return BundleFileStream(f, self.size)

    def __repr__(self):
        return '<CASFile %r>' % self.hash


class CASCatalog(TypeReaderMixin):
    """Not sure yet how to read this."""

    def __init__(self, filename):
        self._fp = open(filename, 'rb')
        header = self._fp.read(len(CAS_CAT_HEADER))
        if header != CAS_CAT_HEADER:
            self.close()
            raise CASException('Does not look like a CAS catalog')

    def close(self):
        self._fp.close()


def decrypt(filename, new_filename=None):
    """Decrypts a file for debugging."""
    if new_filename is None:
        new_filename = filename + '.decrypt'
    with open(new_filename, 'wb') as f:
        with TOCReader(filename) as reader:
            f.write(reader.read())


def loads(string):
    """Quick"""
    return load(StringIO(string))


def load(filename_or_fp):
    """Loads a TOC object from a file."""
    with TOCReader(filename_or_fp) as reader:
        parser = TOCParser(reader)
        parser.read_object()
        return parser.pop()
