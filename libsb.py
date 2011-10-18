# -*- coding: utf-8 -*-
"""
    libsb
    ~~~~~

    Reads frostbite2 sb and toc files.  Thanks to gibbed for the original
    analysis of the XOR trick for the obfuscation.

    :copyright: (c) Copyright 2011 by Armin Ronacher, Richard Lacharite.
    :license: BSD, see LICENSE for more details.
"""
import struct
from array import array
from itertools import imap
from pprint import pformat


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
        # I don't know if that makes sense.  I do not currently use the
        # values that this function returns
        rv = 0
        while 1:
            b = self.read_byte()
            if b <= 127:
                rv = rv << 7 | b
                break
            rv = rv << 8 | b
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
        rv = self.read(self.read_byte())
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
        return '<FileDef %r>' % self.id


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
        if typecode == 0:
            self.push(None)
        elif typecode == 1:
            self.read_list()
        elif typecode == 2:
            self.push(self.reader.read_sst('h'))
        elif typecode == 6:
            self.push(bool(self.reader.read_byte()))
        elif typecode == 7:
            self.push(self.reader.read_bstring())
        elif typecode == 8:
            self.push(self.reader.read_sst('l'))
        elif typecode == 9:
            self.push(self.reader.read_sst('q'))
        elif typecode == 15:
            self.push(self.reader.read(16).encode('hex')) # md5
        elif typecode == 16:
            self.push(self.reader.read(20).encode('hex')) # sha1
        elif typecode == 19:
            self.push(self.reader.read_varint())
        elif typecode == 129:
            self.read_list()
            x = self.pop()
            self.push(x)
        elif typecode == 130:
            self.read_dict()
        elif typecode == 135:
            # XXX: how is this string different?  I don't know but it's
            # used in the layout.toc file in the fs list.
            self.push(self.reader.read_bstring())
        else:
            raise TOCException('Unknown typecode %d' % typecode)

    def push(self, obj):
        self.stack.append(obj)

    def pop(self):
        return self.stack.pop()

    def read_list(self):
        rv = []
        self.push(rv)
        size_info = self.reader.read_varint()
        # XXX: what is the size info used for?

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
        # XXX: what is the size info used for?

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
