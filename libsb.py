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
CAS_HEADER = '\xfa\xce\x0f\xf0'


_structcache = {}


def get_cached_struct(typecode):
    if isinstance(typecode, struct.Struct):
        return typecode
    rv = _structcache.get(typecode)
    if rv is None:
        _structcache[typecode] = rv = struct.Struct(typecode)
    return rv


class SBException(Exception):
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
            byte = self.read_byte()
            val = byte & 0x7f
            if rv == 0:
                rv = val
            else:
                rv = (val << 7) | rv
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
            raise SBException('missing bstring delimiter')
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


class SBReader(TypeReaderMixin):
    """Reads optionally encrypted files.  If the file starts with the
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
            raise SBException(message)

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
            raise SBException('Unexpected end of file')
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
        else:
            length = min(length, self.limit - self.pos)
        rv = self._fp.read(length)
        if len(rv) != length:
            raise SBException('Unexpected end of file')
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
        self._parsed_contents = None

    def get_raw_contents(self):
        with self.open() as f:
            return f.read()

    def get_parsed_contents(self):
        if self._parsed_contents is not None:
            return self._parsed_contents
        with self.open() as f:
            parser = SBParser(f)
            parser.read_object()
            rv = parser.pop()
            self._parsed_contents = rv
            return rv

    def iter_chunk_files(self):
        if self.bundle.cat is None:
            raise RuntimeError('Catalog not loaded')
        meta = self.get_parsed_contents()
        for chunk in meta['chunks']:
            yield chunk['id'], self.bundle.cat.get_file(chunk['sha1'].hex)

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


class SBParser(object):
    """Parses SB/Superbundle files.  Each value read is put on on a stack
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
            size = self.reader.read_varint()
            self.push(Blob(self.reader.read(size)))
        else:
            raise SBException('Unknown type marker %x (type=%d)' %
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


class Bundle(object):
    """Gives access to a SB and SB bundle.  Pass it the basename
    (for instance UI, Weapons etc.) and it will add .toc for the SB
    and .sb for the actual contents.

    :attr:`files` gives access to all files by id in a sanish way.
    The contents of those files are not yet parsed.
    """

    def __init__(self, basename, cat=None):
        self.basename = basename
        self.cat = cat
        self.bundle_files = {}
        with SBReader(basename + '.toc') as reader:
            parser = SBParser(reader)
            parser.read_object()
            self.root = parser.pop()
            assert not parser.stack, 'Parsing error left stack filled'

        for bundle in self.root['bundles']:
            if 'size' in bundle and 'offset' in bundle:
                self.bundle_files[bundle['id']] = BundleFile(self, **bundle)

    def list_files(self):
        """Lists all files in the bundle."""
        result = []
        for bundle in self.root['bundles']:
            result.append(bundle['id'])
        return result

    def get_file(self, id):
        """Opens a file by id."""
        return self.bundle_files[id]


class CASFileReader(TypeReaderMixin):
    """Reads CAS files without the help of the catalog.  This is mainly
    useful for dumping everything in case someone forgot to add an entry
    into the .cat.  It can only read one file after another.
    """

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
        if not header:
            raise EOFError()
        if header != CAS_HEADER:
            raise ValueError('Expected cas header, got %r' % header)
        sha1 = SHA1(self.read(20))
        data_length = self.read_sst('i')
        padding = self.read(4)
        rv = CASFile(sha1, self._fp.tell(), data_length, fp=self._fp)
        self._fp.seek(data_length, 1)
        return rv

    def __iter__(self):
        while 1:
            try:
                yield self.get_next_file()
            except EOFError:
                break

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def close(self):
        if self._managed_fp:
            self._fp.close()


class CASFile(object):
    """A single file from a CAS."""

    def __init__(self, sha1, offset, size, cas_num=-1,
                 cat=None, fp=None):
        self.sha1 = sha1
        self.fp = fp
        self.offset = offset
        self.size = size
        self.cas_num = cas_num
        self.cat = cat

    def get_raw_contents(self):
        with self.open() as f:
            return f.read()

    def open(self):
        if self.fp is not None:
            f = os.fdopen(os.dup(self.fp.fileno()))
        else:
            f = self.cat.open_cas(self.cas_num)
        f.seek(self.offset)
        return BundleFileStream(f, self.size)

    def __repr__(self):
        return '<CASFile %r>' % self.sha1.hex


class CASCatalog(object):
    """Reads CAT files."""

    def __init__(self, filename):
        self.filename = os.path.abspath(filename)
        self.files = {}
        with open(filename, 'rb') as f:
            reader = SBReader(f)
            header = reader.read(len(CAS_CAT_HEADER))
            if header != CAS_CAT_HEADER:
                raise ValueError('Not a cas cat file')
            while not reader.eof:
                sha1 = SHA1(reader.read(20))
                offset = reader.read_sst('i')
                size = reader.read_sst('i')
                cas_num = reader.read_sst('i')
                self.files[sha1.hex] = CASFile(sha1, offset, size, cas_num,
                                               cat=self)

    def get_file(self, sha1):
        return self.files[sha1]

    def read(self, length=None):
        return self._fp.read(length or -1)

    def open_cas(self, num):
        directory, base = os.path.split(self.filename)
        filename = '%s_%02d.cas' % (os.path.splitext(base)[0], num)
        full_filename = os.path.join(directory, filename)
        return open(full_filename, 'rb')


def decrypt(filename, new_filename=None):
    """Decrypts a file for debugging."""
    if new_filename is None:
        new_filename = filename + '.decrypt'
    with open(new_filename, 'wb') as f:
        with SBReader(filename) as reader:
            f.write(reader.read())


def loads(string):
    """Quick"""
    return load(StringIO(string))


def load(filename_or_fp):
    """Loads an SB object from a file."""
    with SBReader(filename_or_fp) as reader:
        parser = SBParser(reader)
        parser.read_object()
        return parser.pop()
