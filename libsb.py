# -*- coding: utf-8 -*-
"""
    libsb
    ~~~~~

    Reads frostbite2 sb and toc files.  Thanks to gibbed for the original
    analysis of the XOR trick for the obfuscation.

    :copyright: (c) Copyright 2011 by Armin Ronacher.
    :license: BSD, see LICENSE for more details.
"""
import struct
from array import array
from itertools import imap


DICE_HEADER = '\x00\xd1\xce\x00'
HASH_OFFSET = 0x08
HASH_SIZE = 256
MAGIC_OFFSET = 0x0128
MAGIC_SIZE = 257
MAGIC_XOR = 0x7b
DATA_OFFSET = 0x022c


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


class TOCReader(object):

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

        self.header = self._fp.read(len(DICE_HEADER))
        if self.header != DICE_HEADER:
            _fail_init('File does not appear to be a TOC file')

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
        self.end = self._fp.tell() - DATA_OFFSET
        self._fp.seek(DATA_OFFSET)
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
        for offset, byte in enumerate(imap(ord, data)):
            i = self.pos + offset
            data[offset] = chr(byte ^ self.magic[i % MAGIC_SIZE] ^ MAGIC_XOR)
        self.pos += length
        return data.tostring()

    def read_st(self, typecode, arch='<'):
        st = get_cached_struct(arch + typecode)
        data = self.read(st.size)
        return st.unpack(data)

    def read_sst(self, typecode, arch='<'):
        rv = self.read_st(typecode, arch)
        assert len(rv) == 1, 'Expected exactly one item, got %d' % len(rv)
        return rv[0]

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

    def close(self):
        if self._managed_fp:
            self._fp.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


def parse_toc_items(reader):
    header = reader.read(4)
    toc_type = reader.read_cstring()
    padding = reader.read(4)

    item = {}

    while 1:
        typecode = reader.read_byte()
        if typecode == 0:
            yield item
            item = {}
            # XXX: I am 12 and what is this?
            garbage = reader.read(2)
            continue
        key = reader.read_cstring()
        if typecode == 7:
            value = reader.read_bstring()
        elif typecode == 8:
            value = reader.read_sst('l')
        elif typecode == 9:
            value = reader.read_sst('q')
        elif typecode == 99:
            # XXX: end of file?
            break
        else:
            raise TOCException('Unknown typecode %r' % typecode)

        item[key] = value

    if item:
        yield item


class FileDefStream(object):

    def __init__(self, fp, limit):
        self._fp = fp
        self.limit = limit
        self.pos = 0

    def read(self, length=None):
        if length is None:
            length = self.limit - self.pos
        rv = self._fp.read(length)
        self.pos += len(rv)
        return rv

    def readline(self, length=None):
        if length is None:
            length = self.limit - self.pos
        rv = self._fp.readline(length)
        self.pos += len(rv)
        return rv

    def close(self):
        if self._fp is not None:
            self._fp.close()
            self._fp = None

    def __iter__(self):
        while 1:
            rv = self.readline()
            if not rv:
                break
            yield rv

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        self.close()


class FileDef(object):

    def __init__(self, bundle, id, offset, size):
        self.bundle = bundle
        self.id = id
        self.offset = offset
        self.size = size

    def get_contents(self):
        with self.open() as f:
            return f.read()

    def open(self):
        f = open(self.bundle.basename + '.sb', 'rb')
        f.seek(self.offset)
        return FileDefStream(f, self.size)

    def __repr__(self):
        return '<FileDef %r>' % self.id


class BundleReader(object):
    """Gives access to a TOC and SB bundle.  Pass it the basename
    (for instance UI, Weapons etc.) and it will add .toc for the TOC
    and .sb for the actual contents.

    :attr:`files` gives access to all files by id in a sanish way.
    The contents of those files are not yet parsed.
    """

    def __init__(self, basename):
        self.basename = basename
        self.files = {}
        with TOCReader(basename + '.toc') as reader:
            for item in parse_toc_items(reader):
                self.files[item['id']] = FileDef(self, **item)
