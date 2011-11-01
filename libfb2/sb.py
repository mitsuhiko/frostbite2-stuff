# -*- coding: utf-8 -*-
"""
    libfb2.sb
    ~~~~~~~~~

    Reads frostbite2 sb and toc files.  Thanks to gibbed for the original
    analysis of the XOR trick for the obfuscation.

    :copyright: (c) Copyright 2011 by Armin Ronacher, Richard Lacharite, Pilate.
    :license: BSD, see LICENSE for more details.
"""
import os
import shutil
from StringIO import StringIO
from uuid import UUID
from itertools import izip, chain

from .utils import TypeReader, DecryptingTypeReader, \
     open_fp_or_filename


CAS_CAT_HEADER = 'Nyan' * 4
CAS_HEADER = '\xfa\xce\x0f\xf0'


def generate_one(item):
    yield item


class SBException(Exception):
    pass


class CASException(Exception):
    pass


class CommonFileAccessMethodsMixin(object):
    """Assumes that give accsess to a file returned by the :meth:`open`
    method of the class.
    """
    _parsed_contents = None

    def get_raw_contents(self):
        with self.open() as f:
            return f.read()

    def iter_parse_contents(self, selector):
        with self.open() as f:
            for obj in iterload(f, selector):
                yield obj

    def get_parsed_contents(self, cache=True):
        if self._parsed_contents is not None:
            return self._parsed_contents
        with self.open() as f:
            rv = load(f)
            if cache:
                self._parsed_contents = rv
            return rv


class BundleFile(CommonFileAccessMethodsMixin):

    def __init__(self, bundle, id, offset, size):
        self.bundle = bundle
        self.id = id
        self.offset = offset
        self.size = size

    def iter_chunk_files(self):
        if self.bundle.cat is None:
            raise RuntimeError('Catalog not loaded')
        meta = self.get_parsed_contents()
        for chunk in meta['chunks']:
            yield chunk['id'], self.bundle.cat.get_file(chunk['sha1'].hex)

    def open(self):
        f = open(self.bundle.basename + '.sb', 'rb')
        f.seek(self.offset)
        return TypeReader(f, self.size)

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


class SBParser(object):
    """Parses SB/Superbundle files.  Each value read is put on on a stack
    temporarily until something else consumes it.  Even things such as
    dictionary keys end up on there temporarily to aid debugging.

    Instead of using this use :meth:`load`, :meth:`loads`, :meth:`iterload`
    and :meth:`iterloads`.
    """

    def __init__(self, reader):
        self.reader = reader

    def parse(self):
        """Parse a single object from the reader."""
        gen = self.read_object()
        rv = self.make_object(gen)
        try:
            gen.next()
        except StopIteration:
            return rv
        raise RuntimeError('Garbage left in stream')

    def iterparse(self, selector=None):
        """Parses objects that are below one of the selector."""
        if not callable(selector):
            selector = self.make_selector_function(selector)

        iterator = self.read_object()
        stack = []

        for event in iterator:
            event_type, event_value = event
            if event_type in ('list_start', 'dict_start'):
                if selector(stack):
                    yield self.make_object(chain([event], iterator))
                else:
                    stack.append(None)
            elif event_type in ('list_item', 'dict_key'):
                stack[-1] = event_value
            elif event_type in ('dict_end', 'list_end'):
                stack.pop()
            elif selector(stack):
                yield self.make_object(chain([event], iterator))

    def make_selector_function(self, selector):
        if isinstance(selector, basestring):
            selector = [x.strip() for x in selector.split(',')]
        selectors = [self.parse_selector(x) for x in selector]
        def selector_func(stack):
            for selector in selectors:
                if self.selector_matches(selector, stack):
                    return True
            return False
        return selector_func

    def selector_matches(self, selector, stack):
        if len(stack) != len(selector):
            return False
        for stack_part, selector_part in izip(stack, selector):
            if selector_part is not None and \
               selector_part != stack_part:
                return False
        return True

    def parse_selector(self, selector):
        test_selector = []
        for part in selector.split('.'):
            if part == '*':
                test_selector.append(None)
            elif part.isdigit():
                test_selector.append(int(part))
            else:
                test_selector.append(part)
        return test_selector

    def make_object(self, iterator):
        event_type, event_value = iterator.next()
        if event_type == 'value':
            return event_value
        elif event_type == 'list_start':
            rv = []
            for event in iterator:
                if event[0] == 'list_end':
                    break
                assert event[0] == 'list_item', 'expected list item'
                rv.append(self.make_object(iterator))
            return rv
        elif event_type == 'dict_start':
            rv = {}
            for event in iterator:
                if event[0] == 'dict_end':
                    break
                assert event[0] == 'dict_key', 'expected dict key'
                key = event[1]
                value = self.make_object(iterator)
                rv[key] = value
            return rv
        elif event_type == 'blob_start':
            rv = []
            for event in iterator:
                if event[0] == 'blob_end':
                    break
                assert event[0] == 'blob_chunk', 'expected blob chunk'
                rv.append(event[1])
            return Blob(''.join(rv))
        else:
            raise RuntimeError('Unexpected event %r' % event_type)

    def read_object(self, typecode=None):
        if typecode is None:
            typecode = self.reader.read_byte()
        raw_typecode = typecode
        flags = typecode >> 5
        typecode = typecode & 0x1f

        if typecode == 0:
            yield 'value', None
        elif typecode == 1:
            for event in self.read_list():
                yield event
        elif typecode == 2:
            for event in self.read_dict():
                yield event
        elif typecode == 5:
            yield 'value', Unknown(5, self.reader.read(8))
        elif typecode == 6:
            yield 'value', bool(self.reader.read_byte())
        elif typecode == 7:
            yield 'value', self.reader.read_bstring()
        elif typecode == 8:
            yield 'value', self.reader.read_sst('l')
        elif typecode == 9:
            yield 'value', self.reader.read_sst('q')
        elif typecode == 15:
            yield 'value', UUID(bytes=self.reader.read(16))
        elif typecode == 16:
            yield 'value', SHA1(self.reader.read(20))
        elif typecode == 19:
            for event in self.read_blob():
                yield event
        else:
            raise SBException('Unknown type marker %x (type=%d)' %
                               (raw_typecode, typecode))

    def read_list(self):
        size_info = self.reader.read_varint()
        # We don't need the size_info since the collection is delimited
        yield 'list_start', None

        idx = 0
        while 1:
            typecode = self.reader.read_byte()
            if typecode == 0:
                break
            yield 'list_item', idx
            for event in self.read_object(typecode):
                yield event
            idx += 1

        yield 'list_end', None

    def read_dict(self):
        size_info = self.reader.read_varint()
        # We don't need the size_info since the collection is delimited
        yield 'dict_start', None

        while 1:
            typecode = self.reader.read_byte()
            if typecode == 0:
                break
            yield 'dict_key', self.reader.read_cstring()
            for event in self.read_object(typecode=typecode):
                yield event

        yield 'dict_end', None

    def read_blob(self):
        to_read = self.reader.read_varint()
        yield 'blob_start', to_read
        while to_read > 0:
            read_now = min(to_read, 4096)
            yield 'blob_chunk', self.reader.read(read_now)
            to_read -= read_now
        yield 'blob_end', None


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
        self.root = load(basename + '.toc')

        for bundle in self.root['bundles']:
            if 'size' in bundle and 'offset' in bundle:
                self.bundle_files[bundle['id']] = BundleFile(self, **bundle)

    def list_files(self):
        """Lists all files in the bundle."""
        return self.bundle_files.values()

    def iter_files(self):
        """Iterates oveo all files in the bundle."""
        return self.bundle_files.itervalues()

    def get_file(self, id):
        """Opens a file by id."""
        return self.bundle_files.get(id)


def iter_cas_file(fp_or_filename):
    """Iterates over all files in a CAS."""
    with open_fp_or_filename(fp_or_filename) as f:
        reader = TypeReader(f)
        while 1:
            header = self.read(4)
            if not header:
                break
            if header != CAS_HEADER:
                raise ValueError('Expected cas header, got %r' % header)
            sha1 = SHA1(self.read(20))
            data_length = self.read_sst('i')
            padding = self.read(4)
            rv = CASFile(sha1, self._fp.tell(), data_length, fp=self._fp)
            self._fp.seek(data_length, 1)
            yield rv


class CASFile(CommonFileAccessMethodsMixin):
    """A single file from a CAS."""

    def __init__(self, sha1, offset, size, cas_num=-1,
                 cat=None, fp=None):
        self.sha1 = sha1
        self.fp = fp
        self.offset = offset
        self.size = size
        self.cas_num = cas_num
        self.cat = cat

    def open(self):
        if self.fp is not None:
            f = os.fdopen(os.dup(self.fp.fileno()))
        else:
            f = self.cat.open_cas(self.cas_num)
        f.seek(self.offset)
        return TypeReader(f, self.size)

    def __repr__(self):
        return '<CASFile %r>' % self.sha1.hex


class CASCatalog(object):
    """Reads CAT files."""

    def __init__(self, filename):
        self.filename = os.path.abspath(filename)
        self.files = {}
        with open(filename, 'rb') as f:
            reader = DecryptingTypeReader(f)
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
        """Returns a file by its sha1 checksum."""
        if hasattr(sha1, 'hex'):
            sha1 = sha1.hex
        return self.files.get(sha1)

    def open_cas(self, num):
        """Opens a CAS by number.  This is usually not needed to use directly
        since :meth:`get_file` opens the CAS as necessary.
        """
        directory, base = os.path.split(self.filename)
        filename = '%s_%02d.cas' % (os.path.splitext(base)[0], num)
        full_filename = os.path.join(directory, filename)
        if os.path.isfile(full_filename):
            return open(full_filename, 'rb')

    def open_superbundle(self, name):
        """Opens a superbundle that is relative to the CAS catalog.  This bundle
        has to have a .toc and a .sb file.
        """
        directory = os.path.dirname(self.filename)
        basename = os.path.join(directory, name)
        if os.path.isfile(basename + '.toc'):
            return Bundle(basename, cat=self)


def decrypt(filename, new_filename=None):
    """Decrypts a file for debugging."""
    if new_filename is None:
        new_filename = filename + '.decrypt'
    with open(new_filename, 'wb') as f:
        with DecryptingTypeReader(filename) as reader:
            shutil.copyfileobj(reader, f)


def loads(string):
    """Loads an SB object from a string."""
    return load(StringIO(string))


def load(fp_or_filename):
    """Loads an SB object from a file."""
    with open_fp_or_filename(fp_or_filename) as f:
        reader = DecryptingTypeReader(f)
        return SBParser(reader).parse()


def iterloads(string, selector):
    """Loads SB objects iteratively from from a string that match a selector."""
    return iterload(StringIO(string), selector)


def iterload(fp_or_filename, selector):
    """Loads SB objects iteratively from from a file that match a selector."""
    with open_fp_or_filename(fp_or_filename) as f:
        reader = DecryptingTypeReader(f)
        for obj in SBParser(reader).iterparse(selector):
            yield obj
