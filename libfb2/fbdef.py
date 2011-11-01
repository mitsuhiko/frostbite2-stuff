# -*- coding: utf-8 -*-
"""
    libfb2.fbdef
    ~~~~~~~~~~~~

    Reads frostbite2 definition files.

    :copyright: (c) Copyright 2011 by Armin Ronacher, Pilate.
    :license: BSD, see LICENSE for more details.
"""
from StringIO import StringIO
from uuid import UUID
from .utils import TypeReader


FB_DEF_HEADER = '\xce\xd1\xb2\x0f'


class FBDefException(Exception):
    pass


class FBDefParser(object):

    def __init__(self, fp):
        self.reader = TypeReader(fp)

    def parse(self):
        rv = {}
        self.parse_header()

        fn_offset = self.reader.read_sst('i')
        fn_to_eof = self.reader.read_sst('i')
        extra_uuids = self.reader.read_sst('i')

        # TODO: what are those?
        rv['unknown0'] = self.reader.read_sst('i')
        rv['unknown1'] = self.reader.read_sst('i')

        chunk0_size = self.reader.read_sst('i')
        chunk1_size = self.reader.read_sst('i')
        header_size = self.reader.read_sst('i')
        fn_size = self.reader.read_sst('i')

        # TODO: what is this?
        rv['unknown2'] = self.reader.read_sst('i')

        payload_size = self.reader.read_sst('i')

        # TODO: That's currently our best guess
        rv['uuids'] = self.parse_uuids(extra_uuids)
        rv['headers'] = self.parse_headers(header_size)

        rv['chunk0'] = self.reader.read(chunk0_size)
        rv['chunk1'] = self.reader.read(chunk1_size)

        rv['unknown3'] = self.reader.read(fn_offset - self.reader.tell())
        rv['name'] = self.reader.read(fn_size)
        rv['unknown4'] = self.reader.read(fn_to_eof - fn_size)

        return rv

    def parse_uuids(self, extra):
        rv = []
        for x in xrange((extra + 1) * 2):
            rv.append(UUID(bytes=self.reader.read(16)))
        return rv

    def parse_headers(self, size):
        headers = self.reader.read(size).split('\x00')
        if not headers or headers.pop() != '':
            raise FBDefException('Invalid header list')
        return headers

    def parse_header(self):
        header = self.reader.read(len(FB_DEF_HEADER))
        if header != FB_DEF_HEADER:
            raise FBDefException('Expected fbdef header')


def load(fp_or_filename):
    if hasattr(fp_or_filename, 'read'):
        fp = fp_or_filename
        close = False
    else:
        fp = open(fp_or_filename, 'rb')
        close = True
    try:
        return FBDefParser(fp).parse()
    finally:
        if close:
            fp.close()


def loads(string):
    return load(StringIO(string))
