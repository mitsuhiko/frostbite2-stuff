# -*- coding: utf-8 -*-
"""
    libfb2.settings
    ~~~~~~~~~~~~~~~

    Reads the settings format from the user profile.

    :copyright: (c) Copyright 2011 by Armin Ronacher.
    :license: BSD, see LICENSE for more details.
"""
import os
import struct
from .types import Blob
from .utils import TypeReader


class ShittyReader(TypeReader):

    def read_cstr(self, size):
        # just guessing
        value = self.read(size)
        if value and len(value) < 255 and value[-1] == '\x00':
            return value[:-1]
        return Blob(value)


def parse_body_settings(f):
    reader = ShittyReader(f)
    garbage = reader.read(20)
    sections = []
    while 1:
        section = {}
        sections.append(section)
        item_count = reader.read_sst('i')
        if item_count == 0:
            break
        for x in xrange(item_count):
            item_type = reader.read_sst('i')
            caption_size = reader.read_sst('i')
            key = reader.read_cstr(caption_size)
            value_size = reader.read_sst('i')
            value = reader.read_cstr(value_size)
            # XXX: convert value by item type
            section[key] = value
    return sections


def parse_profile_settings(f):
    reader = ShittyReader(f)
    rv = {}
    for x in f.read().split('\x0a'):
        if x:
            key, value = x.split('\x20', 1)
            rv[key] = value
    return rv


def load_settings(basepath=None):
    rv = {}
    if basepath is None:
        basepath = os.path.expanduser('~/Documents/Battlefield 3/settings/')
    with open(basepath + 'PROF_SAVE_body', 'rb') as f:
        rv['body'] = parse_body_settings(f)
    with open(basepath + 'PROF_SAVE_profile', 'rb') as f:
        rv['profile'] = parse_profile_settings(f)
    return rv
