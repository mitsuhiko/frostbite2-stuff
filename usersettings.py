import os
import struct


_int32 = struct.Struct('<i')


class Blob(object):

    def __init__(self, data):
        self.data = data

    def __repr__(self):
        return '<Blob %r (%d bytes)>' % (
            self.data[:20],
            len(self.data)
        )


def _read_structval(f, st):
    return st.unpack(f.read(st.size))


def _read_cstr(f, size):
    # just guessing
    value = f.read(size)
    if value and len(value) < 255 and value[-1] == '\x00':
        return value[:-1]
    return Blob(value)


def parse_body_settings(f):
    garbage = f.read(20)
    sections = []
    while 1:
        section = {}
        sections.append(section)
        item_count = _read_structval(f, _int32)[0]
        if item_count == 0:
            break
        for x in xrange(item_count):
            item_type = _read_structval(f, _int32)[0]
            caption_size = _read_structval(f, _int32)[0]
            key = _read_cstr(f, caption_size)
            value_size = _read_structval(f, _int32)[0]
            value = _read_cstr(f, value_size)
            # XXX: convert value by item type
            section[key] = value
    return sections


def parse_profile_settings(f):
    rv = {}
    for x in f.read().split('\x0a'):
        if x:
            key, value = x.split('\x20', 1)
            rv[key] = value
    return rv


def load_settings():
    rv = {}
    basepath = os.path.expanduser('~/Documents/Battlefield 3/settings/')
    with open(basepath + 'PROF_SAVE_body', 'rb') as f:
        rv['body'] = parse_body_settings(f)
    with open(basepath + 'PROF_SAVE_profile', 'rb') as f:
        rv['profile'] = parse_profile_settings(f)
    return rv


if __name__ == '__main__':
    import pprint
    pprint.pprint(load_settings())
