"""
A simple example script that dumps all the contents of the
bundles onto the filesystem.
"""
import os
import shutil
from libsb import CASCatalog


def dump_all(source, dst):
    print 'Reading catalog...'
    cat = CASCatalog(source)
    idx = 0
    total = len(cat.files)
    print 'Found %d files' % total

    for idx, (hash, file) in enumerate(cat.files.iteritems()):
        fn = os.path.join(dst, hash[0], hash[:2], hash)
        directory = os.path.dirname(fn)
        if not os.path.isdir(directory):
            os.makedirs(directory)
        with open(fn, 'wb') as out:
            print 'Extracting %s % 8d Bytes cas=%02d (%d/%d)' % \
                (hash, file.size, file.cas_num, idx, total)
            shutil.copyfileobj(file.open(), out)


if __name__ == '__main__':
    dump_all(source=r'C:\Program Files (x86)\Origin Games\Battlefield 3\Data\cas.cat',
             dst=r'C:\Temp\BF3')
