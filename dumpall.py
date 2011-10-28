import os
import shutil
from libsb import CASCatalog


def dump_all(source, dst):
    if not os.path.isdir(dst):
        os.makedirs(dst)

    cat = CASCatalog(source)
    for hash, file in cat.files.iteritems():
        with open(os.path.join(dst, hash), 'wb') as out:
            print 'Extracting', hash
            shutil.copyfileobj(file.open(), out)


if __name__ == '__main__':
    dump_all(source=r'C:\Program Files (x86)\Origin Games\Battlefield 3\Data\cas.cat',
             dst=r'C:\Temp\BF3')
