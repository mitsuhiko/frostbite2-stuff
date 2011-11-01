"""
A simple example script that iterates over the data of
a given map.
"""
from libfb2.sb import CASCatalog


CAS_PATH = r'C:\Program Files (x86)\Origin Games\Battlefield 3\Data\cas.cat'
MAP = 'MP_001'
cat = CASCatalog(CAS_PATH)


def show_map_data(show_related=False):
    """Iterates over all dogtags and their definition file."""
    map_bundle = cat.open_superbundle('Win32/Levels/%s/%s' % (MAP, MAP))
    for file in map_bundle.iter_files():
        print file.id
        if show_related:
            for obj in file.iter_parse_contents('ebx.*'):
                print ' ', obj['sha1'].hex, obj['name']
    return ()


if __name__ == '__main__':
    show_map_data(show_related=False)
