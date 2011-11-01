"""
A simple example script that iterates over the dogtag definitions
that can be found in the default_settings bundle.
"""
from libfb2.sb import CASCatalog


CAS_PATH = r'C:\Program Files (x86)\Origin Games\Battlefield 3\Data\cas.cat'
cat = CASCatalog(CAS_PATH)


def iter_dogtags():
    """Iterates over all dogtags and their definition file."""
    setting_bundle = cat.open_superbundle('Win32/default_settings_win32')
    settings = setting_bundle.get_file('Win32/default_settings_win32')
    ebx = settings.get_parsed_contents()['ebx']
    for entry in ebx:
        if entry['name'].startswith('persistence/dogtags/'):
            dogtag_file = cat.get_file(entry['sha1'].hex)
            yield entry['name'], dogtag_file.get_raw_contents()


if __name__ == '__main__':
    for name, _ in iter_dogtags():
        print name
