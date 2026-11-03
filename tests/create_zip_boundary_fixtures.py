"""Create non-sensitive hostile ZIP fixtures in a caller-owned temp directory."""
from pathlib import Path
import sys
import zipfile

root = Path(sys.argv[1])
root.mkdir(parents=True, exist_ok=True)

def make(name, items, compression=zipfile.ZIP_DEFLATED):
    path = root / name
    with zipfile.ZipFile(path, 'w', compression) as z:
        for filename, content in items:
            z.writestr(filename, content)
    return path

make('flat.zip', [('one.conf', b'synthetic')])
make('nested.zip', [('phone/one.conf', b'synthetic')])
make('count60.zip', [(f'f{i}.conf', b'x') for i in range(60)])
make('count61.zip', [(f'f{i}.conf', b'x') for i in range(61)])
make('entry-too-large.zip', [('one.conf', b'x' * (1_048_576 + 1))])
make('total-too-large.zip', [(f'f{i}.conf', b'x' * 1_048_576) for i in range(9)])
make('crc.zip', [('one.conf', b'abcdefghijklmnop')], zipfile.ZIP_STORED)
path = root / 'crc.zip'
raw = bytearray(path.read_bytes())
where = raw.index(b'abcdefghijklmnop')
raw[where] ^= 1
path.write_bytes(raw)
path = make('nul.zip', [('one.confX../hidden', b'synthetic')], zipfile.ZIP_STORED)
raw = path.read_bytes()
assert raw.count(b'one.confX../hidden') == 2
path.write_bytes(raw.replace(b'one.confX../hidden', b'one.conf\x00../hidden'))
path = root / 'truncated.zip'
path.write_bytes((root / 'flat.zip').read_bytes()[:-10])
print('Created 9 synthetic ZIP fixtures')
