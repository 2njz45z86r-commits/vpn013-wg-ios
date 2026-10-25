"""Refresh pinned official Go modules while preserving customized client vendors.

This prepares source only. It never builds, runs, signs or installs the client.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

workspace = Path(sys.argv[1]).resolve()
root = Path(sys.argv[2]).resolve()
assert root.name == 'vpn013-wg-windows' and root.is_dir()
spec = json.loads((workspace / 'windows/dependencies/pins.json').read_text(encoding='utf-8'))
vendor = root / 'vendor'
backup = Path(os.environ['RUNNER_TEMP']).resolve() / 'before-go-dependency-refresh'
assert not backup.exists()

def digest(path):
    return hashlib.file_digest(path.open('rb'), 'sha256').hexdigest()

for name, expected in spec['before'].items():
    assert digest(root / name) == expected, 'Unexpected source manifest: ' + name

sections = re.split(r'(?m)(?=^# [^#])', (vendor / 'modules.txt').read_text(encoding='utf-8'))
replacements = {}
selected = {row['path'] for row in spec['modules']}
before_custom = {p.relative_to(vendor).as_posix(): digest(p) for p in vendor.rglob('*')
                 if p.is_file() and p.name != 'modules.txt'
                 and not any(p.is_relative_to(vendor / module) for module in selected)}

for row in spec['modules']:
    module = row['path']
    assert re.fullmatch(r'golang.org/x/[a-z]+', module)
    module_target = vendor / module
    assert module_target.resolve().is_relative_to(vendor.resolve())
    downloaded = {}
    for version_key, sum_key in (('old', 'oldSum'), ('new', 'newSum')):
        data = json.loads(subprocess.check_output(['go', 'mod', 'download', '-json',
            module + '@' + row[version_key]], cwd=root, text=True, encoding='utf-8'))
        assert data['Path'] == module and data['Version'] == row[version_key]
        assert data['Sum'] == row[sum_key], 'Pinned official module checksum mismatch'
        downloaded[version_key] = Path(data['Dir']).resolve()
    # Refuse to overwrite any customization in these vendor subtrees.
    for path in module_target.rglob('*'):
        if not path.is_file():
            continue
        assert not path.is_symlink()
        original = downloaded['old'] / path.relative_to(module_target)
        assert original.is_file() and digest(original) == digest(path), 'Customized dependency requires manual review'
    destination = backup / module
    assert destination.resolve().is_relative_to(backup)
    destination.parent.mkdir(parents=True, exist_ok=True)
    module_target.rename(destination)
    assert not any(path.is_symlink() for path in downloaded['new'].rglob('*'))
    shutil.copytree(downloaded['new'], module_target,
                    ignore=shutil.ignore_patterns('.git', '.github', 'vendor', 'testdata', '*_test.go', 'go.mod', 'go.sum'))
    packages = sorted({module + ('/' + p.parent.relative_to(module_target).as_posix()
                                  if p.parent != module_target else '')
                       for p in module_target.rglob('*.go')})
    go_version = re.search(r'(?m)^go ([0-9.]+)$', (downloaded['new'] / 'go.mod').read_text()).group(1)
    replacements[module] = '# ' + module + ' ' + row['new'] + '\n## explicit; go ' + go_version + '\n' + '\n'.join(packages) + '\n'

output = []
for section in sections:
    match = re.match(r'# (golang.org/x/[a-z]+) ', section)
    module = match.group(1) if match else None
    output.append(replacements.pop(module) if module in replacements else section)
assert not replacements, 'Expected module section missing'
(vendor / 'modules.txt').write_text(''.join(output), encoding='utf-8', newline='\n')
for name, expected in spec['after'].items():
    source = workspace / 'windows/dependencies' / name
    assert digest(source) == expected
    shutil.copyfile(source, root / name)
verified = subprocess.run(['go', 'mod', 'verify'], cwd=root, capture_output=True, text=True)
assert verified.returncode == 0, 'Official module cache integrity verification failed'
assert before_custom == {p.relative_to(vendor).as_posix(): digest(p) for p in vendor.rglob('*')
                         if p.is_file() and p.name != 'modules.txt'
                         and not any(p.is_relative_to(vendor / module) for module in selected)}
print('Pinned official Go modules refreshed; all unrelated vendor customizations preserved')
