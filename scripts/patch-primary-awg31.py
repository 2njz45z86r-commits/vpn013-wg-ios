"""Apply source-pinned AWG 3.1 corrections to a private core copy."""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import sys

root = Path(sys.argv[1]).resolve(strict=True)
cache = Path(subprocess.check_output(['go', 'env', 'GOMODCACHE'], text=True).strip()).resolve(strict=True)
assert root != cache and not root.is_relative_to(cache), 'never patch the global Go module cache'
device = root / 'device'
scripts = Path(__file__).resolve().parent
assert (root / 'go.mod').read_text(encoding='utf-8').startswith('module github.com/amnezia-vpn/amneziawg-go/v3\n')
changes = json.loads((scripts / 'primary-awg31-changes.json').read_text(encoding='utf-8'))
for name in ('send.go', 'receive.go'):
    path = device / name
    assert path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(root)
    text = path.read_text(encoding='utf-8')
    assert hashlib.sha256(text.encode()).hexdigest() == changes[name]['before'], f'unexpected staged {name}'
    for old, new in changes[name]['changes']:
        assert text.count(old) == 1, f'changed or ambiguous anchor in {name}'
        text = text.replace(old, new, 1)
    assert hashlib.sha256(text.encode()).hexdigest() == changes[name]['after'], f'wrong patched {name}'
    path.write_text(text, encoding='utf-8', newline='\n')

for name in ('primary-awg31-classifier.go', 'primary-awg31-testhelper_test.go',
             'primary-vpn013_auth_classifier_test.go', 'primary-vpn013_auth_control_test.go',
             'primary-vpn013_auth_live_test.go', 'primary-vpn013_auth_robustness_test.go',
             'primary-vpn013_awg31_runtime_test.go', 'primary-vpn013_queued_classifier_test.go'):
    source = scripts / name
    target = device / name.replace('primary-', 'r013_', 1).replace('-', '_')
    assert source.is_file() and not source.is_symlink() and not target.exists()
    shutil.copyfile(source, target)
