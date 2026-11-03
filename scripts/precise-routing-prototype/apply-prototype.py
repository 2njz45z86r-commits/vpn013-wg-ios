"""Apply source-pinned diagnostic Go files to a fresh local Xray checkout."""
import hashlib
import json
import shutil
import sys
from pathlib import Path

directory = Path(__file__).resolve().parent
target = Path(sys.argv[1]).resolve(strict=True)
manifest = json.loads((directory / 'manifest.json').read_text())
assert manifest['module'] == 'github.com/amnezia-vpn/amnezia-xray-core'
assert manifest['version'] == 'v1.260728.0'
allowed = {'proxy/wireguard/client.go', 'proxy/wireguard/bind.go', 'proxy/wireguard/config.proto',
           'proxy/wireguard/config.pb.go', 'infra/conf/wireguard.go', 'proxy/wireguard/vpn013_awg.go',
           'proxy/wireguard/vpn013_gated_tun.go', 'proxy/wireguard/vpn013_awg_test.go',
           'proxy/wireguard/vpn013_listen_port_test.go', 'proxy/wireguard/vpn013_precise_converter.go',
           'proxy/wireguard/vpn013_precise_converter_test.go', 'proxy/wireguard/vpn013_precise_parser_test.go'}
assert set(manifest['files']) == allowed
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
for name, hashes in manifest['files'].items():
    source, destination = directory / name, target / name
    assert not source.is_symlink() and sha(source) == hashes['prototypeSHA256']
    assert destination.parent.resolve().is_relative_to(target) and not destination.is_symlink()
    if hashes['sourceSHA256'] is None:
        assert not destination.exists()
    else:
        assert destination.is_file() and sha(destination) == hashes['sourceSHA256']
for name in sorted(allowed):
    destination = target / name
    # Go's module cache is read-only on Unix; copytree preserves directory modes.
    # Make only verified directories in this private checkout writable.
    parent = destination.parent
    assert not parent.is_symlink() and parent.resolve().is_relative_to(target)
    parent.chmod(0o700)
    if destination.exists(): destination.chmod(0o600)
    shutil.copyfile(directory / name, destination)
    assert sha(destination) == manifest['files'][name]['prototypeSHA256']
print('Twelve source-pinned diagnostic files applied to private copy')
