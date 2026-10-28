"""Private build overlay for pinned upstream injected-fd ownership; never edit module cache."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

root = Path(sys.argv[1]).resolve()
output = Path(sys.argv[2]).resolve()
subprocess.run(['go', 'mod', 'download'], cwd=root, check=True)
subprocess.run(['go', 'mod', 'verify'], cwd=root, check=True)
info = json.loads(subprocess.check_output(['go', 'list', '-m', '-json', 'github.com/xtls/xray-core'], cwd=root))
replacement = info['Replace']
assert replacement['Path'] == 'github.com/amnezia-vpn/amnezia-xray-core' and replacement['Version'] == 'v1.260728.0'
source = Path(replacement['Dir']) / 'proxy/tun/tun_darwin.go'
original = source.read_text()
needle = '\t\tif err = unix.SetNonblock(fd, true); err != nil {\n\t\t\treturn nil, err\n\t\t}'
assert original.count(needle) == 1
owned = '''\t\t// VPN013 owns an internal duplicate, not the caller's injected fd.
\t\tfd, err = unix.Dup(fd)
\t\tif err != nil { return nil, err }
\t\tif err = unix.SetNonblock(fd, true); err != nil {
\t\t\t_ = unix.Close(fd)
\t\t\treturn nil, err
\t\t}'''
patched = original.replace(needle, owned)
needle = "\t// iOS: don't close the fd, it's owned by NetworkExtension\n\treturn routeErr"
assert patched.count(needle) == 1
patched = patched.replace(needle, '\t// VPN013: close only our internal os.File duplicate and disarm its cleanup.\n\treturn xerrors.Combine(routeErr, t.tunFile.Close())')
output.mkdir(parents=True, exist_ok=True)
target = output / 'tun_darwin_owned.go'
target.write_text(patched)
overlay = output / 'proxy-tun-overlay.json'
overlay.write_text(json.dumps({'Replace': {str(source): str(target)}}))
(output / 'proxy-tun-provenance.json').write_text(json.dumps({'module': replacement['Path'], 'version': replacement['Version'], 'originalSHA256': hashlib.sha256(source.read_bytes()).hexdigest(), 'patchedSHA256': hashlib.sha256(target.read_bytes()).hexdigest(), 'moduleCacheUnchanged': True}))
print('Pinned TUN fd ownership overlay prepared; module cache unchanged')
