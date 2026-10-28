"""Private build overlay for pinned upstream injected-fd ownership; never edit module cache."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import shutil

root = Path(sys.argv[1]).resolve()
output = Path(sys.argv[2]).resolve()
output.mkdir(parents=True, exist_ok=True)
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
local = output / 'xray-core-owned'
assert not local.exists(), 'Use a fresh isolated build directory'
shutil.copytree(Path(replacement['Dir']), local, copy_function=shutil.copyfile)
target = local / 'proxy/tun/tun_darwin.go'
target.write_text(patched)
modfile = output / 'proxy-tun.mod'
shutil.copyfile(root/'go.mod', modfile)
shutil.copyfile(root/'go.sum', output/'proxy-tun.sum')
subprocess.run(['go', 'mod', 'edit', '-modfile='+str(modfile), '-replace=github.com/xtls/xray-core='+str(local)], cwd=root, check=True)
(output / 'proxy-tun-provenance.json').write_text(json.dumps({'module': replacement['Path'], 'version': replacement['Version'], 'originalSHA256': hashlib.sha256(source.read_bytes()).hexdigest(), 'patchedSHA256': hashlib.sha256(target.read_bytes()).hexdigest(), 'moduleCacheUnchanged': True}))
print('Pinned TUN fd ownership copy and explicit modfile prepared; upstream lock files and module cache unchanged')
