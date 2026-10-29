"""Patch only an isolated pinned module copy; retain explicit fd ownership on Android."""
import hashlib,json,pathlib,shutil,subprocess,sys
root=pathlib.Path(sys.argv[1]).resolve();output=pathlib.Path(sys.argv[2]).resolve()
output.mkdir(parents=True,exist_ok=True)
subprocess.run(['go','mod','download'],cwd=root,check=True)
subprocess.run(['go','mod','verify'],cwd=root,check=True)
info=json.loads(subprocess.check_output(['go','list','-m','-json','github.com/xtls/xray-core'],cwd=root))['Replace']
assert info['Path']=='github.com/amnezia-vpn/amnezia-xray-core' and info['Version']=='v1.260728.0'
source=pathlib.Path(info['Dir'])/'proxy/tun/tun_android.go';original=source.read_text()
patched=original.replace('"strconv"','"strconv"\n "sync"')
patched=patched.replace('type AndroidTun struct {','type AndroidTun struct {\n closeOnce sync.Once\n closeError error')
needle='\terr = unix.SetNonblock(fd, true)';assert patched.count(needle)==1
patched=patched.replace(needle,'\tif err != nil || fd < 3 { return nil, errors.New("invalid injected fd") }\n\tfd, err = unix.Dup(fd)\n\tif err != nil { return nil, err }\n'+needle)
needle='func (t *AndroidTun) Close() error {\n\treturn nil\n}';assert patched.count(needle)==1
patched=patched.replace(needle,'func (t *AndroidTun) Close() error {\n t.closeOnce.Do(func(){ t.closeError = unix.Close(t.tunFd) })\n return t.closeError\n}')
local=output/'xray-core-owned';assert not local.exists(),'Use a fresh isolated build directory'
shutil.copytree(pathlib.Path(info['Dir']),local,copy_function=shutil.copyfile)
(local/'proxy/tun/tun_android.go').write_text(patched)
modfile=output/'proxy-tun.mod';shutil.copyfile(root/'go.mod',modfile);shutil.copyfile(root/'go.sum',output/'proxy-tun.sum')
subprocess.run(['go','mod','edit','-modfile='+str(modfile),'-replace=github.com/xtls/xray-core='+str(local)],cwd=root,check=True)
anet=json.loads(subprocess.check_output(['go','list','-m','-json','github.com/wlynxg/anet'],cwd=root))
assert anet['Version']=='v0.0.5'
anet_source=pathlib.Path(anet['Dir'])/'interface_android.go';anet_original=anet_source.read_text();anet_patched=anet_original
for directive in ('//go:linkname zoneCache net.zoneCache','//go:linkname zoneCacheX golang.org/x/net/internal/socket.zoneCache'):
    assert anet_patched.count(directive)==1
    anet_patched=anet_patched.replace(directive,'// VPN013: package-local zone cache; no writes to private Go runtime state.')
anet_local=output/'anet-owned';shutil.copytree(pathlib.Path(anet['Dir']),anet_local,copy_function=shutil.copyfile)
(anet_local/'interface_android.go').write_text(anet_patched)
subprocess.run(['go','mod','edit','-modfile='+str(modfile),'-replace=github.com/wlynxg/anet='+str(anet_local)],cwd=root,check=True)
(output/'proxy-tun-provenance.json').write_text(json.dumps({'module':info['Path'],'version':info['Version'],'originalSHA256':hashlib.sha256(original.encode()).hexdigest(),'patchedSHA256':hashlib.sha256(patched.encode()).hexdigest(),'moduleCacheUnchanged':True,'anetVersion':'v0.0.5','anetOriginalSHA256':hashlib.sha256(anet_original.encode()).hexdigest(),'anetPatchedSHA256':hashlib.sha256(anet_patched.encode()).hexdigest(),'linkerChecksDisabled':False,'numericProtectedEndpointsOnly':True}))
print('Prepared isolated Android TUN ownership overlay')
