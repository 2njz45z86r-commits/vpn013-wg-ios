"""Read-only observed-runtime protocol on the exact verified lifecycle prototype."""
from pathlib import Path
import hashlib,json,subprocess,sys
root=Path(sys.argv[1]).resolve();folder=root/'vendor/github.com/amnezia-vpn/amneziawg-windows/v3/tunnel'
pins={'service.go':'1c4127724c6a214a326bc6b64d303a4f83c7d63acf979b765cd7ea1d0539320e',
 'interfacewatcher.go':'39969264ca3e74b0fa38a4cbb46277b9dcff025a8323e41de98b8872ec05edd0',
 'defaultroutemonitor.go':'be764cd677e7261d6e153581827f5e7299f87bb44cd9f52e4168833ffd2b5f38'}
before={f:hashlib.sha256((folder/f).read_bytes()).hexdigest() for f in pins}
assert before==pins,('Unknown lifecycle source; no observation patch applied',before)
texts={f:(folder/f).read_text() for f in pins}
def replace(s,old,new):
 assert s.count(old)==1,(old[:100],s.count(old))
 return s.replace(old,new,1)
s=texts['service.go']
s=replace(s,'\tvar primaryUAPI *r013gate.PrimaryUAPIServer','\tvar primaryUAPI *r013gate.PrimaryUAPIServer\n var observation comparisonServiceObservation')
s=replace(s,'\t\tstopPaths()','\t\tobservation.ready.Store(false)\n\t\tstopPaths()')
s=replace(s,'primaryUAPI, err = r013gate.NewPrimaryUAPIServer(context.Background(), dev)','primaryUAPI, err = r013gate.NewObservedPrimaryUAPIServer(context.Background(), dev,func()(r013gate.Observation,error){return observation.snapshot(primaryGate,dev),nil})')
s=replace(s,'\tchanges <- svc.Status{State: svc.Running, Accepts:', '\tobservation.config.Store(config)\n observation.watcher.Store(watcher)\n observation.ready.Store(true)\n\tchanges <- svc.Status{State: svc.Running, Accepts:')
texts['service.go']=s
s=texts['interfacewatcher.go']
s=replace(s,'"sync"','"sync"\n "sync/atomic"')
s=replace(s,'\tcomparisonStop    context.CancelFunc','''\tcomparisonStop    context.CancelFunc
 comparison4 r013gate.PathObservationState
 comparison6 r013gate.PathObservationState
 comparisonTunIndex atomic.Uint32''')
s=replace(s,'\t\tvar changeCallbacks *[]winipcfg.ChangeCallback','\t\tvar changeCallbacks *[]winipcfg.ChangeCallback\n var comparisonState *r013gate.PathObservationState')
s=replace(s,'changeCallbacks = &iw.changeCallbacks4','changeCallbacks = &iw.changeCallbacks4\n comparisonState=&iw.comparison4')
s=replace(s,'changeCallbacks = &iw.changeCallbacks6','changeCallbacks = &iw.changeCallbacks6\n comparisonState=&iw.comparison6')
s=replace(s,'iw.tun, iw.comparisonGate, iw.comparisonContext)','iw.tun, iw.comparisonGate, iw.comparisonContext,comparisonState)')
s=replace(s,'\tiw.binder, iw.conf, iw.tun = binder, conf, tun','\tiw.binder, iw.conf, iw.tun = binder, conf, tun\n if row,err:=winipcfg.LUID(tun.LUID()).Interface();err==nil{iw.comparisonTunIndex.Store(row.InterfaceIndex)}')
texts['interfacewatcher.go']=s
s=texts['defaultroutemonitor.go']
s=replace(s,'\t*lastLUID = luid\n\t*lastIndex = index\n','')
s=replace(s,'return binder.BindSocketToInterface4(index, blackhole)','err=binder.BindSocketToInterface4(index, blackhole)')
s=replace(s,'return binder.BindSocketToInterface6(index, blackhole)','err=binder.BindSocketToInterface6(index, blackhole)')
marker='\treturn nil\n}\n\nfunc monitorDefaultRoutes'
s=replace(s,marker,'\tif err!=nil{return err}\n *lastLUID=luid\n *lastIndex=index\n\treturn nil\n}\n\nfunc monitorDefaultRoutes')
s=replace(s,'comparisonContext context.Context) ([]winipcfg.ChangeCallback, error)','comparisonContext context.Context, comparisonState *r013gate.PathObservationState) ([]winipcfg.ChangeCallback, error)')
s=replace(s,'\tdoIt := func() error {',''' comparisonState.Changed()
 doIt := func() (workError error) {
 revision:=comparisonState.Revision()
 defer func(){comparisonState.Commit(revision,lastIndex,workError)}()''')
s=replace(s,'\tcbr, err := winipcfg.RegisterRouteChangeCallback','\tnotify:=func(){comparisonState.Changed();worker.Notify()}\n\tcbr, err := winipcfg.RegisterRouteChangeCallback')
assert s.count('worker.Notify()')==3
s=s.replace('\t\t\tworker.Notify()','\t\t\tnotify()')
texts['defaultroutemonitor.go']=s
helper='''// SPDX-License-Identifier: MIT
package tunnel

import (
 "net"
 "os"
 "strings"
 "sync/atomic"
 "github.com/amnezia-vpn/amneziawg-go/v3/device"
 probe "github.com/amnezia-vpn/amneziawg-windows-client/r013probe"
 "github.com/amnezia-vpn/amneziawg-windows-client/r013gate"
 "github.com/amnezia-vpn/amneziawg-windows/v3/conf"
 "github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
)

// No watcher setupMutex is taken here. An OS callback may own it while waiting
// for the global barrier held by the process requesting this observation.
// Metadata is advisory outside Candidate; the consumer validates its token,
// SCM PID/membership and actual IpcGet identity while holding that barrier.
type comparisonServiceObservation struct {
 ready atomic.Bool
 config atomic.Pointer[conf.Config]
 watcher atomic.Pointer[interfaceWatcher]
}
func(o *comparisonServiceObservation)snapshot(gate *r013gate.Gate,dev *device.Device)r013gate.Observation{
 out:=r013gate.Observation{Version:r013gate.ObservationVersion,PID:uint32(os.Getpid()),Stamp:gate.Current()}
 cfg,iw:=o.config.Load(),o.watcher.Load()
 if cfg==nil||iw==nil{return out}
 out.Name=cfg.Name
 out.Scripts=strings.TrimSpace(cfg.Interface.PreUp+cfg.Interface.PostUp+cfg.Interface.PreDown+cfg.Interface.PostDown)!=""
 out.TunnelIndex=iw.comparisonTunIndex.Load()
 var aligned4,aligned6 bool
 out.Physical4,aligned4=iw.comparison4.Snapshot()
 out.Physical6,aligned6=iw.comparison6.Snapshot()
 if !aligned6{out.Physical6=0}
 out.Dirty=!aligned4
 if !o.ready.Load()||iw.comparisonContext.Err()!=nil||out.Scripts||out.Dirty||out.TunnelIndex==0||out.Physical4==0||out.Physical4==out.TunnelIndex||cfg.Interface.TableOff||len(cfg.Peers)!=1{return out}
 luid,err:=winipcfg.LUIDFromIndex(out.TunnelIndex);if err!=nil{return out}
 preferred:=false
 if len(cfg.Interface.Addresses)>16||len(cfg.Peers[0].AllowedIPs)>1024{return out}
 for _,address:=range cfg.Interface.Addresses{
  if ip:=address.IP.To4();ip!=nil{row,err:=luid.IPAddress(ip);if err==nil&&row.DadState==winipcfg.DadStatePreferred{preferred=true}}
 }
 if !preferred{return out}
 routeCount:=0
 for _,prefix:=range cfg.Peers[0].AllowedIPs{
  if prefix.IP.To4()==nil{continue}
  routeCount++
  if _,err=luid.Route(prefix.IPNet(),net.IPv4zero);err!=nil{return out}
 }
 if routeCount==0{return out}
 raw,err:=dev.IpcGet();if err!=nil{return out}
 out.Identity,err=probe.PublicIdentityDigest(raw);if err!=nil{return out}
 out.Ready=o.ready.Load()&&iw.comparisonContext.Err()==nil&&gate.Current()==out.Stamp
 return out
}
'''
assert not (folder/'r013_observation.go').exists()
for file,text in texts.items():(folder/file).write_text(text,newline='\n')
(folder/'r013_observation.go').write_text(helper,newline='\n')
subprocess.run(['gofmt','-w',*(str(folder/f) for f in (*pins,'r013_observation.go'))],check=True)
record={'before':before,'after':{f:hashlib.sha256((folder/f).read_bytes()).hexdigest() for f in (*pins,'r013_observation.go')},'scope':'read-only actual service metadata and committed path observations; no manager hourly coordinator or switch'}
(root.parent/'observation-evidence.json').write_text(json.dumps(record,indent=2))
print(json.dumps(record))
