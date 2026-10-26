"""Pinned watcher retirement and explicit existing-TUN configuration, no release."""
from pathlib import Path
import hashlib,json,subprocess,sys
root=Path(sys.argv[1]).resolve()
base=root/'vendor/github.com/amnezia-vpn/amneziawg-windows/v3/tunnel'
expected={'interfacewatcher.go':'59932df7c22f3f8420a2e851cd300390cb52185cf195a077ed532dbd1e8101eb',
          'addressconfig.go':'a758741737ee2eaed35f3207a1eda0539a245ccf1fa66c3153e1d90554af6aec'}
records={}
for name,want in expected.items():
 p=base/name; actual=hashlib.sha256(p.read_bytes()).hexdigest()
 assert actual==want,(name,actual,'Unknown source; no watcher patch')
 records[name]={'before':actual}
p=base/'interfacewatcher.go';s=p.read_text()
s=s.replace('"context"','"context"\n"errors"\n"fmt"\n"time"',1)
s=s.replace('setupMutex              sync.Mutex','retirementMutex sync.Mutex\nexistingBackend bool\nsetupMutex              sync.Mutex',1)
start=s.index('func (iw *interfaceWatcher) setup(')
end=s.index('func watchInterface(',start)
s=s[:start]+'''// setupFamilyLocked is only called with the primary barrier followed by
// setupMutex. A watcher belongs to one backend; replacement uses a new watcher.
func (iw *interfaceWatcher) setupFamilyLocked(family winipcfg.AddressFamily, existing bool) error {
 if err:=iw.comparisonContext.Err();err!=nil{return err}
 var callbacks *[]winipcfg.ChangeCallback
 var state *r013gate.PathObservationState
 switch family {case windows.AF_INET:callbacks=&iw.changeCallbacks4;state=&iw.comparison4
 case windows.AF_INET6:callbacks=&iw.changeCallbacks6;state=&iw.comparison6
 default:return windows.ERROR_INVALID_PARAMETER}
 if len(*callbacks)!=0{return nil}
 var err error
 *callbacks,err=monitorDefaultRoutes(family,iw.binder,iw.conf.Interface.MTU==0,hasDefaultRoute(family,iw.conf.Peers),iw.tun,iw.comparisonGate,iw.comparisonContext,state)
 if err!=nil{return err}
 log.Printf("Setting existing=%v device family=%d addresses",existing,family)
 return configureInterfaceWithCleanup(family,iw.conf,iw.tun,!existing)
}

func (iw *interfaceWatcher) report(err error){
 if err!=nil&&iw.comparisonContext.Err()==nil{select{case iw.errors<-interfaceWatcherError{services.ErrorSetNetConfig,err}:default:}}
}

''' +s[end:]
start=s.index('\t\tiw.setupMutex.Lock()',s.index('func watchInterface('))
end=s.index('\n\t})',start)
s=s[:start]+'''        if notificationType!=winipcfg.MibAddInstance||ctx.Err()!=nil{return}
        // Never hold setupMutex while waiting for the primary barrier. The
        // owner may hold that barrier while draining this very subscription.
        iw.setupMutex.Lock()
        relevant:=iw.tun==nil||iface.InterfaceLUID==winipcfg.LUID(iw.tun.LUID())
        iw.setupMutex.Unlock()
        if !relevant{return}
        iw.report(gate.Primary(ctx,r013gate.Stamp{},func(context.Context)error{
          iw.setupMutex.Lock();defer iw.setupMutex.Unlock()
          if ctx.Err()!=nil{return ctx.Err()}
          if iw.tun==nil{iw.storedEvents=append(iw.storedEvents,interfaceWatcherEvent{iface.InterfaceLUID,iface.Family});return nil}
          if iface.InterfaceLUID!=winipcfg.LUID(iw.tun.LUID()){return nil}
          return iw.setupFamilyLocked(iface.Family,iw.existingBackend)
        }))''' +s[end:]
start=s.index('func (iw *interfaceWatcher) Configure(')
s=s[:start]+'''func (iw *interfaceWatcher) Configure(binder conn.BindSocketToInterface, configuration *conf.Config, native *tun.NativeTun) {
 iw.report(iw.comparisonGate.Primary(iw.comparisonContext,r013gate.Stamp{},func(context.Context)error{
  iw.setupMutex.Lock();defer iw.setupMutex.Unlock()
  iw.binder,iw.conf,iw.tun=binder,configuration,native
  if row,err:=winipcfg.LUID(native.LUID()).Interface();err==nil{iw.comparisonTunIndex.Store(row.InterfaceIndex)}
  var result error
  for _,event:=range iw.storedEvents{if event.luid==winipcfg.LUID(native.LUID()){result=errors.Join(result,iw.setupFamilyLocked(event.family,false))}}
  iw.storedEvents=nil
  return result
 }))
}

// RetireForBackend drains all real callbacks before flushing this watcher's
// own network state. It never removes the preceding WFP policy or closes TUN.
// A failed unregister stays owned and is retried by later cleanup.
func (iw *interfaceWatcher) RetireForBackend(ctx context.Context) error { return iw.retire(ctx,true) }

func (iw *interfaceWatcher) retire(ctx context.Context,preservePolicy bool) error {
 began:=time.Now()
 trace:=func(phase string){log.Printf("VPN013 watcher-retire phase=%s elapsedMS=%d",phase,time.Since(began).Milliseconds())}
 trace("retirement-lock")
 iw.retirementMutex.Lock();defer iw.retirementMutex.Unlock()
 trace("cancel-context")
 iw.comparisonStop();iw.comparisonGate.NotifyChange()
 trace("detach-lock")
 iw.setupMutex.Lock()
 callbacks:=append([]winipcfg.ChangeCallback{},iw.changeCallbacks4...)
 callbacks=append(callbacks,iw.changeCallbacks6...)
 if iw.interfaceChangeCallback!=nil{callbacks=append(callbacks,iw.interfaceChangeCallback)}
 iw.changeCallbacks4=nil;iw.changeCallbacks6=nil;iw.interfaceChangeCallback=nil
 iw.setupMutex.Unlock()
 var failed []winipcfg.ChangeCallback
 var drainError error
 for i,cb:=range callbacks{
  trace(fmt.Sprintf("callback-%d-begin",i))
  if err:=cb.Unregister();err!=nil{failed=append(failed,cb);drainError=errors.Join(drainError,err)}
  trace(fmt.Sprintf("callback-%d-done",i))
 }
 if len(failed)!=0{
  iw.setupMutex.Lock();iw.changeCallbacks4=failed;iw.setupMutex.Unlock()
  return fmt.Errorf("watcher subscriptions did not retire: %w",drainError)
 }
 trace("primary-barrier")
 return iw.comparisonGate.Primary(ctx,r013gate.Stamp{},func(context.Context)error{
  trace("primary-owned")
  iw.setupMutex.Lock();defer iw.setupMutex.Unlock()
  trace("setup-owned")
  if !preservePolicy{firewall.DisableFirewall()}
  if iw.tun==nil{return nil}
  luid:=winipcfg.LUID(iw.tun.LUID())
  trace("flush-network")
  flushErr:=flushOwnNetwork(luid)
  trace("verify-retired")
  verifyErr:=verifyRetiredNetwork(luid,iw.conf)
  trace("network-retired")
  return errors.Join(flushErr,verifyErr)
 })
}

func (iw *interfaceWatcher) Destroy(){if err:=iw.retire(context.Background(),false);err!=nil{log.Printf("Interface cleanup failed: %v",err)}}
'''
p.write_text(s,newline='\n')
p=base/'addressconfig.go';s=p.read_text()
old='func configureInterface(family winipcfg.AddressFamily, conf *conf.Config, tun *tun.NativeTun) error {'
assert s.count(old)==1
s=s.replace(old,'''func configureInterface(family winipcfg.AddressFamily, configuration *conf.Config, native *tun.NativeTun) error {
 return configureInterfaceWithCleanup(family,configuration,native,true)
}

func configureInterfaceWithCleanup(family winipcfg.AddressFamily, conf *conf.Config, tun *tun.NativeTun, cleanupForeign bool) error {''')
s=s.replace('if err == windows.ERROR_OBJECT_ALREADY_EXISTS {','if err == windows.ERROR_OBJECT_ALREADY_EXISTS && cleanupForeign {',1)
p.write_text(s,newline='\n')
subprocess.run(['gofmt','-w',str(base/'interfacewatcher.go'),str(p)],check=True)
for name in records:records[name]['after']=hashlib.sha256((base/name).read_bytes()).hexdigest()
(root.parent/'existing-network-evidence.json').write_text(json.dumps(records,indent=2))
print(json.dumps(records))
