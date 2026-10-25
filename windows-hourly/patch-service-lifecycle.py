"""Install actual service/path fences without changing routes, profiles or privilege policy."""
from pathlib import Path
import hashlib,json,re,subprocess,sys

root=Path(sys.argv[1]).resolve()
folder=root/'vendor/github.com/amnezia-vpn/amneziawg-windows/v3/tunnel'
names=('service.go','interfacewatcher.go','defaultroutemonitor.go')
texts={f:(folder/f).read_text() for f in names}
before={f:hashlib.sha256((folder/f).read_bytes()).hexdigest() for f in names}
# Exact hashes supplied with the inspected client baseline, never patch an
# arbitrary future upstream function by a loose substring match.
pins={'service.go':'d621a0541095e6f730fec9eb32a06f6c187b21e742bb2dd0daf4cd622698903d',
      'interfacewatcher.go':'b75ed809874cd5aabc73c6fff102475e12ec4c657f07ef652827c9a8e29eb022',
      'defaultroutemonitor.go':'b117d960af724cc5dfb1afe03acb0dcab8fff5fb4b03aed86156eed632a76e62'}
assert before==pins,('Unexpected tunnel source; no service patch applied',before)
def replace(s,old,new):
    assert s.count(old)==1,(old[:100],s.count(old))
    return s.replace(old,new,1)
def fence(block,gate='primaryGate',ctx='pathContext'):
    block=re.sub(r'(?m)^(\s*)return$',r'\1return err',block)
    block=re.sub(r'\breturn(?=\s*})','return err',block)
    return '\terr = '+gate+'.Primary('+ctx+', r013gate.Stamp{}, func(context.Context) error {\n'+''.join('\t'+line+'\n' for line in block.rstrip('\n').splitlines())+'\t\treturn nil\n\t})\n\tif err != nil { return }\n\n'

s=texts['service.go']
s=replace(s,'"bytes"','"bytes"\n "context"\n "github.com/amnezia-vpn/amneziawg-windows-client/r013gate"')
s=replace(s,'\tserviceError := services.ErrorSuccess\n','''\tserviceError := services.ErrorSuccess
 primaryGate, gateError := r013gate.Open()
 if gateError != nil { return services.DetermineErrorCode(gateError, services.ErrorDeviceSetConfig) }
 pathContext, stopPaths := context.WithCancel(context.Background())
 primaryGate.NotifyChange()
 defer primaryGate.Close(context.Background())
 defer stopPaths()
 var primaryUAPI *r013gate.PrimaryUAPIServer
 drainBeforeScript := func()error { primaryGate.NotifyChange();return primaryGate.Primary(context.Background(),r013gate.Stamp{},func(context.Context)error{return nil}) }
''')
s=replace(s,'\tdefer func() {\n\t\tsvcSpecificEC','\tdefer func() {\n stopPaths()\n primaryGate.NotifyChange()\n\t\tsvcSpecificEC')
s=replace(s,'watcher, err = watchInterface()','watcher, err = watchInterface(primaryGate,pathContext)')
start=s.index('\tlog.Println("Creating Wintun interface")')
end=s.index('\terr = runScriptCommand(config.Interface.PreUp',start)
block=s[start:end]
block=replace(block,'\tvar wintun tun.Device\n','')
s=s[:start]+'\tvar wintun tun.Device\n'+fence(block)+s[end:]
start=s.index('\terr = enableFirewall(config, nativeTun)')
end=s.index('\tlog.Println("Listening for UAPI requests")',start)
block=s[start:end]
block=replace(block,'\tdev.Up()','\tif err=dev.Up();err!=nil { serviceError=services.ErrorDeviceSetConfig;return }')
marker='\tdev = device.NewDevice(wintun, bind, &device.Logger{log.Printf, log.Printf})\n'
block=replace(block,marker,marker+''' if !dev.SetPrimaryMutationFence(func(work func()error)error { return primaryGate.Primary(context.Background(),r013gate.Stamp{},func(context.Context)error{return work()}) }) { err=fmt.Errorf("primary lifecycle fence unavailable");return }
''')
s=s[:start]+fence(block)+s[end:]
start=s.index('\tlog.Println("Listening for UAPI requests")')
end=s.index('\terr = runScriptCommand(config.Interface.PostUp',start)
s=s[:start]+''' log.Println("Listening for UAPI requests")
 primaryUAPI,err=r013gate.NewPrimaryUAPIServer(context.Background(),dev)
 if err!=nil { serviceError=services.ErrorUAPIListen;return }
 go func(){for{connection,acceptError:=uapi.Accept();if acceptError!=nil{return};primaryUAPI.Serve(connection)}}()

'''+s[end:]
# Preserve user script ordering and own UAPI availability. A script may itself
# issue a protected UAPI command, so never hold the recursive kernel mutex
# across a subprocess/IPC wait. Drain existing probes first; future coordinator
# must require observed Ready and refuse scripted Auto snapshots.
for name in ('PreUp','PostUp'):
    marker='\terr = runScriptCommand(config.Interface.'+name
    assert s.count(marker)==1
    s=s.replace(marker,'\tif err=drainBeforeScript();err!=nil{return}\n'+marker,1)
    line=s[s.index(marker):].splitlines()[0]
    s=replace(s,line,line+'\n primaryGate.NotifyChange()')
s=replace(s,'\t\t\tlogErr = runScriptCommand(config.Interface.PreDown, "VPN013-"+config.Name)', '''            if logErr=drainBeforeScript();logErr==nil { logErr = runScriptCommand(config.Interface.PreDown, "VPN013-"+config.Name) }
            primaryGate.NotifyChange()''')
old='''\t\tif watcher != nil {
\t\t\twatcher.Destroy()
\t\t}
\t\tif uapi != nil {
\t\t\tuapi.Close()
\t\t}'''
new='''        if uapi != nil { uapi.Close() }
        if primaryUAPI != nil { primaryUAPI.Close(context.Background()) }
        if watcher != nil { watcher.Destroy() }'''
s=replace(s,old,new)
s=replace(s,'\t\t\t_ = runScriptCommand(config.Interface.PostDown, "VPN013-"+config.Name)','''            if drainBeforeScript()==nil { _ = runScriptCommand(config.Interface.PostDown,"VPN013-"+config.Name) }
            primaryGate.NotifyChange()''')
texts['service.go']=s

s=texts['interfacewatcher.go']
s=replace(s,'"log"','"log"\n "context"\n "github.com/amnezia-vpn/amneziawg-windows-client/r013gate"')
s=replace(s,'type interfaceWatcher struct {','''type interfaceWatcher struct {
 comparisonGate *r013gate.Gate
 comparisonContext context.Context
 comparisonStop context.CancelFunc''')
start=s.index('func (iw *interfaceWatcher) setup(')
bodyStart=s.index('\n',start)+1
end=s.index('\nfunc watchInterface()',bodyStart)
body=s[bodyStart:end].rstrip()
assert body.endswith('}')
body=body[:-1]
body=re.sub(r'(?m)^(\s*)return$',r'\1return nil',body)
body=replace(body,'hasDefaultRoute(family, iw.conf.Peers), iw.tun)','hasDefaultRoute(family, iw.conf.Peers), iw.tun, iw.comparisonGate, iw.comparisonContext)')
body=re.sub(r'(?m)^(\s*)iw.errors <- (interfaceWatcherError\{[^\n]+\})$',r'\1select { case iw.errors <- \2: default: }',body)
s=s[:bodyStart]+''' if iw.comparisonContext.Err()!=nil{return}
 fenceError:=iw.comparisonGate.Primary(iw.comparisonContext,r013gate.Stamp{},func(context.Context)error{
'''+body+''' return nil
 })
 if fenceError!=nil&&iw.comparisonContext.Err()==nil { select {case iw.errors<-interfaceWatcherError{services.ErrorSetNetConfig,fenceError}:default:} }
}
'''+s[end:]
s=replace(s,'func watchInterface() (*interfaceWatcher, error) {','''func watchInterface(gate *r013gate.Gate,parent context.Context) (*interfaceWatcher,error) {
 ctx,cancel:=context.WithCancel(parent)''')
s=replace(s,'\tiw := &interfaceWatcher{','\tiw := &interfaceWatcher{comparisonGate:gate,comparisonContext:ctx,comparisonStop:cancel,')
s=replace(s,'\tif err != nil {\n\t\treturn nil, err\n\t}\n\treturn iw, nil','\tif err != nil {\n cancel()\n\t\treturn nil, err\n\t}\n\treturn iw, nil')
s=replace(s,'func (iw *interfaceWatcher) Destroy() {','''func (iw *interfaceWatcher) Destroy() {
 iw.comparisonStop()
 iw.comparisonGate.NotifyChange()''')
start=s.index('\tiw.setupMutex.Lock()\n\tif interfaceChangeCallback == iw.interfaceChangeCallback')
tail=s[start:]
assert tail.rstrip().endswith('}')
tail=tail.rstrip()[:-1]
s=s[:start]+''' _ = iw.comparisonGate.Primary(context.Background(),r013gate.Stamp{},func(context.Context)error{
'''+tail+''' return nil
 })
}
'''
texts['interfacewatcher.go']=s

s=texts['defaultroutemonitor.go']
s=replace(s,'"sync"','"context"\n "errors"\n "github.com/amnezia-vpn/amneziawg-windows-client/r013gate"')
s=replace(s,'tun *tun.NativeTun) ([]winipcfg.ChangeCallback, error)','tun *tun.NativeTun,comparisonGate *r013gate.Gate,comparisonContext context.Context) ([]winipcfg.ChangeCallback, error)')
start=s.index('\terr := doIt()')
s=s[:start]+''' err:=comparisonGate.Primary(comparisonContext,r013gate.Stamp{},func(context.Context)error{return doIt()})
 if err!=nil{return nil,err}
 worker,err:=r013gate.NewCoalescer(comparisonContext,comparisonGate,150*time.Millisecond,2*time.Second,doIt)
 if err!=nil{return nil,err}
 cbr,err:=winipcfg.RegisterRouteChangeCallback(func(_ winipcfg.MibNotificationType,route *winipcfg.MibIPforwardRow2){if route!=nil&&route.DestinationPrefix.PrefixLength==0{worker.Notify()}})
 if err!=nil{worker.Close(context.Background());return nil,err}
 cbi,err:=winipcfg.RegisterInterfaceChangeCallback(func(notification winipcfg.MibNotificationType,_ *winipcfg.MibIPInterfaceRow){if notification==winipcfg.MibParameterNotification{worker.Notify()}})
 if err!=nil{worker.Close(context.Background());cbr.Unregister();return nil,err}
 return []winipcfg.ChangeCallback{&comparisonRouteSubscription{cbr,worker},&comparisonRouteSubscription{cbi,worker}},nil
}

type comparisonRouteSubscription struct{callback winipcfg.ChangeCallback;worker *r013gate.Coalescer}
func(s *comparisonRouteSubscription)Unregister()error{
 return errors.Join(s.worker.Close(context.Background()),s.callback.Unregister())
}
'''
texts['defaultroutemonitor.go']=s
for file,text in texts.items():(folder/file).write_text(text,newline='\n')
subprocess.run(['gofmt','-w',*(str(folder/f) for f in names)],check=True)
record={'before':before,'after':{f:hashlib.sha256((folder/f).read_bytes()).hexdigest() for f in names},'scope':'actual service mutation/path/UAPI safety wired, no manager hourly coordinator/observed census yet'}
(root.parent/'service-lifecycle-evidence.json').write_text(json.dumps(record,indent=2))
print(json.dumps(record))
