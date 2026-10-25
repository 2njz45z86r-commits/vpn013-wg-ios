"""Keep the previous dynamic WFP policy until its replacement is installed."""
from pathlib import Path
import hashlib,json,subprocess,sys
root=Path(sys.argv[1]).resolve();folder=root/'vendor/github.com/amnezia-vpn/amneziawg-windows/v3/tunnel'
paths={'blocker':folder/'firewall/blocker.go','syscalls':folder/'firewall/zsyscall_windows.go'}
pins={'blocker':'ddd1d467237b8f0355b97b1685bf1849ae1f6a9bdee23e1eb5edec0b1d44a85e','syscalls':'244f6780b094a08b81720189c91b5dd79deff0be54df73483eaaeb308cb947e7'}
before={k:hashlib.sha256(v.read_bytes()).hexdigest() for k,v in paths.items()};assert before==pins,('Unknown WFP source',before)
s=paths['syscalls'].read_text();assert s.count('err = errnoErr(e1)')==9
# fwpmu.h APIs return DWORD status directly. LastError is not the status.
# Sources: Microsoft FwpmEngineOpen0/Close0, FwpmFilterAdd0 and FwpmTransaction*
# docs, https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/ .
s=s.replace('r1, _, e1 :=','r1, _, _ :=').replace('err = errnoErr(e1)','err = syscall.Errno(r1)')
paths['syscalls'].write_text(s,newline='\n')
s=paths['blocker'].read_text()
def replace(old,new):
 global s
 assert s.count(old)==1,(old[:100],s.count(old))
 s=s.replace(old,new,1)
replace('var wfpSession uintptr','var wfpSession uintptr\nvar wfpRetired uintptr')
replace('if wfpSession != 0 {\n\t\treturn errors.New("The firewall has already been enabled")','if wfpSession != 0 || wfpRetired != 0 {\n\t\treturn errors.New("The firewall has already been enabled or awaits cleanup")')
replace('''		fwpmEngineClose0(session)
		return wrapErr(err)''','''        closeErr:=fwpmEngineClose0(session)
        if closeErr!=nil{wfpRetired=session}
        return errors.Join(wrapErr(err),closeErr)''')
replace('''func DisableFirewall() {
	if wfpSession != 0 {
		fwpmEngineClose0(wfpSession)
		wfpSession = 0
	}
}''','''// ReplaceFirewall is called only inside the actual primary mutation fence.
// The preceding dynamic policy remains installed while the next transaction
// commits. Failure retains it. At most two native sessions can remain owned;
// a failed old-session close refuses further replacements until real cleanup.
func ReplaceFirewall(luid uint64,doNotRestrict bool,dns []net.IP)error{
 if len(dns)>64{return errors.New("WFP DNS resource bound exceeded")}
 for _,ip:=range dns{if ip.To4()==nil&&ip.To16()==nil{return errors.New("invalid WFP DNS address")}}
 if wfpRetired!=0{return errors.New("previous WFP session still awaits cleanup")}
 previous:=wfpSession
 wfpSession=0
 if err:=EnableFirewall(luid,doNotRestrict,dns);err!=nil{wfpSession=previous;return err}
 if err:=VerifyFirewall();err!=nil{
  failed:=wfpSession;wfpSession=previous
  if closeErr:=fwpmEngineClose0(failed);closeErr!=nil{wfpRetired=failed;return errors.Join(err,closeErr)}
  return err
 }
 if previous!=0{
  if err:=fwpmEngineClose0(previous);err!=nil{wfpRetired=previous;return err}
 }
 return nil
}

// VerifyFirewall checks a real read-only transaction on the owned native
// engine. It does not equate API success with network traffic enforcement.
func VerifyFirewall()error{
 if wfpSession==0||wfpRetired!=0{return errors.New("native WFP policy unavailable")}
 if err:=fwpmTransactionBegin0(wfpSession,1);err!=nil{return err}
 return fwpmTransactionAbort0(wfpSession)
}

func DisableFirewall() {
 if wfpSession!=0{if fwpmEngineClose0(wfpSession)==nil{wfpSession=0}}
 if wfpRetired!=0{if fwpmEngineClose0(wfpRetired)==nil{wfpRetired=0}}
}''')
paths['blocker'].write_text(s,newline='\n')
subprocess.run(['gofmt','-w',*[str(p) for p in paths.values()]],check=True)
record={'before':before,'after':{k:hashlib.sha256(v.read_bytes()).hexdigest() for k,v in paths.items()},'scope':'native WFP direct DWORD errors, overlapping dynamic replacement, bounded retained cleanup; not a completed backend switch'}
(root.parent/'firewall-replace-evidence.json').write_text(json.dumps(record,indent=2));print(json.dumps(record))
