"""Add bounded service-selection RPCs to the native manager IPC source."""
from pathlib import Path
import sys
root = Path(sys.argv[1]).resolve()
client = root/'manager/ipc_client.go'
server = root/'manager/ipc_server.go'
s=client.read_text(encoding='utf-8')
anchor='\tInstallR013UpdateMethodType\n'
assert s.count(anchor)==1
s=s.replace(anchor,anchor+'\tGetServicePoliciesMethodType\n\tUpdateServicePoliciesMethodType\n\tGetServiceTargetsMethodType\n')
s=s.replace('import (','import (\n "github.com/amnezia-vpn/amneziawg-windows-client/r013routing"',1)
s += '''
func IPCClientGetServicePolicies() (r013routing.ServicePolicies,error) {
 rpcMutex.Lock();defer rpcMutex.Unlock()
 if err:=rpcEncoder.Encode(GetServicePoliciesMethodType);err!=nil{return r013routing.ServicePolicies{},err}
 var value r013routing.ServicePolicies
 if err:=rpcDecoder.Decode(&value);err!=nil{return value,err}
 return value,rpcDecodeError()
}
func IPCClientUpdateServicePolicies(changes []r013routing.ProfilePolicy) error {
 if len(changes)==0||len(changes)>90{return errors.New("Выберите серверы для применения.")}
 rpcMutex.Lock();defer rpcMutex.Unlock()
 if err:=rpcEncoder.Encode(UpdateServicePoliciesMethodType);err!=nil{return err}
 if err:=rpcEncoder.Encode(changes);err!=nil{return err}
 return rpcDecodeError()
}
func IPCClientGetServiceTargets() ([]ServiceTarget,error) {
 rpcMutex.Lock();defer rpcMutex.Unlock()
 if err:=rpcEncoder.Encode(GetServiceTargetsMethodType);err!=nil{return nil,err}
 var value []ServiceTarget
 if err:=rpcDecoder.Decode(&value);err!=nil{return nil,err}
 return value,rpcDecodeError()
}
'''
client.write_text(s,encoding='utf-8',newline='\n')
s=server.read_text(encoding='utf-8')
s=s.replace('import (','import (\n "github.com/amnezia-vpn/amneziawg-windows-client/r013routing"',1)
anchor='\t\tcase InstallR013UpdateMethodType:'
assert s.count(anchor)==1
s=s.replace(anchor,'''        case GetServicePoliciesMethodType:
            doc, err := s.GetServicePolicies()
            if encoder.Encode(doc)!=nil || encoder.Encode(errToString(err))!=nil{return}
        case UpdateServicePoliciesMethodType:
            var changes []r013routing.ProfilePolicy
            if decoder.Decode(&changes)!=nil{return}
            if encoder.Encode(errToString(s.UpdateServicePolicies(changes)))!=nil{return}
        case GetServiceTargetsMethodType:
            targets, err := s.GetServiceTargets()
            if encoder.Encode(targets)!=nil || encoder.Encode(errToString(err))!=nil{return}
'''+anchor)
server.write_text(s,encoding='utf-8',newline='\n')
