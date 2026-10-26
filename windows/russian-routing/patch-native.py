"""Add destination-only split routes and narrow WFP exceptions after the safety overlays."""
from pathlib import Path
import shutil,sys
root=Path(sys.argv[1]);source=Path(__file__).resolve().parent
tunnel=root/'vendor/github.com/amnezia-vpn/amneziawg-windows/v3/tunnel'
p=tunnel/'addressconfig.go';s=p.read_text(encoding='utf-8')
assert s.count('routes = append(routes, route)')==1
s=s.replace('routes = append(routes, route)','''original,parseErr:=netip.ParsePrefix(route.Destination.String())
            if parseErr!=nil{return parseErr}
            parts := []netip.Prefix{original.Masked()}
            var splitErr error
            if r013routing.Enabled() { parts,splitErr = r013routing.Exclude(parts[0]) }
            if splitErr != nil { return splitErr }
            for _, part := range parts {
                ip := net.IP(part.Addr().AsSlice())
                copy := route
                copy.Destination = net.IPNet{IP: ip, Mask: net.CIDRMask(part.Bits(), part.Addr().BitLen())}
                routes = append(routes, copy)
            }''')
s=s.replace('import (','import (\n "net/netip"\n "github.com/amnezia-vpn/amneziawg-windows-client/r013routing"',1)
s=s.replace('"sort"','"sort"\n "time"',1)
anchor='err = luid.SetRoutesForFamily(family, deduplicatedRoutes)'
assert s.count(anchor)==1
s=s.replace(anchor,'''started:=time.Now()
        if r013routing.Enabled(){log.Printf("R013Routing: applying %d effective routes, family %d",len(deduplicatedRoutes),family)}
        '''+anchor+'''
        if r013routing.Enabled(){log.Printf("R013Routing: route apply family %d finished in %s (error=%v)",family,time.Since(started),err)}''')
p.write_text(s,encoding='utf-8',newline='\n')
p=tunnel/'firewall/blocker.go';s=p.read_text(encoding='utf-8')
anchor='\t\t\terr = blockAll(session, baseObjects, 0)';assert s.count(anchor)==1
s=s.replace(anchor,'''            if r013routing.Enabled() {
                err = permitRussianNetworks(session, baseObjects, 11)
                if err != nil { return wrapErr(err) }
            }
''' + anchor)
s=s.replace('import (','import (\n \"github.com/amnezia-vpn/amneziawg-windows-client/r013routing\"',1)
p.write_text(s,encoding='utf-8',newline='\n')
shutil.copyfile(source/'russian_networks_windows.go',tunnel/'firewall/russian_networks_windows.go')
shutil.copyfile(source/'russian_networks_windows_test.go',tunnel/'firewall/russian_networks_windows_test.go')
# Readback must test the effective OS prefixes, while retaining original exact
# peer settings in membership, UAPI, vault and rollback snapshots.
p=tunnel/'r013_existing_network.go';s=p.read_text(encoding='utf-8')
s=s.replace('import (','import (\n "net/netip"\n "github.com/amnezia-vpn/amneziawg-windows-client/r013routing"',1)
start=s.index('\tif !configuration.Interface.TableOff {',s.index('func verifyOwnNetwork'))
end=s.index('\n\tdns, err := luid.DNS()',start)
s=s[:start]+'''    if !configuration.Interface.TableOff {
        rows,err:=winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
        if err!=nil{return err}
        actual:=make(map[string]bool,len(rows))
        for _,row:=range rows{if row.InterfaceLUID==luid&&row.Metric==0&&row.NextHop.IP().IsUnspecified(){network:=row.DestinationPrefix.IPNet();actual[network.String()]=true}}
        for _,peer:=range configuration.Peers{for _,prefix:=range peer.AllowedIPs{
            haveSource:=false
            for _,address:=range configuration.Interface.Addresses{if address.Bits()==prefix.Bits(){haveSource=true}}
            if !haveSource{continue}
            network:=prefix.IPNet();original,err:=netip.ParsePrefix(network.String());if err!=nil{return err}
            parts:=[]netip.Prefix{original.Masked()}
            if r013routing.Enabled(){parts,err=r013routing.Exclude(original);if err!=nil{return err}}
            for _,part:=range parts{if !actual[part.String()]{return errors.New("effective split route readback missing or differs")}}
        }}
    }
'''+s[end:]
# Retired cleanup already enumerates and deletes all own-LUID rows. Existing
# specific original-route absence check remains an additional invariant.
p.write_text(s,encoding='utf-8',newline='\n')
print('Russian OS routes and WFP exceptions staged; native validation required')

# Observation must read the effective OS routes instead of the deliberately
# removed default. Keep every existing identity, watcher and barrier check.
p=tunnel/'r013_observation.go';s=p.read_text(encoding='utf-8')
s=s.replace('import (','import (\n "github.com/amnezia-vpn/amneziawg-windows-client/r013routing"',1)
old='''\t\tif _, err = luid.Route(prefix.IPNet(), net.IPv4zero); err != nil {
\t\t\treturn out
\t\t}'''
assert s.count(old)==1
s=s.replace(old,'''        if !r013routing.Enabled() {
            if _,err=luid.Route(prefix.IPNet(),net.IPv4zero);err!=nil{return out}
        }''',1)
anchor='\traw, err := dev.IpcGet()';assert s.count(anchor)==1
s=s.replace(anchor,'''    if r013routing.Enabled() {
        if verifyOwnNetwork(luid,cfg)!=nil{return out}
    }
'''+anchor,1)
p.write_text(s,encoding='utf-8',newline='\n')

# Internal split routes belong to the owned TUN. Bound the whole native table,
# but retain the original 8192-row budget for ALL foreign routes, after only
# own-LUID exclusion. External route/interface fingerprints remain unchanged.
p=tunnel/'r013_backend_owner.go';s=p.read_text(encoding='utf-8')
anchor='if err != nil || len(routes) > 8192 {';assert s.count(anchor)==1
s=s.replace(anchor,'if err != nil || len(routes) > 65536 {',1)
start=s.index('func comparisonForeignPath(')
anchor='\tfor _, row := range routes {';pos=s.index(anchor,start)
s=s[:pos]+'\tforeignRouteCount := 0\n'+s[pos:]
anchor='''\t\tinterfaces[row.InterfaceLUID] = true
\t\tparts = append(parts, fmt.Sprintf("r:''';assert s.count(anchor)==1
s=s.replace(anchor,'''        foreignRouteCount++
        if foreignRouteCount>8192{return "",errBackendUnknown}
'''+anchor,1)
p.write_text(s,encoding='utf-8',newline='\n')

p=tunnel/'service.go';s=p.read_text(encoding='utf-8')
s=s.replace('import (','import (\n "github.com/amnezia-vpn/amneziawg-windows-client/r013routing"',1)
anchor='\tchanges <- svc.Status{State: svc.StartPending}';assert s.count(anchor)==1
s=s.replace(anchor,anchor+'\n\tr013routing.Enable()')
p.write_text(s,encoding='utf-8',newline='\n')
