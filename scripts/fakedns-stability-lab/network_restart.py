"""Isolated Xray FakeDNS restart check. Local synthetic names only; no VPN or iPhone."""
import contextlib, hashlib, importlib.util, json, os, socket, subprocess, tempfile, threading, time
from pathlib import Path

root=Path(__file__).resolve().parent
p=root/'test_fakedns.py'
spec=importlib.util.spec_from_file_location('vpn013_prior_fakedns_lab',p);lib=importlib.util.module_from_spec(spec);spec.loader.exec_module(lib)
XRAY=root/'xray-fakedns-lab.exe'

def run():
 a,b,udp,socks_reserve=lib.listener(),lib.listener(),lib.listener(socket.SOCK_DGRAM),lib.listener()
 ap,bp,dp,sp=a.getsockname()[1],b.getsockname()[1],udp.getsockname()[1],socks_reserve.getsockname()[1]
 udp.close();socks_reserve.close()
 for s,m in ((a,'A'),(b,'B')):threading.Thread(target=lib.serve,args=(s,m),daemon=True).start()
 cfg={'log':{'loglevel':'warning'},'dns':{'servers':['fakedns'],'queryStrategy':'UseIP'},'fakedns':[{'ipPool':'198.18.0.0/29','poolSize':2},{'ipPool':'2001:2::/125','poolSize':2}],
  'inbounds':[{'tag':'dns-in','listen':'127.0.0.1','port':dp,'protocol':'dokodemo-door','settings':{'address':'127.0.0.1','port':53,'network':'udp'}},{'tag':'socks-in','listen':'127.0.0.1','port':sp,'protocol':'socks','settings':{'udp':False},'sniffing':{'enabled':True,'destOverride':['fakedns'],'metadataOnly':True}}],
  'outbounds':[{'tag':'dns-out','protocol':'dns'},{'tag':'route-a','protocol':'freedom','settings':{'redirect':f'127.0.0.1:{ap}'}},{'tag':'route-b','protocol':'freedom','settings':{'redirect':f'127.0.0.1:{bp}'}},{'tag':'blocked','protocol':'blackhole'}],
  'routing':{'rules':[{'type':'field','inboundTag':['dns-in'],'outboundTag':'dns-out'},{'type':'field','domain':['full:service-a.invalid'],'outboundTag':'route-a'},{'type':'field','domain':['full:service-b.invalid'],'outboundTag':'route-b'},{'type':'field','inboundTag':['socks-in'],'outboundTag':'blocked'}]}}
 with tempfile.TemporaryDirectory(prefix='vpn013-stable-dns-') as d:
  path=Path(d)/'config.json';path.write_text(json.dumps(cfg),encoding='utf8');env=os.environ.copy();env['VPN013_LAB_FAKEDNS_DIR']=d
  def start():
   proc=subprocess.Popen([str(XRAY),'run','-config',str(path)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env=env,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
   for _ in range(80):
    if proc.poll() is not None:raise RuntimeError(proc.stdout.read().decode(errors='replace'))
    try:
     with socket.create_connection(('127.0.0.1',sp),timeout=.2):return proc
    except OSError:time.sleep(.1)
   proc.terminate();proc.wait(timeout=5);raise RuntimeError('local Xray did not listen')
  def stop(proc):
   proc.terminate()
   try:proc.wait(timeout=5)
   except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)
  try:
   p1=start()
   try:
    names=('service-a.invalid','service-b.invalid'); ips4=[lib.dns(n,dp,1) for n in names];ips6=[lib.dns(n,dp,28) for n in names]
    assert len(set(ips4))==len(set(ips6))==2
    first4=[lib.socks(ip,sp) for ip in ips4];first6=[lib.socks(ip,sp) for ip in ips6];assert first4==first6==['A','B']
   finally:stop(p1)
   p2=start()
   try:
    # No DNS lookup after restart: use addresses retained from process one.
    second4=[lib.socks(ip,sp) for ip in ips4];second6=[lib.socks(ip,sp) for ip in ips6];assert second4==second6==['A','B']
    assert [lib.dns(n,dp,1) for n in names]==ips4 and [lib.dns(n,dp,28) for n in names]==ips6
   finally:stop(p2)
   result={'status':'PASS','initial_v4':first4,'initial_v6':first6,'after_restart_without_dns_v4':second4,'after_restart_without_dns_v6':second6,'no_reuse_unit_tests':'separate Go tests','scope':'macOS local Xray DNS and SOCKS, synthetic names and redirection; no iPhone, real service, VPN, DNS bypass, crash or power-loss proof','binary_sha256':hashlib.sha256(XRAY.read_bytes()).hexdigest()}
   (root/'network-restart-result.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8');print(json.dumps(result))
  finally:a.close();b.close()
if __name__=='__main__':run()
