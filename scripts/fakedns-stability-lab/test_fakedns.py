"""Synthetic loopback-only FakeDNS experiment, no real DNS or VPN involved."""
import contextlib, ipaddress, json, socket, struct, subprocess, tempfile, threading, time
from pathlib import Path

XRAY = Path('D:/vpn/work/vpn013-popup-ios-evidence-20261102/xray-awg-dynamic-synthetic.exe')

def listener(kind=socket.SOCK_STREAM):
    s = socket.socket(socket.AF_INET, kind)
    s.bind(('127.0.0.1', 0))
    if kind == socket.SOCK_STREAM: s.listen(4)
    return s

def serve(sock, marker):
    sock.settimeout(8)
    try:
        while True:
            conn, _ = sock.accept()
            with conn:
                conn.sendall(marker.encode('ascii'))
    except (socket.timeout, OSError):
        return

def dns(name, port, qtype=1):
    ident = 0x7131
    labels = b''.join(bytes([len(x)]) + x.encode() for x in name.split('.')) + b'\x00'
    query = struct.pack('!HHHHHH', ident, 0x0100, 1, 0, 0, 0) + labels + struct.pack('!HH', qtype, 1)
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as s:
        s.settimeout(4); s.sendto(query, ('127.0.0.1', port)); data, _ = s.recvfrom(4096)
    head = struct.unpack('!HHHHHH', data[:12]); assert head[0] == ident and head[3] == 1, head
    size = {1:4, 28:16}[qtype]
    assert data[-size-2:-size] == struct.pack('!H',size), data.hex()
    return str(ipaddress.ip_address(data[-size:]))

def exact(sock, n):
    result = b''
    while len(result) < n:
        part = sock.recv(n-len(result))
        if not part: raise RuntimeError('unexpected EOF')
        result += part
    return result

def socks(fake_ip, socks_port):
    with socket.create_connection(('127.0.0.1', socks_port), timeout=4) as s:
        s.sendall(b'\x05\x01\x00'); assert exact(s,2) == b'\x05\x00'
        ip = ipaddress.ip_address(fake_ip)
        s.sendall(b'\x05\x01\x00' + (b'\x01' if ip.version == 4 else b'\x04') + ip.packed + struct.pack('!H', 443))
        header = exact(s,4); assert header[:2] == b'\x05\x00', header
        size = {1:4,4:16}.get(header[3]); assert size is not None
        exact(s,size+2)
        return s.recv(100).decode()

def main():
    a, b, udp, socks_reserve = listener(), listener(), listener(socket.SOCK_DGRAM), listener()
    ap,bp,dp,sp = a.getsockname()[1],b.getsockname()[1],udp.getsockname()[1],socks_reserve.getsockname()[1]
    udp.close(); socks_reserve.close()
    for s,m in ((a,'A'),(b,'B')): threading.Thread(target=serve,args=(s,m),daemon=True).start()
    config = {
       'log': {'loglevel':'warning'}, 'dns':{'servers':['fakedns'],'queryStrategy':'UseIP'},
       'fakedns':[{'ipPool':'198.18.0.0/16','poolSize':65535}, {'ipPool':'2001:2::/48','poolSize':65535}],
       'inbounds':[
          {'tag':'dns-in','listen':'127.0.0.1','port':dp,'protocol':'dokodemo-door','settings':{'address':'127.0.0.1','port':53,'network':'udp'}},
          {'tag':'socks-in','listen':'127.0.0.1','port':sp,'protocol':'socks','settings':{'udp':False},'sniffing':{'enabled':True,'destOverride':['fakedns'],'metadataOnly':True}}],
       'outbounds':[
          {'tag':'dns-out','protocol':'dns'},
          {'tag':'route-a','protocol':'freedom','settings':{'redirect':f'127.0.0.1:{ap}'}},
          {'tag':'route-b','protocol':'freedom','settings':{'redirect':f'127.0.0.1:{bp}'}},
          {'tag':'blocked','protocol':'blackhole'}],
       'routing':{'rules':[
          {'type':'field','inboundTag':['dns-in'],'outboundTag':'dns-out'},
          {'type':'field','domain':['full:service-a.invalid'],'outboundTag':'route-a'},
          {'type':'field','domain':['full:service-b.invalid'],'outboundTag':'route-b'},
          {'type':'field','inboundTag':['socks-in'],'outboundTag':'blocked'}]}}
    with tempfile.TemporaryDirectory(prefix='vpn013-fakedns-') as d:
        path = Path(d)/'config.json'; path.write_text(json.dumps(config),encoding='utf8')
        with subprocess.Popen([str(XRAY),'run','-config',str(path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
            try:
                for _ in range(40):
                    if proc.poll() is not None: raise RuntimeError(proc.stdout.read().decode(errors='replace'))
                    try:
                        with socket.create_connection(('127.0.0.1',sp),timeout=.2): break
                    except OSError: time.sleep(.1)
                else: raise RuntimeError('Xray did not listen')
                names = ('service-a.invalid','service-b.invalid')
                ips4 = [dns(name,dp,1) for name in names]
                ips6 = [dns(name,dp,28) for name in names]
                assert len(set(ips4)) == 2 and all(ipaddress.ip_address(x) in ipaddress.ip_network('198.18.0.0/16') for x in ips4), ips4
                assert len(set(ips6)) == 2 and all(ipaddress.ip_address(x) in ipaddress.ip_network('2001:2::/48') for x in ips6), ips6
                results4 = [socks(ip,sp) for ip in ips4]
                results6 = [socks(ip,sp) for ip in ips6]
                assert results4 == results6 == ['A','B'], (results4,results6)
                print(json.dumps({'status':'PASS','fake_ipv4_count':len(set(ips4)),'fake_ipv6_count':len(set(ips6)), 'domain_routes_v4':results4,'domain_routes_v6':results6,
                    'scope':'loopback fake DNS and SOCKS only; no iPhone, WireGuard, real DNS or ECH tested'}))
            finally:
                proc.terminate()
                try: proc.wait(timeout=5)
                except subprocess.TimeoutExpired: proc.kill(); proc.wait()
                a.close(); b.close()

if __name__ == '__main__': main()
