"""Create one disabled disposable inbound inside a network-isolated synthetic H1 panel."""
import base64
import http.cookiejar
import json
import os
from pathlib import Path
import socket
import sys
import time
import urllib.error
import urllib.request

base = 'http://127.0.0.1:25119/fixture/'
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

def request(path, payload=None, token=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['X-CSRF-Token'] = token
    body = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(base + path, data=body, headers=headers)
    try:
        with opener.open(req, timeout=10) as resp:
            value = json.load(resp)
    except urllib.error.HTTPError as exc:
        print('synthetic_http_rejected=' + path + ' status=' + str(exc.code), file=sys.stderr)
        raise
    if not isinstance(value, dict) or value.get('success') is not True:
        raise RuntimeError('Synthetic panel rejected a request: ' + path)
    return value.get('obj')

try:
    initial_token = request('csrf-token')
    if not isinstance(initial_token, str) or not initial_token:
        raise RuntimeError('Synthetic pre-login CSRF response was not a token')
    request('login', {'username': 'fixtureuser', 'password': 'fixturepassword'}, initial_token)
    token = request('csrf-token')
    if not isinstance(token, str) or not token:
        raise RuntimeError('Synthetic CSRF response was not a token')
    if len(sys.argv) > 1 and sys.argv[1] == 'activate':
        rows = request('panel/api/inbounds/list')
        found = [r for r in rows if r.get('remark') == 'fixture-only-wg']
        if len(found) != 1 or found[0].get('enable') is not False:
            raise RuntimeError('Synthetic disabled inbound unavailable')
        def processes():
            matches = {}
            for p in Path('/proc').iterdir():
                if p.name.isdigit():
                    try:
                        args = (p/'cmdline').read_bytes().split(b'\0')
                        if args and args[0].endswith(b'xray-linux-amd64'):
                            matches[p.name] = (p/'stat').read_text().split()[21]
                    except (FileNotFoundError, ProcessLookupError, PermissionError):
                        pass
            return matches
        initial = processes()
        if len(initial) != 1:
            raise RuntimeError('Synthetic Xray process count was not one')
        request('panel/api/inbounds/setEnable/' + str(found[0]['id']), {'enable':True}, token)
        for _ in range(60):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                try:
                    probe.bind(('127.0.0.1', 25120))
                except OSError:
                    break
            time.sleep(.2)
        else:
            raise RuntimeError('Synthetic WireGuard UDP listener unavailable')
        time.sleep(2)
        if processes() != initial:
            raise RuntimeError('Synthetic Xray process changed on enable')
        print('synthetic_panel_wireguard_udp_enabled=true synthetic_xray_process_unchanged=true')
        sys.exit(0)
    payload = {'remark':'fixture-only-wg', 'tag':'fixture-wg', 'listen':'0.0.0.0', 'port':25120,
               'protocol':'wireguard', 'enable':False, 'excludeFromSub':True,
               'up':0, 'down':0, 'total':0, 'expiryTime':0,
               'settings':json.dumps({'secretKey':base64.b64encode(os.urandom(32)).decode(),
                                      'clients':[], 'peers':[], 'mtu':1420, 'noKernelTun':True,
                                      'subnetIp':'10.244.240.0', 'subnetCidr':24}),
               'streamSettings':'{}', 'sniffing':'{"enabled":false,"destOverride":[]}'}
    result = request('panel/api/inbounds/add', payload, token)
    if not isinstance(result, dict) or not isinstance(result.get('id'), int):
        raise RuntimeError('Synthetic inbound was not created')
    print('synthetic_disabled_inbound_created=true')
except Exception as exc:
    print('synthetic_panel_request_failed=' + type(exc).__name__, file=sys.stderr)
    sys.exit(1)
