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
    if len(sys.argv) > 1 and sys.argv[1] == 'occupied':
        before = processes()
        if len(before) != 1:
            raise RuntimeError('Synthetic Xray process count was not one before occupied-port test')
        payload = {'remark':'fixture-conflicting-wg', 'tag':'fixture-conflicting-wg',
                   'listen':'0.0.0.0', 'port':25122, 'protocol':'wireguard', 'enable':False,
                   'excludeFromSub':True, 'up':0, 'down':0, 'total':0, 'expiryTime':0,
                   'settings':json.dumps({'secretKey':base64.b64encode(os.urandom(32)).decode(),
                                          'clients':[], 'peers':[], 'mtu':1420, 'noKernelTun':True,
                                          'subnetIp':'10.244.241.0', 'subnetCidr':24}),
                   'streamSettings':'{}', 'sniffing':'{"enabled":false,"destOverride":[]}'}
        row = request('panel/api/inbounds/add', payload, token)
        if not isinstance(row, dict) or not isinstance(row.get('id'), int):
            raise RuntimeError('Synthetic conflicting inbound was not created')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as holder:
            holder.bind(('0.0.0.0', 25122))
            try:
                request('panel/api/inbounds/setEnable/' + str(row['id']), {'enable':True}, token)
                accepted = True
            except (RuntimeError, urllib.error.HTTPError):
                accepted = False
            seen = []
            for _ in range(25):
                after = processes()
                if after != before:
                    seen.append(after)
                time.sleep(.2)
            held_snapshot = {'synthetic_conflicting_udp_held':True, 'synthetic_enable_accepted':accepted,
                             'synthetic_core_changed_or_disappeared':bool(seen),
                             'synthetic_core_running_at_end':bool(processes()), 'production_contact':False}
        # After releasing the synthetic blocker, check actual port occupancy
        # independently of the panel's success reply and stored enable flag.
        time.sleep(1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            try:
                probe.bind(('0.0.0.0',25122))
                held_snapshot['synthetic_udp_free_after_release'] = True
            except OSError:
                held_snapshot['synthetic_udp_free_after_release'] = False
        rows = request('panel/api/inbounds/list')
        matches = [r for r in rows if r.get('remark') == 'fixture-conflicting-wg']
        held_snapshot['synthetic_panel_record_enabled'] = len(matches)==1 and matches[0].get('enable') is True
        print(json.dumps(held_snapshot))
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
