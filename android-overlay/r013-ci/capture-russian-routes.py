"""Exact hosted-only OS route readback over a streaming dump, not a Binder parcel."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

EXPECTED_SHA = '0b947f48b2053a98616b33d9f5074aa0a8d15d092a7025d9080e3f2c29061679'
REVIEW = '/sdcard/Android/data/com.vpn013.awg.debug/files/review/'

def verify_dump(text, interface, expected):
    # Active NetworkAgentInfo records only; never accept a historical event.
    records = [line.strip() for line in text.splitlines()
               if line.strip().startswith('NetworkAgentInfo{') and
               re.search(r'InterfaceName:\s+' + re.escape(interface) + r'\s', line)]
    assert len(records) == 1, 'Actual active VPN route record missing or ambiguous'
    record = records[0]
    transports = re.search(r'Transports:\s+([A-Z0-9_|]+)', record)
    assert transports and 'VPN' in transports[1].split('|'), 'Actual record is not a VPN'
    match = re.search(r'Routes:\s*\[([^\]]*)\]', record)
    assert match, 'Actual OS routes missing'
    throw, v6_default = set(), False
    for entry in match[1].split(','):
        fields = entry.split()
        assert fields, 'Empty route entry'
        prefix = ipaddress.ip_network(fields[0], strict=True)
        if 'throw' in fields:
            assert str(prefix) not in throw, 'Duplicate throw route'
            throw.add(str(prefix))
        if prefix.version == 6 and prefix.prefixlen == 0 and '->' in fields:
            assert interface in fields, 'IPv6 default has wrong interface'
            v6_default = True
    assert throw == expected, 'Full exact Russian exclusion inventory differs'
    assert v6_default, 'Foreign IPv6 is not captured by VPN'
    return {'exactRussianExclusions': len(throw), 'foreignIPv6Captured': True}

def main():
    assert os.environ.get('GITHUB_ACTIONS') == 'true'
    assert os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
    assert os.environ.get('GITHUB_REPOSITORY') == '2njz45z86r-commits/vpn013-wg-ios'
    raw = Path('tunnel/src/main/assets/ru-networks.cidr').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == EXPECTED_SHA
    expected = {str(ipaddress.ip_network(row, strict=True)) for row in raw.decode().splitlines()}
    assert len(expected) == 10838
    request = subprocess.check_output(['adb', 'shell',
        'while [ ! -s ' + REVIEW + 'russian-route-request.json ]; do sleep 0.2; done; cat ' +
        REVIEW + 'russian-route-request.json'], timeout=60)
    assert len(request) <= 1024
    values = json.loads(request)
    interface, nonce = values['interface'], values['nonce']
    assert re.fullmatch(r'tun[0-9]{1,6}', interface) and re.fullmatch(r'[0-9a-f]{32}', nonce)
    with tempfile.TemporaryFile() as output:
        subprocess.run(['adb', 'shell', 'dumpsys', 'connectivity'], stdout=output,
                       stderr=subprocess.DEVNULL, timeout=25, check=True)
        output.seek(0)
        dump = output.read(8_000_001)
    assert len(dump) <= 8_000_000
    result = verify_dump(dump.decode(), interface, expected)
    result.update({'interface': interface, 'nonce': nonce, 'snapshotSHA256': EXPECTED_SHA,
                   'source': 'actual hosted Android ConnectivityService dump'})
    path = Path('output/review/russian-route-proof.json')
    path.write_text(json.dumps(result))
    subprocess.run(['adb', 'push', str(path), REVIEW + 'russian-route-proof.json'],
                   timeout=10, check=True, stdout=subprocess.DEVNULL)
    print('Actual complete 10838-route OS inventory and IPv6 capture verified')

if __name__ == '__main__':
    main()
