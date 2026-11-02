"""Select an available iPhone simulator from simctl JSON, or fail closed."""
import json
import re
import sys


PREFERRED = ('iPhone 16 Pro', 'iPhone 17 Pro', 'iPhone 17', 'iPhone 16')
RUNTIME = re.compile(r'^com\.apple\.CoreSimulator\.SimRuntime\.iOS-(\d+(?:-\d+)*)$')
UDID = re.compile(r'^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$')


def select(data):
    candidates = []
    for runtime, devices in data.get('devices', {}).items():
        match = RUNTIME.fullmatch(runtime)
        if not match or not isinstance(devices, list):
            continue
        version = tuple(int(part) for part in match.group(1).split('-'))
        for item in devices:
            name, udid = item.get('name', ''), item.get('udid', '')
            if (not item.get('isAvailable', True) or not name.startswith('iPhone ') or
                    not UDID.fullmatch(udid)):
                continue
            rank = len(PREFERRED) - PREFERRED.index(name) if name in PREFERRED else 0
            candidates.append((version, rank, name, udid))
    if not candidates:
        raise ValueError('No available iOS iPhone simulator')
    return max(candidates)


def main():
    try:
        version, _, name, udid = select(json.load(sys.stdin))
    except (ValueError, TypeError, AttributeError, json.JSONDecodeError) as exc:
        print('iPhone simulator selection failed: ' + str(exc), file=sys.stderr)
        return 1
    print('Selected iOS ' + '.'.join(map(str, version)) + ' ' + name, file=sys.stderr)
    print(udid)
    return 0


if __name__ == '__main__':
    sys.exit(main())
