import hashlib
import io
import ast
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from scripts.verify_public_ipa import SafeRedirect, allowed_url, verify_public_ipa


class Response(io.BytesIO):
    status = 200
    def __init__(self, data, url):
        super().__init__(data)
        self.url = url
    def geturl(self):
        return self.url


class Opener:
    def __init__(self, data, url='https://release-assets.githubusercontent.com/file'):
        self.data, self.url = data, url
    def open(self, request, timeout):
        return Response(self.data, self.url)


class PublicIpaTests(unittest.TestCase):
    def test_accepts_exact_bytes(self):
        data = b'synthetic ipa'
        verify_public_ipa('https://github.com/org/repo/releases/download/a/app.ipa', hashlib.sha256(data).hexdigest(), len(data), Opener(data))

    def test_rejects_wrong_hash_size_and_host(self):
        data = b'synthetic ipa'
        url = 'https://github.com/org/repo/releases/download/a/app.ipa'
        digest = hashlib.sha256(data).hexdigest()
        for payload, size, destination in [(b'wrong', len(data), None), (data + b'x', len(data), None), (data[:-1], len(data), None), (data, len(data), 'https://evil.invalid/file')]:
            with self.subTest(payload=payload, size=size, destination=destination):
                with self.assertRaises(ValueError):
                    verify_public_ipa(url, digest, size, Opener(payload, destination or 'https://release-assets.githubusercontent.com/file'))

    def test_rejects_bad_url_and_untrusted_redirect(self):
        for url in ('http://github.com/a', 'https://github.com.evil.invalid/a', 'https://user@github.com/a', 'https://github.com:8443/a'):
            self.assertFalse(allowed_url(url))
        with self.assertRaises(ValueError):
            SafeRedirect().redirect_request(None, None, 302, '', {}, 'https://evil.invalid/ipa')

    def test_publisher_fails_closed_without_creating_bytecode(self):
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp)
            (target / 'scripts').mkdir()
            for name in ('native_ui_shards.py', 'verify_public_ipa.py', 'security_release_gate.py'):
                shutil.copy2(root / 'scripts' / name, target / 'scripts' / name)
            shutil.copy2(root / 'publish-client-release.py', target / 'publish-client-release.py')
            env = os.environ.copy()
            env.pop('PYTHONDONTWRITEBYTECODE', None)
            for optimization in ([], ['-O']):
                result = subprocess.run([sys.executable, *optimization, 'publish-client-release.py'], cwd=target, env=env, capture_output=True, text=True, timeout=30)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Security release gate: BLOCKED', result.stdout)
            self.assertFalse(list(target.rglob('*.pyc')))

    def test_publisher_does_not_use_optimizable_assertions(self):
        root = Path(__file__).resolve().parents[2]
        source = (root / 'publish-client-release.py').read_text(encoding='utf-8')
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(ast.parse(source))))


if __name__ == '__main__':
    unittest.main()
