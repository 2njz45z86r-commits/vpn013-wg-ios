"""Verify the actual public IPA before publishing its download metadata."""
import hashlib
import urllib.parse
import urllib.request

MAX_IPA_BYTES = 256 * 1024 * 1024
ALLOWED_HOSTS = frozenset({'github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'})


def allowed_url(url):
    try:
        parts = urllib.parse.urlsplit(url)
        return (parts.scheme == 'https' and parts.hostname in ALLOWED_HOSTS and
                parts.port in (None, 443) and parts.username is None and
                parts.password is None and not parts.fragment)
    except ValueError:
        return False


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not allowed_url(newurl):
            raise ValueError('Public IPA redirect is not an allowed HTTPS host')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def verify_public_ipa(url, expected_sha256, expected_size, opener=None):
    if (not allowed_url(url) or not isinstance(expected_size, int) or
            not 0 < expected_size <= MAX_IPA_BYTES or
            not isinstance(expected_sha256, str) or len(expected_sha256) != 64 or
            any(c not in '0123456789abcdef' for c in expected_sha256)):
        raise ValueError('Invalid public IPA verification inputs')
    opener = opener or urllib.request.build_opener(SafeRedirect())
    request = urllib.request.Request(url, headers={'Accept-Encoding': 'identity', 'User-Agent': 'VPN013-release-verifier'})
    digest, size = hashlib.sha256(), 0
    with opener.open(request, timeout=60) as response:
        if response.status != 200 or not allowed_url(response.geturl()):
            raise ValueError('Public IPA response is not an allowed HTTPS success')
        while True:
            chunk = response.read(min(1024 * 1024, expected_size - size + 1))
            if not chunk:
                break
            size += len(chunk)
            if size > expected_size:
                raise ValueError('Public IPA is larger than the reviewed file')
            digest.update(chunk)
    if size != expected_size or digest.hexdigest() != expected_sha256:
        raise ValueError('Public IPA does not match the reviewed file')
