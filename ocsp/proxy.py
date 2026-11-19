"""OCSP validation proxy.

nginx's auth_request calls this service with the client certificate in the
`X-Client-Cert` header. We check the certificate against an OCSP responder and
answer 200 (good) or 403 (anything else). Details are reported in headers:

  X-OCSP-Status  good | revoked | unknown | expired | not-yet-valid | no-cert |
                 invalid-cert | no-upn | unknown-issuer | unreachable | error
  X-OCSP-Reason  human readable detail (revocation reason, error message, ...)
  X-UPN          the UPN from the certificate's SAN, when one could be parsed

Configuration (environment variables):

  OCSP_HOST           default responder host (default: ocsp.penryn.local)
  CAC_HOST            host serving ca.crt (default: cac.penryn.local)
  OCSP_CA_PATH        trusted CA bundle (default: /etc/ocsp/ca.crt)
  OCSP_ALLOWED_HOSTS  comma separated hosts we may contact for the OCSP and
                      CA-issuer URLs found in a certificate's AIA extension
                      (default: OCSP_HOST,CAC_HOST). `*` allows any host.
  OCSP_CACHE_TTL      seconds to cache `good` and `revoked` results (default: 60,
                      0 disables caching). Never longer than the OCSP response's
                      nextUpdate or the certificate's own expiry. Also sent to nginx
                      as X-Accel-Expires so nginx can cache the auth subrequest too.
  OCSP_MAX_RESPONSE_AGE  seconds an OCSP response without a nextUpdate stays acceptable
                      (default: 3600). Stops an old "good" response being replayed forever.
  OCSP_REQUIRE_NONCE  1 to reject responses that do not echo our request nonce
                      (default: a nonce is sent and checked only if the responder echoes it)
  OCSP_EXPOSE_DETAILS 1 to put the detailed failure reason in X-OCSP-Reason. By default clients
                      only get a generic reason (details can name internal hosts); everything
                      is always in the logs.
  OCSP_VERBOSE        1 to log extra detail for every request

Revocations take up to OCSP_CACHE_TTL seconds to be noticed.
"""
import contextlib
import datetime
import os
import re
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse

import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID

UPN_OID = "1.3.6.1.4.1.311.20.2.3"
# The UPN identifies the user to the downstream app, so it is passed through untouched or not
# at all: never stripped or truncated, which could make two users look like one.
UPN_RE = re.compile(r"[\x21-\x7e]{1,256}")

# What clients are told. The detailed reason (which can contain internal host names,
# library error text, ...) only goes to the logs unless OCSP_EXPOSE_DETAILS is set.
PUBLIC_REASONS = {
    "no-cert": "no client certificate",
    "invalid-cert": "certificate could not be parsed",
    "no-upn": "certificate has no UPN",
    "invalid-upn": "certificate UPN is not acceptable",
    "expired": "certificate has expired",
    "not-yet-valid": "certificate is not valid yet",
    "unknown-issuer": "certificate was not issued by a trusted CA",
    "unknown": "certificate status is unknown",
    "unreachable": "OCSP responder unavailable",
    "error": "certificate status could not be verified",
}
MAX_FETCH_BYTES = 1024 * 1024
CLOCK_SKEW = datetime.timedelta(minutes=5)
MAX_CHAIN_DEPTH = 4

OCSP_HOST = os.environ.get("OCSP_HOST", "ocsp.penryn.local")
CAC_HOST = os.environ.get("CAC_HOST", "cac.penryn.local")
DEFAULT_OCSP_URL = f"http://{OCSP_HOST}:2560"
TRUSTED_CA_PATH = os.environ.get("OCSP_CA_PATH", "/etc/ocsp/ca.crt")
ALLOWED_HOSTS = {
    h.strip().lower()
    for h in (os.environ.get("OCSP_ALLOWED_HOSTS") or f"{OCSP_HOST},{CAC_HOST}").split(",")
    if h.strip()
}


def _int_env(name, default):
    try:
        return max(0, int(os.environ.get(name, default)))
    except ValueError:
        return default


CACHE_TTL = _int_env("OCSP_CACHE_TTL", 60)
CACHE_MAX_ENTRIES = 1000
ISSUER_CACHE_TTL = 3600
MAX_RESPONSE_AGE = _int_env("OCSP_MAX_RESPONSE_AGE", 3600)
REQUIRE_NONCE = os.environ.get("OCSP_REQUIRE_NONCE", "").lower() in ("1", "true", "yes")
EXPOSE_DETAILS = os.environ.get("OCSP_EXPOSE_DETAILS", "").lower() in ("1", "true", "yes")
VERBOSE = os.environ.get("OCSP_VERBOSE", "").lower() in ("1", "true", "yes")

TRUSTED_CAS = []


def vlog(message):
    if VERBOSE:
        print(message, flush=True)


class Denied(Exception):
    """The certificate was not accepted; `status` is reported in X-OCSP-Status."""

    def __init__(self, status, reason="", upn=None):
        super().__init__(f"{status}: {reason}")
        self.status = status
        self.reason = reason
        self.upn = upn


# --- certificate helpers ----------------------------------------------------

def utc_opt(obj, attr):
    """Timezone aware datetime (or None) for a cert/OCSP response date, across cryptography versions."""
    if hasattr(obj, f"{attr}_utc"):
        return getattr(obj, f"{attr}_utc")
    value = getattr(obj, attr)
    return None if value is None else value.replace(tzinfo=datetime.timezone.utc)


def utc(obj, attr):
    return utc_opt(obj, attr)


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


def strip_newlines(data):
    return "\n".join(line.strip() for line in data.splitlines())


def parse_client_cert(header):
    """Parse the X-Client-Cert header.

    nginx sends $ssl_client_escaped_cert (URL encoded, one line); the raw
    multi-line $ssl_client_cert (with tabs added after newlines) also works.
    """
    value = header.strip()
    if "\n" not in value:  # a single line means it is URL encoded
        value = unquote(value)
    return x509.load_pem_x509_certificate(strip_newlines(value).encode())


def parse_der_utf8(value):
    """Decode a DER wrapped string (tag, length, contents), including long-form lengths."""
    if len(value) < 2:
        raise ValueError("DER value too short")
    length = value[1]
    offset = 2
    if length & 0x80:
        num = length & 0x7F
        length = int.from_bytes(value[2:2 + num], "big")
        offset = 2 + num
    return value[offset:offset + length].decode("utf-8")


def get_upn(cert):
    try:
        sans = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.ExtensionNotFound:
        return None
    for general_name in sans:
        if isinstance(general_name, x509.OtherName) and general_name.type_id.dotted_string == UPN_OID:
            return parse_der_utf8(general_name.value)
    return None


def load_certificates(data):
    """Load certificates from PEM, DER, or a PKCS#7 bundle (PEM or DER)."""
    if b"-----BEGIN" in data:
        try:
            return x509.load_pem_x509_certificates(data)
        except ValueError:
            return pkcs7.load_pem_pkcs7_certificates(data)
    try:
        return [x509.load_der_x509_certificate(data)]
    except ValueError:
        return pkcs7.load_der_pkcs7_certificates(data)


def parse_aia(cert):
    ocsp_urls, issuer_urls = [], []
    try:
        aia = cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    except x509.ExtensionNotFound:
        return ocsp_urls, issuer_urls
    for description in aia:
        if not isinstance(description.access_location, x509.UniformResourceIdentifier):
            continue
        if description.access_method == x509.AuthorityInformationAccessOID.OCSP:
            ocsp_urls.append(description.access_location.value)
        elif description.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS:
            issuer_urls.append(description.access_location.value)
    return ocsp_urls, issuer_urls


def issued_by(cert, issuer):
    try:
        cert.verify_directly_issued_by(issuer)
        return True
    except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm):
        return False


def is_trusted(cert, pool, depth=MAX_CHAIN_DEPTH):
    """True if `cert` is a trusted CA, or chains to one through certs in `pool`."""
    if cert in TRUSTED_CAS:
        return True
    if depth == 0:
        return False
    if any(issued_by(cert, ca) for ca in TRUSTED_CAS):
        return True
    return any(p != cert and issued_by(cert, p) and is_trusted(p, pool, depth - 1) for p in pool)


def find_issuer(cert, pool):
    """Find the issuer of `cert`, only ever returning a certificate that chains to a trusted CA.

    Certificates downloaded from the (attacker controllable) AIA extension are
    just candidates in `pool`; they are never trusted on their own.
    """
    for candidate in TRUSTED_CAS + pool:
        if issued_by(cert, candidate) and is_trusted(candidate, pool):
            return candidate
    return None


# --- caching ----------------------------------------------------------------

class TTLCache:
    """Small thread safe cache with per-entry expiry (epoch seconds) and a size bound."""

    def __init__(self, max_entries):
        self.max_entries = max_entries
        self._data = {}
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            value, expires = entry
            if expires <= time.time():
                del self._data[key]
                return None
            return value, expires

    def put(self, key, value, expires):
        with self._lock:
            if len(self._data) >= self.max_entries:
                now = time.time()
                for k in [k for k, (_, exp) in self._data.items() if exp <= now]:
                    del self._data[k]
                while len(self._data) >= self.max_entries:  # still full: drop the oldest
                    del self._data[next(iter(self._data))]
            self._data[key] = (value, expires)


RESULT_CACHE = TTLCache(CACHE_MAX_ENTRIES)
ISSUER_CACHE = TTLCache(32)

_inflight_guard = threading.Lock()
_inflight = {}


@contextlib.contextmanager
def key_lock(key):
    """Serialize work per key, so concurrent requests for the same cert share one lookup."""
    with _inflight_guard:
        entry = _inflight.setdefault(key, [threading.Lock(), 0])
        entry[1] += 1
    try:
        with entry[0]:
            yield
    finally:
        with _inflight_guard:
            entry[1] -= 1
            if entry[1] == 0:
                del _inflight[key]


# --- network helpers --------------------------------------------------------

def url_allowed(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    return "*" in ALLOWED_HOSTS or parsed.hostname.lower() in ALLOWED_HOSTS


def read_limited(response):
    data = b""
    for chunk in response.iter_content(65536):
        data += chunk
        if len(data) > MAX_FETCH_BYTES:
            raise ValueError("response too large")
    return data


def fetch_issuers(url):
    cached = ISSUER_CACHE.get(url)
    if cached is not None:
        return cached[0]
    response = requests.get(url, timeout=3, allow_redirects=False, stream=True)
    response.raise_for_status()
    certs = load_certificates(read_limited(response))
    ISSUER_CACHE.put(url, certs, time.time() + ISSUER_CACHE_TTL)
    return certs


# --- OCSP -------------------------------------------------------------------

def responder_matches(resp, cert):
    if resp.responder_name is not None:
        return cert.subject == resp.responder_name
    if resp.responder_key_hash is not None:
        return x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest == resp.responder_key_hash
    return False


def verify_signature(resp, issuer, now):
    """Check the OCSP response was signed by the issuer or a responder it delegated to."""
    signer = next((c for c in list(resp.certificates) + [issuer] if responder_matches(resp, c)), None)
    if signer is None:
        raise Denied("error", "could not find the OCSP response signer")

    if signer != issuer:
        if not issued_by(signer, issuer):
            raise Denied("error", "OCSP signer was not issued by the CA")
        try:
            ekus = signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except x509.ExtensionNotFound:
            ekus = []
        if ExtendedKeyUsageOID.OCSP_SIGNING not in ekus:
            raise Denied("error", "OCSP signer is not allowed to sign OCSP responses")
        if not utc(signer, "not_valid_before") <= now <= utc(signer, "not_valid_after"):
            raise Denied("error", "OCSP signer certificate is not currently valid")

    key = signer.public_key()
    sig, tbs, digest = resp.signature, resp.tbs_response_bytes, resp.signature_hash_algorithm
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(sig, tbs, padding.PKCS1v15(), digest)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(sig, tbs, ec.ECDSA(digest))
        elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            key.verify(sig, tbs)
        else:
            raise Denied("error", f"unsupported OCSP signer key type {type(key).__name__}")
    except (InvalidSignature, UnsupportedAlgorithm, TypeError, ValueError):
        raise Denied("error", "OCSP response signature is invalid")


def check_ocsp(cert, issuer, url):
    nonce = os.urandom(16)
    request = (
        ocsp.OCSPRequestBuilder()
        .add_certificate(cert, issuer, hashes.SHA1())
        .add_extension(x509.OCSPNonce(nonce), critical=False)
        .build()
    )
    try:
        response = requests.post(
            url,
            data=request.public_bytes(Encoding.DER),
            headers={
                "Content-Type": "application/ocsp-request",
                "Accept": "application/ocsp-response",
                # Without the port, as some responders (e.g. ActivID) reject it
                "Host": urlparse(url).hostname,
            },
            timeout=5,
            allow_redirects=False,
            stream=True,
        )
        response.raise_for_status()
        body = read_limited(response)
    except (requests.RequestException, ValueError) as e:
        raise Denied("unreachable", f"OCSP responder {url} failed: {e}")

    try:
        resp = ocsp.load_der_ocsp_response(body)
    except ValueError as e:
        raise Denied("error", f"unparseable OCSP response: {e}")

    if resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        raise Denied("error", f"OCSP responder status {resp.response_status.name}")

    now = now_utc()
    verify_signature(resp, issuer, now)

    if (resp.serial_number != request.serial_number
            or resp.issuer_key_hash != request.issuer_key_hash
            or resp.issuer_name_hash != request.issuer_name_hash):
        raise Denied("error", "OCSP response is for a different certificate")

    try:
        echoed = resp.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
    except x509.ExtensionNotFound:
        echoed = None
    if echoed is not None and echoed != nonce:
        raise Denied("error", "OCSP response nonce does not match (replayed response?)")
    if echoed is None and REQUIRE_NONCE:
        raise Denied("error", "OCSP response did not echo the request nonce")

    this_update = utc(resp, "this_update")
    next_update = utc_opt(resp, "next_update")
    if this_update > now + CLOCK_SKEW:
        raise Denied("error", "OCSP response is from the future")
    if next_update is not None and next_update < now - CLOCK_SKEW:
        raise Denied("error", "OCSP response is stale")
    if next_update is None and echoed is None and now - this_update > datetime.timedelta(seconds=MAX_RESPONSE_AGE):
        # No nextUpdate and no nonce: nothing else limits how long a (replayed) response is believed
        raise Denied("error", "OCSP response is too old")

    if resp.certificate_status == ocsp.OCSPCertStatus.GOOD:
        return "good", "", next_update
    if resp.certificate_status == ocsp.OCSPCertStatus.REVOKED:
        reason = resp.revocation_reason.name if resp.revocation_reason else "unspecified"
        return "revoked", reason, next_update
    return "unknown", "responder does not know this certificate", None


# --- request handling -------------------------------------------------------

class Result:
    """What we tell nginx. `expires` (epoch seconds) is set when the answer may be cached."""

    def __init__(self, status, reason="", upn=None, cache="none", expires=None):
        self.status = status
        self.reason = reason
        self.upn = upn
        self.cache = cache
        self.expires = expires

    @property
    def code(self):
        return 200 if self.status == "good" else 403


def validate(header):
    """Validate the certificate in `header`; always returns a Result (or raises on a bug)."""
    if not header:
        return Result("no-cert", "missing X-Client-Cert header")

    try:
        cert = parse_client_cert(header)
    except ValueError as e:
        return Result("invalid-cert", f"could not parse certificate: {e}")

    try:
        upn = get_upn(cert)
    except (ValueError, UnicodeDecodeError) as e:
        return Result("no-upn", f"could not parse UPN: {e}")
    if upn is None:
        return Result("no-upn", "certificate has no UPN in its SAN")
    if not UPN_RE.fullmatch(upn):
        return Result("invalid-upn", f"UPN {upn[:50]!r} is empty, too long or has unsupported characters")

    # Cheap local checks are never cached
    now = now_utc()
    if now > utc(cert, "not_valid_after"):
        return Result("expired", f"expired on {utc(cert, 'not_valid_after').isoformat()}", upn)
    if now < utc(cert, "not_valid_before"):
        return Result("not-yet-valid", f"valid from {utc(cert, 'not_valid_before').isoformat()}", upn)

    key = cert.fingerprint(hashes.SHA256())
    cached = RESULT_CACHE.get(key)
    if cached is not None:
        (status, reason), expires = cached
        return Result(status, reason, upn, "hit", expires)

    # Concurrent requests for the same cert wait here and then hit the cache
    with key_lock(key):
        cached = RESULT_CACHE.get(key)
        if cached is not None:
            (status, reason), expires = cached
            return Result(status, reason, upn, "hit", expires)

        try:
            status, reason, next_update = lookup(cert)
        except Denied as d:
            return Result(d.status, d.reason, upn)  # errors are never cached

        expires = None
        if CACHE_TTL and status in ("good", "revoked"):
            limit = time.time() + CACHE_TTL
            for bound in (next_update, utc(cert, "not_valid_after")):
                if bound is not None:
                    limit = min(limit, bound.timestamp())
            if limit > time.time() + 1:
                expires = limit
                RESULT_CACHE.put(key, (status, reason), expires)
        return Result(status, reason, upn, "miss" if CACHE_TTL else "none", expires)


def lookup(cert):
    """Resolve the issuer and ask the responder. Returns (status, reason, next_update)."""
    ocsp_urls, issuer_urls = parse_aia(cert)
    vlog(f"AIA ocsp={ocsp_urls} ca_issuers={issuer_urls}")

    # Only contact hosts we've been told are fine (the AIA is attacker controlled)
    ocsp_url = DEFAULT_OCSP_URL
    if ocsp_urls:
        if url_allowed(ocsp_urls[0]):
            ocsp_url = ocsp_urls[0]
        else:
            print(f"AIA OCSP url {ocsp_urls[0]} is not in OCSP_ALLOWED_HOSTS, using {DEFAULT_OCSP_URL}", flush=True)

    pool = []
    if issuer_urls:
        if url_allowed(issuer_urls[0]):
            try:
                pool = fetch_issuers(issuer_urls[0])
            except (requests.RequestException, ValueError) as e:
                print(f"could not fetch issuer from {issuer_urls[0]}: {e}", flush=True)
        else:
            print(f"AIA CA issuer url {issuer_urls[0]} is not in OCSP_ALLOWED_HOSTS, ignoring", flush=True)

    issuer = find_issuer(cert, pool)
    if issuer is None:
        raise Denied("unknown-issuer", "certificate was not issued by a trusted CA")

    vlog(f"ocsp check using responder {ocsp_url} and issuer {issuer.subject.rfc4514_string()}")
    return check_ocsp(cert, issuer, ocsp_url)


def header_safe(value):
    return "".join(c for c in value if c.isascii() and c.isprintable())[:200]


class OCSPValidationHandler(BaseHTTPRequestHandler):
    server_version = "ocsp-proxy"
    timeout = 10  # drop clients that connect and then stall (slowloris)

    def do_GET(self):
        if self.path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        try:
            result = validate(self.headers.get("X-Client-Cert"))
            code = result.code
        except Exception as e:
            traceback.print_exc()
            result, code = Result("error", f"internal error: {e}"), 500

        # repr() so certificate contents can't forge extra log lines
        print(f"ocsp-proxy: status={result.status} cache={result.cache} upn={result.upn!r} reason={result.reason!r}", flush=True)

        shown = result.reason if (EXPOSE_DETAILS or result.status == "revoked") else PUBLIC_REASONS.get(result.status, "")

        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "0")
        self.send_header("X-OCSP-Status", result.status)
        self.send_header("X-OCSP-Cache", result.cache)
        if shown:
            self.send_header("X-OCSP-Reason", header_safe(shown))
        if result.upn and UPN_RE.fullmatch(result.upn):
            self.send_header("X-UPN", result.upn)
        # Lets nginx cache this answer, for exactly as long as we would
        remaining = int(result.expires - time.time()) if result.expires else 0
        self.send_header("X-Accel-Expires", str(max(remaining, 0)))
        self.end_headers()


def run(port=9000):
    global TRUSTED_CAS
    with open(TRUSTED_CA_PATH, "rb") as f:
        TRUSTED_CAS = load_certificates(f.read())
    print(f"Loaded {len(TRUSTED_CAS)} trusted CA(s) from {TRUSTED_CA_PATH}", flush=True)
    print(f"Default responder: {DEFAULT_OCSP_URL}; allowed AIA hosts: {sorted(ALLOWED_HOSTS)}", flush=True)
    print(f"Result cache TTL: {CACHE_TTL}s" if CACHE_TTL else "Result cache disabled", flush=True)
    httpd = ThreadingHTTPServer(("", port), OCSPValidationHandler)
    print(f"Starting OCSP validation proxy on port {port}...", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    try:
        run()
    except Exception as e:
        print(f"fatal: {e}", file=sys.stderr, flush=True)
        sys.exit(1)
