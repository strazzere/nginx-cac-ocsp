"""A small OCSP responder (RFC 6960, plus the RFC 5019 GET form) backed by an `openssl ca` index.txt.

Replaces `openssl ocsp -index`, which is single threaded, wedges on an idle TCP connection, and
only re-reads the index when it feels like it. This one is threaded, times out stalled clients,
and re-reads the index whenever the file changes, so a `openssl ca -revoke` shows up immediately.

Configuration (environment variables):

  RESPONDER_INDEX        openssl index.txt             (default: /etc/ocsp/db/index.txt)
  RESPONDER_CA           certificate of the issuing CA (default: /etc/ocsp/ca.crt)
  RESPONDER_CERT/KEY     signer certificate / key      (default: /etc/ocsp/ocsp_cert.pem, ocsp_key.pem)
  RESPONDER_PORT         listen port                   (default: 2560)
  RESPONDER_NEXT_UPDATE  seconds in nextUpdate, 0 to omit it (default: 3600)

Knobs that exist to imitate other responders in tests:

  RESPONDER_ECHO_NONCE   0 to not echo the request nonce (default: 1)
  RESPONDER_STRICT_HOST  1 to answer 400 if the Host header contains a port (default: 0)
  RESPONDER_STATIC       /path=/file[,/path=/file...] static files to serve on GET
"""
import base64
import datetime
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

MAX_REQUEST_BYTES = 64 * 1024

INDEX_PATH = os.environ.get("RESPONDER_INDEX", "/etc/ocsp/db/index.txt")
CA_PATH = os.environ.get("RESPONDER_CA", "/etc/ocsp/ca.crt")
CERT_PATH = os.environ.get("RESPONDER_CERT", "/etc/ocsp/ocsp_cert.pem")
KEY_PATH = os.environ.get("RESPONDER_KEY", "/etc/ocsp/ocsp_key.pem")
PORT = int(os.environ.get("RESPONDER_PORT", "2560"))
NEXT_UPDATE = int(os.environ.get("RESPONDER_NEXT_UPDATE", "3600") or 0)
ECHO_NONCE = os.environ.get("RESPONDER_ECHO_NONCE", "1").lower() not in ("0", "false", "no")
STRICT_HOST = os.environ.get("RESPONDER_STRICT_HOST", "").lower() in ("1", "true", "yes")
STATIC = dict(
    entry.split("=", 1) for entry in os.environ.get("RESPONDER_STATIC", "").split(",") if "=" in entry
)

REASONS = {
    "unspecified": x509.ReasonFlags.unspecified,
    "keyCompromise": x509.ReasonFlags.key_compromise,
    "CACompromise": x509.ReasonFlags.ca_compromise,
    "affiliationChanged": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessationOfOperation": x509.ReasonFlags.cessation_of_operation,
    "certificateHold": x509.ReasonFlags.certificate_hold,
    "removeFromCRL": x509.ReasonFlags.remove_from_crl,
}


class Index:
    """The `openssl ca` database, reloaded whenever the file is replaced or modified."""

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._signature = None
        self._entries = {}

    @staticmethod
    def _parse_date(value):
        # YYMMDDHHMMSSZ, two digit years as per RFC 5280
        year = int(value[:2])
        year += 2000 if year < 50 else 1900
        return datetime.datetime(year, int(value[2:4]), int(value[4:6]), int(value[6:8]),
                                 int(value[8:10]), int(value[10:12]), tzinfo=datetime.timezone.utc)

    def _load(self):
        entries = {}
        with open(self.path, encoding="utf-8", errors="replace") as f:
            for line in f:
                fields = line.rstrip("\n").split("\t")
                if len(fields) < 4 or not fields[3].strip():
                    continue
                status, revocation, serial = fields[0], fields[2], int(fields[3], 16)
                if status == "R":
                    date, _, reason = revocation.partition(",")
                    entries[serial] = ("R", self._parse_date(date), REASONS.get(reason, x509.ReasonFlags.unspecified))
                else:  # V (valid) and E (expired): neither is revoked
                    entries[serial] = ("V", None, None)
        return entries

    def lookup(self, serial):
        st = os.stat(self.path)
        signature = (st.st_ino, st.st_mtime_ns, st.st_size)
        with self._lock:
            if signature != self._signature:
                self._entries = self._load()
                self._signature = signature
            return self._entries.get(serial)


def der_length(buf, off):
    """Returns (length, offset of the contents) for the DER element whose length starts at `off`."""
    length = buf[off]
    off += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(buf[off:off + n], "big")
        off += n
    return length, off


def key_bytes(cert):
    """The contents of the subjectPublicKey BIT STRING, which is what OCSP's issuerKeyHash covers."""
    der = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    _, off = der_length(der, 1)                  # outer SEQUENCE
    length, off = der_length(der, off + 1)       # AlgorithmIdentifier SEQUENCE
    off += length
    length, off = der_length(der, off + 1)       # BIT STRING
    return der[off + 1:off + length]             # skip the "unused bits" byte


def digest(algorithm, data):
    h = hashes.Hash(algorithm)
    h.update(data)
    return h.finalize()


class Responder:
    def __init__(self):
        with open(CA_PATH, "rb") as f:
            self.ca = x509.load_pem_x509_certificate(f.read())
        with open(CERT_PATH, "rb") as f:
            self.cert = x509.load_pem_x509_certificate(f.read())
        with open(KEY_PATH, "rb") as f:
            self.key = serialization.load_pem_private_key(f.read(), None)
        self.index = Index(INDEX_PATH)
        self.index.lookup(0)  # fail at startup if the index is unreadable

    def respond(self, request_der):
        """Returns (DER response, description for the log)."""
        try:
            request = ocsp.load_der_ocsp_request(request_der)
            algorithm = request.hash_algorithm
        except (ValueError, UnsupportedAlgorithm):
            return self._unsuccessful(ocsp.OCSPResponseStatus.MALFORMED_REQUEST), "malformed request"

        # Only answer for certificates issued by our CA
        if (request.issuer_name_hash != digest(algorithm, self.ca.subject.public_bytes())
                or request.issuer_key_hash != digest(algorithm, key_bytes(self.ca))):
            return self._unsuccessful(ocsp.OCSPResponseStatus.UNAUTHORIZED), f"serial={request.serial_number:x} unauthorized (other issuer)"

        entry = self.index.lookup(request.serial_number)
        now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        next_update = now + datetime.timedelta(seconds=NEXT_UPDATE) if NEXT_UPDATE else None

        if entry is None:
            status, revoked_at, reason, label = ocsp.OCSPCertStatus.UNKNOWN, None, None, "unknown"
        elif entry[0] == "R":
            status, revoked_at, reason, label = ocsp.OCSPCertStatus.REVOKED, entry[1], entry[2], "revoked"
        else:
            status, revoked_at, reason, label = ocsp.OCSPCertStatus.GOOD, None, None, "good"

        builder = ocsp.OCSPResponseBuilder().add_response_by_hash(
            issuer_name_hash=request.issuer_name_hash,
            issuer_key_hash=request.issuer_key_hash,
            serial_number=request.serial_number,
            algorithm=algorithm,
            cert_status=status,
            this_update=now,
            next_update=next_update,
            revocation_time=revoked_at,
            revocation_reason=reason,
        )
        builder = builder.responder_id(ocsp.OCSPResponderEncoding.HASH, self.cert).certificates([self.cert])

        nonce = None
        if ECHO_NONCE:
            try:
                nonce = request.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
                builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)
            except x509.ExtensionNotFound:
                pass

        response = builder.sign(self.key, hashes.SHA256())
        return response.public_bytes(serialization.Encoding.DER), f"serial={request.serial_number:x} {label} nonce={'yes' if nonce else 'no'}"

    @staticmethod
    def _unsuccessful(status):
        return ocsp.OCSPResponseBuilder.build_unsuccessful(status).public_bytes(serialization.Encoding.DER)


RESPONDER = None


class Handler(BaseHTTPRequestHandler):
    server_version = "ocsp-responder"
    timeout = 10  # a client that connects and stalls must not tie us up

    def log_message(self, *args):
        pass  # we log one line per OCSP request ourselves

    def _send(self, code, body=b"", content_type="text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _answer(self, request_der):
        try:
            body, description = RESPONDER.respond(request_der)
        except Exception as e:
            print(f"ocsp-responder: internal error: {e!r}", file=sys.stderr, flush=True)
            body = Responder._unsuccessful(ocsp.OCSPResponseStatus.INTERNAL_ERROR)
            description = "internal error"
        print(f"ocsp-responder: {description}", flush=True)
        self._send(200, body, "application/ocsp-response")

    def _host_ok(self):
        if STRICT_HOST and ":" in (self.headers.get("Host") or ""):
            self._send(400, b"Host header must not contain a port\n")
            return False
        return True

    def do_POST(self):
        if not self._host_ok():
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self._send(411)
        if not 0 < length <= MAX_REQUEST_BYTES:
            return self._send(413)
        self._answer(self.rfile.read(length))

    def do_GET(self):
        if self.path == "/healthz":
            return self._send(200, b"ok\n")
        if self.path in STATIC:
            with open(STATIC[self.path], "rb") as f:
                return self._send(200, f.read(), "application/pkcs7-mime")
        if not self._host_ok():
            return
        # RFC 5019: the (URL encoded, base64) request is the path
        try:
            request_der = base64.b64decode(unquote(self.path.lstrip("/")), validate=True)
        except ValueError:
            return self._send(400)
        if len(request_der) > MAX_REQUEST_BYTES:
            return self._send(414)
        self._answer(request_der)


def main():
    global RESPONDER
    RESPONDER = Responder()
    print(f"ocsp-responder: issuer={RESPONDER.ca.subject.rfc4514_string()!r} index={INDEX_PATH} "
          f"nextUpdate={NEXT_UPDATE or 'omitted'} nonce={'echoed' if ECHO_NONCE else 'ignored'}", flush=True)
    print(f"ocsp-responder: listening on port {PORT}", flush=True)
    ThreadingHTTPServer(("", PORT), Handler).serve_forever()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"fatal: {e}", file=sys.stderr, flush=True)
        sys.exit(1)
