#!/bin/sh
# End to end test: brings up the stack with a header-echoing downstream, then checks
# each of the client certificate cases (valid, revoked, expired, no UPN, none).
# Needs the certs from `make`. Usage: ./test/run.sh   (or `make test`)
cd "$(dirname "$0")/.." || exit 1

BASE=${BASE:-https://localhost:8443}
CLIENT=client
FAILED=0

cleanup() {
    docker compose --profile test down >/dev/null 2>&1
}
trap cleanup EXIT

export DOWNSTREAM_SERVICE=echo:8080
# `realpki` (see docker-compose.yml) stands in for a third party PKI whose certificates point at it
export OCSP_ALLOWED_HOSTS="${OCSP_HOST:-ocsp.penryn.local},${CAC_HOST:-cac.penryn.local},realpki"
docker compose --profile test up -d --build --wait || exit 1

# nginx has no healthcheck of its own, wait for it to accept connections
wait_for_nginx() {
    for _ in $(seq 1 30); do
        curl -sk -o /dev/null "$BASE/" && return 0
        sleep 1
    done
    return 1
}
wait_for_nginx

# check NAME EXPECTED_STATUS EXPECTED_OCSP_STATUS EXPECTED_BODY_TEXT URL [curl args...]
check() {
    name=$1 want_code=$2 want_ocsp=$3 want_text=$4 url=$5
    shift 5
    # Retry connection level failures only (nginx may still be coming up after a restart);
    # a wrong answer is never retried.
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        out=$(curl -sk -D - "$@" "$url")
        rc=$?
        case $rc in 7|35|52|56) sleep 1 ;; *) break ;; esac
    done
    code=$(printf '%s\n' "$out" | sed -n '1s/^HTTP[^ ]* \([0-9]*\).*/\1/p')
    ocsp=$(printf '%s\n' "$out" | tr -d '\r' | sed -n 's/^x-ocsp-status: //Ip')
    ok=1
    [ "$code" = "$want_code" ] || ok=0
    [ "$ocsp" = "$want_ocsp" ] || ok=0
    if [ -n "$want_text" ]; then
        printf '%s\n' "$out" | grep -qF -- "$want_text" || ok=0
    fi
    if [ $ok = 1 ]; then
        echo "PASS  $name"
    else
        echo "FAIL  $name: want status=$want_code ocsp='$want_ocsp' text='$want_text', got status=$code ocsp='$ocsp' (curl exit $rc)"
        FAILED=1
    fi
}

cert() { echo --cert "$CLIENT/$1.pem" --key "$CLIENT/$1.key"; }

# shellcheck disable=SC2046
check "valid cert is accepted on /cac-test"      200 good    "1234567890123456@notmil"            "$BASE/cac-test" $(cert yubico_client)
# shellcheck disable=SC2046
check "valid cert reaches downstream with UPN"   200 good    "X-Client-UPN: 1234567890123456@notmil" "$BASE/" $(cert yubico_client)
# shellcheck disable=SC2046
check "client supplied X-Client-UPN is replaced" 200 good    "X-Client-UPN: 1234567890123456@notmil" "$BASE/" $(cert yubico_client) -H "X-Client-UPN: evil@example"
# shellcheck disable=SC2046
check "revoked cert is denied on /cac-test"      403 revoked ""                                    "$BASE/cac-test" $(cert test_revoked)
# shellcheck disable=SC2046
check "revoked cert is denied on /"              403 revoked ""                                    "$BASE/" $(cert test_revoked)
# shellcheck disable=SC2046
check "cert without a UPN is denied"             403 no-upn  ""                                    "$BASE/" $(cert test_no_upn)
# shellcheck disable=SC2046
check "non-ASCII UPN is denied, not mangled"     403 invalid-upn ""                                "$BASE/" $(cert test_bad_upn)
# nginx itself rejects expired certs, before the OCSP proxy is involved
# shellcheck disable=SC2046
check "expired cert is denied"                   403 ""      ""                                    "$BASE/" $(cert test_expired)
check "no cert gets 401"                         401 ""      ""                                    "$BASE/"

# A "real world" style PKI: root -> intermediate -> client. The intermediate is only available as a
# PKCS#7 bundle from the caIssuers URL, and the intermediate's responder is a delegated signer
# that has no nonce support, sets nextUpdate and rejects a Host header with a port.
check "cert from an intermediate CA is accepted"  200 good    "" "$BASE/cac-test" --cert "$CLIENT/pki_leaf_chain.pem" --key "$CLIENT/pki_leaf.key"
check "revoked cert from an intermediate is denied" 403 revoked "" "$BASE/cac-test" --cert "$CLIENT/pki_revoked_chain.pem" --key "$CLIENT/pki_revoked.key"

# Verdicts are cached for OCSP_CACHE_TTL seconds (default 60); 0 turns caching off.
# The checks above already primed the cache, so this request must be a hit (or never one).
cache_status() {
    curl -sk -D - -o /dev/null "$@" | tr -d '\r' | sed -n 's/^x-auth-cache: //Ip'
}
# shellcheck disable=SC2046
got=$(cache_status $(cert yubico_client) "$BASE/cac-test")
# shellcheck disable=SC2046
got_revoked=$(cache_status $(cert test_revoked) "$BASE/cac-test")
if [ "${OCSP_CACHE_TTL:-60}" = 0 ]; then
    want=""; [ "$got" != HIT ] && [ "$got_revoked" != HIT ] && ok=1 || ok=0
else
    want=HIT; [ "$got" = HIT ] && [ "$got_revoked" = HIT ] && ok=1 || ok=0
fi
if [ $ok = 1 ]; then
    echo "PASS  verdict caching (OCSP_CACHE_TTL=${OCSP_CACHE_TTL:-60}): good=$got revoked=$got_revoked"
else
    echo "FAIL  verdict caching (OCSP_CACHE_TTL=${OCSP_CACHE_TTL:-60}): good=$got revoked=$got_revoked"
    FAILED=1
fi

# nginx must not execute SSI directives that appear in the downstream app's responses
# shellcheck disable=SC2046
if curl -sk $(cert yubico_client) "$BASE/" | grep -q "BEGIN CERTIFICATE"; then
    echo "FAIL  SSI directives in downstream responses are executed"; FAILED=1
else
    echo "PASS  SSI directives in downstream responses are not executed"
fi

# The port 80 redirect goes to our own host name
CAC_HOST=${CAC_HOST:-cac.penryn.local}
loc=$(docker compose exec -T echo python3 -c "
import http.client
c = http.client.HTTPConnection('$CAC_HOST', 80)
c.request('GET', '/x?y=1', headers={'Host': 'evil.example'})
print(c.getresponse().getheader('Location'))")
if [ "$loc" = "https://$CAC_HOST/x?y=1" ]; then echo "PASS  http redirects to the canonical https host"
else echo "FAIL  http redirect went to '$loc'"; FAILED=1; fi

# The proxy must survive garbage, and tell clients only a generic reason
docker compose exec -T ocsp python3 -c '
import urllib.request, urllib.error
req = urllib.request.Request("http://localhost:9000/", headers={"X-Client-Cert": "garbage"})
try:
    urllib.request.urlopen(req)
except urllib.error.HTTPError as e:
    assert e.code == 403 and e.headers["X-OCSP-Status"] == "invalid-cert", (e.code, e.headers)
    assert e.headers["X-OCSP-Reason"] == "certificate could not be parsed", e.headers["X-OCSP-Reason"]
else:
    raise SystemExit("expected a 403")
' && echo "PASS  garbage certificate header is a 403 with a generic reason" || { echo "FAIL  garbage certificate header"; FAILED=1; }

# Revoked verdicts may be cached longer than good ones (OCSP_CACHE_TTL_REVOKED, default 10x).
# Asked of the proxy directly, since X-Accel-Expires is consumed by nginx.
accel_expires() {
    encoded=$(python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(open(sys.argv[1]).read(), safe=""))' "$1")
    docker compose exec -T ocsp python3 -c '
import sys, urllib.request, urllib.error
req = urllib.request.Request("http://localhost:9000/", headers={"X-Client-Cert": sys.argv[1]})
try:
    resp = urllib.request.urlopen(req)
except urllib.error.HTTPError as e:
    resp = e
print(resp.headers["X-Accel-Expires"])' "$encoded"
}
ttl=${OCSP_CACHE_TTL:-60}
good_ttl=$(accel_expires "$CLIENT/yubico_client.pem")
revoked_ttl=$(accel_expires "$CLIENT/test_revoked.pem")
if [ "$ttl" = 0 ]; then
    [ "$good_ttl" = 0 ] && [ "$revoked_ttl" = 0 ] && ok=1 || ok=0
else
    [ "$good_ttl" -gt 0 ] && [ "$good_ttl" -le "$ttl" ] && [ "$revoked_ttl" -gt "$ttl" ] && ok=1 || ok=0
fi
if [ $ok = 1 ]; then echo "PASS  cache lifetimes: good=${good_ttl}s revoked=${revoked_ttl}s (OCSP_CACHE_TTL=$ttl)"
else echo "FAIL  cache lifetimes: good=${good_ttl}s revoked=${revoked_ttl}s (OCSP_CACHE_TTL=$ttl)"; FAILED=1; fi

# Revoking a certificate is picked up by the (running) responder without a rebuild. With caching
# enabled `make revoke` restarts the services to drop cached verdicts; with OCSP_CACHE_TTL=0 there
# is nothing cached, so we don't, which shows the responder really does re-read its database.
LIVE=test_live_$$
make -C "$CLIENT" "$LIVE.pem" >/dev/null 2>&1
check "freshly issued cert is accepted"          200 good    ""                                    "$BASE/cac-test" $(cert "$LIVE")
if [ "$ttl" = 0 ]; then
    make revoke CERT="$CLIENT/$LIVE.pem" RESTART=no >/dev/null 2>&1
else
    make revoke CERT="$CLIENT/$LIVE.pem" >/dev/null 2>&1
    docker compose --profile test up -d --wait >/dev/null 2>&1
    wait_for_nginx
fi
check "cert revoked while running is denied"     403 revoked ""                                    "$BASE/cac-test" $(cert "$LIVE")

# Many concurrent requests for one certificate (a page and its assets) must share a single lookup
if [ "$ttl" != 0 ]; then
    docker compose restart ocsp cac >/dev/null 2>&1
    docker compose --profile test up -d --wait >/dev/null 2>&1
    wait_for_nginx
    lookups() { docker compose logs --no-log-prefix ocsp 2>/dev/null | grep -c 'ocsp-responder: serial='; }
    before=$(lookups)
    # shellcheck disable=SC2046
    seq 30 | xargs -P 30 -I{} curl -sk -o /dev/null $(cert yubico_client) "$BASE/cac-test"
    after=$(lookups)
    if [ $((after - before)) = 1 ]; then echo "PASS  30 concurrent requests caused 1 OCSP lookup"
    else echo "FAIL  30 concurrent requests caused $((after - before)) OCSP lookups"; FAILED=1; fi
fi

# Idle connections (a port scanner, a stuck client) must not block the responder, which is what
# used to wedge `openssl ocsp`
if docker compose exec -T ocsp python3 -c '
import socket, urllib.request
idle = [socket.create_connection(("localhost", 2560), 2) for _ in range(5)]
urllib.request.urlopen("http://localhost:2560/healthz", timeout=3)
print("ok")' | grep -q ok; then echo "PASS  idle connections do not block the responder"
else echo "FAIL  idle connections block the responder"; FAILED=1; fi

# With the responder down we fail closed, and that failure must not be remembered once it is back
LIVE_B=test_live_b$$
make -C "$CLIENT" "$LIVE_B.pem" >/dev/null 2>&1
docker compose exec -T ocsp pkill -STOP -f '[r]esponder.py'
check "responder down: denied as unreachable"    403 unreachable ""                                "$BASE/cac-test" $(cert "$LIVE_B")
docker compose exec -T ocsp pkill -CONT -f '[r]esponder.py'
check "responder back: the outage was not cached" 200 good   ""                                    "$BASE/cac-test" $(cert "$LIVE_B")

if [ $FAILED = 0 ]; then echo "all tests passed"; else echo "some tests FAILED"; fi
exit $FAILED
