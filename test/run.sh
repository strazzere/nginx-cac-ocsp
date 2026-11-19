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
docker compose --profile test up -d --build --wait || exit 1
# nginx has no healthcheck of its own, wait for it to accept connections
for _ in $(seq 1 30); do
    curl -sk -o /dev/null "$BASE/" && break
    sleep 1
done

# check NAME EXPECTED_STATUS EXPECTED_OCSP_STATUS EXPECTED_BODY_TEXT URL [curl args...]
check() {
    name=$1 want_code=$2 want_ocsp=$3 want_text=$4 url=$5
    shift 5
    out=$(curl -sk -D - "$@" "$url")
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
        echo "FAIL  $name: want status=$want_code ocsp='$want_ocsp' text='$want_text', got status=$code ocsp='$ocsp'"
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
# nginx itself rejects expired certs, before the OCSP proxy is involved
# shellcheck disable=SC2046
check "expired cert is denied"                   403 ""      ""                                    "$BASE/" $(cert test_expired)
check "no cert gets 401"                         401 ""      ""                                    "$BASE/"

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

# The proxy must not leave temp files behind, and must survive garbage
docker compose exec -T ocsp python3 -c '
import urllib.request, urllib.error
req = urllib.request.Request("http://localhost:9000/", headers={"X-Client-Cert": "garbage"})
try:
    urllib.request.urlopen(req)
except urllib.error.HTTPError as e:
    assert e.code == 403 and e.headers["X-OCSP-Status"] == "invalid-cert", (e.code, e.headers)
else:
    raise SystemExit("expected a 403")
' && echo "PASS  garbage certificate header is a 403" || { echo "FAIL  garbage certificate header"; FAILED=1; }

if [ $FAILED = 0 ]; then echo "all tests passed"; else echo "some tests FAILED"; fi
exit $FAILED
