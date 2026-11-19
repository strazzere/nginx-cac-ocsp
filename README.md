# nginx-cac-ocsp

A small project designed to encapsulate a full end-to-end test of CAC/PIV cards for testing purposes.

This project arose from a need to integrate into a system with limited and unclear documentation. The general guidance was that "this is done on an F5, and we check the OCSP as needed." This led to the development of a solution to properly test authentication and edge cases outside of the production environment.

## Warning

This is meant for local development purposes for testing mTLS/CAC usage during development of "protected" applications. This allows you to run locally a mTLS framework and also test different components of them performing in different ways without exposing a production environment to having multiple test keys issued. This will let you speed up development and ensure your application will react appropriately to different use cases like surrounding certificates (credentials/cac keys);

1. Expired
2. Revoked
3. Valid
4. None provided

These services have _not_ been extensively tested for scale, security or should be considered a secure way to deploy this type of product for usage in the wild. We explicitly are generating things using inherently insecure ways (no HSM, generating private keys outside of secure modules) and we also clean them up in makefiles!

_You have been warned!_

## Building

This project consists of a few components:

1. **Certificate Authority (CA)**: The CA is the root issuer and signer of all certificates in the system. Used for signing (trusting), revoking (removing trust), and validating (via OCSP interactions) the current status.
2. **OCSP Server**: The OCSP server serves as the AIA (Authority Information Access) for the CSR used with the CAC cards.
3. **OCSP Proxy**: This captures the mTLS cert and validates the certificate, responding to nginx in a way it can understand.
4. **Nginx Server**: Enforces an mTLS connection, passing the certificate to the OCSP proxy for validation.

To build the project, simply run `make`. This will generate all the certificates required for each service. You will need to manually import the generated client keys onto a `YubiKey` or another key-holding device. Alternatively, you can use the certificates directly for `curl` requests.

After generating the certificates and configuring your local machine for using CAC devices in Chrome or Firefox, you can run `make run` to start the services. The services are reachable at `https://127.0.0.1:8443` (set `BIND_ADDR=0.0.0.0` to expose them to your network), as defined in the `docker-compose.yml`. Generated certificates are valid for ten years (the client certs for just under three).

## Configuration

Hostnames live in `.env`, which is read by both the Makefiles and `docker compose`:

| Variable | Default | Purpose |
|---|---|---|
| `OCSP_HOST` | `ocsp.penryn.local` | Hostname of the OCSP responder (baked into the certs' AIA extension) |
| `CAC_HOST` | `cac.penryn.local` | Hostname of the nginx server (also serves `ca.crt` over http) |
| `DOWNSTREAM_SERVICE` | `www.penryn.com` | The app nginx proxies authenticated requests to |

Changing the hostnames means regenerating the certs (`make clean && make`).

The OCSP proxy also understands (set them under `ocsp.environment` in `docker-compose.yml`, or in your shell):

| Variable | Default | Purpose |
|---|---|---|
| `OCSP_ALLOWED_HOSTS` | `OCSP_HOST,CAC_HOST` | Hosts the proxy may contact for the OCSP / CA-issuer URLs found in a client certificate. Use `*` to allow any host, e.g. when testing against a real CA's responder. |
| `OCSP_CACHE_TTL` | `60` | Seconds to cache `good` and `revoked` verdicts, `0` disables caching (see below) |
| `OCSP_MAX_RESPONSE_AGE` | `3600` | Seconds an OCSP response with neither `nextUpdate` nor a nonce stays acceptable |
| `OCSP_REQUIRE_NONCE` | _(off)_ | Reject responders that don't echo the request nonce (a nonce is always sent, and checked when echoed) |
| `OCSP_EXPOSE_DETAILS` | _(off)_ | Put detailed failure reasons in `X-OCSP-Reason` (handy for debugging, but leaks internals) |
| `BIND_ADDR` | `127.0.0.1` | Address the https port (8443) is published on; use `0.0.0.0` to reach it from other machines |
| `OCSP_VERBOSE` | _(off)_ | Set to `1` for detailed per-request logging |

## What the services tell you

For every request nginx asks the proxy whether the client certificate is acceptable. The result is exposed in:

* the HTTP status: `200` accepted, `401` no certificate sent, `403` anything else (revoked, expired, untrusted, no UPN, ...)
* an `X-OCSP-Status` response header: `good`, `revoked`, `unknown`, `expired`, `not-yet-valid`, `no-upn`, `invalid-cert`, `invalid-upn`, `unknown-issuer`, `unreachable` or `error`, with a short reason in `X-OCSP-Reason` (the details, which can name internal hosts, only go to the logs unless `OCSP_EXPOSE_DETAILS=1`)

Requests that pass are proxied to `DOWNSTREAM_SERVICE` with `X-Client-UPN`, `X-Client-CN`, `X-Client-Verified` and `X-Subject-DN` headers. These always overwrite anything the client sent itself, and the downstream app should only trust them if it is reachable exclusively through this nginx. `/cac-test` shows what nginx knows about your certificate without needing a downstream.

Certificates the proxy checks: the issuer must chain to `ca/certs/ca.crt`. Intermediates may be fetched from the certificate's `caIssuers` URL (PEM, DER or PKCS#7), but only from `OCSP_ALLOWED_HOSTS` and they are never trusted unless they chain to the trusted CA.

## Security notes

What is and isn't trusted:

* **nginx** terminates TLS and verifies the client certificate chain against `ca/certs/ca.crt`. The **OCSP proxy** trusts nginx to have done that, and only decides revocation. It's on the internal docker network only (port 9000 is not published); don't expose it, since anyone who can reach it can submit any certificate for a verdict.
* **Failing closed:** a missing/invalid certificate, an unreachable responder, a bad or replayed OCSP response, or any internal error all result in a denial.
* **The UPN is passed through untouched or not at all.** Certificates whose UPN is empty, over 256 characters, or contains anything but printable ASCII are denied (`invalid-upn`) instead of being stripped or truncated, which could make two different users look identical downstream.
* **OCSP responses** are signature checked (against the CA or a responder it delegated to with the OCSP-signing usage), matched to the request, checked for freshness and a nonce, so a captured "good" response can't be replayed after a revocation.
* **AIA URLs** in a certificate are only contacted if their host is in `OCSP_ALLOWED_HOSTS`, never follow redirects, and a downloaded issuer is only used if it chains to the trusted CA.
* nginx does **not** run SSI on downstream responses, has TLS session tickets turned off (their long-lived keys undermine forward secrecy), and the pages it serves itself carry a strict CSP.
* The containers run with a read-only filesystem, no capabilities beyond what nginx needs to start, and `no-new-privileges`. The OCSP container runs as an unprivileged user; nginx's workers do too.

What you should still do:

* **Downstream app:** only trust `X-Client-UPN` and friends if it is reachable *only* through this nginx. The connection from nginx to `DOWNSTREAM_SERVICE` is plain http; use a TLS (ideally mutually authenticated) upstream if it leaves a trusted network.
* **The `session=valid` cookie is a mock.** It is the same for everyone and unsigned, so it proves nothing: don't let an app treat it as a session.
* **Keys are baked into the images** (`nginx/key.pem`, `ocsp/ocsp_key.pem`), and `ca/private/ca.key` is unencrypted on disk. That's fine for local testing; never push the images or reuse these certificates anywhere real.
* Client certs made here have no `clientAuth`/smartcard-logon extended key usage, unlike real CAC certs, so nothing checks for it.

## Caching

Checking OCSP on every request would be slow (a page with many assets would do dozens of lookups at once), so verdicts are cached, much as an F5 or any production setup would:

* the proxy caches `good` and `revoked` results per certificate for `OCSP_CACHE_TTL` seconds, or less if the OCSP response's `nextUpdate` or the certificate's own expiry comes first. Concurrent requests for the same certificate share a single lookup, and downloaded issuer certs are cached for an hour.
* the proxy tells nginx how long its answer is valid (`X-Accel-Expires`), so nginx caches the `auth_request` subrequest too and doesn't even call the proxy for repeat requests. nginx's cache is in memory and cleared when the container restarts.
* errors (an unreachable responder, a bad response) and `unknown` are never cached.

The cost is that a revocation takes up to `OCSP_CACHE_TTL` seconds to be noticed, so when testing a revocation either wait, restart the services (`docker compose restart ocsp cac`) or set `OCSP_CACHE_TTL=0`. Responses show where a verdict came from in `X-OCSP-Cache` (the proxy's cache, which reflects the original lookup) and `X-Auth-Cache` (`HIT` when nginx answered from its cache).

## Testing

`make` creates the CA, the responder/server certs and a handful of client certs in `client/`:

* `yubico_client` - valid
* `test_revoked` - signed and then revoked
* `test_expired` - signed, but already expired
* `test_no_upn` - valid, but without a UPN in its SAN

`make test` starts the stack alongside a tiny downstream that echoes headers, runs `curl` against every case above (once with caching on and once with `OCSP_CACHE_TTL=0`), and tears everything down again. It needs docker and the certs from `make`.

_Note: don't open and close a bare TCP connection to the OCSP responder's port (2560), e.g. with a port scanner or a naive healthcheck. The `openssl ocsp` server is single threaded and gets stuck on the empty connection. Send it a real OCSP request instead (see the healthcheck in `docker-compose.yml`)._

## Troubleshooting

### Not being prompted to select a certificate or enter a PIN on Linux?

Check the status of the `pcscd` service. It may need to be restarted:

```sh
$ systemctl status pcscd
$ sudo systemctl restart pcscd
```

After restarting `pcscd`, you will also need to close and restart Chrome or Firefox for the changes to take effect.


## Notes

Private keys and certificates generated by the Makefiles are gitignored; they are for local testing only.

## License

```
Copyright 2024-2026 Tim 'diff' Strazzere <diff@protonmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```