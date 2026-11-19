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

After generating the certificates and configuring your local machine for using CAC devices in Chrome or Firefox, you can run `make run` to start the services. The services will be reachable at `https://0.0.0.0:8443`, as defined in the `docker-compose.yml`. Generated certificates are valid for ten years (the client certs for just under three).

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
| `OCSP_VERBOSE` | _(off)_ | Set to `1` for detailed per-request logging |

## What the services tell you

For every request nginx asks the proxy whether the client certificate is acceptable. The result is exposed in:

* the HTTP status: `200` accepted, `401` no certificate sent, `403` anything else (revoked, expired, untrusted, no UPN, ...)
* an `X-OCSP-Status` response header: `good`, `revoked`, `unknown`, `expired`, `not-yet-valid`, `no-upn`, `invalid-cert`, `unknown-issuer`, `unreachable` or `error`, with details in `X-OCSP-Reason`

Requests that pass are proxied to `DOWNSTREAM_SERVICE` with `X-Client-UPN`, `X-Client-CN`, `X-Client-Verified` and `X-Subject-DN` headers. These always overwrite anything the client sent itself, and the downstream app should only trust them if it is reachable exclusively through this nginx. `/cac-test` shows what nginx knows about your certificate without needing a downstream.

Certificates the proxy checks: the issuer must chain to `ca/certs/ca.crt`. Intermediates may be fetched from the certificate's `caIssuers` URL (PEM, DER or PKCS#7), but only from `OCSP_ALLOWED_HOSTS` and they are never trusted unless they chain to the trusted CA.

## Testing

`make` creates the CA, the responder/server certs and a handful of client certs in `client/`:

* `yubico_client` - valid
* `test_revoked` - signed and then revoked
* `test_expired` - signed, but already expired
* `test_no_upn` - valid, but without a UPN in its SAN

`make test` starts the stack alongside a tiny downstream that echoes headers, runs `curl` against every case above, and tears everything down again. It needs docker and the certs from `make`.

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