# nginx-cac-ocsp

A small project designed to encapsulate a full end-to-end test of CAC/PIV cards for testing purposes.

This project arose from a need to integrate into a system with limited and unclear documentation. The general guidance was that "this is done on an F5, and we check the OCSP as needed." This led to the development of a solution to properly test authentication and edge cases outside of the production environment.

## Warning

This is meant for local development purposes for testing mTLS/CAC usage during development of "protected" applications. This allows you to run locally a mTLS framework and also test different components of them performing in different ways without exposing a production environment to having multiple test keys issued. This will let you speed up development and ensure your application will react appropriately to different use cases like surrounding certificates (credentials/cac keys);

1. Expired
2. Revolked
3. Valid
4. None-provided

These services have _not_ been extensively tested for scale, security or should be considered a secure way to deploy this type of product for usage in the wild. We explicitly are generating things using inherently insecure ways (no HSM, generating private keys outside of secure modules) and we also clean them up in makefiles!

_You have been warned!_

## Building

This project consists of a few components:

1. **Certificate Authority (CA)**: The CA is the root issuer and signer of all certificates in the system. Used for signing (trusting), revoking (removing trust), and validating (via OCSP interactions) the current status.
2. **OCSP Server**: The OCSP server serves as the AIA (Authority Information Access) for the CSR used with the CAC cards.
3. **OCSP Proxy**: This captures the mTLS cert and validates the certificate, responding to nginx in a way it can understand.
4. **Nginx Server**: Enforces an mTLS connection, passing the certificate to the OCSP proxy for validation.

To build the project, simply run `make`. This will generate all the certificates required for each service. You will need to manually import the generated client keys onto a `YubiKey` or another key-holding device. Alternatively, you can use the certificates directly for `curl` requests.

After generating the certificates and configuring your local machine for using CAC devices in Chrome or Firefox, you can run `make run` to start the services. The services will be reachable at `https://0.0.0.0:8443`, as defined in the `docker-compose.yml`.

## Troubleshooting

### Not being prompted to select a certificate or enter a PIN on Linux?

Check the status of the `pcscd` service. It may need to be restarted:

```sh
$ systemctl status pcscd
$ sudo systemctl restart pcscd
```

After restarting `pcscd`, you will also need to close and restart Chrome or Firefox for the changes to take effect.


## License

```
Copyright 2024 Tim 'diff' Strazzere <diff@protonmail.com>

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