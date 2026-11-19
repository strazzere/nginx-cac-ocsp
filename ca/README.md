# CA
The primary CA directory for signing, validating against and revoking the client certs.

`make` (here or from the top level) builds everything below; `make clean` removes it again.

## Building the CA by hand
```sh
$ mkdir -p certs newcerts private
$ mkdir db
$ touch db/index.txt
$ echo "unique_subject = no" > db/index.txt.attr
$ echo 01 > serial
$ echo 01 > crlnumber
$ openssl genrsa -out private/ca.key 2048
$ openssl req -x509 -new -nodes -key private/ca.key -sha256 -days 3650 -out certs/ca.crt -batch -subj "/C=US/O=Not U.S. Government/CN=Not DOD ID CA-64/OU=PKI/OU=Not DoD"
```

## Generating a CRL
Issued and revoked certificates are recorded in `db/index.txt`. It has a directory of its own because `openssl ca` replaces the file on every write, so the OCSP responder container mounts the directory and picks up changes immediately. To revoke a certificate (from the top level directory): `make revoke CERT=client/yubico_client.pem`.

If you also want a CRL:
```sh
$ make crl
```
