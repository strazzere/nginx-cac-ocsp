# CA
The primary CA directory for signing, validating against and revoking the client certs.

`make` (here or from the top level) builds everything below; `make clean` removes it again.

## Building the CA by hand
```sh
$ mkdir -p certs newcerts private
$ touch index.txt
$ echo "unique_subject = no" > index.txt.attr
$ echo 01 > serial
$ echo 01 > crlnumber
$ openssl genrsa -out private/ca.key 2048
$ openssl req -x509 -new -nodes -key private/ca.key -sha256 -days 3650 -out certs/ca.crt -batch -subj "/C=US/O=Not U.S. Government/CN=Not DOD ID CA-64/OU=PKI/OU=Not DoD"
```

## Generating a CRL
Revocations live in `index.txt`, which the OCSP responder reads. If you also want a CRL:
```sh
$ make crl
```
