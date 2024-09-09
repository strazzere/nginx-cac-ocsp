# CA
The primary CA directory for signing, validating against and revoking the client certs.

## Building the CA
```sh
$ mkdir -p certs newcerts private
$ touch index.txt
$ echo 01 > serial
$ openssl genrsa -out private/ca.key 2048
$ openssl req -x509 -new -nodes -key private/ca.key -sha256 -days 365 -out certs/ca.crt -batch -subj "/C=US/ST=CA/O=Red Naga, LLC/CN=cac.penryn.local/emailAddress=diff@protonmail.com"
```