```sh
openssl genpkey -algorithm RSA -out ocsp_key.pem
openssl req -new -key ocsp_key.pem -out ocsp_req.csr -subj "/CN=Mock OCSP Responder"
openssl ca -in ocsp_req.csr -out ocsp_cert.pem -keyfile ../ca/private/ca.key -cert ../ca/certs/ca.crt -extensions req_ext -config ../config/openssl_config.cnf
Using configuration from ../config/openssl_config.cnf
Check that the request matches the signature
Signature ok
The Subject's Distinguished Name is as follows
commonName            :ASN.1 12:'Mock OCSP Responder'
Certificate is to be certified until Aug 29 20:24:56 2025 GMT (365 days)
Sign the certificate? [y/n]:y


1 out of 1 certificate requests certified, commit? [y/n]y
Write out database with 1 new entries
Database updated
```

```sh
openssl ocsp -index ../ca/index.txt -port 2560 -rsigner ./ocsp_cert.pem -rkey ./ocsp_key.pem -CA ../ca/certs/ca.crt -text
ACCEPT 0.0.0.0:2560 PID=2112881
ocsp: waiting for OCSP client connections...
```