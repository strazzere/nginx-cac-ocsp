# Client (Yubikey) Certificates
Creating certificates and placing them onto `yubikeys`. Since we cannot request SAN changes directly to a `yubikey` via `ykman`, we generate a private key _outside_ of the `yubikey` (this in general is consider insecure). Though since this is for testing purposes only, that is fine.

The `makefile` in this directory will create and sign a key using the CA, however the importing in to a `yubikey` is not automated, this will need to be run manually.

### Provisioning a piv (cac) card onto a yubikey

Reset the current `yubikey` - this is a destructive step, only do this with `yubikeys` you're using for testing this process with.
```sh
$ ykman piv reset
WARNING! This will delete all stored PIV data and restore factory settings. Proceed? [y/N]: Y
Resetting PIV data...
Reset complete. All PIV data has been cleared from the YubiKey.
Your YubiKey now has the default PIN, PUK and Management Key:
	PIN:	123456
	PUK:	12345678
	Management Key:	010203040506070801020304050607080102030405060708
```

If you wanted to actually use this in a meaningful way, change the PIN/PUK/Management Key. You can do this with commands like `ykman piv access change-pin`.

Generate a private key, CSR and CRT, then import to the `yubikey` the private key;
```sh
$ openssl req -new -newkey rsa:2048 -nodes -keyout yubico_client.key -out yubico_client.csr \
-sha256 -batch \
-subj "/C=US/O=Not U.S. Government/OU=PKI/OU=Not DoD/CN=DOE.JOHN.FAKE.0123456789"
$ openssl req -x509 -new -nodes -key yubico_client.key \
	-sha256 -days 365 -out yubico_client.crt -batch \
	-subj "/C=US/O=Not U.S. Government/CN=Not DOD/OU=PKI/OU=Not DoD/CN=DOE.JOHN.FAKE.0123456789"
$ openssl x509 -req -days 365 -in yubico_client.csr -signkey yubico_client.key -out yubico_client.pem \
-extfile <(printf "subjectAltName=email:john.doe.civ@fake.mil")
$ ykman piv keys import 9a yubico_client.key
Private key imported into slot AUTHENTICATION.
```

Sign the CSR and ensure it is added to the index.txt for OCSP verification;
```sh
openssl ca -in yubico_client.csr -out yubico_client.pem -cert ../ca/certs/ca.crt -keyfile ../ca/private/ca.key -days 1024 -config ../config/openssl_config.cnf -extensions req_ext -batch 
```

Import the signed by the CA CSR into the `yubikey`:
```sh
$ ykman piv certificates import 9a yubico_client.pem -v
Enter a management key [blank to use default key]: 
Enter PIN: 
Certificate imported into slot AUTHENTICATION
```

### Manually verifying the cert via OCSP
_Note: The docker container does not expose the OCSP daemon, so this would only work if you're running the OCSP daemon locally and it is reachable.
```sh
$ openssl ocsp --issuer ../ca/certs/ca.crt -cert yubico_client.pem -url 0.0.0.0:2560 -CAfile ../ca/certs/ca.crt -verify_other ../ca/certs/ca.crt -trust_other -header Host=0.0.0.0:2560
Response verify OK
yubico_client.pem: good
	This Update: Sep  6 18:54:00 2024 GMT
```

### Revoking a certificate
```sh
$ openssl ca -revoke yubico_client.pem -config ../config/openssl_config.cnf
```