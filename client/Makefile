include ../config.mk

.PHONY: all test_certs pki_certs clean revoke_csr

# Keep keys and CSRs that were only built as a step towards a certificate (make would delete them)
.SECONDARY:

# Some hints taken from https://stackoverflow.com/questions/611057/dod-common-access-card-cac-authentication
COUNTRY = US
ORG = Not U.S. Government
OU1 = PKI
OU2 = Not DoD
EPID = 0123456789
CN = DOE.JOHN.FAKE.$(EPID)

SUBJ = /C=$(COUNTRY)/O=$(ORG)/OU=$(OU1)/OU=$(OU2)/CN=$(CN)

CA_ARGS = -cert ../ca/certs/ca.crt -keyfile ../ca/private/ca.key -config ../config/openssl_config.cnf -batch

all: yubico_client.key yubico_client.crt yubico_client.pem test_certs pki_certs

# The "happy path" client cert, signed by the CA (and recorded in ca/index.txt for OCSP)
yubico_client.key:
	openssl req -new -newkey rsa:2048 -nodes -keyout yubico_client.key -out yubico_client.csr \
		-sha256 -batch \
		-subj "$(SUBJ)"

yubico_client.crt: yubico_client.key
	openssl req -x509 -new -nodes -key yubico_client.key \
		-sha256 -days 365 -out yubico_client.crt -batch \
		-subj "$(SUBJ)"

yubico_client.pem: yubico_client.key
	openssl ca -in yubico_client.csr -out yubico_client.pem -days 1024 -extensions req_ext $(CA_ARGS)

# Certs for exercising the edge cases:
#   test_expired.pem - signed by the CA but already expired
#   test_revoked.pem - signed by the CA, then revoked
#   test_no_upn.pem  - signed by the CA, has no UPN in its SAN
#   test_bad_upn.pem - signed by the CA, UPN has a non-ASCII character
test_certs: test_expired.pem test_revoked.pem test_no_upn.pem test_bad_upn.pem

test_%.key:
	openssl req -new -newkey rsa:2048 -nodes -keyout $@ -out test_$*.csr -sha256 -batch \
		-subj "/C=$(COUNTRY)/O=$(ORG)/OU=$(OU1)/OU=$(OU2)/CN=DOE.JOHN.$(shell echo $* | tr a-z_ A-Z-).$(EPID)"

test_expired.pem: test_expired.key
	openssl ca -in test_expired.csr -out $@ -startdate 20200101000000Z -enddate 20200102000000Z \
		-extensions req_ext $(CA_ARGS)

test_revoked.pem: test_revoked.key
	openssl ca -in test_revoked.csr -out $@ -days 1024 -extensions req_ext $(CA_ARGS)
	openssl ca -revoke $@ $(CA_ARGS)

test_no_upn.pem: test_no_upn.key
	openssl ca -in test_no_upn.csr -out $@ -days 1024 -extensions noupn_ext $(CA_ARGS)

test_bad_upn.pem: test_bad_upn.key
	openssl ca -in test_bad_upn.csr -out $@ -days 1024 -extensions badupn_ext $(CA_ARGS)

# --- A "real world" style PKI for tests -------------------------------------------------------
# root (our CA) -> intermediate -> client certs. The intermediate is only available as a PKCS#7
# bundle from a caIssuers URL, and its OCSP responder (a delegated signer, without nonce support,
# picky about the Host header) runs on another host: `realpki` in docker-compose.yml.
PKI_SUBJ = /C=$(COUNTRY)/O=$(ORG)/OU=$(OU1)

pki_certs: pki_leaf_chain.pem pki_revoked_chain.pem pki/resp.pem pki/int.p7c pki/index.txt

pki:
	mkdir -p pki

pki/int.key: | pki
	openssl req -new -newkey rsa:2048 -nodes -keyout pki/int.key -out pki/int.csr -sha256 -batch \
		-subj "$(PKI_SUBJ)/CN=Not DOD INTERMEDIATE CA-1"

pki/int.pem: pki/int.key
	openssl ca -notext -in pki/int.csr -out pki/int.pem -days 1024 -extensions v3_int $(CA_ARGS)

# What a caIssuers URL usually serves: a PKCS#7 bundle (here the intermediate and the root), DER encoded
pki/int.p7c: pki/int.pem
	openssl crl2pkcs7 -nocrl -certfile pki/int.pem -certfile ../ca/certs/ca.crt -outform DER -out pki/int.p7c

# The responder's signing cert, issued by the intermediate (a delegated responder)
pki/resp.key: | pki
	openssl req -new -newkey rsa:2048 -nodes -keyout pki/resp.key -out pki/resp.csr -sha256 -batch \
		-subj "$(PKI_SUBJ)/CN=Not DOD INTERMEDIATE OCSP"
	chmod 644 pki/resp.key # test only: it is mounted into a container that runs as another user

pki/resp.pem: pki/resp.key pki/int.pem
	openssl x509 -req -in pki/resp.csr -CA pki/int.pem -CAkey pki/int.key -set_serial 0x10 -days 1024 \
		-extfile ../config/openssl_config.cnf -extensions ocsp_ext -out pki/resp.pem

pki_leaf.key pki_revoked.key:
	openssl req -new -newkey rsa:2048 -nodes -keyout $@ -out $(basename $@).csr -sha256 -batch \
		-subj "$(PKI_SUBJ)/CN=DOE.JOHN.$(shell echo $(basename $@) | tr a-z_ A-Z-).$(EPID)"

pki_leaf.pem: pki_leaf.key pki/int.pem
	openssl x509 -req -in pki_leaf.csr -CA pki/int.pem -CAkey pki/int.key -set_serial 0x1001 -days 1024 \
		-extfile ../config/openssl_config.cnf -extensions pki_leaf_ext -out pki_leaf.pem

pki_revoked.pem: pki_revoked.key pki/int.pem
	openssl x509 -req -in pki_revoked.csr -CA pki/int.pem -CAkey pki/int.key -set_serial 0x1002 -days 1024 \
		-extfile ../config/openssl_config.cnf -extensions pki_leaf_ext -out pki_revoked.pem

# Clients send their intermediate along with their own certificate
%_chain.pem: %.pem pki/int.pem
	cat $< pki/int.pem > $@

# The intermediate's "database", in the format of openssl's index.txt
pki/index.txt: pki_leaf.pem pki_revoked.pem
	printf 'V\t290101000000Z\t\t1001\tunknown\t/CN=pki_leaf\nR\t290101000000Z\t261119000000Z,keyCompromise\t1002\tunknown\t/CN=pki_revoked\n' > $@

# Fresh, valid, disposable certs (not part of `all`): test/run.sh makes some, revokes them
# and stops the responder to check how the services react. `make clean` removes them.
test_live_%.pem: test_live_%.key
	openssl ca -in test_live_$*.csr -out $@ -days 1024 -extensions req_ext $(CA_ARGS)

# Revoke the main client cert in the CA database (a no-op if it was never issued)
revoke_csr:
	@if [ -f yubico_client.pem ]; then \
		openssl ca -revoke yubico_client.pem $(CA_ARGS) || true; \
	fi

clean: revoke_csr
	@rm -f yubico_client.key yubico_client.csr yubico_client.crt yubico_client.pem \
		test_*.key test_*.csr test_*.pem pki_*.key pki_*.csr pki_*.pem pki/*
	@rmdir pki 2>/dev/null || true
