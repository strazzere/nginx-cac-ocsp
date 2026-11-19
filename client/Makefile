include ../config.mk

.PHONY: all test_certs clean revoke_csr

# Some hints taken from https://stackoverflow.com/questions/611057/dod-common-access-card-cac-authentication
COUNTRY = US
ORG = Not U.S. Government
OU1 = PKI
OU2 = Not DoD
EPID = 0123456789
CN = DOE.JOHN.FAKE.$(EPID)

SUBJ = /C=$(COUNTRY)/O=$(ORG)/OU=$(OU1)/OU=$(OU2)/CN=$(CN)

CA_ARGS = -cert ../ca/certs/ca.crt -keyfile ../ca/private/ca.key -config ../config/openssl_config.cnf -batch

all: yubico_client.key yubico_client.crt yubico_client.pem test_certs

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
test_certs: test_expired.pem test_revoked.pem test_no_upn.pem

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

# Revoke the main client cert in the CA database (a no-op if it was never issued)
revoke_csr:
	@if [ -f yubico_client.pem ]; then \
		openssl ca -revoke yubico_client.pem $(CA_ARGS) || true; \
	fi

clean: revoke_csr
	@rm -f yubico_client.key yubico_client.csr yubico_client.crt yubico_client.pem \
		test_*.key test_*.csr test_*.pem
