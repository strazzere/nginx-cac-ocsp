.PHONY: all clean

# Some hints taken from https://stackoverflow.com/questions/611057/dod-common-access-card-cac-authentication
COUNTRY = US
ORG = Not U.S. Government
OU1 = PKI
OU2 = Not DoD
EPID = 0123456789
CN = DOE.JOHN.FAKE.$(EPID)
EMAIL = john.doe.civ@fake.mil

SUBJ = /C=$(COUNTRY)/O=$(ORG)/OU=$(OU1)/OU=$(OU2)/CN=$(CN)

all: yubico_client.key yubico_client.crt yubico_client.pem

yubico_client.key:
	openssl req -new -newkey rsa:2048 -nodes -keyout yubico_client.key -out yubico_client.csr \
		-sha256 -batch \
		-subj "$(SUBJ)"

yubico_client.crt:
	openssl req -x509 -new -nodes -key yubico_client.key \
		-sha256 -days 365 -out yubico_client.crt -batch \
		-subj "$(SUBJ)"

yubico_client.pem:
	# @echo "subjectAltName=email:$(EMAIL)" > san_extfile.cnf
	openssl x509 -req -days 365 -in yubico_client.csr -signkey yubico_client.key -out yubico_client.pem
	# @rm -f san_extfile.cnf
	# sign_csr:
	openssl ca -in yubico_client.csr -out yubico_client.pem \
		-cert ../ca/certs/ca.crt -keyfile ../ca/private/ca.key -days 1024 \
		-config ../config/openssl_config.cnf -extensions req_ext -batch

revoke_csr:
	openssl ca -revoke yubico_client.pem -config ../config/openssl_config.cnf

clean: revoke_csr
	@rm -f yubico_client.key yubico_client.csr yubico_client.crt yubico_client.pem
