include ../config.mk

.PHONY: all clean ca deps crl

COUNTRY = US
ORG = Not U.S. Government
CN = Not DOD ID CA-64
OU1 = PKI
OU2 = Not DoD

SUBJ = /C=$(COUNTRY)/O=$(ORG)/CN=$(CN)/OU=$(OU1)/OU=$(OU2)

all: ca

ca: deps certs/ca.crt

index.txt:
	touch index.txt

# Allow several certs with the same subject (e.g. re-issuing after a clean)
index.txt.attr:
	echo "unique_subject = no" > index.txt.attr

serial:
	echo 01 > serial

crlnumber:
	echo 01 > crlnumber

deps: index.txt index.txt.attr serial crlnumber
	mkdir -p certs newcerts private

certs/ca.crt: private/ca.key
	openssl req -x509 -new -nodes -key private/ca.key \
		-sha256 -days 3650 -out certs/ca.crt -batch \
		-subj "$(SUBJ)"

private/ca.key: deps
	openssl genrsa -out private/ca.key 2048

# Generate a CRL from the current index.txt
crl: ca
	openssl ca -gencrl -config ../config/openssl_config.cnf -out crl.pem

clean:
	@rm -rf certs/* newcerts/* private/* crl.pem crlnumber crlnumber.old index.txt index.txt.attr index.txt.old index.txt.attr.old serial serial.old
