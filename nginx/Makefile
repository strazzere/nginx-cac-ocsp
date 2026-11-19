include ../config.mk

.PHONY: all cert clean

COUNTRY = US
STATE = CA
ORG = Red Naga, LLC
CN = $(CAC_HOST)

SUBJ = /C=$(COUNTRY)/ST=$(STATE)/O=$(ORG)/CN=$(CN)

all: cert

cert: certificate.pem

certificate.pem: key.pem
	openssl req -batch -sha256 -days 3650 \
	    -new -x509 -key key.pem -out certificate.pem \
	    -subj "$(SUBJ)"

key.pem:
	openssl genrsa -out key.pem 2048

clean:
	@rm -f key.pem certificate.pem
