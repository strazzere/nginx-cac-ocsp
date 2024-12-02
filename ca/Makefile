.PHONY: all run ca deps clean

COUNTRY = US
ORG = Not U.S. Government
CN = Not DOD ID CA-64
OU1 = PKI
OU2 = Not DoD

SUBJ = /C=$(COUNTRY)/O=$(ORG)/CN=$(CN)/OU=$(OU1)/OU=$(OU2)

all: ca

ca: deps ca.crt

index.txt:
	touch index.txt

serial:
	echo 01 > serial

deps: index.txt serial
	mkdir -p certs newcerts private

ca.crt: ca.key
	openssl req -x509 -new -nodes -key private/ca.key \
		-sha256 -days 365 -out certs/ca.crt -batch \
		-subj "$(SUBJ)"

ca.key:
	openssl genrsa -out private/ca.key 2048

clean:
	@rm -f certs/* newcerts/* private/* index.txt index.txt.attr index.txt.old index.txt.attr.old serial serial.old