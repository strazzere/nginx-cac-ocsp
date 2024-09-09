.PHONY: all run cert clean

COUNTRY = US
STATE = CA
ORG = Red Naga, LLC
CN = cac.penryn.local

SUBJ = /C=$(COUNTRY)/ST=$(STATE)/O=$(ORG)/CN=$(CN)

cert: certificate.pem

certificate.pem: key.pem
	openssl req -batch -sha256 -days 365             \
	    -new -x509 -key key.pem -out certificate.pem \
	    -subj "$(SUBJ)"

key.pem:
	openssl genrsa -out key.pem 2048

clean:
	@rm -f key.pem certificate.pem