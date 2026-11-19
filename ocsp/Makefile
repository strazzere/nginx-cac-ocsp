include ../config.mk

.PHONY: all clean

CN = Penryn Mock OCSP Responder
SUBJ = /CN=$(CN)

all: ocsp_cert.pem

ocsp_key.pem:
	openssl genpkey -algorithm RSA -out ocsp_key.pem

ocsp_req.csr: ocsp_key.pem
	openssl req -new -key ocsp_key.pem -out ocsp_req.csr \
		-subj "$(SUBJ)" -extensions ocsp_ext -config ../config/openssl_config.cnf

ocsp_cert.pem: ocsp_req.csr ../ca/certs/ca.crt
	openssl x509 -req -in ocsp_req.csr -CA ../ca/certs/ca.crt \
		-CAkey ../ca/private/ca.key -CAcreateserial -out ocsp_cert.pem -days 3650 \
		-extfile ../config/openssl_config.cnf -extensions ocsp_ext

clean:
	@rm -f ocsp_key.pem ocsp_req.csr ocsp_cert.pem
