.PHONY: all ocsp_key.pem ocsp_req.pem ocsp_req.csr clean

CN = Penryn Mock OCSP Responder
SUBJ = /CN=$(CN)

all: ocsp_req.csr

ocsp_key.pem:
	openssl genpkey -algorithm RSA -out ocsp_key.pem

ocsp_req.pem: ocsp_key.pem
	openssl req -new -key ocsp_key.pem -out ocsp_req.csr \
		-subj "$(SUBJ)"

ocsp_req.csr: ocsp_req.pem
	openssl ca -in ocsp_req.csr -out ocsp_cert.pem \
		-keyfile ../ca/private/ca.key -cert ../ca/certs/ca.crt \
		-extensions req_ext -config ../config/openssl_config.cnf \
		-batch

clean:
	@rm -f ocsp_key.pem ocsp_req.csr ocsp_req.csr ocsp_cert.pem