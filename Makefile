include config.mk

CLEAN_DIRS := ocsp client nginx
DIRS := ca $(CLEAN_DIRS)

.PHONY: all clean $(DIRS) run test revoke

all: $(DIRS)

# Build order matters: everything else is signed by the CA
ocsp client nginx: ca

$(DIRS):
	@echo "Entering directory '$@'"
	@$(MAKE) -C $@
	@echo "Leaving directory '$@'"

run:
	docker compose up --build

# Revoke a client certificate, e.g. `make revoke CERT=client/yubico_client.pem`.
# The OCSP responder reads the CA database live. Cached verdicts are dropped by restarting the
# services (skip with RESTART=no, e.g. when OCSP_CACHE_TTL=0 or you are happy to wait for the TTL).
RESTART ?= yes
revoke:
	@test -n "$(CERT)" || { echo "usage: make revoke CERT=client/yubico_client.pem"; exit 1; }
	@test -f "$(CERT)" || { echo "no such certificate: $(CERT)"; exit 1; }
	cd ca && openssl ca -revoke ../$(CERT) -config ../config/openssl_config.cnf \
		-cert certs/ca.crt -keyfile private/ca.key
	@if [ "$(RESTART)" = yes ] && [ -n "$$(docker compose ps -q 2>/dev/null)" ]; then \
		echo "Restarting the services to drop cached verdicts"; \
		docker compose restart ocsp cac; \
	fi

# Spin up the stack (plus a header-echoing downstream), exercise it with curl, and tear it down.
# Run once with verdict caching on (the default) and once with it off.
test: all
	./test/run.sh
	OCSP_CACHE_TTL=0 ./test/run.sh

clean:
	@for dir in $(CLEAN_DIRS); do \
		echo "Entering directory '$$dir' for clean"; \
		$(MAKE) -C $$dir clean; \
		echo "Leaving directory '$$dir'"; \
	done
