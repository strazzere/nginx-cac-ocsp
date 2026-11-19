include config.mk

CLEAN_DIRS := ocsp client nginx
DIRS := ca $(CLEAN_DIRS)

.PHONY: all clean $(DIRS) run test

all: $(DIRS)

# Build order matters: everything else is signed by the CA
ocsp client nginx: ca

$(DIRS):
	@echo "Entering directory '$@'"
	@$(MAKE) -C $@
	@echo "Leaving directory '$@'"

run:
	docker compose up --build

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
