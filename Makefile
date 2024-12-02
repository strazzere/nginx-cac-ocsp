CLEAN_DIRS := ocsp client nginx
DIRS := ca $(CLEAN_DIRS)

.PHONY: all clean $(DIRS) run

all: $(DIRS)

$(DIRS):
	@echo "Entering directory '$@'"
	@$(MAKE) -C $@
	@echo "Leaving directory '$@'"

run:
	docker compose up --build

clean:
	@for dir in $(DIRS); do \
		echo "Entering directory '$$dir' for clean"; \
		$(MAKE) -C $$dir clean; \
		echo "Leaving directory '$$dir'"; \
	done