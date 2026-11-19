# Shared configuration, included by every Makefile in the project.
# Values come from .env (also used by docker compose); override on the command line if needed.
-include $(dir $(lastword $(MAKEFILE_LIST)))/.env

OCSP_HOST ?= ocsp.penryn.local
CAC_HOST ?= cac.penryn.local
DOWNSTREAM_SERVICE ?= www.penryn.com

# openssl_config.cnf reads these via ${ENV::...}
export OCSP_HOST CAC_HOST DOWNSTREAM_SERVICE
