#!/bin/sh

# Run the OpenSSL OCSP server in the background and pipe output to stdout
openssl ocsp -index /etc/ocsp/index.txt -port 2560 -rsigner /etc/ocsp/ocsp_cert.pem -rkey /etc/ocsp/ocsp_key.pem -CA /etc/ocsp/ca.crt -timeout 2 -text  &
OCSP_PID=$!

# Ensure we can easily push our print statements from python
export PYTHONUNBUFFERED=1
# Run the Python proxy script in the background and pipe output to stdout
python3 /etc/ocsp/proxy.py &
PROXY_PID=$!

# Wait for both processes to finish
wait $OCSP_PID $PROXY_PID