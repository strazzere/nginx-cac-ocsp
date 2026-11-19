#!/bin/sh

# Ensure we can easily push our print statements from python
export PYTHONUNBUFFERED=1

# Run the OCSP responder in the background
python3 /etc/ocsp/responder.py &
OCSP_PID=$!

# Run the Python proxy in the background
python3 /etc/ocsp/proxy.py &
PROXY_PID=$!

# Forward termination signals so `docker stop` is quick and clean
trap 'kill $OCSP_PID $PROXY_PID 2>/dev/null; wait; exit 0' TERM INT

# Exit as soon as either process dies, so the container is restarted/reported
# as failed instead of silently running with half of the service missing
while kill -0 $OCSP_PID 2>/dev/null && kill -0 $PROXY_PID 2>/dev/null; do
    sleep 1
done

echo "a child process exited, shutting down" >&2
kill $OCSP_PID $PROXY_PID 2>/dev/null
wait
exit 1
