"""Tiny downstream app for tests: replies with the request headers it received.

The page is HTML and reflects an SSI directive on purpose: nginx must NOT execute it.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer


class Echo(BaseHTTPRequestHandler):
    def do_GET(self):
        body = ('<html><body>reflected: <!--# echo var="ssl_client_cert" -->\n<pre>'
                + "".join(f"{k}: {v}\n" for k, v in self.headers.items())
                + "</pre>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


HTTPServer(("", 8080), Echo).serve_forever()
