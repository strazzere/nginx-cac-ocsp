from http.server import BaseHTTPRequestHandler, HTTPServer
import subprocess
import tempfile
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import requests
from urllib.parse import urlparse, urlunparse

# Utility to ensure the passed ca.crt is available at a reachable destination
# otherwise the oscp responder will fail and hold indefinitely
def check_file_availability(url):
    try:
        response = requests.head(url, timeout=1)  # Use HEAD request
        if response.status_code == 200:
            return True
        else:
            return False
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return False

def fetch_file(url):
    try:
        response = requests.get(url, timeout=2)
        response.raise_for_status()  # Raise an error for HTTP codes 4xx/5xx
        return response.content
    except requests.RequestException as e:
        raise

class OCSPValidationHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Get the client certificate from the header
        client_cert_pem = self.headers.get('X-Client-Cert')

        if not client_cert_pem:
            self.send_response(400)
            self.end_headers()
            return
        
        cleaned_cert_pem = "\n".join(line.strip() for line in client_cert_pem.splitlines())

        # Load the certificate
        cert = x509.load_pem_x509_certificate(cleaned_cert_pem.encode(), default_backend())

        # Default OCSP and CA Issuer URLs
        ocsp_url = 'http://ocsp.penryn.local:2560'
        default_issuer_cert_path = '/etc/ocsp/ca.crt'
        issuer_cert_path = '/etc/ocsp/ca.crt'

        ocsp_urls = []
        ca_issuer_urls = []

        try:
            # Parse AIA extension
            aia = cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value


            for access_description in aia:
                if access_description.access_method == x509.AuthorityInformationAccessOID.OCSP:
                    ocsp_urls.append(access_description.access_location.value)
                elif access_description.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS:
                    ca_issuer_urls.append(access_description.access_location.value)
            
            print('****')
            print(ocsp_urls)
            print(ca_issuer_urls)
            print('****')

            # Use the parsed URLs if available

            # Use the first OCSP URL found
            if ocsp_urls:
                # simplistic shoving of a default port on this
                parsed = urlparse(ocsp_urls[0])
                if parsed.port is None:
                    parsed = parsed._replace(netloc=f"{parsed.hostname}:2560")
                    ocsp_url = urlunparse(parsed)
                else:
                    ocsp_url = ocsp_urls[0]

            # Use the first CA Issuer URL found (assuming local path or downloading)
            if ca_issuer_urls and check_file_availability(ca_issuer_urls[0]):
                with tempfile.NamedTemporaryFile(delete=False, mode='wb') as ca_file:
                    ca_file.write(fetch_file(ca_issuer_urls[0]))
                    issuer_cert_path = ca_file.name
        except:
            # Just use the default, but more than likely we should fail
            pass

        # Create a temporary file to store the client certificate
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as cert_file:
            cert_file.write(cleaned_cert_pem)
            cert_file_path = cert_file.name  # Get the file path

        try:
            # Perform the OCSP check using OpenSSL
            print('ocsp check using issuer {0}'.format(issuer_cert_path))
            ocsp_response = subprocess.run(
                [
                    'openssl', 'ocsp',
                    '-issuer', issuer_cert_path,
                    '-cert', cert_file_path,
                    '-url', ocsp_url,
                    '-CAfile', default_issuer_cert_path,
                    '-verify_other', issuer_cert_path,
                    '-trust_other',
                    '-header', 'Host={0}'.format(ocsp_url)
                ],
                capture_output=True,
                text=True,
                timeout=10
            )
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            print(f"Error: {str(e)}")
            os.remove(cert_file_path)
            return

        cert_check_string = f"{cert_file.name}: good"

        # Check the response on the stderr, for some reason it's pushed there
        if "Response verify OK" in ocsp_response.stderr and cert_check_string in ocsp_response.stdout:
            self.send_response(200)
        else:
            self.send_response(403)

        self.end_headers()

        os.remove(cert_file_path)

def run(server_class=HTTPServer, handler_class=OCSPValidationHandler, port=9000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Starting OCSP validation proxy on port {port}...')
    httpd.serve_forever()

if __name__ == "__main__":
    run()
