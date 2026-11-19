from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import subprocess
import tempfile
import os
from cryptography.hazmat.primitives.serialization import pkcs7, Encoding
from cryptography import x509
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

def get_upn(cert):
    try:
        san_extension = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = san_extension.value
    except x509.ExtensionNotFound:
        sans = None

    # Parse the SANs and extract the UPN
    if sans:
        for general_name in sans:
            if isinstance(general_name, x509.OtherName):
                oid = general_name.type_id.dotted_string
                # Match the OID for UPN (1.3.6.1.4.1.311.20.2.3)
                if oid == "1.3.6.1.4.1.311.20.2.3":
                    upn = parse_der_utf8(general_name.value)
                    print("UPN:", upn)
                    return upn

    return None

def parse_der_utf8(value):
    """Decode a DER-wrapped string (tag, length, contents), handling long-form lengths."""
    if len(value) < 2:
        raise ValueError("DER value too short")
    length = value[1]
    offset = 2
    if length & 0x80:
        num = length & 0x7f
        length = int.from_bytes(value[2:2 + num], 'big')
        offset = 2 + num
    return value[offset:offset + length].decode('utf-8')

def sanitize_header(value):
    """Drop anything that could allow header injection."""
    return "".join(c for c in value if c.isprintable() and c not in "\r\n")

def strip_newlines(data):
    return "\n".join(line.strip() for line in data.splitlines())

def is_pkcs7_der(data):
    """Check if a data is a DER-encoded PKCS#7 file."""
    try:
        pkcs7.load_der_pkcs7_certificates(data)

        return True
    except ValueError:
        return False

def convert_pkcs7_der_to_pem(der_data):
    """Convert DER-encoded PKCS#7 to PEM format."""
    pem_certs = None

    try:
        certificates = pkcs7.load_der_pkcs7_certificates(der_data)
        pem_certs = b"".join(cert.public_bytes(Encoding.PEM) for cert in certificates)
    except ValueError as e:
        print(f"Error: {e}")

    return pem_certs

class OCSPValidationHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Get the client certificate from the header
        client_cert_pem = self.headers.get('X-Client-Cert')

        if not client_cert_pem:
            self.send_response(403)
            self.end_headers()
            return

        cleaned_cert_pem = strip_newlines(client_cert_pem)

        # Load the certificate
        try:
            cert = x509.load_pem_x509_certificate(cleaned_cert_pem.encode())
        except ValueError as e:
            print(f"Invalid client certificate: {e}")
            self.send_response(403)
            self.end_headers()
            return

        ocsp_urls = []
        ca_issuer_urls = []
        temp_paths = []

        try:
            # Parse UPN
            try:
                upn = get_upn(cert)
            except (ValueError, UnicodeDecodeError) as e:
                print(f"Unable to parse UPN: {e}")
                upn = None

            if upn is None:
                self.send_response(403)
                self.end_headers()
                return

            try:
                self.check_cert(cert, cleaned_cert_pem, upn, ocsp_urls, ca_issuer_urls, temp_paths)
            finally:
                for path in temp_paths:
                    try:
                        os.remove(path)
                    except OSError:
                        pass
        except Exception as e:
            print(f"Error: {e}")
            self.send_response(500)
            self.end_headers()

    def check_cert(self, cert, cleaned_cert_pem, upn, ocsp_urls, ca_issuer_urls, temp_paths):
        # Default OCSP and CA Issuer URLs
        ocsp_url = 'http://ocsp.penryn.local:2560'
        default_issuer_cert_path = '/etc/ocsp/ca.crt'
        issuer_cert_path = default_issuer_cert_path

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

            # Use the first OCSP URL found
            if ocsp_urls:
                ocsp_url = ocsp_urls[0]

            # Use the first CA Issuer URL found (downloading it)
            if ca_issuer_urls and check_file_availability(ca_issuer_urls[0]):
                ca_data = fetch_file(ca_issuer_urls[0])
                if is_pkcs7_der(ca_data):
                    ca_data = convert_pkcs7_der_to_pem(ca_data)
                with tempfile.NamedTemporaryFile(delete=False, mode='w+b') as ca_file:
                    temp_paths.append(ca_file.name)
                    ca_file.write(ca_data)
                    issuer_cert_path = ca_file.name
        except x509.ExtensionNotFound:
            print("No AIA extension found, using default OCSP URL and issuer")
        except Exception as e:
            # Fall back to the defaults, but make the reason visible
            print(f"Failed to use AIA information, falling back to defaults: {e}")

        # Create a temporary file to store the client certificate
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as cert_file:
            temp_paths.append(cert_file.name)
            cert_file.write(cleaned_cert_pem)
            cert_file_path = cert_file.name

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
                    '-header', 'Host={0}'.format(urlparse(ocsp_url).hostname)
                ],
                capture_output=True,
                text=True,
                timeout=10
            )
        except Exception as e:
            print(f"Error: {str(e)}")
            self.send_response(500)
            self.end_headers()
            return

        cert_check_string = f"{cert_file_path}: good"

        print("ocsp_response.stderr: {0}".format("Response verify OK" in ocsp_response.stderr))
        print(ocsp_response.stderr)

        print("ocsp_response.stdout: {0}".format(cert_check_string in ocsp_response.stdout))
        print(ocsp_response.stdout)

        print("checking")

        # Check the response on the stderr, for some reason it's pushed there
        if "Response verify OK" in ocsp_response.stderr and cert_check_string in ocsp_response.stdout:
            self.send_response(200)
        else:
            self.send_response(403)

        self.send_header("Content-Type", "text/plain")
        self.send_header("X-UPN", sanitize_header(upn))
        self.end_headers()

def run(server_class=ThreadingHTTPServer, handler_class=OCSPValidationHandler, port=9000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Starting OCSP validation proxy on port {port}...')
    httpd.serve_forever()

if __name__ == "__main__":
    run()
