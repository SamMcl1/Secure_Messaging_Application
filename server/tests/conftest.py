"""
conftest.py — pytest fixtures that spin up minimal in-process HTTPS test servers.

Three fixture variants are provided:

self_signed_server
    Presents a certificate signed by its own private key, not by any CA.
    No CA cert is supplied; ``requests`` / ``httpx`` will reject it.

expired_server  →  (url, ca_cert_path)
    Presents a certificate that is validly signed by a local test CA but
    expired one day ago.  The CA cert path is yielded so tests can pass it
    to ``verify=ca_path`` — the expiry check still fires.

trusted_server  →  (url, ca_cert_path)
    Presents a current, CA-signed certificate.  Passing the CA cert path to
    ``verify=ca_path`` should result in a successful connection (HTTP 200).

All servers run on ``127.0.0.1`` on an OS-assigned ephemeral port, use a
daemon thread, and are shut down automatically after the test module ends.
"""

import datetime
import ipaddress
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


# certificate generation helpers

def _gen_key() -> rsa.RSAPrivateKey:
    """Generate a 2048-bit RSA private key."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _to_cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _to_key_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


def _base_builder(
    subject: x509.Name,
    issuer: x509.Name,
    public_key,
) -> x509.CertificateBuilder:
    """Return a builder pre-loaded with the fields common to all test certs."""
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        # SAN must cover 127.0.0.1 so that Python's hostname check passes
        # (hostname check and cert-chain check are independent; we only want
        # the *chain* check to fail in the self-signed / expired tests).
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]
            ),
            critical=False,
        )
    )


def _now() -> datetime.datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.datetime.now(datetime.timezone.utc)


# cert generators

def gen_self_signed() -> tuple[bytes, bytes]:
    """
    Return (cert_pem, key_pem) for a self-signed certificate.

    The cert is valid (not expired) but signed by its own key, so it will
    not be trusted by a standard CA bundle.
    """
    key = _gen_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "self-signed.test")])
    cert = (
        _base_builder(name, name, key.public_key())
        .not_valid_before(_now() - datetime.timedelta(days=1))
        .not_valid_after(_now() + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return _to_cert_pem(cert), _to_key_pem(key)


def gen_expired() -> tuple[bytes, bytes, bytes]:
    """
    Return (cert_pem, key_pem, ca_cert_pem) for an expired certificate.

    The leaf cert is signed by a local test CA (so the chain is valid) but its
    ``notAfter`` was yesterday — the client should reject it.
    """
    # Local test CA (long-lived so the CA itself is not expired)
    ca_key = _gen_key()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA — expired-cert suite")])
    ca_cert = (
        _base_builder(ca_name, ca_name, ca_key.public_key())
        .not_valid_before(_now() - datetime.timedelta(days=730))
        .not_valid_after(_now() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    # Leaf cert — expired one day ago
    leaf_key = _gen_key()
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired.test")])
    leaf_cert = (
        _base_builder(leaf_name, ca_name, leaf_key.public_key())
        .not_valid_before(_now() - datetime.timedelta(days=730))
        .not_valid_after(_now() - datetime.timedelta(days=1))   # <-- already expired
        .sign(ca_key, hashes.SHA256())
    )
    return _to_cert_pem(leaf_cert), _to_key_pem(leaf_key), _to_cert_pem(ca_cert)


def gen_trusted() -> tuple[bytes, bytes, bytes]:
    """
    Return (cert_pem, key_pem, ca_cert_pem) for a currently-valid certificate.

    The leaf cert is signed by a local test CA and has not expired.
    Passing ``verify=ca_cert_path`` should allow a successful connection.
    """
    # Local test CA
    ca_key = _gen_key()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA — trusted-cert suite")])
    ca_cert = (
        _base_builder(ca_name, ca_name, ca_key.public_key())
        .not_valid_before(_now() - datetime.timedelta(days=1))
        .not_valid_after(_now() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    # Leaf cert — valid for one year
    leaf_key = _gen_key()
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "trusted.test")])
    leaf_cert = (
        _base_builder(leaf_name, ca_name, leaf_key.public_key())
        .not_valid_before(_now() - datetime.timedelta(days=1))
        .not_valid_after(_now() + datetime.timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )
    return _to_cert_pem(leaf_cert), _to_key_pem(leaf_key), _to_cert_pem(ca_cert)


# minimal HTTPS server

class _SilentOKHandler(BaseHTTPRequestHandler):
    """Always returns HTTP 200 OK; suppresses access-log noise."""

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, *_):  # silence per-request log lines
        pass


def _start_tls_server(cert_pem: bytes, key_pem: bytes, tmp_dir: str) -> tuple[str, HTTPServer]:
    """
    Write cert/key to *tmp_dir*, wrap an HTTPServer with TLS, start a daemon
    thread, and return (base_url, server_instance).
    """
    cert_path = os.path.join(tmp_dir, "server.crt")
    key_path  = os.path.join(tmp_dir, "server.key")

    with open(cert_path, "wb") as f:
        f.write(cert_pem)
    with open(key_path, "wb") as f:
        f.write(key_pem)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)

    httpd = HTTPServer(("127.0.0.1", 0), _SilentOKHandler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return f"https://127.0.0.1:{port}", httpd


# pytest fixtures

@pytest.fixture(scope="module")
def self_signed_server(tmp_path_factory):
    """
    Yield a URL whose server presents a **self-signed** certificate.

    Clients must raise an SSL error when ``verify=True`` (the default).
    """
    tmp_dir = str(tmp_path_factory.mktemp("self_signed"))
    cert_pem, key_pem = gen_self_signed()
    url, httpd = _start_tls_server(cert_pem, key_pem, tmp_dir)
    try:
        yield url
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture(scope="module")
def expired_server(tmp_path_factory):
    """
    Yield ``(url, ca_cert_path)`` whose server presents an **expired** certificate.

    The CA cert path is provided so tests can supply it as ``verify=ca_cert_path``.
    Even with the CA trusted, the client must raise an SSL error because the leaf
    cert's ``notAfter`` is in the past.
    """
    tmp_dir = str(tmp_path_factory.mktemp("expired"))
    cert_pem, key_pem, ca_pem = gen_expired()

    ca_path = os.path.join(tmp_dir, "ca.crt")
    with open(ca_path, "wb") as f:
        f.write(ca_pem)

    url, httpd = _start_tls_server(cert_pem, key_pem, tmp_dir)
    try:
        yield url, ca_path
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture(scope="module")
def trusted_server(tmp_path_factory):
    """
    Yield ``(url, ca_cert_path)`` whose server presents a **valid, CA-signed**
    certificate.

    Passing ``verify=ca_cert_path`` to requests/httpx should succeed (HTTP 200).
    """
    tmp_dir = str(tmp_path_factory.mktemp("trusted"))
    cert_pem, key_pem, ca_pem = gen_trusted()

    ca_path = os.path.join(tmp_dir, "ca.crt")
    with open(ca_path, "wb") as f:
        f.write(ca_pem)

    url, httpd = _start_tls_server(cert_pem, key_pem, tmp_dir)
    try:
        yield url, ca_path
    finally:
        httpd.shutdown()
        httpd.server_close()
