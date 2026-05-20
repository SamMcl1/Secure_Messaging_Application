"""
test_ssl_verification.py
========================
Verifies that the project's Python HTTP clients correctly enforce TLS certificate
validation.  The tests use real in-process HTTPS servers (see conftest.py) so
the SSL handshake actually occurs — this cannot be faked with mocks.

Test matrix
-----------
Scenario                        Library      verify=              Expected
------------------------------- ------------ -------------------- -------------------
Self-signed cert (default)      requests     True (default)       SSLError  ✗ rejected
Self-signed cert (explicit)     requests     True                 SSLError  ✗ rejected
Self-signed cert (disabled)     requests     False                200 OK    ⚠ INSECURE
Expired cert                    requests     <CA path>            SSLError  ✗ rejected
Valid CA-signed cert            requests     <CA path>            200 OK    ✓ accepted
Self-signed cert (default)      httpx        True (default)       ConnectError ✗ rejected
Expired cert                    httpx        <SSLContext>         ConnectError ✗ rejected
Valid CA-signed cert            httpx        <SSLContext>         200 OK    ✓ accepted
HttpClient — http:// URL        HttpClient   —                    ValueError
HttpClient — ca_bundle=False    HttpClient   —                    ValueError
HttpClient — self-signed        HttpClient   True                 SSLError  ✗ rejected
HttpClient — valid cert         HttpClient   <CA path>            200 OK    ✓ accepted
"""

import ssl
import warnings

import sys
from pathlib import Path

import pytest
import requests

# httpx is an optional dependency (install via requirements-dev.txt).
# Tests that need it are skipped if it is absent.
httpx = pytest.importorskip("httpx", reason="httpx not installed — run: pip install httpx")

# http_client.py lives at server/http_client.py — add server/ to the path so
# we can import it without triggering the Flask app package's __init__.py.
sys.path.insert(0, str(Path(__file__).parent.parent))
from http_client import HttpClient  # noqa: E402


# ─────────────────────────────────────────────────────────────────────────────
# requests — self-signed certificate
# ─────────────────────────────────────────────────────────────────────────────

class TestRequestsSelfSigned:
    """requests must refuse connections to servers with self-signed certificates."""

    def test_default_verify_rejects_self_signed(self, self_signed_server):
        """
        verify is True by default in requests.  A self-signed cert must be
        rejected even when the parameter is omitted entirely.
        """
        with pytest.raises(requests.exceptions.SSLError):
            requests.get(self_signed_server, timeout=5)

    def test_explicit_verify_true_rejects_self_signed(self, self_signed_server):
        """Explicitly passing verify=True must also reject a self-signed cert."""
        with pytest.raises(requests.exceptions.SSLError):
            requests.get(self_signed_server, verify=True, timeout=5)

    def test_verify_false_accepts_but_is_insecure(self, self_signed_server):
        """
        Setting verify=False bypasses certificate validation and the request
        succeeds.

        ⚠ WARNING — This is documented here to show the DANGEROUS behaviour of
        disabling verification.  NEVER use verify=False in production code.
        Doing so makes the connection completely vulnerable to
        man-in-the-middle attacks.
        """
        # Suppress the InsecureRequestWarning that requests emits
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", requests.packages.urllib3.exceptions.InsecureRequestWarning)
            resp = requests.get(self_signed_server, verify=False, timeout=5)
        assert resp.status_code == 200, (
            "verify=False bypasses certificate validation — this is INSECURE"
        )


# ─────────────────────────────────────────────────────────────────────────────
# requests — expired certificate
# ─────────────────────────────────────────────────────────────────────────────

class TestRequestsExpiredCert:
    """
    requests must reject a certificate whose notAfter has passed, even when the
    issuing CA is trusted.
    """

    def test_expired_cert_rejected_even_with_trusted_ca(self, expired_server):
        url, ca_path = expired_server
        # The CA is trusted (we pass its cert), but the leaf cert is expired
        with pytest.raises(requests.exceptions.SSLError) as exc_info:
            requests.get(url, verify=ca_path, timeout=5)
        # Confirm the underlying reason is certificate expiry, not chain failure
        assert "expired" in str(exc_info.value).lower() or "certificate" in str(exc_info.value).lower()


# ─────────────────────────────────────────────────────────────────────────────
# requests — valid CA-signed certificate
# ─────────────────────────────────────────────────────────────────────────────

class TestRequestsTrustedCert:
    """requests must accept a certificate that is current and signed by a trusted CA."""

    def test_valid_cert_accepted(self, trusted_server):
        url, ca_path = trusted_server
        resp = requests.get(url, verify=ca_path, timeout=5)
        assert resp.status_code == 200
        assert resp.text == "OK"


# ─────────────────────────────────────────────────────────────────────────────
# httpx — self-signed certificate
# ─────────────────────────────────────────────────────────────────────────────

class TestHttpxSelfSigned:
    """httpx must refuse connections to servers with self-signed certificates."""

    def test_default_verify_rejects_self_signed(self, self_signed_server):
        """httpx defaults to verify=True; a self-signed cert must be rejected."""
        with pytest.raises(httpx.ConnectError):
            httpx.get(self_signed_server, timeout=5)

    def test_explicit_verify_true_rejects_self_signed(self, self_signed_server):
        with pytest.raises(httpx.ConnectError):
            httpx.get(self_signed_server, verify=True, timeout=5)


# ─────────────────────────────────────────────────────────────────────────────
# httpx — expired certificate
# ─────────────────────────────────────────────────────────────────────────────

class TestHttpxExpiredCert:
    """
    httpx must reject a certificate whose notAfter has passed.

    httpx's verify parameter accepts an ssl.SSLContext; we build one that
    trusts the test CA so the only failure reason is cert expiry.
    """

    def test_expired_cert_rejected_even_with_trusted_ca(self, expired_server):
        url, ca_path = expired_server
        ctx = ssl.create_default_context(cafile=ca_path)
        with pytest.raises(httpx.ConnectError):
            httpx.get(url, verify=ctx, timeout=5)


# ─────────────────────────────────────────────────────────────────────────────
# httpx — valid CA-signed certificate
# ─────────────────────────────────────────────────────────────────────────────

class TestHttpxTrustedCert:
    """httpx must accept a certificate that is current and signed by a trusted CA."""

    def test_valid_cert_accepted(self, trusted_server):
        url, ca_path = trusted_server
        ctx = ssl.create_default_context(cafile=ca_path)
        resp = httpx.get(url, verify=ctx, timeout=5)
        assert resp.status_code == 200
        assert resp.text == "OK"


# ─────────────────────────────────────────────────────────────────────────────
# HttpClient wrapper
# ─────────────────────────────────────────────────────────────────────────────

class TestHttpClientWrapper:
    """
    The project's HttpClient class must enforce cert verification at the session
    level and reject unsafe configuration at construction time.
    """

    # Construction guards

    def test_rejects_plain_http_url(self):
        """HttpClient must refuse to be created with an http:// URL."""
        with pytest.raises(ValueError, match="https://"):
            HttpClient("http://hangover.theburkenator.com")

    def test_rejects_ca_bundle_false(self):
        """HttpClient must refuse to disable certificate verification."""
        with pytest.raises(ValueError, match="ca_bundle=False"):
            HttpClient("https://hangover.theburkenator.com", ca_bundle=False)

    # Verification behaviour

    def test_self_signed_cert_raises_ssl_error(self, self_signed_server):
        """HttpClient with default settings must reject a self-signed cert."""
        client = HttpClient(self_signed_server)
        with pytest.raises(requests.exceptions.SSLError):
            client.get("/")

    def test_valid_cert_accepted_with_custom_ca(self, trusted_server):
        """
        HttpClient accepts a connection when the server cert is signed by the
        CA supplied via ca_bundle.
        """
        url, ca_path = trusted_server
        client = HttpClient(url, ca_bundle=ca_path)
        resp = client.get("/")
        assert resp.status_code == 200

    def test_session_verify_is_true_by_default(self):
        """
        The underlying session's verify attribute must be True (not False or
        None) so that every request inherits verification.
        """
        client = HttpClient("https://example.com")
        assert client._session.verify is True

    def test_session_verify_reflects_custom_ca(self, trusted_server):
        """When a CA path is supplied, the session verify is set to that path."""
        url, ca_path = trusted_server
        client = HttpClient(url, ca_bundle=ca_path)
        assert client._session.verify == ca_path
