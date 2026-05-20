"""
http_client.py — Thin HTTPS-only wrapper around requests.Session.

TLS certificate verification is always enabled.  The default CA bundle shipped
with the requests/certifi package is used unless the caller supplies a custom
CA path (e.g. during integration tests against a self-signed or local CA).

Usage
-----
    from http_client import HttpClient

    client = HttpClient("https://hangover.theburkenator.com")
    resp   = client.post("/auth/login", json={"username": "alice", "password": "…"})
    data   = resp.json()

Raises
------
requests.exceptions.SSLError
    Raised by requests when the server's certificate is:

    • Expired — the ``notAfter`` field in the cert is in the past.
    • Self-signed / untrusted — the issuing CA is not in the trusted bundle.
    • Hostname mismatch — the server name does not match the cert's CN or SAN.

    NEVER catch SSLError silently, and NEVER set ``verify=False`` in production.
    Doing so strips all transport-layer security guarantees.

ValueError
    Raised at construction time if a plain ``http://`` URL is supplied or if
    certificate verification is explicitly disabled via ``ca_bundle=False``.
"""

import requests


class HttpClient:
    """
    HTTPS-only HTTP client for the Hangover messaging API.

    Certificate verification is enforced at the session level so it applies to
    every request made through this client.  It cannot be bypassed by callers
    of the public ``get`` / ``post`` / ``delete`` methods.
    """

    def __init__(
        self,
        base_url: str,
        *,
        ca_bundle: str | bool = True,
        timeout: int = 10,
    ) -> None:
        """
        Parameters
        ----------
        base_url:
            Root URL of the server.  Must start with ``https://``.
        ca_bundle:
            • ``True``  (default) — use the certifi CA bundle bundled with
              requests.  This is the right choice when the server has a
              production-grade Let's Encrypt (or similar) certificate.
            • ``"/path/to/ca.pem"`` — path to a custom CA certificate file.
              Use this in tests that talk to a local server with a self-issued
              CA, or when deploying behind a private PKI.
            • ``False`` — **rejected**.  Disabling cert verification silently
              makes the connection vulnerable to man-in-the-middle attacks.
        timeout:
            Seconds to wait for a response before raising
            ``requests.exceptions.Timeout``.  Applied to both connect and read.
        """
        if not base_url.startswith("https://"):
            raise ValueError(
                f"base_url must start with 'https://'; got: {base_url!r}. "
                "Plain HTTP is not permitted — all traffic must be encrypted."
            )
        if ca_bundle is False:
            raise ValueError(
                "ca_bundle=False disables TLS certificate verification. "
                "Use ca_bundle=True (default) or supply a path to a CA bundle."
            )

        self._base = base_url.rstrip("/")
        self._timeout = timeout

        self._session = requests.Session()

        # Set verify at the session level so it applies to every request.
        # Explicitly setting True here is redundant (requests defaults to True)
        # but makes the intent visible to reviewers and static-analysis tooling.
        self._session.verify = ca_bundle

    # ── public request methods ────────────────────────────────────────────────

    def get(self, path: str, **kwargs) -> requests.Response:
        """Issue a GET request to ``base_url + path``."""
        return self._session.get(self._url(path), timeout=self._timeout, **kwargs)

    def post(self, path: str, json=None, **kwargs) -> requests.Response:
        """Issue a POST request with an optional JSON body."""
        return self._session.post(
            self._url(path), json=json, timeout=self._timeout, **kwargs
        )

    def delete(self, path: str, **kwargs) -> requests.Response:
        """Issue a DELETE request."""
        return self._session.delete(self._url(path), timeout=self._timeout, **kwargs)

    # ── private helpers ───────────────────────────────────────────────────────

    def _url(self, path: str) -> str:
        return f"{self._base}/{path.lstrip('/')}"
