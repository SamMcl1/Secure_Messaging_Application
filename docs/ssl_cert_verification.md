# TLS Certificate Verification — Python & C++ Clients

**Group:** The Hangover  
**Related Jira ticket:** SSL/TLS cert setup — cert-verification sub-task  
**Date:** May 2026

---

## Overview

Every connection between a client and `hangover.theburkenator.com` is encrypted
with TLS.  For encryption to actually protect against man-in-the-middle (MITM)
attacks, the client must **verify** the server's certificate:

1. The certificate was issued by a trusted Certificate Authority (CA).  
2. The certificate has not expired.  
3. The hostname in the certificate matches the server being contacted.

If any check fails the connection must be refused.  Disabling verification
(`verify=False` in Python, `CURLOPT_SSL_VERIFYPEER=0` in libcurl) renders
TLS useless against MITM attacks and is never acceptable in production.

---

## Python clients — `requests` and `httpx`

### Default behaviour

Both libraries **enable certificate verification by default**.  No explicit
configuration is needed for production use against a server with a valid
Let's Encrypt certificate.

| Library   | Default         | How to check |
|-----------|-----------------|--------------|
| `requests`| `verify=True`   | `session.verify` is `True` on a freshly created `Session` |
| `httpx`   | `verify=True`   | `httpx.Client(verify=True)` is the default constructor |

### Project wrapper — `server/app/http_client.py`

`HttpClient` is a thin wrapper around `requests.Session` that enforces safe
defaults and makes the intent explicit.  It lives at `server/http_client.py`
(outside the Flask `app` package since it has no Flask dependency):

```python
from http_client import HttpClient

# Production — uses certifi CA bundle (Let's Encrypt is included)
client = HttpClient("https://hangover.theburkenator.com")
resp = client.post("/auth/login", json={"username": "alice", "password": "…"})

# Integration test against a server signed by a private CA
client = HttpClient("https://hangover.theburkenator.com", ca_bundle="/path/to/ca.pem")
```

Construction-time guards:

| Invalid call                                  | Error raised |
|-----------------------------------------------|--------------|
| `HttpClient("http://…")`                      | `ValueError` — plain HTTP is rejected |
| `HttpClient("https://…", ca_bundle=False)`    | `ValueError` — disabling verification is rejected |

The `verify` attribute is set **at the session level**, not per-request.  This
means verification cannot be bypassed by callers of `get()` / `post()` /
`delete()`.

### What happens with bad certificates

```
┌──────────────────────────────┬──────────────────────────────┬─────────────────────────┐
│ Scenario                     │ requests exception           │ httpx exception         │
├──────────────────────────────┼──────────────────────────────┼─────────────────────────┤
│ Self-signed / untrusted CA   │ requests.exceptions.SSLError │ httpx.ConnectError      │
│ Expired certificate          │ requests.exceptions.SSLError │ httpx.ConnectError      │
│ Hostname mismatch            │ requests.exceptions.SSLError │ httpx.ConnectError      │
│ verify=False (⚠ INSECURE)    │ 200 OK — no protection!      │ 200 OK — no protection! │
└──────────────────────────────┴──────────────────────────────┴─────────────────────────┘
```

### Tested scenarios

Automated tests are in `server/tests/test_ssl_verification.py`.  The test suite
spins up real in-process HTTPS servers using Python's `ssl` module and generates
certificates on the fly with the `cryptography` library.

Run with:

```bash
cd server
pip install -r requirements.txt
pytest tests/test_ssl_verification.py -v
```

Expected output (abbreviated):

```
PASSED  test_ssl_verification.py::TestRequestsSelfSigned::test_default_verify_rejects_self_signed
PASSED  test_ssl_verification.py::TestRequestsSelfSigned::test_explicit_verify_true_rejects_self_signed
PASSED  test_ssl_verification.py::TestRequestsSelfSigned::test_verify_false_accepts_but_is_insecure
PASSED  test_ssl_verification.py::TestRequestsExpiredCert::test_expired_cert_rejected_even_with_trusted_ca
PASSED  test_ssl_verification.py::TestRequestsTrustedCert::test_valid_cert_accepted
PASSED  test_ssl_verification.py::TestHttpxSelfSigned::test_default_verify_rejects_self_signed
PASSED  test_ssl_verification.py::TestHttpxExpiredCert::test_expired_cert_rejected_even_with_trusted_ca
PASSED  test_ssl_verification.py::TestHttpxTrustedCert::test_valid_cert_accepted
PASSED  test_ssl_verification.py::TestHttpClientWrapper::test_rejects_plain_http_url
PASSED  test_ssl_verification.py::TestHttpClientWrapper::test_rejects_ca_bundle_false
PASSED  test_ssl_verification.py::TestHttpClientWrapper::test_self_signed_cert_raises_ssl_error
PASSED  test_ssl_verification.py::TestHttpClientWrapper::test_valid_cert_accepted_with_custom_ca
```

---

## C++ client — libcurl

### Status

The C++ client (`client/cpp/`) is currently a stub.  The build system
(`CMakeLists.txt`) already links against `libcurl`, which will be used for all
HTTP communication once the client is implemented.

### libcurl default behaviour

libcurl enables TLS certificate verification **by default** via two options:

| Option                    | Default value | Effect |
|---------------------------|---------------|--------|
| `CURLOPT_SSL_VERIFYPEER`  | `1L`          | Verify that the server cert was signed by a trusted CA |
| `CURLOPT_SSL_VERIFYHOST`  | `2L`          | Verify that the server hostname matches the cert's CN / SAN |

No explicit `curl_easy_setopt` calls are required to enable these — they are on
by default.  They would only appear in code if someone was **disabling** them,
which must never happen in production.

### Correct usage pattern (reference implementation)

When the C++ client is implemented it should follow this pattern:

```cpp
#include <curl/curl.h>

CURL* curl = curl_easy_init();
if (!curl) { /* handle error */ }

// Verification is on by default — these two lines are shown explicitly
// so the intent is clear; remove them only with a documented justification.
curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);   // verify CA chain
curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);   // verify hostname

// For production (Let's Encrypt cert) the system CA bundle is used automatically.
// For a private CA (e.g. local dev), supply the CA cert path:
// curl_easy_setopt(curl, CURLOPT_CAINFO, "/path/to/ca.pem");

curl_easy_setopt(curl, CURLOPT_URL, "https://hangover.theburkenator.com/auth/login");
// … set CURLOPT_POSTFIELDS, CURLOPT_HTTPHEADER, etc. …

CURLcode res = curl_easy_perform(curl);
if (res != CURLE_OK) {
    // CURLE_SSL_CACERT         — cert not trusted / self-signed
    // CURLE_SSL_CERTPROBLEM    — cert problem (expired, etc.)
    // CURLE_PEER_FAILED_VERIFICATION — hostname mismatch
    fprintf(stderr, "curl error: %s\n", curl_easy_strerror(res));
}
curl_easy_cleanup(curl);
```

### Error codes to handle

| CURLcode                       | Meaning |
|-------------------------------|---------|
| `CURLE_SSL_CACERT`            | Server cert not trusted (self-signed, or unknown CA) |
| `CURLE_SSL_CERTPROBLEM`       | General cert problem — includes expired certificates |
| `CURLE_PEER_FAILED_VERIFICATION` | Hostname in cert does not match the URL |

These error codes should be caught and reported to the user; the connection must
**not** be retried with verification disabled.

### CA bundle on Linux (VM)

On the project VM (Ubuntu), libcurl uses the system CA bundle at
`/etc/ssl/certs/ca-certificates.crt`.  This bundle is updated via
`apt upgrade` and includes Let's Encrypt's root CAs.

Once Petr's team configures the `hangover.theburkenator.com` subdomain on the
shared gateway, run `sudo certbot --nginx -d hangover.theburkenator.com` to
replace the self-signed cert with a real Let's Encrypt cert.  After that the
C++ client will work without any additional CA configuration.

---

## Transition: self-signed → Let's Encrypt

During development the VM is running with a self-signed certificate located at
`/etc/ssl/certs/hangover-selfsigned.crt` (key at
`/etc/ssl/private/hangover-selfsigned.key`).  To connect from Python or C++
during this phase, copy the cert from the VM and point the client at it:

**Python (requests):**
```python
# Point verify at the self-signed cert itself (it acts as its own CA)
resp = requests.get("https://200.69.13.70", verify="hangover-selfsigned.crt")
```

**Python (HttpClient):**
```python
client = HttpClient("https://200.69.13.70", ca_bundle="hangover-selfsigned.crt")
```

**C++ (libcurl):**
```cpp
curl_easy_setopt(curl, CURLOPT_CAINFO, "hangover-selfsigned.crt");
```

> **Team action item:** confirm whether the Flask server should run on port
> 8000 (current Nginx proxy assumption) or port 5000 (current `run.py` default).
> Update either `run.py` or the Nginx config to make them consistent before
> running the full stack.

Once the Let's Encrypt cert is in place (`hangover.theburkenator.com`), remove
the custom CA path.  All of the above revert to `verify=True` / default CA
bundle and will work automatically.

---

## What must never appear in production code

```python
# ❌ NEVER DO THIS
requests.get(url, verify=False)
httpx.get(url, verify=False)
HttpClient("https://…", ca_bundle=False)   # raises ValueError — intentionally blocked
```

```cpp
// ❌ NEVER DO THIS
curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
```
