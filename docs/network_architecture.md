# Network Architecture

**Group:** The Hangover

---

## System Overview

<!-- Diagram of client(s) <-> server <-> database <-> Sepolia -->

## Components

| Component | Technology | Location |
|---|---|---|
| Python backend | Flask + SSL/TLS | the-hangover.theburkenator.com |
| SQLite database | SQLite | Server-local |
| C++ client | TBD | Client machine |
| Web client | HTML/JS | Client browser |
| Blockchain | Ethereum Sepolia | Public testnet |

## SSL/TLS Configuration

- Certificate: (self-signed / Let's Encrypt — TBD)
- Client certificate verification: yes/no — TBD
- TLS version minimum: TLS 1.2 / 1.3

## External Connections

| Connection | Protocol | Port |
|---|---|---|
| Client → Flask backend | HTTPS (TLS) | 5000 |
| Backend → Sepolia RPC | HTTPS | 443 |

## Security Controls Implemented

- [ ] Input validation
- [ ] Broken authentication mitigations
- [ ] Broken access control mitigations
- [ ] Injection prevention (parameterised queries)
- [ ] Security misconfiguration checks
- [ ] Sensitive data exposure controls
- [ ] Vulnerable component audit
