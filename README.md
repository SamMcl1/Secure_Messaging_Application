# Secure Messaging Application

CS4455 Cybersecurity — Epic Project 2026  
**Group:** hangover | University of Limerick

---

## Structure

```
.
├── server/                  # Flask backend (networking & security)
│   ├── app/
│   │   ├── __init__.py      # app factory
│   │   ├── config.py
│   │   ├── routes.py        # all API endpoints
│   │   ├── models.py        # User, Message
│   │   ├── crypto.py        # E2EE / key management
│   │   └── blockchain.py    # web3.py integration
│   ├── database/
│   │   └── schema.sql
│   ├── certs/               # SSL/TLS certificates (not committed)
│   ├── tests/
│   ├── run.py
│   └── requirements.txt
├── client/
│   ├── cpp/                 # C++ component
│   │   ├── src/main.cpp
│   │   ├── include/
│   │   └── CMakeLists.txt
│   └── web/                 # Static HTML/JS web client
│       ├── index.html
│       ├── css/style.css
│       └── js/app.js
├── blockchain/
│   ├── contracts/           # MessageDigest.sol (Solidity, Sepolia)
│   ├── scripts/deploy.py
│   ├── verification/        # Standalone verification page
│   └── abi/                 # Contract ABI after deployment
└── docs/
    ├── crypto_design.md
    ├── network_architecture.md
    ├── pentest_report.md
    ├── cover_document.md
    └── ai_artefacts/
```

## Setup

### 1. Python backend

```bash
cd server
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Copy `server/.env.example` to `server/.env` and fill in the values (see
**Environment variables** below).

#### Generate JWT RSA keys (required — server will not start without these)

```bash
# From the repo root
openssl genrsa -out server/certs/private_key.pem 2048
openssl rsa -in server/certs/private_key.pem -pubout -out server/certs/public_key.pem
```

These files are git-ignored. Alternatively, set the `JWT_PRIVATE_KEY` and
`JWT_PUBLIC_KEY` environment variables directly in `server/.env` (paste the
full PEM text, including header/footer lines).

Then start the server:

```bash
cd server
python run.py
```

The server listens on `http://127.0.0.1:8000` by default. The web client is
served from the same Flask process at `http://localhost:8000/` — no separate
web server is needed.

### 2. Database (Supabase PostgreSQL)

The backend uses a hosted Supabase PostgreSQL instance (connection string in
`DATABASE_URL`). Apply the migrations **in order** from the Supabase SQL editor
(or any `psql` client) the first time you set up a project:

```
server/database/migrations/001_initial_schema.sql     # users, messages, message_access
server/database/migrations/002_crypto_additions.sql   # encrypted_private_key, eph_pub, revoked_tokens
server/database/migrations/003_blockchain.sql         # messages.tx_hash, blockchain_records
```

Each migration is idempotent except the column rename in 002 — run each one
exactly once on a fresh database.

### 3. C++ client

Install system dependencies (Ubuntu/Debian):

```bash
sudo apt install -y build-essential cmake libcurl4-openssl-dev
```

Build:

```bash
cd client/cpp
mkdir build && cd build
cmake ..
make
```

Run:

```bash
./secure_client https://the-hangover.theburkenator.com <username> <password>
```

See `client/cpp/README.md` for full build instructions including macOS and
Windows.

### 4. Web client

The web client is served directly by Flask from the same process as the API.
Once the server is running (step 1), open:

```
http://localhost:8000/
```

No separate web server is needed. Running the client from `file://` will not
work — the Web Crypto API and the Content Security Policy both require a real
HTTP origin.

### 5. Blockchain verification page

The standalone verification page does not require the messaging app to be
running. Serve from the `blockchain/` directory (not the repo root) so the
relative ABI path resolves correctly:

```bash
cd blockchain
python -m http.server 3001
```

Then open `http://localhost:3001/verification/index.html`. Paste a message's
original plaintext and its Sepolia transaction hash to confirm the on-chain
keccak256 digest matches.

To **redeploy** the smart contract (e.g. to your own wallet):

```bash
pip install py-solc-x          # one-off, deploy-only dependency
python blockchain/scripts/deploy.py
```

This compiles `blockchain/contracts/MessageDigest.sol`, deploys it to Sepolia,
and rewrites `blockchain/abi/MessageDigest.json` with the new address + ABI.
The deployer wallet needs a small amount of Sepolia ETH (free from a faucet).

## Environment variables (`server/.env`)

| Variable | Required | Purpose |
|---|---|---|
| `SECRET_KEY` | Yes | Flask session signing key — generate with `python -c "import secrets; print(secrets.token_hex(32))"` |
| `DATABASE_URL` | Yes | Supabase PostgreSQL connection string |
| `SUPABASE_URL` | Yes | Supabase project URL |
| `SUPABASE_SERVICE_KEY` | Yes | Supabase service role key (server-only — never expose this) |
| `JWT_PRIVATE_KEY` | No* | RSA private key PEM for JWT signing (alternative to `server/certs/private_key.pem`) |
| `JWT_PUBLIC_KEY` | No* | RSA public key PEM for JWT verification (alternative to `server/certs/public_key.pem`) |
| `FLASK_DEBUG` | No | Set to `1` for local development only; never in production |
| `ALLOWED_ORIGIN` | No | Exact origin the web client is served from (CORS); leave empty if client and API share the same origin |
| `TRUSTED_PROXY_COUNT` | No | Number of trusted reverse proxy hops (set to `1` in production behind Nginx) |
| `FORCE_HTTPS` | No | Set to `1` in production to redirect HTTP → HTTPS |
| `SEPOLIA_RPC_URL` | No | Ethereum Sepolia RPC endpoint (e.g. Infura) |
| `CONTRACT_ADDRESS` | No | Deployed `MessageDigest` contract address |
| `DEPLOYER_PRIVATE_KEY` | No | Wallet key the server signs digest transactions with |

\* If neither the env var nor the `server/certs/` PEM file is present, the
server will refuse to start with a clear error message.

`SEPOLIA_RPC_URL`, `CONTRACT_ADDRESS`, and `DEPLOYER_PRIVATE_KEY` are optional —
if unset, the server runs normally and simply skips on-chain recording.

## Key Dates

| Milestone | Date |
|---|---|
| Status report 1 | Friday 23rd May 2026, 5:00 PM |
| Status report 2 | Friday 30th May 2026, 5:00 PM |
| **Submission** | **Wednesday 3rd June 2026, 5:00 PM** |
| Presentations | 4th–5th June 2026 |
