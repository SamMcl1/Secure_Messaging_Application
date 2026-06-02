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
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Copy `server/.env.example` to `server/.env` and fill in the values (see
**Environment variables** below), then run:
```bash
python run.py
```
The crypto stack (`cryptography`, `argon2-cffi`) is installed by
`requirements.txt` — no extra setup is needed for E2EE.

### 2. Database (Supabase PostgreSQL)

The backend uses a hosted Supabase PostgreSQL instance (connection string in
`DATABASE_URL`). Apply the migrations **in order** from the Supabase SQL editor
(or any `psql` client) the first time you set up a project:

```
server/database/migrations/001_initial_schema.sql     # users, messages, message_access
server/database/migrations/002_crypto_additions.sql   # encrypted_private_key, eph_pub, revoked_tokens
server/database/migrations/003_blockchain.sql          # messages.tx_hash
```

Each migration is idempotent except the column rename in 002 — run each one
exactly once on a fresh database.

### 3. C++ client
```bash
cd client/cpp
mkdir build && cd build
cmake .. && make
./secure_client
```

### 4. Web client
Serve `client/web/` over HTTP from any static server (it must be a real origin,
not `file://`, for the Web Crypto API and CSP to work):
```bash
cd client/web
python -m http.server 3000
```

### 5. Blockchain (Ethereum Sepolia)

The contract is already deployed; its address and ABI live in
`blockchain/abi/MessageDigest.json` and are read by the server at startup. To
**redeploy** (e.g. to your own wallet):

```bash
pip install py-solc-x          # one-off, deploy-only dependency
python blockchain/scripts/deploy.py
```
This compiles `blockchain/contracts/MessageDigest.sol`, deploys it to Sepolia,
and rewrites `blockchain/abi/MessageDigest.json` with the new address + ABI.
The deployer wallet needs a small amount of Sepolia ETH (free from a faucet).

**Verification page** — serve the repo root and open
`/blockchain/verification/index.html`, for example:

```bash
python -m http.server 3001
```

Then visit `http://localhost:3001/blockchain/verification/index.html`. It runs
independently of the messaging app: paste a message's original content and its
transaction hash to confirm the on-chain keccak256 digest matches.

## Environment variables (`server/.env`)

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Flask/JWT signing secret |
| `DATABASE_URL` | Supabase PostgreSQL connection string |
| `SUPABASE_URL` / `SUPABASE_ANON_KEY` / `SUPABASE_SERVICE_KEY` | Supabase project keys |
| `ALLOWED_ORIGIN` | Exact origin the web client is served from (CORS) |
| `SEPOLIA_RPC_URL` | Ethereum Sepolia RPC endpoint (e.g. Infura) |
| `CONTRACT_ADDRESS` | Deployed `MessageDigest` contract address |
| `DEPLOYER_PRIVATE_KEY` | Wallet key the server signs digest transactions with |

`SEPOLIA_RPC_URL`, `CONTRACT_ADDRESS`, and `DEPLOYER_PRIVATE_KEY` are optional —
if unset, the server runs normally and simply skips on-chain recording.

## Key Dates

| Milestone | Date |
|---|---|
| Status report 1 | Friday 23rd May 2026, 5:00 PM |
| Status report 2 | Friday 30th May 2026, 5:00 PM |
| **Submission** | **Wednesday 3rd June 2026, 5:00 PM** |
| Presentations | 4th–5th June 2026 |
