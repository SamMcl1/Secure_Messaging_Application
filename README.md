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

### Python backend
```bash
cd server
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python run.py
```

### C++ client
```bash
cd client/cpp
mkdir build && cd build
cmake .. && make
./secure_client
```

### Database
```bash
sqlite3 server/database/hangover.db < server/database/schema.sql
```

## Key Dates

| Milestone | Date |
|---|---|
| Status report 1 | Friday 23rd May 2026, 5:00 PM |
| Status report 2 | Friday 30th May 2026, 5:00 PM |
| **Submission** | **Wednesday 3rd June 2026, 5:00 PM** |
| Presentations | 4th–5th June 2026 |
