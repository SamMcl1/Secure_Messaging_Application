# C++ Secure Messaging Client

Command-line client for the Secure Messaging Application.  
Connects to the Python/Flask backend over HTTPS, sends and receives E2EE messages,
and stores them locally in memory for the session.

---

## Dependencies

| Dependency | Version | How obtained |
|---|---|---|
| g++ (or clang++) | ≥ 9 (g++) / ≥ 10 (clang++) | System package manager |
| CMake | ≥ 3.16 | System package manager |
| libcurl (with OpenSSL) | any recent | System package manager |
| nlohmann/json | v3.11.3 | Downloaded automatically by CMake |

`nlohmann/json` is header-only. CMake fetches and SHA-256-verifies `json.hpp` into
`build/_deps/` at configure time — no manual step needed.

---

## Install system dependencies

### Ubuntu / Debian (target platform)

```bash
sudo apt update
sudo apt install -y build-essential cmake libcurl4-openssl-dev
```

That single command covers g++, make, CMake, and libcurl with OpenSSL support.
Nothing else is needed on a fresh Ubuntu install before building.

### macOS (Homebrew)

```bash
brew install cmake curl
```

### Windows (vcpkg)

```powershell
vcpkg install curl:x64-windows
# Pass -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake to cmake
```

---

## Building

```bash
# From the repo root
cd client/cpp

# Create an out-of-source build directory
mkdir build && cd build

# Configure — CMake downloads nlohmann/json automatically here
cmake ..

# Compile
make
```

The binary is produced at `client/cpp/build/secure_client`.

> **Offline builds:** If the machine has no internet access, manually place
> `json.hpp` at `client/cpp/build/_deps/nlohmann/nlohmann/json.hpp` before
> running `cmake ..`. CMake will detect the file, verify its SHA-256, and skip
> the download.

---

## Running

```
./secure_client <server_url> <username> <password>
```

| Argument | Description | Example |
|---|---|---|
| `server_url` | Base URL of the backend (no trailing slash) | `https://the-hangover.theburkenator.com` |
| `username` | Registered account username | `alice` |
| `password` | Account password | `hunter2` |

### Example

```bash
./secure_client https://the-hangover.theburkenator.com alice hunter2
```

---

## Example session

```
Logged in as alice (user_id=3)

Commands: send | inbox | quit
> inbox
2 message(s)
[2026-05-30 14:22:11] #7  bob -> alice
  ciphertext: 3Kj9mPqRvXwZ8nYtLsBcDe...
[2026-05-30 14:23:45] #8  charlie -> alice
  ciphertext: xZ7nVwYtKp2mRqLsDcBaFe...

Commands: send | inbox | quit
> send
Recipient user ID: 2
Ciphertext (base64): <base64-encoded ciphertext from crypto layer>
Ephemeral public key (base64, eph_pub): <base64-encoded ephemeral public key>
Message sent.

Commands: send | inbox | quit
> quit
Goodbye.
```

Ciphertext and ephemeral public keys are produced by the cryptographic layer
before being passed to the client — the C++ component transmits them as-is
and never sees plaintext.

---

## TLS and certificate pinning

Every connection is made over HTTPS with two layers of verification:

1. **Certificate chain** (`CURLOPT_SSL_VERIFYPEER`) — the server certificate must
   chain to a trusted CA. Let's Encrypt is used on `the-hangover.theburkenator.com`.
2. **Public key pin** (`CURLOPT_PINNEDPUBLICKEY`) — the server's public key must
   match the hardcoded SHA-256 SPKI pin in `main.cpp`. This rejects connections
   even from a rogue CA-signed certificate.

If the pin does not match, libcurl returns `CURLE_SSL_PINNEDPUBKEYNOTMATCH` and
the client exits at login with:

```
Login failed — check credentials and server URL
```

`CURLOPT_SSL_VERIFYHOST` is always set to `2` — hostname verification is never
disabled.

---

## Project structure

```
client/cpp/
├── CMakeLists.txt          build configuration; handles nlohmann/json download
├── README.md               this file
├── include/
│   ├── Client.hpp          HTTPS client interface
│   ├── Conversation.hpp    groups messages into per-pair threads
│   ├── Message.hpp         single message value type
│   ├── MessageStore.hpp    in-memory message collection
│   └── User.hpp            user identity (id, username, public key)
└── src/
    ├── Client.cpp          libcurl-based HTTPS implementation
    ├── Conversation.cpp
    ├── main.cpp            entry point and interactive REPL
    ├── Message.cpp
    ├── MessageStore.cpp
    └── User.cpp
```

---

## Class overview

| Class | Responsibility |
|---|---|
| `Client` | Owns the libcurl session; performs login, send, and fetch over HTTPS. Stores JWT tokens in memory only — never written to disk. |
| `Message` | Immutable value type holding sender, recipient, ciphertext, ephemeral public key, and timestamp. |
| `MessageStore` | In-memory collection of `Message` objects owned via `std::unique_ptr`. Supports lookup by id, by sender, and sorted by timestamp. |
| `Conversation` | Groups messages into per-participant-pair threads keyed by canonical `"userA|userB"` string. Backed by `std::map<std::string, std::vector<std::unique_ptr<Message>>>`. |
| `User` | Holds a user's id, username, and public key string. |

Memory ownership: `MessageStore` and `Conversation` own their `Message` objects
via `std::unique_ptr`. Methods that return `const Message*` are non-owning
observers — callers must not delete them.
