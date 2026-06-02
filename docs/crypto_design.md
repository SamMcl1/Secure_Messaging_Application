# Cryptographic Design Document

**Group:** hangover
**Module:** CS4455 Cybersecurity — Epic Project 2026
**Component:** End-to-end encrypted messaging (Cryptography minor)
**Implementation:**
- **End-to-end encryption (live path):** `client/web/js/app.js` — the browser generates the
  X25519 keypair, seals the private key under the user's password, and performs all message
  AEAD via the Web Crypto API. The server never holds plaintext or any key that recovers it.
- **Server-side password hashing:** `server/app/password_utils.py` (Argon2id).
- **Reference implementation (not in the live path):** `server/app/crypto.py` — a
  byte-compatible Python mirror of the client scheme, kept as an executable specification and
  cross-check. No server route imports its encryption functions; only its Argon2id parameter
  constants are used (by `password_utils.py`).

---

## 1. Overview

The application provides end-to-end encrypted (E2EE) messaging. When Alice sends a
message to Bob, only Bob can decrypt it, and Bob can verify it genuinely came from
Alice. The server relays and stores **only ciphertext plus metadata** (sender/recipient
IDs, an ephemeral public key, a timestamp, and an optional blockchain transaction hash).
It never holds message plaintext or any key capable of producing it under normal
operation.

The construction is an **HPKE Mode_Auth-inspired** scheme:

* **KEM:** X25519 (two Diffie–Hellman operations — ephemeral-static and static-static)
* **KDF:** HKDF-SHA256
* **AEAD:** AES-256-GCM
* **Password hashing / key wrapping:** Argon2id → HKDF-SHA256 → AES-256-GCM
* **Tamper-evidence:** keccak256 message digests recorded on the Ethereum Sepolia testnet

All primitives come from vetted libraries: the Python [`cryptography`](https://cryptography.io)
library (OpenSSL-backed) and [`argon2-cffi`](https://argon2-cffi.readthedocs.io) on the
server, and the browser-native **Web Crypto API** plus
[`argon2-browser`](https://github.com/antelle/argon2-browser) (WASM) on the web client.
No primitive is hand-rolled. All randomness comes from a CSPRNG (`os.urandom` server-side,
`crypto.getRandomValues` / Web Crypto key generation client-side).

---

## 2. Threat Model

We consider the four attacker classes defined in the brief. "Holds" means the property is
guaranteed by the design; "Partial" means it holds only under stated conditions, named
explicitly below.

| Attacker | Confidentiality | Integrity | Authenticity |
|---|---|---|---|
| (a) Passive network attacker | **Holds** | **Holds** | **Holds** |
| (b) Active network attacker | **Holds** | **Holds** | **Holds** |
| (c) Honest-but-curious server | **Holds** | **Holds** | **Holds** (within TOFU) |
| (d) Fully compromised server | **Partial** | **Partial** | **Partial** |

**Against (a) and (b) — network attackers.** All transport is over TLS (Networking minor),
and independently every message payload is sealed with AES-256-GCM under a key only the two
endpoints can derive. A passive attacker sees only ciphertext. An active attacker who
modifies, drops, replays, or injects traffic cannot forge a valid GCM authentication tag
(§4), so any tampering causes decryption to fail. Authenticity is provided by the
static-static DH (§3) being mixed into the key: only the holder of the sender's private key
can produce a ciphertext that decrypts under the derived key.

**Against (c) — honest-but-curious server.** The server stores: Argon2id password hashes,
X25519 public keys, per-user *encrypted* private-key envelopes, and message ciphertexts with
their ephemeral public keys. None of these reveal plaintext. The server cannot recover
passwords (Argon2id is one-way), cannot open the private-key envelope (it is sealed under a
key derived from the user's password, which the server does not store), and cannot decrypt
messages (it holds no recipient private key). Logging everything it sees yields only
ciphertext and metadata.

**Against (d) — fully compromised server.** The following properties are **explicitly not
guaranteed**, and are stated honestly:

1. **Trust in delivered client code (inherent to browser E2EE).** The web client is
   JavaScript served by the server, so a fully compromised server could serve *modified*
   client code that exfiltrates the password or keys. This is an inherent property of all
   browser-delivered E2EE, not specific to this design, and applies equally to any web app.
   Native clients (the C++ client) are not exposed to this code-delivery risk. Note that the
   keypair is generated **in the client** and the server never receives or stores a raw
   private key, so a passively compromised server or a database breach yields no private
   keys — the residual is limited to *active* tampering with delivered code.
2. **TOFU first-contact MITM.** Public keys are trusted on first lookup (Trust On First
   Use, §3). A compromised server can serve an attacker-controlled public key for a
   recipient the sender has never messaged before, mounting a man-in-the-middle on that
   first conversation. Subsequent messages to an already-seen key are safe (the client can
   pin it).
3. **No anti-replay / ordering / availability.** The server can drop, reorder, or replay
   stored ciphertexts. There is no message sequence number or freshness token, so replay of
   a previously valid ciphertext is not detected at the crypto layer.
4. **No forward secrecy (see §3).** If a recipient's long-term private key is later
   exfiltrated, all past messages to that recipient become decryptable.

Because the private key is generated in the client and only its password-encrypted envelope
is ever uploaded, a server compromised *after* registration cannot read or forge a user's
messages — it never holds the raw private key, and the Argon2id password hash is one-way —
subject to the no-forward-secrecy caveat (4) and the delivered-code caveat (1).

---

## 3. Key Establishment and Sender Authentication

**Protocol.** An HPKE Mode_Auth-inspired KEM over X25519, following the two-DH pattern of
**RFC 9180 §5.1.3 (AuthEncap)** with **DHKEM(X25519, HKDF-SHA256)** (RFC 9180 §7.1.2). For
each message the sender generates a fresh ephemeral X25519 keypair and computes two DH
shared secrets:

```
dh1 = DH(ephemeral_sk, recipient_pk)   # ephemeral-static — KEM secrecy
dh2 = DH(sender_sk,    recipient_pk)   # static-static    — sender authentication
ikm = dh1 || dh2
```

The recipient reconstructs the identical `ikm` using their own private key:
`dh1' = DH(recipient_sk, ephemeral_pk)` and `dh2' = DH(recipient_sk, sender_pk)`. Because
DH is symmetric, `dh1' = dh1` and `dh2' = dh2`.

**Sender authentication.** `dh2` can only be computed by someone holding the sender's
static private key (or the recipient's). A third party cannot produce a ciphertext that
decrypts under the derived key, so the recipient is assured the message came from the named
sender. As with all HPKE Mode_Auth, this authentication is **deniable** (symmetric, not a
signature): the recipient is convinced of the origin but cannot prove it to a third party,
since they could have produced `dh2` themselves. This is acceptable for private messaging
and is an intentional property, not a flaw.

**Trust model — TOFU.** Public keys are published to the server at registration and fetched
on demand (`GET /auth/users/<username>/pubkey`). The first key a client sees for a given
peer is trusted and should be pinned (Trust On First Use). We chose TOFU over PKI because
there is no certificate authority appropriate to a self-contained student deployment, and a
web-of-trust adds UX complexity disproportionate to the project scope. The TOFU limitation
(first-contact MITM by a malicious server) is stated in §2(d) and §7.

**Forward secrecy.** Both DH operations use the recipient's **static** key, so the scheme
does **not** provide forward secrecy with respect to the recipient: disclosure of the
recipient's long-term private key retroactively decrypts all messages sent to them. The
per-message ephemeral key only protects against compromise of the *sender's* key for past
messages. Full forward secrecy would require a ratchet (e.g. Double Ratchet / RFC 9420),
which is out of scope.

---

## 4. End-to-End Authenticated Encryption

**Scheme:** AES-256-GCM (NIST SP 800-38D), a standardised AEAD. Custom constructions,
Encrypt-and-MAC, MAC-then-Encrypt, and non-AEAD modes are not used.

**Key and nonce derivation.** From the KEM `ikm` we derive both the content key and the
nonce with HKDF-SHA256, using distinct `info` strings concatenated with a binding context:

```
kem_context = ephemeral_pk || sender_pk || recipient_pk
key   = HKDF-SHA256(ikm, L=32, info = "SecureMsg-v1-key"   || kem_context)
nonce = HKDF-SHA256(ikm, L=12, info = "SecureMsg-v1-nonce" || kem_context)
```

* **Key:** 256-bit (32-byte) AES key.
* **Nonce:** 96-bit (12-byte), the size recommended by SP 800-38D §5.2.1.1 for GCM.
* **Tag:** 128-bit GCM authentication tag (library default), appended to the ciphertext.

**Nonce-reuse safety.** Each message uses a freshly generated ephemeral keypair, so `ikm`
(and therefore both the derived key *and* the derived nonce) is unique per message. A
(key, nonce) pair is never reused, which is the critical safety condition for GCM. Because
the nonce is a deterministic function of unique inputs rather than a counter, there is no
risk of a counter rolling over or resetting across server restarts or concurrent senders.

**Associated data.** The sender/recipient/ephemeral public keys are bound into the
derivation via `kem_context` (they are inputs to HKDF `info`), so a ciphertext is
cryptographically tied to its intended parties — altering any of them changes the derived
key and decryption fails. The GCM `aad` parameter is therefore left empty in the current
build; the binding is achieved through the key schedule rather than through AAD. Both are
valid; we note it for completeness.

**Domain separation.** Three independent `info` labels keep the three derivations
separate so output of one can never collide with another:
`"SecureMsg-v1-key"`, `"SecureMsg-v1-nonce"`, and `"SecureMsg-v1-key-protection"` (§5). The
`v1` tag allows future scheme versioning without ambiguity.

---

## 5. Password and Key Derivation

**Server-side password verification.** Passwords are hashed with **Argon2id** (RFC 9106)
via `argon2-cffi`, parameters: **time cost t = 3, memory cost m = 65536 KiB (64 MiB),
parallelism p = 4**, Type = ID. This is the memory-constrained recommended configuration of
**RFC 9106 §4** (the "second recommended option"), and meets the OWASP 2023 minimum. Argon2id
is chosen over bcrypt/PBKDF2 because it is **memory-hard**, raising the cost of GPU/ASIC
offline cracking after a database breach; the `id` variant combines Argon2i's side-channel
resistance with Argon2d's resistance to time–memory trade-off attacks. The brief's
requirement that "passwords must not be recoverable from a server database breach" is met:
only the Argon2id hash is stored.

**Local private-key protection at rest.** A user's X25519 private key is never stored raw.
It is sealed in an envelope under a key derived from the password, with KDF parameters
**separate from server-side verification** (a fresh 16-byte random salt per envelope, then an
HKDF expansion under a dedicated `info` label):

```
prk    = Argon2id(password, salt=random(16), t=3, m=64MiB, p=4, len=32, type=ID)
aes_key = HKDF-SHA256(prk, L=32, info="SecureMsg-v1-key-protection")
envelope = { v, salt, nonce=random(12), ct = AES-256-GCM(aes_key, nonce, private_key, aad="private-key") }
```

The envelope is base64-encoded JSON, stored in the `users.encrypted_private_key` column and
mirrored to the browser's `sessionStorage`. Because it requires the password to open, the
brief's requirement that "local private keys at rest must not be recoverable from a stolen
unlocked laptop" is met: an attacker with the stored envelope but not the password faces the
full Argon2id work factor per guess. The raw decrypted key is held only in volatile JavaScript
memory for the session and is never written to storage (`app.js` stores the envelope, not the
bytes).

**HKDF usage.** HKDF-SHA256 (RFC 5869) is used with explicit `info` (and salt where
applicable) for every derivation of a working key from a shared secret — both in message
sealing (§4) and in key wrapping above — providing cryptographic domain separation between
unrelated keys derived from the same input material.

---

## 6. Construction Walkthrough

### 6.1 Registration

```mermaid
sequenceDiagram
    participant C as Client (browser)
    participant S as Server
    participant DB as Database
    Note over C: generateIdentityKeypair() → (sk, pk)  [in browser]
    Note over C: encryptPrivateKey(sk, password) → envelope
    C->>S: POST /auth/register {username, password, public_key, envelope}  (over TLS)
    Note over S: hash_password(password) → Argon2id hash
    S->>DB: INSERT username, Argon2id hash, pk, envelope
    S-->>C: {public_key, encrypted_private_key, JWT tokens}
    Note over C: keep sk in memory; envelope mirrored to sessionStorage
```

> The private key `sk` is generated in the browser and never leaves it in plaintext. The
> server and DB only ever hold the public key, the Argon2id password hash (for login), and
> the password-sealed envelope — never the raw private key. The password is sent (over TLS)
> solely so the server can compute the login hash; it is never stored in the clear.

### 6.2 Key Publication / Lookup (TOFU)

```mermaid
sequenceDiagram
    participant A as Alice
    participant S as Server
    A->>S: GET /auth/users/bob/pubkey
    S-->>A: {public_key: Bob_pk}
    Note over A: trust on first use; pin Bob_pk for future sends
```

### 6.3 Send Message

```mermaid
sequenceDiagram
    participant A as Alice (client)
    participant S as Server
    participant CH as Sepolia chain
    Note over A: eph_sk, eph_pk = X25519.generate()
    Note over A: dh1 = DH(eph_sk, Bob_pk); dh2 = DH(Alice_sk, Bob_pk)
    Note over A: ikm = dh1||dh2; key,nonce = HKDF(ikm, ctx)
    Note over A: ct = AES-256-GCM(key, nonce, plaintext)
    Note over A: digest = keccak256(plaintext)
    A->>S: POST /messages {recipient_id, ciphertext, eph_pub, content_hash}
    S->>S: store ciphertext + eph_pub (plaintext never seen)
    S-->>CH: recordDigest(digest) [async, rate-limited]
    CH-->>S: tx_hash → stored on message row
```

### 6.4 Receive Message

```mermaid
sequenceDiagram
    participant B as Bob (client)
    participant S as Server
    B->>S: GET /messages
    S-->>B: [{ciphertext, eph_pub, sender_pk, ...}]
    Note over B: dh1 = DH(Bob_sk, eph_pub); dh2 = DH(Bob_sk, Alice_pk)
    Note over B: ikm = dh1||dh2; key,nonce = HKDF(ikm, ctx)
    Note over B: plaintext = AES-256-GCM.open(key, nonce, ciphertext)
    Note over B: InvalidTag ⇒ reject (tampered or wrong sender)
```

### 6.5 Storage at Rest

| Store | Contents | Protection |
|---|---|---|
| `users.password_hash` | Argon2id hash | One-way; memory-hard |
| `users.public_key` | X25519 public key (base64) | Public by design |
| `users.encrypted_private_key` | JSON envelope | AES-256-GCM under Argon2id(password)→HKDF |
| `messages.ciphertext` | AES-256-GCM ciphertext + tag | Only endpoints hold the key |
| `messages.eph_pub` | Ephemeral X25519 public key | Public; needed for decryption |
| `messages.tx_hash` | Sepolia transaction hash | Public; tamper-evidence pointer |
| Browser `sessionStorage` | Envelope + tokens (never raw `sk`) | Envelope needs password to open |

---

## 7. Known Limitations

1. **Trust in delivered client code.** Browser-delivered E2EE inherently trusts the server
   to serve honest client JavaScript; an *actively* malicious server could serve code that
   leaks secrets. This is universal to web E2EE and does not apply to native clients. Keys
   are generated client-side and never uploaded in the clear, so passive compromise and DB
   breaches expose no private keys. *(See §2(d).)*
2. **TOFU first-contact MITM.** A malicious server can substitute a public key on a peer's
   first lookup. Mitigated by key pinning after first contact; not by a CA.
3. **No forward secrecy w.r.t. the recipient.** Both DH operations use the recipient's
   static key; disclosure of that long-term key decrypts all past messages to them.
4. **No anti-replay or ordering guarantees.** The crypto layer does not detect dropped,
   reordered, or replayed ciphertexts; freshness must be enforced at a higher layer.
5. **Deniable (repudiable) authentication.** The recipient is assured of message origin but
   cannot prove it to a third party — an intentional HPKE Mode_Auth property, noted for
   completeness.
6. **Not RFC 9180 wire-compatible.** We follow RFC 9180's Mode_Auth KEM construction and
   security goals but omit its `LabeledExtract`/`LabeledExpand`/`suite_id` key-schedule
   framing (RFC 9180 §4.1) and exporter secrets. The security properties relied upon
   (KEM secrecy, sender authentication) are retained; interoperability with compliant HPKE
   stacks is not. This is a deliberate simplification for a self-contained deployment.

---

## 8. Primitive Justification Summary

| Primitive | Parameters | Security property relied on | Why appropriate | Reference |
|---|---|---|---|---|
| X25519 | 255-bit Montgomery curve, 32-byte keys | DH / KEM secrecy | ~128-bit security; constant-time; avoids invalid-curve and cofactor pitfalls of NIST P-curves | RFC 7748 §5 |
| HKDF-SHA256 | extract+expand, per-use `info`, 32 B / 12 B outputs | Pseudorandom key derivation + domain separation | Standard, analysed; clean separation of multiple keys from one secret | RFC 5869 §2.2–2.3 |
| AES-256-GCM | 256-bit key, 96-bit nonce, 128-bit tag | AEAD: confidentiality + integrity | NIST-standardised AEAD; HW-accelerated; 96-bit nonce is the SP 800-38D recommendation | NIST SP 800-38D §5.2.1.1 |
| Argon2id | t=3, m=64 MiB, p=4, 32 B out | Memory-hard one-way hashing | RFC 9106 recommended memory-constrained config; resists GPU/ASIC offline cracking | RFC 9106 §4 |
| HPKE Mode_Auth (KEM pattern) | DHKEM(X25519, HKDF-SHA256), AuthEncap two-DH | Authenticated key establishment | Provides recipient-verifiable sender authentication without a signature | RFC 9180 §5.1.3, §7.1.2 |
| keccak256 | 256-bit digest | Collision/2nd-preimage resistance | Ethereum-native hash; enables cheap native on-chain comparison for the verification page | Ethereum Yellow Paper; FIPS 202 (Keccak family) |

---

## 9. References

1. R. Barnes et al., *Hybrid Public Key Encryption*, **RFC 9180**, 2022. (§4.1 key schedule;
   §5.1.3 Mode_Auth / AuthEncap; §7.1.2 DHKEM(X25519, HKDF-SHA256).)
2. A. Langley, M. Hamburg, S. Turner, *Elliptic Curves for Security*, **RFC 7748**, 2016. (§5 X25519.)
3. H. Krawczyk, P. Eronen, *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)*,
   **RFC 5869**, 2010. (§2.2 Extract; §2.3 Expand.)
4. M. Dworkin, *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)
   and GMAC*, **NIST SP 800-38D**, 2007. (§5.2.1.1 IV/nonce length.)
5. A. Biryukov, D. Dinu, D. Khovratovich, S. Josefsson, *Argon2 Memory-Hard Function*,
   **RFC 9106**, 2021. (§4 recommended parameters.)
6. NIST, *SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions*, **FIPS 202**, 2015.
7. G. Wood, *Ethereum: A Secure Decentralised Generalised Transaction Ledger* (Yellow Paper) — keccak256 usage.
