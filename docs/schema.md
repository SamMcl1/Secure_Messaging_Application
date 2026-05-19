# Database Schema

**Module:** CS4455 Cybersecurity — Epic Project 2026  
**Group:** hangover  
**Database:** Supabase (PostgreSQL)  
**Schema file:** `server/database/schema.sql`

---

## Overview

Five tables. Row Level Security (RLS) is enabled on all of them with a restrictive deny-all policy — direct Supabase REST and realtime access is blocked for all roles. The Flask server connects via the `service_role` key which bypasses RLS; all access control is enforced in application code.

```
users ──< messages (sender_id, recipient_id)
users ──< message_access
users ──< revoked_tokens
messages ──< message_access
messages ──< blockchain_records
```

---

## Tables

### `users`

Stores registered users and their cryptographic identity.

| Column | Type | Notes |
|---|---|---|
| `id` | BIGSERIAL PK | Auto-incrementing user ID |
| `username` | TEXT UNIQUE NOT NULL | Login handle |
| `password_hash` | TEXT NOT NULL | Argon2id hash (time=3, mem=64MiB, p=4) |
| `public_key` | TEXT NOT NULL | User's X25519 public key, base64-encoded. Published so other users can encrypt messages to this user (TOFU model). |
| `encrypted_private_key` | TEXT | User's X25519 private key encrypted under their password (Argon2id → HKDF → AES-256-GCM envelope, base64 JSON). Server never stores the raw key. |
| `created_at` | TIMESTAMPTZ | Server timestamp at registration |

---

### `messages`

Stores end-to-end encrypted message envelopes. The server cannot read the plaintext.

| Column | Type | Notes |
|---|---|---|
| `id` | BIGSERIAL PK | Message ID |
| `sender_id` | BIGINT FK → users | Who sent it |
| `recipient_id` | BIGINT FK → users | Who it is for |
| `ciphertext` | TEXT NOT NULL | AES-256-GCM ciphertext + 16-byte auth tag, base64-encoded |
| `eph_pub` | TEXT NOT NULL | Sender's ephemeral X25519 public key (32 B, base64). Required by recipient to reconstruct the shared secret. The AES-GCM nonce is derived from the KDF context and is not stored. |
| `created_at` | TIMESTAMPTZ | Server timestamp |

**Why `eph_pub` not `nonce`:** The nonce is deterministic — derived via `HKDF(ikm, info="SecureMsg-v1-nonce" ‖ kem_context)`. What must be stored is the ephemeral public key so the recipient can mirror the DH operations. Storing a random nonce would be the wrong model for this construction.

---

### `message_access`

Tracks which users are permitted to access a given message. Supports forward and revoke operations.

| Column | Type | Notes |
|---|---|---|
| `message_id` | BIGINT FK → messages | |
| `user_id` | BIGINT FK → users | User granted access |
| `granted_at` | TIMESTAMPTZ | When access was granted |
| `revoked_at` | TIMESTAMPTZ (nullable) | NULL = active; non-null = revoked |
| PK | (message_id, user_id) | Composite |

---

### `revoked_tokens`

Server-side JWT denylist for logout and refresh token rotation. Entries with `expires_at < NOW()` can be purged safely.

| Column | Type | Notes |
|---|---|---|
| `jti` | TEXT PK | JWT ID claim — unique per token |
| `user_id` | BIGINT FK → users | Owning user |
| `revoked_at` | TIMESTAMPTZ | When revoked |
| `expires_at` | TIMESTAMPTZ NOT NULL | When the original token would have expired |

---

### `blockchain_records`

Links messages to their on-chain tamper-evident digest on Ethereum Sepolia.

| Column | Type | Notes |
|---|---|---|
| `id` | BIGSERIAL PK | |
| `message_id` | BIGINT FK → messages (nullable) | SET NULL on message delete — the chain record persists |
| `tx_hash` | TEXT NOT NULL | Sepolia transaction hash for the `recordDigest` call |
| `digest_hash` | TEXT NOT NULL | SHA-256 digest of the ciphertext recorded on-chain |
| `recorded_at` | TIMESTAMPTZ | Server timestamp |

---

## Row Level Security

RLS is enabled on all five tables. A `RESTRICTIVE ... USING (false)` deny policy is applied to every table for both `anon` and `authenticated` roles, blocking all direct Supabase REST and realtime access. The application server connects via `service_role` (which bypasses RLS) and enforces its own access control.

---

## Applying the schema

For a fresh database, run `server/database/schema.sql`:

```bash
psql $DATABASE_URL -f server/database/schema.sql
```

For an existing database that already has migration 001 applied, run only:

```bash
psql $DATABASE_URL -f server/database/migrations/002_crypto_additions.sql
```
