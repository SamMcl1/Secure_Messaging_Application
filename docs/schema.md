# Database Schema

**Module:** CS4455 Cybersecurity — Epic Project 2026  
**Group:** hangover  
**Database:** Supabase (PostgreSQL)  
**Schema file:** `server/database/schema.sql`

---

## Overview

Four tables. Row Level Security (RLS) is enabled on all of them — Supabase enforces that users can only read/write their own rows via policy.

```
users ──< messages (sender_id, recipient_id)
users ──< message_access
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
| `public_key` | TEXT NOT NULL | User's X25519 public key, base64-encoded. Published so other users can encrypt messages to this user. |
| `created_at` | TIMESTAMPTZ | Server timestamp at registration |

**Design note:** The `public_key` is the only thing the server needs to know about a user's cryptographic identity. The corresponding private key is stored encrypted under the user's password (see `encrypted_private_key` — to be added in registration hook).

---

### `messages`

Stores end-to-end encrypted message envelopes. The server cannot read the plaintext.

| Column | Type | Notes |
|---|---|---|
| `id` | BIGSERIAL PK | Message ID |
| `sender_id` | BIGINT FK → users | Who sent it |
| `recipient_id` | BIGINT FK → users | Who it is for |
| `ciphertext` | TEXT NOT NULL | AES-256-GCM ciphertext + 16-byte auth tag, base64-encoded |
| `eph_pub` | TEXT NOT NULL | Sender's ephemeral X25519 public key (32 B, base64). Required by recipient to reconstruct the HPKE shared secret. The AES-GCM nonce is derived from the KDF context — it is not stored. |
| `created_at` | TIMESTAMPTZ | Server timestamp |

**Why `eph_pub` not `nonce`:** In HPKE Mode_Auth the nonce is deterministic — it is derived from `HKDF(ikm, info="SecureMsg-v1-nonce" ‖ kem_context)`. What must be stored is the ephemeral public key so the recipient can perform the mirrored DH operations. Storing a separate random nonce would be the wrong model.

---

### `message_access`

Tracks which users are permitted to access a given message. Supports forward and revoke operations.

| Column | Type | Notes |
|---|---|---|
| `message_id` | BIGINT FK → messages | |
| `user_id` | BIGINT FK → users | User granted access |
| `granted_at` | TIMESTAMPTZ | When access was granted |
| `revoked_at` | TIMESTAMPTZ (nullable) | NULL = still active; set to revoke |
| PK | (message_id, user_id) | Composite |

---

### `blockchain_records`

Links messages to their on-chain tamper-evident digest on Ethereum Sepolia.

| Column | Type | Notes |
|---|---|---|
| `id` | BIGSERIAL PK | |
| `message_id` | BIGINT FK → messages (nullable) | SET NULL on message delete — the on-chain record persists even if the message is deleted |
| `tx_hash` | TEXT NOT NULL | Sepolia transaction hash for the `recordDigest` call |
| `digest_hash` | TEXT NOT NULL | SHA-256 digest of the ciphertext that was recorded on-chain |
| `recorded_at` | TIMESTAMPTZ | Server timestamp |

---

## Row Level Security

RLS is enabled on all four tables. Policies (to be added in Supabase dashboard or via SQL):

| Table | Policy | Rule |
|---|---|---|
| `users` | SELECT own row | `id = auth.uid()` |
| `messages` | SELECT | `sender_id = auth.uid() OR recipient_id = auth.uid()` |
| `messages` | INSERT | `sender_id = auth.uid()` |
| `message_access` | SELECT | `user_id = auth.uid()` |
| `blockchain_records` | SELECT | join to messages where user is sender or recipient |

---

## Applying the schema

Run `server/database/schema.sql` once in the Supabase SQL editor or via `psql`:

```bash
psql $DATABASE_URL -f server/database/schema.sql
```
