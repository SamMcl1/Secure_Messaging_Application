-- PostgreSQL schema for Supabase
-- Run once via Supabase SQL editor or psql

CREATE TABLE IF NOT EXISTS users (
    id           BIGSERIAL PRIMARY KEY,
    username     TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    public_key   TEXT NOT NULL,
    created_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS messages (
    id           BIGSERIAL PRIMARY KEY,
    sender_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ciphertext   TEXT NOT NULL,
    -- eph_pub: sender's ephemeral X25519 public key (32 B, base64).
    -- The AES-GCM nonce is derived from the HPKE KDF context, not stored.
    eph_pub      TEXT NOT NULL,
    created_at   TIMESTAMPTZ DEFAULT NOW()
);

-- Tracks who has access to a message (for forward/revoke operations)
CREATE TABLE IF NOT EXISTS message_access (
    message_id   BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    user_id      BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    granted_at   TIMESTAMPTZ DEFAULT NOW(),
    revoked_at   TIMESTAMPTZ,
    PRIMARY KEY (message_id, user_id)
);

-- Stores on-chain records for tamper-evident verification
CREATE TABLE IF NOT EXISTS blockchain_records (
    id           BIGSERIAL PRIMARY KEY,
    message_id   BIGINT REFERENCES messages(id) ON DELETE SET NULL,
    tx_hash      TEXT NOT NULL,
    digest_hash  TEXT NOT NULL,
    recorded_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Enable Row Level Security (RLS) on all tables
-- Users can only see their own data
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE message_access ENABLE ROW LEVEL SECURITY;
ALTER TABLE blockchain_records ENABLE ROW LEVEL SECURITY;
