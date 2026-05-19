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
    nonce        TEXT NOT NULL,
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

-- Server-side token denylist for logout / token revocation
-- Entries whose expires_at < NOW() can be purged safely (the token is expired anyway)
CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti         TEXT PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    revoked_at  TIMESTAMPTZ DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL
);

ALTER TABLE revoked_tokens ENABLE ROW LEVEL SECURITY;

-- Stores on-chain records for tamper-evident verification
CREATE TABLE IF NOT EXISTS blockchain_records (
    id           BIGSERIAL PRIMARY KEY,
    message_id   BIGINT REFERENCES messages(id) ON DELETE SET NULL,
    tx_hash      TEXT NOT NULL,
    digest_hash  TEXT NOT NULL,
    recorded_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Enable Row Level Security (RLS) on all tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE message_access ENABLE ROW LEVEL SECURITY;
ALTER TABLE blockchain_records ENABLE ROW LEVEL SECURITY;

-- Explicitly deny all direct Supabase REST/realtime access for anon and authenticated roles.
-- Our server connects via service_role (bypasses RLS); access control is enforced in application code.
-- AS RESTRICTIVE means this policy overrides any permissive policy that might be added in future.
CREATE POLICY "deny_direct_access" ON users
    AS RESTRICTIVE FOR ALL TO anon, authenticated USING (false);

CREATE POLICY "deny_direct_access" ON messages
    AS RESTRICTIVE FOR ALL TO anon, authenticated USING (false);

CREATE POLICY "deny_direct_access" ON message_access
    AS RESTRICTIVE FOR ALL TO anon, authenticated USING (false);

CREATE POLICY "deny_direct_access" ON revoked_tokens
    AS RESTRICTIVE FOR ALL TO anon, authenticated USING (false);

CREATE POLICY "deny_direct_access" ON blockchain_records
    AS RESTRICTIVE FOR ALL TO anon, authenticated USING (false);
