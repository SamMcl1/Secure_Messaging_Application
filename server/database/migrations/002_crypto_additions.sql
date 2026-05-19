-- Migration 002 — crypto additions
-- Run this in the Supabase SQL editor to bring the live DB up to date.
-- Safe to run on the existing database that has migration 001 applied.

-- 1. Add encrypted private key storage to users
--    Nullable so existing rows are not broken; all new registrations will populate it.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS encrypted_private_key TEXT;

-- 2. Rename nonce → eph_pub on messages
--    In HPKE Mode_Auth the AES-GCM nonce is derived from the KDF context and is
--    not stored. What is stored is the sender's ephemeral X25519 public key (32 B, base64).
ALTER TABLE messages
    RENAME COLUMN nonce TO eph_pub;

-- 3. Token denylist for logout and refresh token rotation
CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti        TEXT PRIMARY KEY,
    user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    revoked_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

ALTER TABLE revoked_tokens ENABLE ROW LEVEL SECURITY;

-- 4. Restrictive RLS deny policies
--    The Flask server connects via service_role which bypasses RLS.
--    These policies block any direct REST or realtime access by anon/authenticated roles,
--    so the database is only reachable through the application layer.
--    DROP IF EXISTS makes this block safe to re-run on an existing database.
DROP POLICY IF EXISTS "deny_direct_access" ON users;
CREATE POLICY "deny_direct_access" ON users
    AS RESTRICTIVE FOR ALL TO anon, authenticated USING (false);

DROP POLICY IF EXISTS "deny_direct_access" ON messages;
CREATE POLICY "deny_direct_access" ON messages
    AS RESTRICTIVE FOR ALL TO anon, authenticated USING (false);

DROP POLICY IF EXISTS "deny_direct_access" ON message_access;
CREATE POLICY "deny_direct_access" ON message_access
    AS RESTRICTIVE FOR ALL TO anon, authenticated USING (false);

DROP POLICY IF EXISTS "deny_direct_access" ON revoked_tokens;
CREATE POLICY "deny_direct_access" ON revoked_tokens
    AS RESTRICTIVE FOR ALL TO anon, authenticated USING (false);

DROP POLICY IF EXISTS "deny_direct_access" ON blockchain_records;
CREATE POLICY "deny_direct_access" ON blockchain_records
    AS RESTRICTIVE FOR ALL TO anon, authenticated USING (false);
