-- Migration 003: add Sepolia transaction hash to messages for blockchain verification
ALTER TABLE messages ADD COLUMN IF NOT EXISTS tx_hash TEXT;
