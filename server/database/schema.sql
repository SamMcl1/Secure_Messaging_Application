CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    public_key  TEXT NOT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id    INTEGER NOT NULL REFERENCES users(id),
    recipient_id INTEGER NOT NULL REFERENCES users(id),
    ciphertext   TEXT NOT NULL,
    nonce        TEXT NOT NULL,
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tracks who has access to a message (for forward/revoke operations)
CREATE TABLE IF NOT EXISTS message_access (
    message_id  INTEGER NOT NULL REFERENCES messages(id),
    user_id     INTEGER NOT NULL REFERENCES users(id),
    granted_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked_at  TIMESTAMP,
    PRIMARY KEY (message_id, user_id)
);

-- Stores on-chain records for tamper-evident verification
CREATE TABLE IF NOT EXISTS blockchain_records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id  INTEGER REFERENCES messages(id),
    tx_hash     TEXT NOT NULL,
    digest_hash TEXT NOT NULL,
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
