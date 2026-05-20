'use strict';

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64ToBytes(b64) {
    const std = b64.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(std);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

function bytesToB64(bytes) {
    let bin = '';
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin);
}

function concatBytes(...arrays) {
    const total = arrays.reduce((s, a) => s + a.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arrays) { out.set(a, off); off += a.length; }
    return out;
}

// HKDF-SHA256 wrapper around the Web Crypto API
async function hkdfDerive(ikm, length, info, salt = null) {
    const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: salt ?? new Uint8Array(0), info },
        key,
        length * 8,
    );
    return new Uint8Array(bits);
}

// Encrypt a message for a recipient using two X25519 DH operations.
// dh1 uses a fresh ephemeral key (gives forward secrecy per-message).
// dh2 uses the sender's static key (proves who sent it).
// Both outputs are combined and fed into HKDF to produce the AES key and nonce.
// Must match server/app/crypto.py hpke_seal exactly — same info strings, same order.
async function hpkeSeal(senderSkKey, senderPkBytes, recipientPkBytes, plaintext, aad = new Uint8Array(0)) {
    const eph = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const ephPubBytes = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey));

    const recipientPkKey = await crypto.subtle.importKey(
        'raw', recipientPkBytes, { name: 'X25519' }, false, [],
    );

    const dh1 = new Uint8Array(await crypto.subtle.deriveBits(
        { name: 'X25519', public: recipientPkKey }, eph.privateKey, 256,
    ));
    const dh2 = new Uint8Array(await crypto.subtle.deriveBits(
        { name: 'X25519', public: recipientPkKey }, senderSkKey, 256,
    ));

    const ikm = concatBytes(dh1, dh2);
    const kemContext = concatBytes(ephPubBytes, senderPkBytes, recipientPkBytes);

    const key   = await hkdfDerive(ikm, 32, concatBytes(enc.encode('SecureMsg-v1-key'),   kemContext));
    const nonce = await hkdfDerive(ikm, 12, concatBytes(enc.encode('SecureMsg-v1-nonce'), kemContext));

    const aesKey = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
    const ctBuf  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, aesKey, plaintext);

    return {
        ephPub:     bytesToB64(ephPubBytes),
        ciphertext: bytesToB64(new Uint8Array(ctBuf)),
    };
}

// Decrypt a message. Reverses hpkeSeal — recipient runs the same two DHs
// (swapping their private key in place of the sender's) to recover the same key/nonce.
async function hpkeOpen(recipientSkKey, recipientPkBytes, senderPkBytes, ephPubB64, ciphertextB64, aad = new Uint8Array(0)) {
    const ephPubBytes = b64ToBytes(ephPubB64);
    const ciphertext  = b64ToBytes(ciphertextB64);

    const ephPubKey   = await crypto.subtle.importKey('raw', ephPubBytes, { name: 'X25519' }, false, []);
    const senderPkKey = await crypto.subtle.importKey('raw', senderPkBytes, { name: 'X25519' }, false, []);

    const dh1 = new Uint8Array(await crypto.subtle.deriveBits(
        { name: 'X25519', public: ephPubKey }, recipientSkKey, 256,
    ));
    const dh2 = new Uint8Array(await crypto.subtle.deriveBits(
        { name: 'X25519', public: senderPkKey }, recipientSkKey, 256,
    ));

    const ikm = concatBytes(dh1, dh2);
    const kemContext = concatBytes(ephPubBytes, senderPkBytes, recipientPkBytes);

    const key   = await hkdfDerive(ikm, 32, concatBytes(enc.encode('SecureMsg-v1-key'),   kemContext));
    const nonce = await hkdfDerive(ikm, 12, concatBytes(enc.encode('SecureMsg-v1-nonce'), kemContext));

    const aesKey = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt']);
    const ptBuf  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, aesKey, ciphertext);

    return dec.decode(ptBuf);
}

// Decrypt the private key envelope stored in the database.
// The server encrypted it with Argon2id(password) → HKDF → AES-256-GCM at registration.
// We use the same parameters here so the two sides produce the same key.
async function decryptPrivateKey(envelopeB64, password) {
    const envelope = JSON.parse(dec.decode(b64ToBytes(envelopeB64)));
    const salt  = b64ToBytes(envelope.salt);
    const nonce = b64ToBytes(envelope.nonce);
    const ct    = b64ToBytes(envelope.ct);

    // Argon2id params must match server/app/crypto.py exactly
    const result = await window.argon2.hash({
        pass:        password,
        salt,
        time:        3,
        mem:         65536,
        hashLen:     32,
        parallelism: 4,
        type:        window.argon2.ArgonType.Argon2id,
    });

    const key = await hkdfDerive(result.hash, 32, enc.encode('SecureMsg-v1-key-protection'));

    const aesKey = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt']);
    const skBuf  = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: enc.encode('private-key') },
        aesKey,
        ct,
    );

    return new Uint8Array(skBuf);
}

// Hash the plaintext with keccak256 so the server can record it on-chain.
// We use js-sha3 because Web Crypto doesn't support keccak.
function keccak256Hex(bytes) {
    return '0x' + window.sha3.keccak_256(bytes);
}

// Session — kept in memory only, cleared on logout
const session = {
    userId:         null,
    username:       null,
    accessToken:    null,
    refreshToken:   null,
    publicKeyBytes: null,
    privateKey:     null,
};

function isLoggedIn() { return !!session.accessToken; }

async function storeSession(data, password) {
    const skBytes = await decryptPrivateKey(data.encrypted_private_key, password);

    session.userId         = data.user_id;
    session.username       = data.username;
    session.accessToken    = data.access_token;
    session.refreshToken   = data.refresh_token;
    session.publicKeyBytes = b64ToBytes(data.public_key);
    session.privateKey     = await crypto.subtle.importKey(
        'raw', skBytes, { name: 'X25519' }, false, ['deriveBits'],
    );
}

function clearSession() {
    for (const k of Object.keys(session)) session[k] = null;
}

// API base — leave empty when the client is served from the same host as the server.
// Set to the server URL (e.g. 'http://localhost:5000') if running separately.
const API_BASE = '';

async function apiFetch(path, options = {}) {
    const headers = { 'Content-Type': 'application/json', ...(options.headers ?? {}) };
    if (session.accessToken) headers['Authorization'] = `Bearer ${session.accessToken}`;

    const res  = await fetch(API_BASE + path, { ...options, headers });
    const body = await res.json().catch(() => ({}));

    if (!res.ok) {
        throw Object.assign(new Error(body.message ?? `HTTP ${res.status}`), { status: res.status });
    }
    return body;
}

async function register(username, password) {
    const data = await apiFetch('/auth/register', {
        method: 'POST',
        body:   JSON.stringify({ username, password }),
    });
    await storeSession(data, password);
}

async function login(username, password) {
    const data = await apiFetch('/auth/login', {
        method: 'POST',
        body:   JSON.stringify({ username, password }),
    });
    await storeSession(data, password);
}

async function logout() {
    if (!isLoggedIn()) return;
    try {
        await apiFetch('/auth/logout', {
            method: 'POST',
            body:   JSON.stringify({ refresh_token: session.refreshToken }),
        });
    } finally {
        clearSession();
    }
}

async function lookupRecipient(username) {
    return apiFetch(`/auth/users/${encodeURIComponent(username)}/pubkey`);
}

async function sendMessage(recipientUsername, plaintext) {
    const recipient = await lookupRecipient(recipientUsername);
    const recipientPkBytes = b64ToBytes(recipient.public_key);
    const plaintextBytes   = enc.encode(plaintext);

    // Compute keccak256 of the plaintext before encrypting so the server can
    // record it on the blockchain. Falls back gracefully if js-sha3 isn't loaded.
    let contentHash = null;
    try { contentHash = keccak256Hex(plaintextBytes); } catch { /* blockchain optional */ }

    const { ephPub, ciphertext } = await hpkeSeal(
        session.privateKey,
        session.publicKeyBytes,
        recipientPkBytes,
        plaintextBytes,
    );

    return apiFetch('/messages/', {
        method: 'POST',
        body:   JSON.stringify({
            recipient_id: recipient.user_id,
            ciphertext,
            eph_pub:      ephPub,
            ...(contentHash ? { content_hash: contentHash } : {}),
        }),
    });
}

async function getMessages() {
    const messages = await apiFetch('/messages/');
    const results  = [];

    for (const msg of messages) {
        let plaintext;

        if (msg.sender_id === session.userId) {
            // The ephemeral key used to encrypt this message was never stored,
            // so we can't decrypt it. This is expected — it's how E2EE works.
            plaintext = '[Sent message — E2EE: plaintext not stored server-side]';
        } else {
            try {
                const senderPkBytes = b64ToBytes(msg.sender_public_key);
                plaintext = await hpkeOpen(
                    session.privateKey,
                    session.publicKeyBytes,
                    senderPkBytes,
                    msg.eph_pub,
                    msg.ciphertext,
                );
            } catch {
                plaintext = '[Decryption failed]';
            }
        }

        results.push({ ...msg, plaintext });
    }

    return results;
}

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function showAuthError(msg) {
    const el = document.getElementById('auth-error');
    el.textContent = msg;
    el.hidden = false;
    setTimeout(() => { el.hidden = true; }, 6000);
}

function renderMessages(messages) {
    const list = document.getElementById('message-list');
    list.innerHTML = '';

    if (!messages.length) {
        list.innerHTML = '<li class="empty">No messages yet.</li>';
        return;
    }

    for (const msg of messages) {
        const li   = document.createElement('li');
        const time = msg.created_at ? new Date(msg.created_at).toLocaleString() : '';
        const direction = msg.sender_id === session.userId
            ? `→ <strong>${escapeHtml(msg.recipient_username)}</strong>`
            : `← <strong>${escapeHtml(msg.sender_username)}</strong>`;

        li.innerHTML = `
            <div class="msg-meta">${direction} <time>${escapeHtml(time)}</time></div>
            <p class="msg-body">${escapeHtml(msg.plaintext)}</p>
            ${msg.tx_hash
                ? `<div class="msg-chain">
                       ⛓ On-chain:
                       <code title="${escapeHtml(msg.tx_hash)}">${escapeHtml(msg.tx_hash.slice(0, 22))}…</code>
                   </div>`
                : ''}`;
        list.appendChild(li);
    }
}

function switchToApp() {
    document.getElementById('auth-panel').hidden = true;
    document.getElementById('app-panel').hidden  = false;
    document.getElementById('logged-in-as').textContent = session.username;
}

function switchToAuth() {
    document.getElementById('auth-panel').hidden = false;
    document.getElementById('app-panel').hidden  = true;
    document.getElementById('login-view').hidden    = false;
    document.getElementById('register-view').hidden = true;
}

document.addEventListener('DOMContentLoaded', () => {

    document.getElementById('show-register').addEventListener('click', e => {
        e.preventDefault();
        document.getElementById('login-view').hidden    = true;
        document.getElementById('register-view').hidden = false;
    });

    document.getElementById('show-login').addEventListener('click', e => {
        e.preventDefault();
        document.getElementById('register-view').hidden = true;
        document.getElementById('login-view').hidden    = false;
    });

    document.getElementById('register-btn').addEventListener('click', async () => {
        const username = document.getElementById('reg-username').value.trim();
        const password = document.getElementById('reg-password').value;
        try {
            await register(username, password);
            switchToApp();
        } catch (e) { showAuthError(e.message); }
    });

    document.getElementById('login-btn').addEventListener('click', async () => {
        const username = document.getElementById('login-username').value.trim();
        const password = document.getElementById('login-password').value;
        try {
            await login(username, password);
            switchToApp();
        } catch (e) { showAuthError(e.message); }
    });

    document.getElementById('logout-btn').addEventListener('click', async () => {
        await logout();
        switchToAuth();
    });

    document.getElementById('send-btn').addEventListener('click', async () => {
        const to     = document.getElementById('send-to').value.trim();
        const body   = document.getElementById('message-body').value.trim();
        const status = document.getElementById('send-status');

        if (!to || !body) { status.textContent = 'Enter a recipient and a message.'; return; }

        status.textContent = 'Encrypting and sending…';
        try {
            const result = await sendMessage(to, body);
            document.getElementById('message-body').value = '';
            status.textContent = result.tx_hash
                ? `Sent! Blockchain tx: ${result.tx_hash.slice(0, 22)}…`
                : 'Sent!';
            setTimeout(() => { status.textContent = ''; }, 5000);
        } catch (e) {
            status.textContent = `Failed: ${e.message}`;
        }
    });

    document.getElementById('refresh-btn').addEventListener('click', async () => {
        const status = document.getElementById('inbox-status');
        status.textContent = 'Loading…';
        try {
            const messages = await getMessages();
            renderMessages(messages);
            status.textContent = '';
        } catch (e) {
            status.textContent = `Error: ${e.message}`;
        }
    });

    ['login-password', 'reg-password'].forEach(id => {
        document.getElementById(id).addEventListener('keydown', e => {
            if (e.key === 'Enter') {
                const btn = id.startsWith('login') ? 'login-btn' : 'register-btn';
                document.getElementById(btn).click();
            }
        });
    });
});
