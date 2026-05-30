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

    try {
        const skBuf = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce, additionalData: enc.encode('private-key') },
            aesKey,
            ct,
        );
        return new Uint8Array(skBuf);
    } catch {
        throw new Error('Incorrect password');
    }
}

// Generate a fresh X25519 identity keypair in the browser.
// Returns the raw 32-byte private and public keys. The private key is
// generated here and never sent to the server in the clear — only the public
// key and a password-encrypted envelope of the private key leave the client.
async function generateIdentityKeypair() {
    const kp = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const pubBytes = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));

    // Raw export of an X25519 private key isn't supported everywhere, so read
    // the scalar out of the JWK 'd' field (base64url) instead.
    const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
    let d = jwk.d.replace(/-/g, '+').replace(/_/g, '/');
    while (d.length % 4) d += '=';
    const skBytes = b64ToBytes(d);

    return { skBytes, pubBytes };
}

// Encrypt a private key under the user's password — the client-side counterpart
// of decryptPrivateKey. Produces the same base64 JSON envelope the server used
// to, so the rest of the app (storeSession → decryptPrivateKey) is unchanged.
async function encryptPrivateKey(privateKeyBytes, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));

    // Argon2id params must match decryptPrivateKey / the server exactly.
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
    const aesKey = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
    const nonce  = crypto.getRandomValues(new Uint8Array(12));

    const ctBuf = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: enc.encode('private-key') },
        aesKey,
        privateKeyBytes,
    );

    const envelope = {
        v:     1,
        salt:  bytesToB64(salt),
        nonce: bytesToB64(nonce),
        ct:    bytesToB64(new Uint8Array(ctBuf)),
    };
    return bytesToB64(enc.encode(JSON.stringify(envelope)));
}

// Hash the plaintext with keccak256 so the server can record it on-chain.
// We use js-sha3 because Web Crypto doesn't support keccak.
function keccak256Hex(bytes) {
    return '0x' + window.sha3.keccak_256(bytes);
}

// Session state — held in memory, mirrored to sessionStorage so a page reload
// doesn't log the user out. Cleared entirely on logout.
const session = {
    userId:         null,
    username:       null,
    accessToken:    null,
    refreshToken:   null,
    publicKeyBytes: null,
    privateKey:     null,
    encPrivateKey:  null,  // encrypted envelope only — raw bytes are never written to storage
};

function isLoggedIn() { return !!session.accessToken; }

async function storeSession(data, password) {
    const skBytes = await decryptPrivateKey(data.encrypted_private_key, password);

    session.userId         = data.user_id;
    session.username       = data.username;
    session.accessToken    = data.access_token;
    session.refreshToken   = data.refresh_token;
    session.publicKeyBytes = b64ToBytes(data.public_key);
    session.encPrivateKey  = data.encrypted_private_key;
    session.privateKey     = await crypto.subtle.importKey(
        'raw', skBytes, { name: 'X25519' }, false, ['deriveBits'],
    );

    // Store the encrypted envelope, not the raw decrypted key bytes.
    // Even if XSS reads sessionStorage it only sees the ciphertext,
    // which is useless without the user's password.
    sessionStorage.setItem('sm_session', JSON.stringify({
        userId:        data.user_id,
        username:      data.username,
        accessToken:   data.access_token,
        refreshToken:  data.refresh_token,
        publicKeyB64:  data.public_key,
        encPrivateKey: data.encrypted_private_key,
    }));
}

function updateSessionStorage() {
    const raw = sessionStorage.getItem('sm_session');
    if (!raw) return;
    const d = JSON.parse(raw);
    d.accessToken  = session.accessToken;
    d.refreshToken = session.refreshToken;
    sessionStorage.setItem('sm_session', JSON.stringify(d));
}

function clearSession() {
    for (const k of Object.keys(session)) session[k] = null;
    sessionStorage.removeItem('sm_session');
}

// Restore a previous session from sessionStorage (survives page reload).
// The private key is NOT restored — it's never stored as raw bytes.
// The caller is responsible for re-prompting the user for their password.
async function restoreSession() {
    const raw = sessionStorage.getItem('sm_session');
    if (!raw) return false;
    try {
        const d = JSON.parse(raw);
        if (!d.encPrivateKey || !d.accessToken) {
            sessionStorage.removeItem('sm_session');
            return false;
        }
        session.userId         = d.userId;
        session.username       = d.username;
        session.accessToken    = d.accessToken;
        session.refreshToken   = d.refreshToken;
        session.publicKeyBytes = b64ToBytes(d.publicKeyB64);
        session.encPrivateKey  = d.encPrivateKey;
        // session.privateKey stays null — requires the user's password to decrypt
        return true;
    } catch {
        sessionStorage.removeItem('sm_session');
        return false;
    }
}

// API base — leave empty when the client is served from the same host as the server.
// Set to the server URL (e.g. 'http://localhost:5000') if running separately.
const API_BASE = '';

// Try to get a new access token using the refresh token.
// Returns true on success and updates the session + sessionStorage.
async function tryRefreshToken() {
    try {
        const res = await fetch(API_BASE + '/auth/refresh', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ refresh_token: session.refreshToken }),
        });
        if (!res.ok) return false;
        const data = await res.json();
        session.accessToken  = data.access_token;
        session.refreshToken = data.refresh_token;
        updateSessionStorage();
        return true;
    } catch {
        return false;
    }
}

async function apiFetch(path, options = {}, _retry = false) {
    const headers = { 'Content-Type': 'application/json', ...(options.headers ?? {}) };
    if (session.accessToken) headers['Authorization'] = `Bearer ${session.accessToken}`;

    const res  = await fetch(API_BASE + path, { ...options, headers });
    const body = await res.json().catch(() => ({}));

    // On 401, attempt a token refresh and retry the request once.
    if (res.status === 401 && !_retry && session.refreshToken) {
        const refreshed = await tryRefreshToken();
        if (refreshed) return apiFetch(path, options, true);
        clearSession();
        switchToAuth();
        throw new Error('Session expired. Please log in again.');
    }

    if (!res.ok) {
        throw Object.assign(new Error(body.message ?? `HTTP ${res.status}`), { status: res.status });
    }
    return body;
}

async function register(username, password) {
    // Generate the identity keypair in the browser and wrap the private key
    // under the password here, so the server only ever receives the public key
    // and an opaque encrypted envelope — never the raw private key.
    const { skBytes, pubBytes } = await generateIdentityKeypair();
    const encrypted_private_key = await encryptPrivateKey(skBytes, password);

    const data = await apiFetch('/auth/register', {
        method: 'POST',
        body:   JSON.stringify({
            username,
            password,
            public_key:            bytesToB64(pubBytes),
            encrypted_private_key,
        }),
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
        const isSent = msg.sender_id === session.userId;
        let plaintext;

        if (isSent) {
            // The ephemeral key used to encrypt this message was never stored,
            // so we can't decrypt it. This is expected — it's how E2EE works.
            plaintext = null;
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
                plaintext = null;
            }
        }

        results.push({ ...msg, plaintext, isSent });
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
        list.innerHTML = '<li class="li-empty">No messages yet.</li>';
        return;
    }

    for (const msg of messages) {
        const li   = document.createElement('li');
        const time = msg.created_at ? new Date(msg.created_at).toLocaleString() : '';

        if (msg.isSent) {
            li.className = 'msg-sent';
            li.innerHTML = `
                <div class="msg-meta">
                    <span>To: <strong>${escapeHtml(msg.recipient_username)}</strong></span>
                    <time>${escapeHtml(time)}</time>
                </div>
                <p class="msg-body msg-body-sent">Encrypted — content not stored server-side</p>
                ${msg.tx_hash ? `<div class="msg-chain">On-chain: <code title="${escapeHtml(msg.tx_hash)}">${escapeHtml(msg.tx_hash.slice(0, 22))}…</code></div>` : ''}`;
        } else {
            li.className = 'msg-received';
            li.innerHTML = `
                <div class="msg-meta">
                    <span>From: <strong>${escapeHtml(msg.sender_username)}</strong></span>
                    <time>${escapeHtml(time)}</time>
                </div>
                <p class="msg-body">${msg.plaintext !== null ? escapeHtml(msg.plaintext) : '<em>Decryption failed</em>'}</p>
                ${msg.tx_hash ? `<div class="msg-chain">On-chain: <code title="${escapeHtml(msg.tx_hash)}">${escapeHtml(msg.tx_hash.slice(0, 22))}…</code></div>` : ''}`;
        }

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

document.addEventListener('DOMContentLoaded', async () => {

    // Restore session tokens from a previous page load.
    // The private key is never persisted, so the user must re-enter their
    // password to decrypt it before we can show the app.
    if (await restoreSession()) {
        document.getElementById('login-username').value = session.username;
    }

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
        const btn      = document.getElementById('register-btn');
        const username = document.getElementById('reg-username').value.trim();
        const password = document.getElementById('reg-password').value;
        btn.disabled = true;
        try {
            await register(username, password);
            switchToApp();
        } catch (e) {
            showAuthError(e.message);
        } finally {
            btn.disabled = false;
        }
    });

    document.getElementById('login-btn').addEventListener('click', async () => {
        const btn      = document.getElementById('login-btn');
        const username = document.getElementById('login-username').value.trim();
        const password = document.getElementById('login-password').value;
        btn.disabled = true;
        try {
            await login(username, password);
            switchToApp();
        } catch (e) {
            showAuthError(e.message);
        } finally {
            btn.disabled = false;
        }
    });

    document.getElementById('logout-btn').addEventListener('click', async () => {
        await logout();
        switchToAuth();
    });

    document.getElementById('send-btn').addEventListener('click', async () => {
        const btn    = document.getElementById('send-btn');
        const to     = document.getElementById('send-to').value.trim();
        const body   = document.getElementById('message-body').value.trim();
        const status = document.getElementById('send-status');

        if (!to || !body) { status.textContent = 'Enter a recipient and a message.'; return; }

        btn.disabled = true;
        status.textContent = 'Encrypting and sending…';
        try {
            const result = await sendMessage(to, body);
            document.getElementById('message-body').value = '';
            status.textContent = result.tx_hash
                ? `Sent. Recorded on-chain: ${result.tx_hash.slice(0, 18)}…`
                : 'Sent.';
            setTimeout(() => { status.textContent = ''; }, 5000);
        } catch (e) {
            status.textContent = `Failed: ${e.message}`;
        } finally {
            btn.disabled = false;
        }
    });

    document.getElementById('refresh-btn').addEventListener('click', async () => {
        const btn    = document.getElementById('refresh-btn');
        const status = document.getElementById('inbox-status');
        btn.disabled = true;
        status.textContent = 'Loading…';
        try {
            const messages = await getMessages();
            renderMessages(messages);
            status.textContent = '';
        } catch (e) {
            status.textContent = `Error: ${e.message}`;
        } finally {
            btn.disabled = false;
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
