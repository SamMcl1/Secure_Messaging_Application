// Verification page — reads MessageDigest contract from Ethereum Sepolia
// Loads ABI + address from ../../abi/MessageDigest.json (same-origin fetch)

const SEPOLIA_RPC = 'https://rpc.sepolia.org';

const ABI = [
    'event DigestRecorded(bytes32 indexed hash, uint256 timestamp, uint256 index)',
    'function getRecord(uint256 index) view returns (bytes32 hash, uint256 timestamp)',
    'function getRecordCount() view returns (uint256)',
];

// ── DOM refs ──────────────────────────────────────────────────────────────────
const verifyBtn    = document.getElementById('verify-btn');
const msgInput     = document.getElementById('message-content');
const txInput      = document.getElementById('tx-hash');
const resultSec    = document.getElementById('result');
const resultStatus = document.getElementById('result-status');
const resultDetail = document.getElementById('result-detail');

// ── Helpers ───────────────────────────────────────────────────────────────────

function keccak256Hex(text) {
    const bytes = new TextEncoder().encode(text);
    return '0x' + window.sha3.keccak_256(bytes);
}

function setResult(pass, detail) {
    resultSec.hidden = false;
    if (pass === null) {
        resultStatus.textContent = 'Error';
        resultStatus.style.color = '#e0a853';
    } else {
        resultStatus.textContent = pass ? '✔ Verified' : '✘ Tampered / Not Found';
        resultStatus.style.color = pass ? '#4caf7d' : '#e05353';
    }
    resultDetail.textContent = detail;
}

// ── Contract address ──────────────────────────────────────────────────────────

let _contractAddress = null;

async function loadContractAddress() {
    if (_contractAddress) return _contractAddress;
    try {
        const resp = await fetch('../../abi/MessageDigest.json');
        const json = await resp.json();
        if (!json.address) throw new Error('Contract not yet deployed — address is empty');
        _contractAddress = json.address;
        return _contractAddress;
    } catch (e) {
        throw new Error(`Failed to load contract address: ${e.message}`);
    }
}

// ── Verify ────────────────────────────────────────────────────────────────────

async function verify() {
    const plaintext = msgInput.value;
    const txHash    = txInput.value.trim();

    if (!plaintext) { setResult(null, 'Please paste the message content.'); return; }
    if (!txHash)    { setResult(null, 'Please enter the transaction hash.'); return; }

    verifyBtn.disabled = true;
    resultSec.hidden   = true;

    try {
        const contentHash = keccak256Hex(plaintext);

        const address = await loadContractAddress();
        const provider = new ethers.JsonRpcProvider(SEPOLIA_RPC);
        const contract = new ethers.Contract(address, ABI, provider);

        // Fetch the tx receipt and look for a DigestRecorded event
        const receipt = await provider.getTransactionReceipt(txHash);
        if (!receipt) {
            setResult(false, 'Transaction not found on Sepolia. Check the hash and try again.');
            return;
        }

        const iface     = new ethers.Interface(ABI);
        let   recorded  = null;
        let   timestamp = null;

        for (const log of receipt.logs) {
            try {
                const parsed = iface.parseLog(log);
                if (parsed && parsed.name === 'DigestRecorded') {
                    recorded  = parsed.args.hash.toLowerCase();
                    timestamp = Number(parsed.args.timestamp);
                    break;
                }
            } catch { /* not this event */ }
        }

        if (!recorded) {
            setResult(false, 'No DigestRecorded event found in this transaction.');
            return;
        }

        const match = recorded === contentHash.toLowerCase();
        if (match) {
            const date = new Date(timestamp * 1000).toUTCString();
            setResult(true,
                `Hash match.\nOn-chain: ${recorded}\nComputed: ${contentHash.toLowerCase()}\nRecorded at: ${date} (block timestamp)`
            );
        } else {
            setResult(false,
                `Hash mismatch — message has been altered.\nOn-chain: ${recorded}\nComputed: ${contentHash.toLowerCase()}`
            );
        }
    } catch (e) {
        setResult(null, e.message);
    } finally {
        verifyBtn.disabled = false;
    }
}

verifyBtn.addEventListener('click', verify);
