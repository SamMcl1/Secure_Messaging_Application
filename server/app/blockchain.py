"""
Web3 integration — record message-content keccak256 hashes on Ethereum Sepolia.

Reads the deployed contract address and ABI from blockchain/abi/MessageDigest.json.
Gracefully disables itself when the file is absent, the env vars are missing, or
the RPC endpoint is unreachable — so the server keeps working without blockchain.

Required env vars (same wallet used to deploy the contract):
    SEPOLIA_RPC_URL        https://sepolia.infura.io/v3/<key>
    DEPLOYER_PRIVATE_KEY   0x-prefixed hex private key
"""

import json
import logging
import os
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

_ABI_PATH = Path(__file__).parents[2] / 'blockchain' / 'abi' / 'MessageDigest.json'

# Module-level singletons — loaded lazily on first call.
_w3       = None
_account  = None
_contract = None
_disabled = False   # set True once we've confirmed config is unavailable


def _load() -> bool:
    """Initialise the web3 connection. Returns True if ready, False otherwise."""
    global _w3, _account, _contract, _disabled

    if _contract is not None:
        return True
    if _disabled:
        return False

    if not _ABI_PATH.exists():
        log.warning('blockchain: %s not found — blockchain recording disabled', _ABI_PATH)
        _disabled = True
        return False

    meta = json.loads(_ABI_PATH.read_text())
    if not meta.get('address') or not meta.get('abi'):
        log.warning('blockchain: MessageDigest.json has no address/abi — run deploy.py first')
        _disabled = True
        return False

    rpc_url     = os.getenv('SEPOLIA_RPC_URL')
    private_key = os.getenv('DEPLOYER_PRIVATE_KEY')
    if not rpc_url or not private_key:
        log.warning('blockchain: SEPOLIA_RPC_URL or DEPLOYER_PRIVATE_KEY not set')
        _disabled = True
        return False

    try:
        from web3 import Web3
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        if not w3.is_connected():
            log.warning('blockchain: cannot connect to %s', rpc_url)
            return False  # don't set _disabled so we retry on next request

        _w3       = w3
        _account  = w3.eth.account.from_key(private_key)
        _contract = w3.eth.contract(
            address=Web3.to_checksum_address(meta['address']),
            abi=meta['abi'],
        )
        log.info('blockchain: connected to MessageDigest at %s', meta['address'])
        return True
    except Exception:
        log.exception('blockchain: initialisation failed')
        return False


def record_digest(content_hash_hex: str) -> Optional[str]:
    """Record a keccak256 content hash on-chain.

    Args:
        content_hash_hex: 0x-prefixed 64-char hex string (32 bytes / bytes32).

    Returns:
        '0x' + tx_hash hex string on success, None if blockchain is unavailable.
    """
    if not _load():
        return None

    try:
        # Strip optional 0x prefix and left-pad to 32 bytes.
        raw_hex  = content_hash_hex.removeprefix('0x').zfill(64)
        hash_b32 = bytes.fromhex(raw_hex)

        nonce = _w3.eth.get_transaction_count(_account.address)
        tx    = _contract.functions.recordDigest(hash_b32).build_transaction({
            'from':     _account.address,
            'nonce':    nonce,
            'gas':      80_000,
            'gasPrice': _w3.eth.gas_price,
        })
        signed  = _account.sign_transaction(tx)
        tx_hash = _w3.eth.send_raw_transaction(signed.raw_transaction)
        hex_hash = '0x' + tx_hash.hex()
        log.info('blockchain: digest recorded tx=%s', hex_hash)
        return hex_hash

    except Exception:
        log.exception('blockchain: record_digest failed')
        return None


def get_record(index: int) -> Optional[dict]:
    """Read a stored record by its sequential index (read-only call, no gas).

    Returns:
        {'hash_hex': '0x...', 'timestamp': <unix seconds>} or None.
    """
    if not _load():
        return None

    try:
        hash_bytes, timestamp = _contract.functions.getRecord(index).call()
        return {
            'hash_hex':  '0x' + hash_bytes.hex(),
            'timestamp': timestamp,
        }
    except Exception:
        log.exception('blockchain: get_record(%d) failed', index)
        return None
