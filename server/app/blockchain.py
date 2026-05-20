"""
Blockchain integration — records message content hashes on Ethereum Sepolia.

Reads the contract address and ABI from blockchain/abi/MessageDigest.json.
If the file doesn't exist, the env vars aren't set, or the RPC is down,
blockchain recording is silently skipped and the server continues normally.

Required env vars:
    SEPOLIA_RPC_URL       e.g. https://sepolia.infura.io/v3/<key>
    DEPLOYER_PRIVATE_KEY  0x-prefixed private key of the account that deployed the contract
"""

import json
import logging
import os
from pathlib import Path

log = logging.getLogger(__name__)

_ABI_PATH = Path(__file__).parents[2] / 'blockchain' / 'abi' / 'MessageDigest.json'

_w3       = None
_account  = None
_contract = None

try:
    from web3 import Web3

    _meta        = json.loads(_ABI_PATH.read_text())
    _rpc_url     = os.getenv('SEPOLIA_RPC_URL')
    _private_key = os.getenv('DEPLOYER_PRIVATE_KEY')

    if _meta.get('address') and _meta.get('abi') and _rpc_url and _private_key:
        _w3       = Web3(Web3.HTTPProvider(_rpc_url))
        _account  = _w3.eth.account.from_key(_private_key)
        _contract = _w3.eth.contract(
            address=Web3.to_checksum_address(_meta['address']),
            abi=_meta['abi'],
        )
        log.info('blockchain: connected to MessageDigest at %s', _meta['address'])
    else:
        log.warning('blockchain: missing config — run deploy.py and set env vars to enable')

except Exception as e:
    log.warning('blockchain: setup failed (%s) — blockchain recording disabled', e)


def record_digest(content_hash_hex: str):
    """Send a keccak256 hash to the MessageDigest contract. Returns tx hash or None."""
    if _contract is None:
        return None

    try:
        raw   = bytes.fromhex(content_hash_hex.removeprefix('0x').zfill(64))
        nonce = _w3.eth.get_transaction_count(_account.address)
        tx    = _contract.functions.recordDigest(raw).build_transaction({
            'from':     _account.address,
            'nonce':    nonce,
            'gas':      80_000,
            'gasPrice': _w3.eth.gas_price,
        })
        signed  = _account.sign_transaction(tx)
        tx_hash = _w3.eth.send_raw_transaction(signed.raw_transaction)

        # Wait for the transaction to be mined and confirm it didn't revert.
        receipt = _w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
        if receipt.status != 1:
            log.error('blockchain: tx reverted hash=%s', '0x' + tx_hash.hex())
            return None

        return '0x' + tx_hash.hex()
    except Exception as e:
        log.error('blockchain: record_digest failed: %s', e)
        return None


def get_record(index: int):
    """Read a stored record by index (read-only, no gas). Returns dict or None."""
    if _contract is None:
        return None

    try:
        hash_bytes, timestamp = _contract.functions.getRecord(index).call()
        return {'hash_hex': '0x' + hash_bytes.hex(), 'timestamp': timestamp}
    except Exception as e:
        log.error('blockchain: get_record failed: %s', e)
        return None
