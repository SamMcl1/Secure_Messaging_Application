#!/usr/bin/env python3
"""
Deploy MessageDigest.sol to Ethereum Sepolia.

Extra deps (not in server requirements — install once for deployment only):
    pip install py-solc-x

Everything else (web3, python-dotenv) is already in server/requirements.txt.

Required environment variables (add to .env in the project root):
    SEPOLIA_RPC_URL        e.g. https://sepolia.infura.io/v3/<your-key>
    DEPLOYER_PRIVATE_KEY   0x-prefixed hex private key of the deployer wallet

The deployer account needs a small amount of Sepolia ETH for gas.
Get free Sepolia ETH from: https://sepoliafaucet.com/

After a successful run this script writes blockchain/abi/MessageDigest.json
with the deployed contract address and ABI. The server reads that file at
startup to connect to the contract.
"""

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]
CONTRACTS_DIR = ROOT / 'blockchain' / 'contracts'
ABI_DIR = ROOT / 'blockchain' / 'abi'
SOL_FILE = CONTRACTS_DIR / 'MessageDigest.sol'
OUT_FILE = ABI_DIR / 'MessageDigest.json'

SOLC_VERSION = '0.8.19'


def main() -> None:
    from dotenv import load_dotenv
    load_dotenv(ROOT / '.env')

    rpc_url     = os.getenv('SEPOLIA_RPC_URL')
    private_key = os.getenv('DEPLOYER_PRIVATE_KEY')

    if not rpc_url or not private_key:
        print('ERROR: Set SEPOLIA_RPC_URL and DEPLOYER_PRIVATE_KEY in .env', file=sys.stderr)
        sys.exit(1)

    # ── Compile ───────────────────────────────────────────────────────────
    try:
        from solcx import compile_source, install_solc
    except ImportError:
        print('ERROR: py-solc-x not installed. Run: pip install py-solc-x', file=sys.stderr)
        sys.exit(1)

    print(f'Installing solc {SOLC_VERSION} …')
    install_solc(SOLC_VERSION, show_progress=True)

    source = SOL_FILE.read_text()
    print(f'Compiling {SOL_FILE.name} …')
    compiled = compile_source(
        source,
        output_values=['abi', 'bin'],
        solc_version=SOLC_VERSION,
    )
    contract_id = next(iter(compiled))
    abi      = compiled[contract_id]['abi']
    bytecode = compiled[contract_id]['bin']
    print(f'Compiled OK — bytecode {len(bytecode) // 2} bytes')

    # ── Connect ───────────────────────────────────────────────────────────
    from web3 import Web3

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        print(f'ERROR: Cannot connect to {rpc_url}', file=sys.stderr)
        sys.exit(1)

    account = w3.eth.account.from_key(private_key)
    balance = w3.from_wei(w3.eth.get_balance(account.address), 'ether')
    print(f'Deploying from {account.address}')
    print(f'Balance: {balance:.6f} Sepolia ETH')

    if balance == 0:
        print('WARNING: Zero balance — transaction will fail. Get Sepolia ETH from sepoliafaucet.com')

    # ── Deploy ────────────────────────────────────────────────────────────
    Contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx = Contract.constructor().build_transaction({
        'from':     account.address,
        'nonce':    w3.eth.get_transaction_count(account.address),
        'gas':      300_000,
        'gasPrice': w3.eth.gas_price,
    })
    signed  = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    print(f'Transaction sent: 0x{tx_hash.hex()}')
    print('Waiting for confirmation …')

    receipt  = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    address  = receipt.contractAddress
    gas_used = receipt.gasUsed
    print(f'Contract deployed at: {address}  (gas used: {gas_used:,})')

    # ── Write ABI + address ───────────────────────────────────────────────
    ABI_DIR.mkdir(exist_ok=True)
    OUT_FILE.write_text(json.dumps({'address': address, 'abi': abi}, indent=2))
    print(f'ABI written to {OUT_FILE.relative_to(ROOT)}')
    print('Done. Add SEPOLIA_RPC_URL and DEPLOYER_PRIVATE_KEY to .env on the server.')


if __name__ == '__main__':
    main()
