// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * MessageDigest — tamper-evident integrity log for the Secure Messaging Application.
 *
 * Only the contract owner (the deploying backend account) may write records.
 * Anyone may read them for independent verification.
 */
contract MessageDigest {
    address public owner;

    struct DigestRecord {
        bytes32 hash;
        uint256 timestamp;
    }

    DigestRecord[] public records;

    event DigestRecorded(
        bytes32 indexed hash,
        uint256 timestamp,
        uint256 index
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "MessageDigest: not authorised");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /**
     * Record a keccak256 message-content hash on-chain.
     * Only callable by the owner (backend deployer account).
     */
    function recordDigest(bytes32 _hash) external onlyOwner {
        uint256 index = records.length;
        records.push(DigestRecord({hash: _hash, timestamp: block.timestamp}));
        emit DigestRecorded(_hash, block.timestamp, index);
    }

    /**
     * Read a stored record by its sequential index.
     */
    function getRecord(uint256 _index)
        external
        view
        returns (bytes32 hash, uint256 timestamp)
    {
        require(_index < records.length, "MessageDigest: index out of bounds");
        DigestRecord storage r = records[_index];
        return (r.hash, r.timestamp);
    }

    function getRecordCount() external view returns (uint256) {
        return records.length;
    }
}
