// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MessageDigest {
    struct DigestRecord {
        bytes32 hash;
        uint256 timestamp;
    }

    DigestRecord[] public records;

    event DigestRecorded(bytes32 indexed hash, uint256 timestamp, uint256 index);

    function recordDigest(bytes32 _hash) external {
        records.push(DigestRecord({hash: _hash, timestamp: block.timestamp}));
        emit DigestRecorded(_hash, block.timestamp, records.length - 1);
    }

    function getRecord(uint256 _index) external view returns (bytes32 hash, uint256 timestamp) {
        require(_index < records.length, "Index out of bounds");
        DigestRecord storage record = records[_index];
        return (record.hash, record.timestamp);
    }

    function getRecordCount() external view returns (uint256) {
        return records.length;
    }
}
