// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ISecureLogAnchor
 * @notice Formal interface specification for HHH SecureLog on-chain anchoring.
 * @dev Defined in docs/technical-integration-contract.md §7.3.
 */
interface ISecureLogAnchor {

    // ─── Data Structures ─────────────────────────────────────────────────────

    struct Commitment {
        bytes32  merkleRoot;
        uint64   startSequence;
        uint64   endSequence;
        uint32   eventCount;
        uint64   timestamp;         // Unix epoch seconds
        address  submitter;
        uint256  blockNumber;
        bool     exists;
    }

    // ─── Events ───────────────────────────────────────────────────────────────

    /// @notice Emitted when a checkpoint is successfully anchored on-chain.
    /// @dev    Indexed fields allow efficient off-chain log filtering.
    event CheckpointAnchored(
        bytes32 indexed checkpointId,
        bytes32 indexed merkleRoot,
        uint64          startSequence,
        uint64          endSequence,
        uint32          eventCount,
        address indexed submitter,
        uint256         blockNumber,
        uint64          timestamp
    );

    /// @notice Emitted when an authorized submitter is added or removed.
    event SubmitterUpdated(address indexed submitter, bool authorized);

    // ─── Write Functions ──────────────────────────────────────────────────────

    /// @notice Anchor a checkpoint commitment on-chain.
    /// @param  checkpointId   keccak256 of the UTF-8 checkpoint UUID string
    /// @param  merkleRoot     Merkle root over Log.currentHash leaves (§6)
    /// @param  startSequence  First sequence number in the checkpoint window
    /// @param  endSequence    Last sequence number in the checkpoint window
    /// @param  eventCount     Number of log events covered
    /// @param  timestamp      Unix epoch seconds of checkpoint creation
    function anchorCheckpoint(
        bytes32 checkpointId,
        bytes32 merkleRoot,
        uint64  startSequence,
        uint64  endSequence,
        uint32  eventCount,
        uint64  timestamp
    ) external;

    /// @notice Grant or revoke checkpoint submission rights.
    /// @dev    Only callable by contract owner.
    function setSubmitter(address submitter, bool authorized) external;

    // ─── Read Functions ───────────────────────────────────────────────────────

    /// @notice Retrieve a stored commitment. Reverts if not found.
    function getCommitment(bytes32 checkpointId)
        external view returns (Commitment memory);

    /// @notice Check whether a checkpointId has been anchored.
    function commitmentExists(bytes32 checkpointId)
        external view returns (bool);

    /// @notice Verify a merkleRoot matches the on-chain stored value.
    /// @return isMatch True if the commitment exists and roots match.
    function verifyCommitment(bytes32 checkpointId, bytes32 expectedMerkleRoot)
        external view returns (bool isMatch);

    /// @notice Total number of anchored checkpoints.
    function getTotalCheckpoints() external view returns (uint256);

    /// @notice Paginated checkpoint ID listing (for auditor enumeration).
    function getCheckpointIds(uint256 offset, uint256 limit)
        external view returns (bytes32[] memory);

    /// @notice Contract owner address.
    function owner() external view returns (address);

    /// @notice Check whether an address is an authorized submitter.
    function authorizedSubmitters(address submitter) external view returns (bool);
}

/**
 * @title SecureLogAnchor
 * @notice Concrete implementation of ISecureLogAnchor for HHH SecureLog.
 * @dev Immutably anchors cryptographic checkpoint commitments to an EVM blockchain.
 *      Enforces access control, duplicate prevention, parameter validation,
 *      and transparent auditor read operations.
 *
 * Security Invariants:
 *  - ZERO raw logs, PII, passwords, secrets, or private keys are accepted or stored on-chain.
 *  - An anchored checkpoint can NEVER be overwritten or deleted (immutability).
 *  - Only designated authorized submitters can anchor checkpoints.
 *  - The contract does NOT prove real-world authenticity; it proves that the cryptographic
 *    commitment was recorded at or before the transaction block and has not been altered.
 */
contract SecureLogAnchor is ISecureLogAnchor {

    // ─── State Variables ─────────────────────────────────────────────────────

    /// @notice Contract owner address (deployer).
    address public override owner;

    /// @notice Registry of accounts permitted to submit checkpoint commitments.
    mapping(address => bool) public override authorizedSubmitters;

    /// @notice Internal mapping of checkpointId => Commitment struct.
    mapping(bytes32 => Commitment) private _commitments;

    /// @notice Ordered list of all anchored checkpoint IDs.
    bytes32[] private _checkpointIds;

    // ─── Modifiers ───────────────────────────────────────────────────────────

    /// @dev Restricts invocation to the contract owner.
    modifier onlyOwner() {
        require(msg.sender == owner, "SecureLogAnchor: caller is not the owner");
        _;
    }

    /// @dev Restricts invocation to authorized submitter addresses.
    modifier onlyAuthorized() {
        require(
            authorizedSubmitters[msg.sender],
            "SecureLogAnchor: caller is not an authorized submitter"
        );
        _;
    }

    // ─── Constructor ─────────────────────────────────────────────────────────

    /**
     * @notice Initializes the SecureLogAnchor contract.
     * @dev Sets the deployer as owner and default authorized submitter.
     */
    constructor() {
        owner = msg.sender;
        authorizedSubmitters[msg.sender] = true;
        emit SubmitterUpdated(msg.sender, true);
    }

    // ─── Write Functions ─────────────────────────────────────────────────────

    /**
     * @notice Anchor a checkpoint commitment on-chain.
     * @param  checkpointId   keccak256 hash of the UTF-8 checkpoint UUID string (bytes32).
     * @param  merkleRoot     SHA-256 Merkle root over Log.currentHash leaves (bytes32).
     * @param  startSequence  First sequence number in the checkpoint window (uint64).
     * @param  endSequence    Last sequence number in the checkpoint window (uint64).
     * @param  eventCount     Number of log events covered (uint32).
     * @param  timestamp      Unix epoch seconds of checkpoint creation (uint64).
     */
    function anchorCheckpoint(
        bytes32 checkpointId,
        bytes32 merkleRoot,
        uint64  startSequence,
        uint64  endSequence,
        uint32  eventCount,
        uint64  timestamp
    ) external override onlyAuthorized {
        // Validation 1: checkpointId must be non-zero
        require(checkpointId != bytes32(0), "SecureLogAnchor: checkpointId cannot be zero");

        // Validation 2: duplicate checkpoint prevention (immutability)
        require(!_commitments[checkpointId].exists, "SecureLogAnchor: checkpoint already anchored");

        // Validation 3: Merkle root must be non-zero
        require(merkleRoot != bytes32(0), "SecureLogAnchor: merkleRoot cannot be zero");

        // Validation 4: sequence range validation
        require(startSequence > 0, "SecureLogAnchor: startSequence must be greater than zero");
        require(endSequence >= startSequence, "SecureLogAnchor: endSequence must be >= startSequence");

        // Validation 5: event count consistency with sequence range
        require(
            uint64(eventCount) == (endSequence - startSequence + 1),
            "SecureLogAnchor: inconsistent eventCount with sequence range"
        );

        // Validation 6: timestamp must be non-zero
        require(timestamp > 0, "SecureLogAnchor: timestamp must be greater than zero");

        // Record commitment
        _commitments[checkpointId] = Commitment({
            merkleRoot:    merkleRoot,
            startSequence: startSequence,
            endSequence:   endSequence,
            eventCount:    eventCount,
            timestamp:     timestamp,
            submitter:     msg.sender,
            blockNumber:   block.number,
            exists:        true
        });

        _checkpointIds.push(checkpointId);

        // Emit audit event
        emit CheckpointAnchored(
            checkpointId,
            merkleRoot,
            startSequence,
            endSequence,
            eventCount,
            msg.sender,
            block.number,
            timestamp
        );
    }

    /**
     * @notice Grant or revoke checkpoint submission rights.
     * @param  submitter   The address to configure.
     * @param  authorized  True to authorize, false to revoke.
     */
    function setSubmitter(address submitter, bool authorized) external override onlyOwner {
        require(submitter != address(0), "SecureLogAnchor: submitter cannot be zero address");
        authorizedSubmitters[submitter] = authorized;
        emit SubmitterUpdated(submitter, authorized);
    }

    // ─── Read Functions ───────────────────────────────────────────────────────

    /**
     * @notice Retrieve an anchored commitment. Reverts if not found.
     * @param  checkpointId The unique identifier of the checkpoint.
     * @return Commitment struct containing all anchored fields.
     */
    function getCommitment(bytes32 checkpointId)
        external
        view
        override
        returns (Commitment memory)
    {
        Commitment memory c = _commitments[checkpointId];
        require(c.exists, "SecureLogAnchor: commitment does not exist");
        return c;
    }

    /**
     * @notice Check whether a checkpointId has been anchored.
     * @param  checkpointId The unique identifier of the checkpoint.
     * @return bool True if anchored, false otherwise.
     */
    function commitmentExists(bytes32 checkpointId)
        external
        view
        override
        returns (bool)
    {
        return _commitments[checkpointId].exists;
    }

    /**
     * @notice Verify whether a checkpoint's on-chain Merkle root matches an expected value.
     * @param  checkpointId        The unique identifier of the checkpoint.
     * @param  expectedMerkleRoot  The Merkle root to compare against.
     * @return isMatch True if the commitment exists and roots match, false otherwise.
     */
    function verifyCommitment(bytes32 checkpointId, bytes32 expectedMerkleRoot)
        external
        view
        override
        returns (bool isMatch)
    {
        Commitment memory c = _commitments[checkpointId];
        if (!c.exists) {
            return false;
        }
        return c.merkleRoot == expectedMerkleRoot;
    }

    /**
     * @notice Return the total number of anchored checkpoints.
     * @return Total count.
     */
    function getTotalCheckpoints() external view override returns (uint256) {
        return _checkpointIds.length;
    }

    /**
     * @notice Retrieve a paginated list of anchored checkpoint IDs for auditor enumeration.
     * @param  offset Starting index.
     * @param  limit  Maximum number of entries to return.
     * @return Array of checkpoint IDs (bytes32).
     */
    function getCheckpointIds(uint256 offset, uint256 limit)
        external
        view
        override
        returns (bytes32[] memory)
    {
        uint256 total = _checkpointIds.length;
        if (offset >= total || limit == 0) {
            return new bytes32[](0);
        }

        uint256 count = limit;
        if (offset + count > total) {
            count = total - offset;
        }

        bytes32[] memory ids = new bytes32[](count);
        for (uint256 i = 0; i < count; i++) {
            ids[i] = _checkpointIds[offset + i];
        }

        return ids;
    }
}
