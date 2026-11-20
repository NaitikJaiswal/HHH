import { expect } from "chai";
import { network } from "hardhat";

const { ethers } = await network.create();

describe("SecureLogAnchor", function () {
  let anchor;
  let owner;
  let submitter;
  let unauthorized;

  // Sample valid test vectors
  const checkpointId = ethers.keccak256(ethers.toUtf8Bytes("checkpoint-test-uuid-0001"));
  const merkleRoot = "0x" + "a".repeat(64);
  const startSeq = 1n;
  const endSeq = 100n;
  const eventCount = 100n;
  const timestamp = 1700000000n;

  beforeEach(async function () {
    [owner, submitter, unauthorized] = await ethers.getSigners();
    anchor = await ethers.deployContract("SecureLogAnchor");
  });

  describe("Deployment & Access Control", function () {
    it("1. Sets the deployer as owner and default authorized submitter", async function () {
      expect(await anchor.owner()).to.equal(owner.address);
      expect(await anchor.authorizedSubmitters(owner.address)).to.equal(true);
      expect(await anchor.authorizedSubmitters(unauthorized.address)).to.equal(false);
    });

    it("2. Owner can authorize and revoke submitters", async function () {
      const txAuth = await anchor.connect(owner).setSubmitter(submitter.address, true);
      const receiptAuth = await txAuth.wait();
      expect(await anchor.authorizedSubmitters(submitter.address)).to.equal(true);

      const eventsAuth = await anchor.queryFilter(anchor.filters.SubmitterUpdated());
      expect(eventsAuth.length).to.be.greaterThan(0);
      const lastAuthEvent = eventsAuth[eventsAuth.length - 1];
      expect(lastAuthEvent.args.submitter).to.equal(submitter.address);
      expect(lastAuthEvent.args.authorized).to.equal(true);

      const txRevoke = await anchor.connect(owner).setSubmitter(submitter.address, false);
      await txRevoke.wait();
      expect(await anchor.authorizedSubmitters(submitter.address)).to.equal(false);

      const eventsRevoke = await anchor.queryFilter(anchor.filters.SubmitterUpdated());
      const lastRevokeEvent = eventsRevoke[eventsRevoke.length - 1];
      expect(lastRevokeEvent.args.submitter).to.equal(submitter.address);
      expect(lastRevokeEvent.args.authorized).to.equal(false);
    });

    it("3. Non-owner cannot manage submitters", async function () {
      let reverted = false;
      try {
        await anchor.connect(unauthorized).setSubmitter(unauthorized.address, true);
      } catch (err) {
        reverted = true;
        expect(err.message).to.include("SecureLogAnchor: caller is not the owner");
      }
      expect(reverted).to.equal(true, "Expected transaction to revert");
    });

    it("4. Rejects setting zero address as submitter", async function () {
      let reverted = false;
      try {
        await anchor.connect(owner).setSubmitter(ethers.ZeroAddress, true);
      } catch (err) {
        reverted = true;
        expect(err.message).to.include("SecureLogAnchor: submitter cannot be zero address");
      }
      expect(reverted).to.equal(true, "Expected transaction to revert");
    });
  });

  describe("Checkpoint Anchoring", function () {
    it("5. Successfully anchors a valid checkpoint and emits CheckpointAnchored", async function () {
      const tx = await anchor.connect(owner).anchorCheckpoint(
        checkpointId,
        merkleRoot,
        startSeq,
        endSeq,
        eventCount,
        timestamp
      );

      const receipt = await tx.wait();
      const currentBlock = BigInt(receipt.blockNumber);

      expect(await anchor.commitmentExists(checkpointId)).to.equal(true);
      expect(await anchor.getTotalCheckpoints()).to.equal(1n);

      // Verify event emission
      const events = await anchor.queryFilter(anchor.filters.CheckpointAnchored());
      expect(events.length).to.equal(1);
      const ev = events[0];
      expect(ev.args.checkpointId).to.equal(checkpointId);
      expect(ev.args.merkleRoot).to.equal(merkleRoot);
      expect(ev.args.startSequence).to.equal(startSeq);
      expect(ev.args.endSequence).to.equal(endSeq);
      expect(ev.args.eventCount).to.equal(eventCount);
      expect(ev.args.submitter).to.equal(owner.address);
      expect(ev.args.blockNumber).to.equal(currentBlock);
      expect(ev.args.timestamp).to.equal(timestamp);
    });

    it("6. Authorized submitter can anchor checkpoint", async function () {
      await (await anchor.connect(owner).setSubmitter(submitter.address, true)).wait();

      const tx = await anchor.connect(submitter).anchorCheckpoint(
        checkpointId,
        merkleRoot,
        startSeq,
        endSeq,
        eventCount,
        timestamp
      );
      await tx.wait();

      const commitment = await anchor.getCommitment(checkpointId);
      expect(commitment.submitter).to.equal(submitter.address);
    });

    it("7. Unauthorized account cannot anchor checkpoint", async function () {
      let reverted = false;
      try {
        await anchor.connect(unauthorized).anchorCheckpoint(
          checkpointId,
          merkleRoot,
          startSeq,
          endSeq,
          eventCount,
          timestamp
        );
      } catch (err) {
        reverted = true;
        expect(err.message).to.include("SecureLogAnchor: caller is not an authorized submitter");
      }
      expect(reverted).to.equal(true, "Expected unauthorized caller to revert");
    });
  });

  describe("Retrieval and Verification", function () {
    beforeEach(async function () {
      await (await anchor.connect(owner).anchorCheckpoint(
        checkpointId,
        merkleRoot,
        startSeq,
        endSeq,
        eventCount,
        timestamp
      )).wait();
    });

    it("8. Successfully retrieves an anchored checkpoint with all correct fields", async function () {
      const commitment = await anchor.getCommitment(checkpointId);

      expect(commitment.merkleRoot).to.equal(merkleRoot);
      expect(commitment.startSequence).to.equal(startSeq);
      expect(commitment.endSequence).to.equal(endSeq);
      expect(commitment.eventCount).to.equal(eventCount);
      expect(commitment.timestamp).to.equal(timestamp);
      expect(commitment.submitter).to.equal(owner.address);
      expect(commitment.exists).to.equal(true);
      expect(commitment.blockNumber > 0n).to.equal(true);
    });

    it("9. Reverts when retrieving non-existent checkpoint", async function () {
      const nonExistentId = ethers.keccak256(ethers.toUtf8Bytes("does-not-exist"));
      let reverted = false;
      try {
        await anchor.getCommitment(nonExistentId);
      } catch (err) {
        reverted = true;
        expect(err.message).to.include("SecureLogAnchor: commitment does not exist");
      }
      expect(reverted).to.equal(true, "Expected getCommitment for non-existent ID to revert");
    });

    it("10. verifyCommitment returns true for matching root, false for mismatched or missing", async function () {
      expect(await anchor.verifyCommitment(checkpointId, merkleRoot)).to.equal(true);

      const wrongRoot = "0x" + "b".repeat(64);
      expect(await anchor.verifyCommitment(checkpointId, wrongRoot)).to.equal(false);

      const nonExistentId = ethers.keccak256(ethers.toUtf8Bytes("random-id"));
      expect(await anchor.verifyCommitment(nonExistentId, merkleRoot)).to.equal(false);
    });

    it("11. Supports checkpoint ID pagination", async function () {
      const id2 = ethers.keccak256(ethers.toUtf8Bytes("checkpoint-2"));
      await (await anchor.connect(owner).anchorCheckpoint(
        id2,
        merkleRoot,
        101n,
        200n,
        100,
        timestamp + 10n
      )).wait();

      expect(await anchor.getTotalCheckpoints()).to.equal(2n);

      const page1 = await anchor.getCheckpointIds(0, 1);
      expect(page1.length).to.equal(1);
      expect(page1[0]).to.equal(checkpointId);

      const page2 = await anchor.getCheckpointIds(1, 1);
      expect(page2.length).to.equal(1);
      expect(page2[0]).to.equal(id2);

      const all = await anchor.getCheckpointIds(0, 10);
      expect(all.length).to.equal(2);
      expect(all[0]).to.equal(checkpointId);
      expect(all[1]).to.equal(id2);
    });
  });

  describe("Validation & Rejection Rules", function () {
    it("12. Rejects duplicate checkpoint IDs and prevents overwrite", async function () {
      await (await anchor.connect(owner).anchorCheckpoint(
        checkpointId,
        merkleRoot,
        startSeq,
        endSeq,
        eventCount,
        timestamp
      )).wait();

      const alteredRoot = "0x" + "f".repeat(64);
      let reverted = false;
      try {
        await anchor.connect(owner).anchorCheckpoint(
          checkpointId,
          alteredRoot,
          startSeq,
          endSeq,
          eventCount,
          timestamp + 5n
        );
      } catch (err) {
        reverted = true;
        expect(err.message).to.include("SecureLogAnchor: checkpoint already anchored");
      }
      expect(reverted).to.equal(true, "Expected duplicate anchor to revert");

      // Verify the original commitment was NOT overwritten
      const original = await anchor.getCommitment(checkpointId);
      expect(original.merkleRoot).to.equal(merkleRoot);
    });

    it("13. Rejects zero checkpointId", async function () {
      let reverted = false;
      try {
        await anchor.connect(owner).anchorCheckpoint(
          ethers.ZeroHash,
          merkleRoot,
          startSeq,
          endSeq,
          eventCount,
          timestamp
        );
      } catch (err) {
        reverted = true;
        expect(err.message).to.include("SecureLogAnchor: checkpointId cannot be zero");
      }
      expect(reverted).to.equal(true);
    });

    it("14. Rejects zero Merkle root", async function () {
      let reverted = false;
      try {
        await anchor.connect(owner).anchorCheckpoint(
          checkpointId,
          ethers.ZeroHash,
          startSeq,
          endSeq,
          eventCount,
          timestamp
        );
      } catch (err) {
        reverted = true;
        expect(err.message).to.include("SecureLogAnchor: merkleRoot cannot be zero");
      }
      expect(reverted).to.equal(true);
    });

    it("15. Rejects invalid sequence range (startSequence = 0)", async function () {
      let reverted = false;
      try {
        await anchor.connect(owner).anchorCheckpoint(
          checkpointId,
          merkleRoot,
          0n,
          10n,
          11,
          timestamp
        );
      } catch (err) {
        reverted = true;
        expect(err.message).to.include("SecureLogAnchor: startSequence must be greater than zero");
      }
      expect(reverted).to.equal(true);
    });

    it("16. Rejects invalid sequence range (endSequence < startSequence)", async function () {
      let reverted = false;
      try {
        await anchor.connect(owner).anchorCheckpoint(
          checkpointId,
          merkleRoot,
          50n,
          49n,
          0,
          timestamp
        );
      } catch (err) {
        reverted = true;
        expect(err.message).to.include("SecureLogAnchor: endSequence must be >= startSequence");
      }
      expect(reverted).to.equal(true);
    });

    it("17. Rejects inconsistent event count", async function () {
      // Range [1, 100] requires eventCount = 100, provide 99
      let reverted1 = false;
      try {
        await anchor.connect(owner).anchorCheckpoint(
          checkpointId,
          merkleRoot,
          1n,
          100n,
          99,
          timestamp
        );
      } catch (err) {
        reverted1 = true;
        expect(err.message).to.include("SecureLogAnchor: inconsistent eventCount with sequence range");
      }
      expect(reverted1).to.equal(true);

      // Provide 101
      let reverted2 = false;
      try {
        await anchor.connect(owner).anchorCheckpoint(
          checkpointId,
          merkleRoot,
          1n,
          100n,
          101,
          timestamp
        );
      } catch (err) {
        reverted2 = true;
        expect(err.message).to.include("SecureLogAnchor: inconsistent eventCount with sequence range");
      }
      expect(reverted2).to.equal(true);
    });

    it("18. Rejects zero timestamp", async function () {
      let reverted = false;
      try {
        await anchor.connect(owner).anchorCheckpoint(
          checkpointId,
          merkleRoot,
          startSeq,
          endSeq,
          eventCount,
          0n
        );
      } catch (err) {
        reverted = true;
        expect(err.message).to.include("SecureLogAnchor: timestamp must be greater than zero");
      }
      expect(reverted).to.equal(true);
    });

    it("19. Rejects sequence range exceeding uint32 capacity without truncation", async function () {
      // Range is 4,294,967,297 events. If cast to uint32, it would truncate to 1.
      const hugeEndSeq = (1n << 32n) + 1n; // 4294967297n
      const truncatedCount = 1;
      let reverted = false;
      try {
        await anchor.connect(owner).anchorCheckpoint(
          checkpointId,
          merkleRoot,
          1n,
          hugeEndSeq,
          truncatedCount,
          timestamp
        );
      } catch (err) {
        reverted = true;
        expect(err.message).to.include("SecureLogAnchor: inconsistent eventCount with sequence range");
      }
      expect(reverted).to.equal(true, "Expected large range with truncated uint32 eventCount to revert");
    });

    it("20. Successfully anchors single-event checkpoint (startSequence == endSequence)", async function () {
      const singleEventId = ethers.keccak256(ethers.toUtf8Bytes("single-event-checkpoint"));
      await (await anchor.connect(owner).anchorCheckpoint(
        singleEventId,
        merkleRoot,
        42n,
        42n,
        1,
        timestamp
      )).wait();

      const commitment = await anchor.getCommitment(singleEventId);
      expect(commitment.startSequence).to.equal(42n);
      expect(commitment.endSequence).to.equal(42n);
      expect(commitment.eventCount).to.equal(1n);
      expect(commitment.exists).to.equal(true);
    });

    it("21. Revoked submitter cannot anchor checkpoints", async function () {
      // First authorize submitter
      await (await anchor.connect(owner).setSubmitter(submitter.address, true)).wait();
      expect(await anchor.authorizedSubmitters(submitter.address)).to.equal(true);

      // Now revoke submitter
      await (await anchor.connect(owner).setSubmitter(submitter.address, false)).wait();
      expect(await anchor.authorizedSubmitters(submitter.address)).to.equal(false);

      // Attempt to anchor as revoked submitter
      const revokedTestId = ethers.keccak256(ethers.toUtf8Bytes("revoked-submitter-test"));
      let reverted = false;
      try {
        await anchor.connect(submitter).anchorCheckpoint(
          revokedTestId,
          merkleRoot,
          startSeq,
          endSeq,
          eventCount,
          timestamp
        );
      } catch (err) {
        reverted = true;
        expect(err.message).to.include("SecureLogAnchor: caller is not an authorized submitter");
      }
      expect(reverted).to.equal(true, "Expected revoked submitter to be rejected");
    });

    it("22. Out-of-bounds pagination returns empty array without reverting", async function () {
      const empty1 = await anchor.getCheckpointIds(999, 10);
      expect(empty1.length).to.equal(0);

      const empty2 = await anchor.getCheckpointIds(0, 0);
      expect(empty2.length).to.equal(0);
    });
  });
});
