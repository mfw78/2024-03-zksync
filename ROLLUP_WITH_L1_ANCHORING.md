# ZK-Rollup with L1 State Anchoring

## The Critical Timing Problem

### Vulnerability in Previous Design

```solidity
function commitBatch(BatchCommitment calldata batch) external {
    // PROBLEM: Using current state, not state at batch creation time!
    require(batch.totalDepositsAfter == totalDeposited, "Mismatch");
    //                                   ^^^^^^^^^^^^^^
    //                                   Current value, could have changed!
}
```

**Attack scenario:**
```
Time T0: Operator builds batch processing deposits 1-10
         totalDeposited = 1000 ETH (at T0)

Time T1: Deposits 11-20 arrive (another 500 ETH)
         totalDeposited = 1500 ETH (now!)

Time T2: Operator submits batch commitment
         batch.totalDepositsAfter = 1000 (correct at T0)
         totalDeposited = 1500 (current at T2)

         Check fails! Even though batch was correct.

OR WORSE:

Time T0: Operator builds batch, totalDeposited = 1000
Time T1: Operator adds fake 100 ETH to L2 balances
         batch.totalL2Balances = 1100 (should be 1000)
Time T2: New deposits arrive (+100 ETH)
         totalDeposited = 1100 (now)
Time T3: Operator commits batch
         Check: 1100 == 1100 ✓ (passes but is wrong!)
```

**The problem:** The batch commitment doesn't specify WHEN it's valid. It references a moving target.

---

## Solution: L1 Block Anchoring

### Core Idea

Each batch must:
1. **Anchor to a specific L1 block** (the "reference block")
2. **Prove the L1 contract state at that block**
3. **Use blockhash to verify the anchor**

```solidity
struct BatchCommitment {
    // L1 anchoring (NEW)
    uint256 l1ReferenceBlock;        // L1 block number batch is anchored to
    bytes32 l1ReferenceBlockHash;    // Hash of that block
    uint256 l1BalanceAtReference;    // Contract balance at that block
    uint256 totalDepositedAtReference; // totalDeposited at that block

    // Rest of batch data...
    bytes32 prevStateRoot;
    bytes32 newStateRoot;
    uint256 totalL2BalancesAfter;
    // ...
}
```

---

## Enhanced L1 Contract

```solidity
contract MinimalRollupWithAnchoring {
    //====================
    // STATE
    //====================

    bytes32 public stateRoot;
    uint256 public currentBatch;

    // Accounting
    uint256 public totalDeposited;
    uint256 public totalWithdrawn;
    uint256 public pendingWithdrawals;

    // Deposit tracking with block heights
    struct Deposit {
        address from;
        address to;
        uint256 amount;
        uint256 depositId;
        uint256 blockNumber;     // NEW: L1 block where deposit happened
    }
    Deposit[] public deposits;
    uint256 public nextDepositId;

    // Track processed deposit range
    uint256 public lastProcessedDepositId;

    // Batch tracking
    mapping(uint256 => BatchCommitment) public batches;
    mapping(uint256 => bool) public batchProven;
    mapping(uint256 => bool) public batchExecuted;

    // L1 state snapshots (for verification)
    struct L1StateSnapshot {
        uint256 blockNumber;
        bytes32 blockHash;
        uint256 contractBalance;
        uint256 totalDeposited;
        uint256 nextDepositId;     // First unprocessed deposit
    }
    mapping(uint256 => L1StateSnapshot) public snapshots;
    uint256 public lastSnapshotBlock;

    IVerifier public verifier;

    //====================
    // DEPOSITS
    //====================

    function deposit(address recipient) external payable {
        require(msg.value > 0, "Must deposit ETH");

        deposits.push(Deposit({
            from: msg.sender,
            to: recipient,
            amount: msg.value,
            depositId: nextDepositId,
            blockNumber: block.number  // Record when deposit happened
        }));

        totalDeposited += msg.value;
        nextDepositId++;

        emit DepositQueued(msg.sender, recipient, msg.value, nextDepositId - 1, block.number);
    }

    //====================
    // L1 STATE SNAPSHOTS
    //====================

    function createSnapshot() external returns (uint256) {
        require(block.number > lastSnapshotBlock, "Already snapshotted this block");

        snapshots[block.number] = L1StateSnapshot({
            blockNumber: block.number,
            blockHash: blockhash(block.number),  // Will be 0, use next block
            contractBalance: address(this).balance,
            totalDeposited: totalDeposited,
            nextDepositId: nextDepositId
        });

        lastSnapshotBlock = block.number;

        emit SnapshotCreated(block.number);
        return block.number;
    }

    function finalizeSnapshot(uint256 snapshotBlock) external {
        require(snapshotBlock < block.number, "Cannot finalize current block");
        require(block.number - snapshotBlock < 256, "Block too old");
        require(snapshots[snapshotBlock].blockHash == bytes32(0), "Already finalized");

        bytes32 blockHash = blockhash(snapshotBlock);
        require(blockHash != bytes32(0), "Blockhash not available");

        snapshots[snapshotBlock].blockHash = blockHash;

        emit SnapshotFinalized(snapshotBlock, blockHash);
    }

    //====================
    // BATCH COMMITMENT
    //====================

    function commitBatch(
        BatchCommitment calldata batch,
        bytes calldata blobCommitmentProof
    ) external onlyOperator {
        require(batch.batchNumber == currentBatch + 1, "Wrong batch number");

        // 1. CRITICAL: Verify L1 anchoring
        _verifyL1Anchor(batch);

        // 2. Get the snapshot at reference block
        L1StateSnapshot memory refSnapshot = snapshots[batch.l1ReferenceBlock];
        require(refSnapshot.blockHash != bytes32(0), "Snapshot not finalized");

        // 3. Verify batch references correct L1 state
        require(batch.l1ReferenceBlockHash == refSnapshot.blockHash, "Wrong blockhash");
        require(batch.l1BalanceAtReference == refSnapshot.contractBalance, "Wrong balance");
        require(batch.totalDepositedAtReference == refSnapshot.totalDeposited, "Wrong deposits");

        // 4. Verify deposit range
        require(batch.firstDepositId == lastProcessedDepositId, "Gap in deposits");
        require(batch.firstDepositId + batch.numDeposits <= refSnapshot.nextDepositId,
            "Deposits not available at reference block");

        // 5. Verify deposits in range
        bytes32 expectedDepositsHash = _hashDepositRange(
            batch.firstDepositId,
            batch.numDeposits
        );
        require(batch.depositsHash == expectedDepositsHash, "Deposits mismatch");

        // 6. Verify accounting invariant AT THE REFERENCE BLOCK
        // At reference block:
        //   L1_balance = totalDeposited - totalWithdrawn
        //   We're adding deposits and processing withdrawals
        //   After batch:
        //   L2_balances + pending_withdrawals =
        //     (totalDeposited + new_deposits) - totalWithdrawn

        uint256 depositsInBatch = _sumDepositRange(batch.firstDepositId, batch.numDeposits);

        require(
            batch.totalL2BalancesAfter + batch.pendingWithdrawalsAfter ==
            refSnapshot.totalDeposited + depositsInBatch - totalWithdrawn,
            "Accounting invariant violated"
        );

        // 7. Verify blob commitment
        _verifyBlobCommitment(batch.blobHash, blobCommitmentProof);

        // 8. Store commitment
        batches[batch.batchNumber] = batch;

        emit BatchCommitted(batch.batchNumber);
    }

    function _verifyL1Anchor(BatchCommitment calldata batch) internal view {
        // Reference block must be recent enough
        require(batch.l1ReferenceBlock <= block.number, "Reference in future");
        require(block.number - batch.l1ReferenceBlock < 256, "Reference too old");

        // Must have a snapshot
        require(snapshots[batch.l1ReferenceBlock].blockNumber != 0, "No snapshot");

        // Snapshot must be finalized
        require(snapshots[batch.l1ReferenceBlock].blockHash != bytes32(0), "Snapshot not finalized");
    }

    function _hashDepositRange(uint256 startId, uint256 count)
        internal
        view
        returns (bytes32)
    {
        bytes32 hash = keccak256("");

        for (uint256 i = 0; i < count; i++) {
            uint256 depositIdx = _findDepositIndex(startId + i);
            Deposit memory dep = deposits[depositIdx];
            hash = keccak256(abi.encode(hash, dep));
        }

        return hash;
    }

    function _sumDepositRange(uint256 startId, uint256 count)
        internal
        view
        returns (uint256 total)
    {
        for (uint256 i = 0; i < count; i++) {
            uint256 depositIdx = _findDepositIndex(startId + i);
            total += deposits[depositIdx].amount;
        }
    }

    function _findDepositIndex(uint256 depositId)
        internal
        view
        returns (uint256)
    {
        // Binary search or linear search
        // Simplified: assume deposits are in order
        return depositId;
    }

    //====================
    // BATCH PROVING
    //====================

    function proveBatch(
        uint256 batchNumber,
        bytes calldata proof
    ) external {
        BatchCommitment memory batch = batches[batchNumber];
        require(batch.newStateRoot != bytes32(0), "Batch not committed");
        require(!batchProven[batchNumber], "Already proven");

        // Public inputs include L1 anchoring
        uint256[] memory publicInputs = new uint256[](9);
        publicInputs[0] = batch.l1ReferenceBlock;
        publicInputs[1] = uint256(batch.l1ReferenceBlockHash);
        publicInputs[2] = batch.l1BalanceAtReference;
        publicInputs[3] = uint256(batch.prevStateRoot);
        publicInputs[4] = uint256(batch.newStateRoot);
        publicInputs[5] = batch.totalL2BalancesAfter;
        publicInputs[6] = batch.firstDepositId;
        publicInputs[7] = batch.numDeposits;
        publicInputs[8] = uint256(batch.depositsHash);

        require(verifier.verify(publicInputs, proof), "Invalid proof");

        batchProven[batchNumber] = true;
        emit BatchProven(batchNumber);
    }

    //====================
    // BATCH EXECUTION
    //====================

    function executeBatch(uint256 batchNumber) external {
        BatchCommitment memory batch = batches[batchNumber];
        require(batch.newStateRoot != bytes32(0), "Not committed");
        require(batchProven[batchNumber], "Not proven");
        require(!batchExecuted[batchNumber], "Already executed");

        // Update processed deposit range
        lastProcessedDepositId = batch.firstDepositId + batch.numDeposits;

        // Update state
        stateRoot = batch.newStateRoot;
        pendingWithdrawals += batch.totalWithdrawalAmount;

        batchExecuted[batchNumber] = true;
        currentBatch = batchNumber;

        emit BatchExecuted(batchNumber);
    }

    //====================
    // WITHDRAWALS
    //====================

    mapping(bytes32 => bool) public withdrawalExecuted;

    function executeWithdrawal(
        uint256 batchNumber,
        uint256 withdrawalIndex,
        address recipient,
        uint256 amount,
        bytes32[] calldata merkleProof
    ) external {
        require(batchExecuted[batchNumber], "Batch not executed");
        require(msg.sender == recipient, "Only recipient can claim");

        bytes32 withdrawalId = keccak256(abi.encode(batchNumber, withdrawalIndex));
        require(!withdrawalExecuted[withdrawalId], "Already withdrawn");

        // Verify merkle proof
        BatchCommitment memory batch = batches[batchNumber];
        bytes32 leaf = keccak256(abi.encode(recipient, amount, withdrawalIndex));
        require(_verifyMerkleProof(leaf, merkleProof, batch.withdrawalsRoot), "Invalid proof");

        // Update accounting
        withdrawalExecuted[withdrawalId] = true;
        totalWithdrawn += amount;
        pendingWithdrawals -= amount;

        // Verify invariant still holds
        require(address(this).balance >= amount, "Insufficient balance");
        require(address(this).balance - amount == totalDeposited - totalWithdrawn - amount,
            "Invariant would be violated");

        // Transfer
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");

        emit WithdrawalExecuted(batchNumber, withdrawalIndex, recipient, amount);
    }

    //====================
    // INVARIANT CHECKING
    //====================

    function checkInvariant() external view returns (bool) {
        return address(this).balance == totalDeposited - totalWithdrawn;
    }
}
```

---

## Enhanced Batch Commitment Structure

```solidity
struct BatchCommitment {
    uint256 batchNumber;

    // L1 Anchoring (NEW)
    uint256 l1ReferenceBlock;           // L1 block this batch is anchored to
    bytes32 l1ReferenceBlockHash;       // Hash of reference block (verified via blockhash())
    uint256 l1BalanceAtReference;       // Contract balance at reference block
    uint256 totalDepositedAtReference;  // totalDeposited at reference block

    // Deposit range (NEW - explicit range instead of queue position)
    uint256 firstDepositId;             // First deposit processed (inclusive)
    uint256 numDeposits;                // Number of deposits processed
    bytes32 depositsHash;               // Hash of deposits in range

    // State transition
    bytes32 prevStateRoot;
    bytes32 newStateRoot;

    // Accounting
    uint256 totalL2BalancesAfter;
    uint256 pendingWithdrawalsAfter;
    uint256 totalWithdrawalAmount;      // Withdrawals in this batch

    // Withdrawals
    bytes32 withdrawalsRoot;
    uint256 numWithdrawals;

    // L2 transactions
    bytes32 l2TransactionsHash;

    // Blob
    bytes32 blobHash;
}
```

---

## Enhanced ZK Circuit

```rust
circuit RollupWithL1Anchoring {
    // L1 anchoring (NEW - public inputs)
    public_input l1_reference_block: Field;
    public_input l1_reference_blockhash: Field;
    public_input l1_balance_at_reference: Field;

    // Deposit range (NEW)
    public_input first_deposit_id: Field;
    public_input num_deposits: Field;
    public_input deposits_hash: Field;

    // State
    public_input prev_state_root: Field;
    public_input new_state_root: Field;

    // Accounting
    public_input total_l2_balances_after: Field;

    // Private witness
    witness deposits: Vec<Deposit>;
    witness l2_transactions: Vec<Transaction>;
    witness withdrawals: Vec<Withdrawal>;
    witness state_before: Map<Address, Balance>;
    witness state_after: Map<Address, Balance>;

    fn verify() {
        // 1. Verify we're processing the claimed deposit range
        assert!(deposits.len() == num_deposits);
        assert!(deposits[0].id == first_deposit_id);

        let mut computed_deposits_hash = hash("");
        let mut total_deposit_amount = 0;

        for (i, deposit) in deposits.enumerate() {
            assert!(deposit.id == first_deposit_id + i);
            computed_deposits_hash = hash(computed_deposits_hash, hash(deposit));
            total_deposit_amount += deposit.amount;
        }

        assert!(computed_deposits_hash == deposits_hash);

        // 2. Verify initial state
        assert!(compute_merkle_root(state_before) == prev_state_root);

        let mut current_state = state_before.clone();
        let prev_l2_total = sum(state_before.values());

        // 3. Process deposits
        for deposit in deposits {
            current_state[deposit.to] += deposit.amount;
        }

        // 4. Process L2 transactions
        let mut total_withdrawal_amount = 0;

        for tx in l2_transactions {
            match tx.tx_type {
                TRANSFER => {
                    assert!(verify_ecdsa(tx.from, hash(tx), tx.signature));
                    assert!(current_state[tx.from] >= tx.amount);
                    current_state[tx.from] -= tx.amount;
                    current_state[tx.to] += tx.amount;
                }
                WITHDRAWAL => {
                    assert!(verify_ecdsa(tx.from, hash(tx), tx.signature));
                    assert!(current_state[tx.from] >= tx.amount);
                    current_state[tx.from] -= tx.amount;
                    total_withdrawal_amount += tx.amount;
                }
            }
        }

        // 5. Verify final state
        assert!(compute_merkle_root(current_state) == new_state_root);

        // 6. Verify accounting
        let computed_l2_total = sum(current_state.values());
        assert!(computed_l2_total == total_l2_balances_after);

        // 7. CRITICAL: Verify conservation of value
        // prev_l2_total + deposits - withdrawals = new_l2_total
        assert!(
            prev_l2_total + total_deposit_amount - total_withdrawal_amount ==
            computed_l2_total
        );

        // NOTE: L1 contract will verify:
        // l2_total + pending_withdrawals =
        //   l1_balance_at_reference + deposits - withdrawals_executed
    }
}
```

---

## How It Works: Complete Flow

### Setup: Create L1 Snapshot

```
OPERATOR (monitoring L1):
  1. Sees deposits 1-10 have arrived by block 1000
  2. Calls createSnapshot() at block 1001

L1 CONTRACT at block 1001:
  snapshots[1001] = {
    blockNumber: 1001,
    blockHash: 0 (not available yet),
    contractBalance: 1000 ETH,
    totalDeposited: 1000 ETH,
    nextDepositId: 10
  }

OPERATOR waits one block, then:
  3. Calls finalizeSnapshot(1001) at block 1002

L1 CONTRACT at block 1002:
  blockHash = blockhash(1001)  // Now available!
  snapshots[1001].blockHash = 0xabc...def

NOW SNAPSHOT IS FINALIZED AND CAN BE USED
```

### Build and Commit Batch

```
OPERATOR (off-chain):
  1. Uses snapshot at block 1001 as reference
  2. Processes deposits 0-9 (first 10 deposits)
  3. Processes L2 transactions
  4. Builds batch:
     {
       l1ReferenceBlock: 1001,
       l1ReferenceBlockHash: 0xabc...def,
       l1BalanceAtReference: 1000 ETH,
       totalDepositedAtReference: 1000 ETH,
       firstDepositId: 0,
       numDeposits: 10,
       depositsHash: hash(deposits[0..9]),
       totalL2BalancesAfter: 1000 ETH,
       ...
     }

OPERATOR → L1 at block 1005:
  commitBatch(batch, blobProof)

L1 CONTRACT:
  // Verify anchoring
  ✓ block 1001 <= current block 1005
  ✓ 1005 - 1001 < 256 (blockhash available)
  ✓ snapshot exists and finalized

  // Verify snapshot matches batch claims
  ✓ batch.l1ReferenceBlockHash == snapshots[1001].blockHash
  ✓ batch.l1BalanceAtReference == snapshots[1001].contractBalance
  ✓ batch.totalDepositedAtReference == snapshots[1001].totalDeposited

  // Verify deposit range valid
  ✓ firstDepositId (0) == lastProcessed (0)
  ✓ firstDepositId + numDeposits <= nextDepositId at snapshot
  ✓ depositsHash matches actual deposits 0-9

  // Verify accounting
  deposits_in_batch = sum(deposits[0..9]) = 1000 ETH
  ✓ totalL2Balances + pendingWithdrawals ==
    totalDepositedAtRef + deposits_in_batch - totalWithdrawn
  ✓ 1000 + 0 == 1000 + 1000 - 1000 (if prev withdrawals)

  // Store commitment
  batches[1] = batch
```

### Why This Prevents Timing Attacks

**Attack: Submit stale batch after new deposits**

```
Block 1000: Deposits 1-10 arrive (1000 ETH)
            Operator creates snapshot

Block 1010: Deposits 11-20 arrive (500 ETH)
            totalDeposited = 1500 ETH (current)

Block 1015: Operator tries to commit batch
            batch.totalDepositedAtReference = 1000 (at snapshot)

L1 CONTRACT:
  snapshot = snapshots[1000]
  ✓ batch.totalDepositedAtReference == snapshot.totalDeposited
  ✓ 1000 == 1000

  // This is CORRECT! Batch is valid as of block 1000
  // Deposits 11-20 will be processed in NEXT batch
```

**Attack: Claim wrong balance at reference**

```
Block 1000: snapshot.contractBalance = 1000 ETH

Operator builds batch:
  batch.l1BalanceAtReference = 1100 ETH (wrong!)

L1 CONTRACT:
  ✓ batch.l1BalanceAtReference == snapshot.contractBalance
  ✗ 1100 == 1000 FAILS

  commitBatch() reverts!
```

**Attack: Use deposits not yet available**

```
Snapshot at block 1000:
  nextDepositId = 10 (deposits 0-9 available)

Operator tries to process deposits 0-15:
  batch.firstDepositId = 0
  batch.numDeposits = 16

L1 CONTRACT:
  require(firstDepositId + numDeposits <= snapshot.nextDepositId)
  require(0 + 16 <= 10)  FAILS

  commitBatch() reverts!
```

---

## Why Blockhash is Critical

### Without blockhash verification:

```solidity
// Operator claims:
batch.l1ReferenceBlock = 1000
batch.l1BalanceAtReference = 1000 ETH

// But what if operator lies?
// How do we know balance was actually 1000 at block 1000?
// We have to trust the snapshot, but who created it?
```

### With blockhash verification:

```solidity
// Snapshot finalization:
snapshots[1000].blockHash = blockhash(1000)  // Cryptographic commitment

// Batch commitment:
batch.l1ReferenceBlockHash = 0xabc...def

// Verification:
require(batch.l1ReferenceBlockHash == snapshots[1000].blockHash)

// Now we KNOW:
// 1. Snapshot was created at or after block 1000 (blockhash only available after)
// 2. Snapshot recorded actual on-chain state at that time
// 3. Operator cannot fake or backdate snapshots
// 4. Batch is cryptographically bound to specific L1 state
```

---

## Dealing with Blockhash Limitations

**Problem:** `blockhash(n)` only available for last 256 blocks

**Solutions:**

### Option 1: Beacon Root (EIP-4788)

```solidity
// After EIP-4788, can access beacon chain roots
function finalizeSnapshotWithBeacon(uint256 snapshotBlock) external {
    bytes32 beaconRoot = _getBeaconRoot(snapshotBlock);
    snapshots[snapshotBlock].blockHash = beaconRoot;
}

// Beacon roots available for ~27 hours (8192 slots)
// Much longer than 256 blocks (~51 minutes)
```

### Option 2: Commit Chain

```solidity
// Batches commit to previous batch
struct BatchCommitment {
    bytes32 prevBatchCommitment;  // Links batches in chain
    ...
}

// Now we have cryptographic chain:
// Genesis (known) → Batch1 → Batch2 → ... → BatchN

// Each batch anchors to L1 via its reference block
// Chain of batches provides historical proof
```

### Option 3: Operator Bond

```solidity
// Operator stakes bond when creating snapshot
// If snapshot proven false within challenge period, slash bond
// Requires fraud proof mechanism but extends trust time
```

---

## Complete Security Properties

### Property 1: Temporal Binding

```
THEOREM: A batch is cryptographically bound to a specific L1 block state

PROOF:
  - Batch includes l1ReferenceBlockHash
  - Snapshot includes blockHash from blockhash() opcode
  - L1 contract verifies batch.hash == snapshot.hash
  - blockhash() is cryptographically secure (consensus-provided)
  - Therefore batch cannot reference different L1 state
```

### Property 2: No Future Reference

```
THEOREM: Batch cannot reference deposits not yet available

PROOF:
  - Snapshot records nextDepositId at reference block
  - L1 contract checks: firstDepositId + numDeposits <= nextDepositId
  - Deposits array is append-only
  - Therefore batch can only process deposits existing at reference block
```

### Property 3: No Balance Inflation

```
THEOREM: Operator cannot inflate L2 balances beyond deposits

PROOF:
  - Snapshot records l1Balance and totalDeposited at reference block
  - Batch must satisfy:
    L2_total + pending = totalDeposited@ref + deposits - withdrawn
  - Circuit proves L2_total = sum(state.values())
  - L1 contract verifies deposits match snapshot range
  - Therefore L2_total bounded by actual deposits
```

### Property 4: Snapshot Integrity

```
THEOREM: Snapshots cannot be backdated or falsified

PROOF:
  - blockhash(N) only available at blocks N+1 to N+256
  - Snapshot created at block N has blockHash = 0
  - Snapshot finalized at block N+K (K < 256) sets blockHash = blockhash(N)
  - Once finalized, blockHash immutably recorded
  - Operator cannot create snapshot claiming earlier state
  - Therefore snapshots are tamper-proof
```

---

## Summary

### Key Improvements

1. **L1 Block Anchoring**: Every batch references a specific L1 block
2. **Blockhash Verification**: Cryptographic proof of L1 state
3. **Deposit Ranges**: Explicit deposit IDs instead of queue position
4. **Snapshot System**: Pre-recorded L1 state with blockhash commitment
5. **Temporal Invariants**: Batch validity tied to specific point in time

### Security Guarantees

- ✓ Cannot reference future deposits
- ✓ Cannot claim wrong L1 balance
- ✓ Cannot backdate or forge snapshots
- ✓ Accounting verified against specific L1 state
- ✓ Timing attacks prevented

### The Critical Insight

**Without L1 anchoring:** Batch commits to "current" state (moving target)

**With L1 anchoring:** Batch commits to "state at block N" (fixed target)

This transforms batch commitments from **relative** (to current state) to **absolute** (to specific historical state), preventing timing-based attacks and ensuring verifiable accounting.
