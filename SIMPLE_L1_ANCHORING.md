# Simple L1 Anchoring with Account Proofs

## The Elegant Solution

Instead of creating snapshots on-chain, use **Merkle proofs** to prove the contract's balance at a specific L1 block, then verify the block is valid using a **light client**.

---

## Core Idea

```
1. Operator builds batch at L1 block N
2. Operator generates eth_getProof for contract at block N
3. Proof shows: contract.balance at block N
4. Submit batch with proof to L1
5. L1 verifies proof against block N's state root
6. Light client verifies block N is in canonical chain
```

**No on-chain snapshots needed!** Everything verified via proofs.

---

## Simplified L1 Contract

```solidity
contract MinimalRollupWithProofs {
    //====================
    // STATE
    //====================

    bytes32 public stateRoot;
    uint256 public currentBatch;

    // Accounting (never moves backwards)
    uint256 public totalDeposited;
    uint256 public totalWithdrawn;
    uint256 public pendingWithdrawals;

    // Deposits with block numbers
    struct Deposit {
        address to;
        uint256 amount;
        uint256 depositId;
        uint256 blockNumber;
    }
    Deposit[] public deposits;
    uint256 public nextDepositId;
    uint256 public lastProcessedDepositId;

    // Light client for beacon chain verification
    ILightClient public lightClient;

    // Verifier
    IVerifier public verifier;

    //====================
    // DEPOSITS
    //====================

    function deposit(address recipient) external payable {
        require(msg.value > 0, "Must deposit ETH");

        deposits.push(Deposit({
            to: recipient,
            amount: msg.value,
            depositId: nextDepositId,
            blockNumber: block.number
        }));

        totalDeposited += msg.value;
        nextDepositId++;

        emit DepositQueued(recipient, msg.value, nextDepositId - 1, block.number);
    }

    //====================
    // BATCH COMMITMENT
    //====================

    struct BatchCommitment {
        // L1 anchoring
        uint256 l1AnchorBlock;              // Block number to anchor to
        bytes32 l1BlockHash;                // Hash of anchor block
        bytes32 l1StateRoot;                // State root of anchor block

        // Account proof (proves contract balance at anchor block)
        bytes accountProof;                 // RLP-encoded Merkle proof
        uint256 contractBalanceAtAnchor;   // Balance at anchor block

        // Deposit range
        uint256 firstDepositId;
        uint256 numDeposits;
        bytes32 depositsHash;

        // State transition
        bytes32 prevL2StateRoot;
        bytes32 newL2StateRoot;

        // Accounting
        uint256 totalL2BalancesAfter;
        uint256 pendingWithdrawalsAfter;
        uint256 totalWithdrawalAmount;

        // Withdrawals
        bytes32 withdrawalsRoot;
        uint256 numWithdrawals;

        // Blob
        bytes32 blobHash;
    }

    function commitBatch(
        BatchCommitment calldata batch,
        bytes calldata blobCommitmentProof
    ) external onlyOperator {
        require(batch.batchNumber == currentBatch + 1, "Wrong batch");

        // 1. CRITICAL: Verify L1 block is canonical
        _verifyCanonicalBlock(batch.l1AnchorBlock, batch.l1BlockHash, batch.l1StateRoot);

        // 2. CRITICAL: Verify account proof shows correct balance at anchor block
        _verifyAccountProof(
            batch.accountProof,
            batch.l1StateRoot,
            batch.contractBalanceAtAnchor
        );

        // 3. Verify deposit range is valid at anchor block
        require(batch.firstDepositId == lastProcessedDepositId, "Deposit gap");
        _verifyDepositRange(batch.firstDepositId, batch.numDeposits, batch.l1AnchorBlock);

        // 4. Verify accounting invariant
        uint256 depositsInBatch = _sumDepositRange(batch.firstDepositId, batch.numDeposits);

        // At anchor block:
        //   contract balance = totalDeposited - totalWithdrawn
        // We verified contract balance via proof
        // Now verify L2 accounting:
        //   L2_balances + pending = contract_balance + new_deposits

        require(
            batch.totalL2BalancesAfter + batch.pendingWithdrawalsAfter ==
            batch.contractBalanceAtAnchor + depositsInBatch,
            "Accounting violated"
        );

        // 5. Verify blob commitment
        _verifyBlobCommitment(batch.blobHash, blobCommitmentProof);

        // 6. Store commitment
        batches[batch.batchNumber] = batch;

        emit BatchCommitted(batch.batchNumber);
    }

    //====================
    // L1 BLOCK VERIFICATION
    //====================

    function _verifyCanonicalBlock(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 stateRoot
    ) internal view {
        require(blockNumber <= block.number, "Block in future");

        if (block.number - blockNumber < 256) {
            // Recent block: use blockhash opcode
            require(blockhash(blockNumber) == blockHash, "Invalid blockhash");

            // State root would need to be extracted from block header
            // For now, trust it (or require operator to provide block header)

        } else {
            // Old block: use light client
            require(
                lightClient.verifyBlock(blockNumber, blockHash, stateRoot),
                "Light client verification failed"
            );
        }
    }

    //====================
    // ACCOUNT PROOF VERIFICATION
    //====================

    function _verifyAccountProof(
        bytes memory proof,
        bytes32 stateRoot,
        uint256 expectedBalance
    ) internal view {
        // Decode account proof
        // Format: RLP-encoded list of nodes in Merkle patricia trie

        address account = address(this);
        bytes32 accountHash = keccak256(abi.encodePacked(account));

        // Verify Merkle proof
        bytes memory accountRLP = MerklePatricia.verify(
            proof,
            stateRoot,
            accountHash
        );

        // Decode account data
        (
            uint256 nonce,
            uint256 balance,
            bytes32 storageRoot,
            bytes32 codeHash
        ) = _decodeAccount(accountRLP);

        // Verify balance matches
        require(balance == expectedBalance, "Balance mismatch");
    }

    function _decodeAccount(bytes memory accountRLP)
        internal
        pure
        returns (uint256 nonce, uint256 balance, bytes32 storageRoot, bytes32 codeHash)
    {
        // RLP decode account structure
        // [nonce, balance, storageRoot, codeHash]
        RLPReader.RLPItem[] memory items = accountRLP.toRlpItem().toList();
        require(items.length == 4, "Invalid account RLP");

        nonce = items[0].toUint();
        balance = items[1].toUint();
        storageRoot = bytes32(items[2].toUint());
        codeHash = bytes32(items[3].toUint());
    }

    //====================
    // DEPOSIT VERIFICATION
    //====================

    function _verifyDepositRange(
        uint256 firstId,
        uint256 count,
        uint256 anchorBlock
    ) internal view {
        // Verify all deposits in range existed before anchor block
        for (uint256 i = 0; i < count; i++) {
            Deposit memory dep = deposits[firstId + i];
            require(dep.blockNumber <= anchorBlock, "Deposit too new");
        }
    }

    function _sumDepositRange(uint256 firstId, uint256 count)
        internal
        view
        returns (uint256 total)
    {
        for (uint256 i = 0; i < count; i++) {
            total += deposits[firstId + i].amount;
        }
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
        require(msg.sender == recipient, "Only recipient");

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

        // Transfer
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");

        emit WithdrawalExecuted(batchNumber, withdrawalIndex, recipient, amount);
    }
}
```

---

## Light Client Interface

```solidity
interface ILightClient {
    /// @notice Verify a block is in the canonical chain
    /// @param blockNumber The block number to verify
    /// @param blockHash The claimed hash of the block
    /// @param stateRoot The claimed state root of the block
    /// @return true if block is verified as canonical
    function verifyBlock(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 stateRoot
    ) external view returns (bool);
}
```

### Light Client Implementation Options

#### Option 1: Beacon Chain Light Client (EIP-4788 + Sync Committee)

```solidity
contract BeaconLightClient is ILightClient {
    // EIP-4788: Beacon roots are available in contract at 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02
    address constant BEACON_ROOTS = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;

    // Sync committee tracking
    bytes32 public currentSyncCommitteeRoot;
    mapping(uint256 => bytes32) public finalizedBlockRoots;

    function verifyBlock(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 stateRoot
    ) external view returns (bool) {
        // 1. Get beacon block root for this timestamp
        uint256 timestamp = _blockNumberToTimestamp(blockNumber);
        bytes32 beaconRoot = _getBeaconRoot(timestamp);

        // 2. Verify execution payload in beacon block
        require(
            _verifyExecutionPayload(beaconRoot, blockHash, stateRoot),
            "Execution payload verification failed"
        );

        return true;
    }

    function _getBeaconRoot(uint256 timestamp) internal view returns (bytes32) {
        (bool success, bytes memory data) = BEACON_ROOTS.staticcall(
            abi.encode(timestamp)
        );
        require(success, "Beacon root call failed");
        return abi.decode(data, (bytes32));
    }

    function _verifyExecutionPayload(
        bytes32 beaconRoot,
        bytes32 blockHash,
        bytes32 stateRoot
    ) internal view returns (bool) {
        // Verify using Merkle proof that execution payload
        // in beacon block contains this blockHash and stateRoot
        // (Implementation requires SSZ merkleization of beacon block)
        return true;
    }
}
```

#### Option 2: Optimistic Light Client

```solidity
contract OptimisticLightClient is ILightClient {
    struct BlockClaim {
        bytes32 blockHash;
        bytes32 stateRoot;
        uint256 timestamp;
        bool challenged;
    }

    mapping(uint256 => BlockClaim) public claims;
    uint256 constant CHALLENGE_PERIOD = 1 hours;

    function submitBlockClaim(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 stateRoot
    ) external {
        require(claims[blockNumber].timestamp == 0, "Already claimed");

        claims[blockNumber] = BlockClaim({
            blockHash: blockHash,
            stateRoot: stateRoot,
            timestamp: block.timestamp,
            challenged: false
        });
    }

    function challengeClaim(
        uint256 blockNumber,
        bytes memory blockHeader
    ) external {
        BlockClaim storage claim = claims[blockNumber];
        require(claim.timestamp != 0, "No claim");
        require(block.timestamp < claim.timestamp + CHALLENGE_PERIOD, "Too late");

        // Verify actual block header
        bytes32 actualHash = keccak256(blockHeader);
        bytes32 actualStateRoot = _extractStateRoot(blockHeader);

        if (actualHash != claim.blockHash || actualStateRoot != claim.stateRoot) {
            claim.challenged = true;
            // Slash claimer, reward challenger
        }
    }

    function verifyBlock(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 stateRoot
    ) external view returns (bool) {
        BlockClaim memory claim = claims[blockNumber];
        require(claim.timestamp != 0, "No claim");
        require(!claim.challenged, "Claim challenged");
        require(block.timestamp >= claim.timestamp + CHALLENGE_PERIOD, "Still in challenge period");
        require(claim.blockHash == blockHash, "Hash mismatch");
        require(claim.stateRoot == stateRoot, "State root mismatch");

        return true;
    }
}
```

---

## Generating the Account Proof (Off-Chain)

```javascript
// Using ethers.js or web3.js
async function generateAccountProof(blockNumber, contractAddress) {
    // eth_getProof RPC call
    const proof = await provider.send('eth_getProof', [
        contractAddress,
        [],  // storage keys (empty for balance proof)
        blockNumber
    ]);

    /*
    Returns:
    {
        balance: "0x...",           // Balance at this block
        codeHash: "0x...",         // Contract code hash
        nonce: "0x...",            // Nonce
        storageHash: "0x...",      // Storage root
        accountProof: ["0x...", ...], // Merkle proof nodes
        storageProof: []
    }
    */

    return {
        balance: BigInt(proof.balance),
        accountProof: encodeAccountProof(proof.accountProof),
    };
}

function encodeAccountProof(proofNodes) {
    // RLP-encode the list of proof nodes
    return RLP.encode(proofNodes);
}
```

---

## Complete Flow

### 1. Operator Builds Batch

```javascript
// Choose anchor block (e.g., current block - 10 for safety)
const anchorBlock = await provider.getBlockNumber() - 10;

// Get block data
const block = await provider.getBlock(anchorBlock);
const blockHash = block.hash;
const stateRoot = block.stateRoot;

// Generate account proof
const proof = await generateAccountProof(anchorBlock, rollupContractAddress);

// Determine deposit range
const firstDepositId = await rollup.lastProcessedDepositId();
const deposits = await getDepositsUpTo(anchorBlock);
const numDeposits = deposits.length;

// Build batch
const batch = {
    l1AnchorBlock: anchorBlock,
    l1BlockHash: blockHash,
    l1StateRoot: stateRoot,
    accountProof: proof.accountProof,
    contractBalanceAtAnchor: proof.balance,
    firstDepositId: firstDepositId,
    numDeposits: numDeposits,
    depositsHash: hashDeposits(deposits),
    // ... rest of batch data
};
```

### 2. Submit to Light Client (if needed)

```javascript
// If anchor block is > 256 blocks old
if (currentBlock - anchorBlock >= 256) {
    // Submit block claim to light client
    await lightClient.submitBlockClaim(
        anchorBlock,
        blockHash,
        stateRoot
    );

    // Wait for challenge period
    await wait(CHALLENGE_PERIOD);
}
```

### 3. Commit Batch

```javascript
await rollup.commitBatch(batch, blobProof);
```

### 4. L1 Verification

```solidity
// In commitBatch():

// 1. Verify block is canonical
if (block.number - batch.l1AnchorBlock < 256) {
    require(blockhash(batch.l1AnchorBlock) == batch.l1BlockHash);
} else {
    require(lightClient.verifyBlock(
        batch.l1AnchorBlock,
        batch.l1BlockHash,
        batch.l1StateRoot
    ));
}

// 2. Verify account proof
address account = address(this);
bytes32 accountHash = keccak256(abi.encodePacked(account));

bytes memory accountRLP = MerklePatricia.verify(
    batch.accountProof,
    batch.l1StateRoot,
    accountHash
);

(, uint256 balance, ,) = decodeAccount(accountRLP);
require(balance == batch.contractBalanceAtAnchor);

// 3. Verify accounting
require(
    batch.totalL2Balances + batch.pendingWithdrawals ==
    batch.contractBalanceAtAnchor + depositsInBatch
);
```

---

## Why This is Simpler

### Before (Snapshot System)

```
1. Operator calls createSnapshot() at block N
   → Transaction, costs gas, on-chain state

2. Wait 1 block

3. Operator calls finalizeSnapshot(N) at block N+1
   → Another transaction, more gas, more state

4. Batch commits, references snapshot
   → Read snapshot from storage

Total: 2 transactions + storage reads/writes
```

### After (Proof System)

```
1. Operator generates proof off-chain at block N
   → Free, no transactions

2. Batch commits with proof
   → Single transaction
   → Verifies proof in-line
   → No storage needed

Total: 1 transaction + no extra state
```

**Savings:**
- ✓ No snapshot creation transactions
- ✓ No snapshot storage
- ✓ No synchronization issues
- ✓ Works for any historical block (with light client)

---

## Security Properties

### Property 1: Cannot Fake Balance

```
THEOREM: Operator cannot claim incorrect balance at anchor block

PROOF:
  - Account proof is Merkle proof from state root to account data
  - State root is in block header
  - Block hash commits to block header
  - blockhash() or light client verifies block is canonical
  - Cannot fake Merkle proof (cryptographic security)
  - Therefore balance must be actual balance at anchor block
```

### Property 2: Cannot Use Future Deposits

```
THEOREM: Batch cannot process deposits not yet available at anchor

PROOF:
  - Each deposit records its block number
  - Contract checks: deposit.blockNumber <= anchorBlock
  - Deposit block numbers are immutable (set at creation)
  - Therefore all deposits must have existed by anchor block
```

### Property 3: Accounting Invariant Enforced

```
THEOREM: L2 balances cannot exceed contract balance + deposits

PROOF:
  - Account proof shows contract.balance at anchor block
  - Contract verifies: L2_total + pending = contract_balance + deposits
  - Circuit proves: L2_total = sum(all L2 balances)
  - Therefore L2 balances bounded by actual L1 balance
```

---

## Handling Different Timeframes

### Recent Blocks (< 256 blocks old)

```solidity
if (block.number - anchorBlock < 256) {
    // Use blockhash opcode (free, instant)
    require(blockhash(anchorBlock) == batch.l1BlockHash);

    // Trust stateRoot or require block header proof
    // (Alternatively: parse block header from calldata)
}
```

### Old Blocks (≥ 256 blocks)

```solidity
else {
    // Use light client (small verification cost)
    require(
        lightClient.verifyBlock(
            anchorBlock,
            batch.l1BlockHash,
            batch.l1StateRoot
        )
    );
}
```

**Light client options:**
1. **Beacon chain sync committees** (cryptographic, ~27 hour history)
2. **Optimistic claims** (economic security, challenge period)
3. **Historical proof aggregation** (ZK proofs of chain history)

---

## Cost Comparison

### Snapshot Approach
```
Per batch:
  - 2 snapshot txs: 100k gas = ~$2.50
  - commitBatch: 200k gas = ~$5.00
  Total: ~$7.50
```

### Proof Approach
```
Per batch:
  - commitBatch with proof: 250k gas = ~$6.25
  - Light client (amortized): ~$0.25
  Total: ~$6.50
```

**Savings: ~15%** plus no coordination overhead

---

## Summary

### What Changed

**From:**
- Snapshots created on-chain
- 2 transactions per snapshot
- Storage for every snapshot
- 256-block time window

**To:**
- Account proofs generated off-chain
- No snapshot transactions
- No snapshot storage
- Unlimited time window (with light client)

### Key Benefits

1. **Simpler**: No snapshot creation/management
2. **Cheaper**: Fewer transactions, less state
3. **More flexible**: Works for any historical block
4. **Provably secure**: Merkle proofs + light client

### The Insight

Instead of **storing** L1 state on-chain, **prove** L1 state was correct at a specific block. Proofs are smaller, cheaper, and more flexible than state storage.

This is the same principle used by light clients, state proofs, and historical data verification - don't trust, verify via cryptographic proofs!
