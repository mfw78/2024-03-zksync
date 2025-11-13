# zkSync Era Proof Mechanism: Complete Technical Analysis

## Executive Summary

zkSync Era is a **ZK-Rollup** Layer 2 scaling solution for Ethereum that uses zero-knowledge proofs (specifically SNARK proofs) to ensure the validity of off-chain computation while maintaining Ethereum's security guarantees. This document explains how the proof mechanism works and how it enforces state transitions.

---

## 1. What is zkSync Era?

zkSync Era is a **validity rollup** (ZK-Rollup) that:
- Executes transactions off-chain on a custom virtual machine (zkEVM/EraVM)
- Generates cryptographic proofs of correct execution
- Posts minimal data to Ethereum L1 for data availability
- Allows anyone to reconstruct the full L2 state from L1 data alone

### Key Architectural Components

1. **Node/Sequencer**: Receives transactions, executes them, creates batches
2. **Prover**: Generates ZK-SNARK proofs of correct execution
3. **ZK Circuits**: Define what constitutes valid computation (EraVM execution rules)
4. **L1 Smart Contracts**: Verify proofs and maintain state commitments on Ethereum
5. **System Contracts (L2)**: Special contracts that handle core protocol logic

---

## 2. The Three-Stage State Transition Process

State transitions in zkSync Era follow a **three-phase commit scheme**:

### Phase 1: COMMIT (`commitBatches`)

**What happens:**
- Operator submits a **batch commitment** to L1
- Includes cryptographic commitments to:
  - New state root
  - Transaction data (via bootloader heap hash)
  - State changes (state diff hash)
  - L2→L1 messages and logs
  - Public data (via calldata or blobs post-EIP4844)

**Key Data Structures:**

```solidity
struct CommitBatchInfo {
    uint64 batchNumber;
    uint64 timestamp;
    uint64 indexRepeatedStorageChanges;
    bytes32 newStateRoot;              // Root of L2 state merkle tree
    uint256 numberOfLayer1Txs;
    bytes32 priorityOperationsHash;
    bytes32 bootloaderHeapInitialContentsHash;  // Commit to txs
    bytes32 eventsQueueStateHash;
    bytes systemLogs;                   // L2→L1 system logs
    bytes pubdataCommitments;          // Data availability commitment
}
```

**What gets verified at commit time:**
- Batch timestamp is valid (not too old, not too far in future)
- Previous batch hash matches
- Priority operations hash matches
- System logs are properly formed (from correct contracts)
- Data availability is ensured (either via calldata or blobs)

**The Batch Commitment Formula:**

The commitment is a hash of three components:

```
commitment = keccak256(
    passThroughData,    // State root, enum indexes
    metadataHash,       // Bootloader/account bytecode hashes
    auxiliaryOutput     // Logs, diffs, events, blob commitments
)
```

Where:
```solidity
passThroughData = abi.encodePacked(
    indexRepeatedStorageChanges,  // Next enum index for storage
    newStateRoot,                 // Post-batch merkle root
    zkPorterData                  // Reserved for future
)

metadataHash = abi.encodePacked(
    zkPorterIsAvailable,
    l2BootloaderBytecodeHash,     // Commit to bootloader version
    l2DefaultAccountBytecodeHash   // Commit to account logic
)

auxiliaryOutput = abi.encodePacked(
    keccak256(systemLogs),         // Hash of L2→L1 logs
    stateDiffHash,                 // Hash of state changes
    bootloaderHeapInitialContentsHash,  // Commit to txs
    eventsQueueStateHash,          // Commit to events
    blobCommitments                // KZG commitments (post-4844)
)
```

**Critical Invariant:** The commitment cryptographically binds together:
- What the new state is (state root)
- What transactions caused it (bootloader heap)
- What changed (state diffs)
- What messages were sent (logs)
- What data is available (pubdata/blobs)

### Phase 2: PROVE (`proveBatches`)

**What happens:**
- Operator submits a ZK-SNARK proof that the state transition was executed correctly
- The proof is verified on-chain using a verifier contract

**The Proof System:**

The proof attests to the statement:
> "Starting from `prevStateRoot`, executing the transactions committed to by `bootloaderHeapHash`, following the rules of EraVM defined by the circuits, results in `newStateRoot` and produces the outputs committed to in `commitment`."

**Public Input Construction:**

```solidity
function _getBatchProofPublicInput(
    bytes32 _prevBatchCommitment,
    bytes32 _currentBatchCommitment,
    VerifierParams memory _verifierParams
) internal pure returns (uint256) {
    return uint256(
        keccak256(
            abi.encodePacked(
                _prevBatchCommitment,      // Links to previous batch
                _currentBatchCommitment,   // Current batch commitment
                _verifierParams.recursionNodeLevelVkHash,
                _verifierParams.recursionLeafLevelVkHash
            )
        )
    ) >> PUBLIC_INPUT_SHIFT;
}
```

**Proof Verification:**

```solidity
function _verifyProof(uint256[] memory proofPublicInput, ProofInput calldata _proof) {
    bool successVerifyProof = s.verifier.verify(
        proofPublicInput,
        _proof.serializedProof,
        _proof.recursiveAggregationInput
    );
    require(successVerifyProof, "p"); // Proof verification fail
}
```

**What the circuits prove:**
1. **Execution correctness**: All transactions executed according to EraVM rules
2. **State transition validity**: State root correctly updated based on storage changes
3. **Commitment consistency**: All committed hashes (bootloader, events, state diffs) match actual execution
4. **System contract correctness**: L1Messenger, SystemContext, etc. behaved correctly
5. **Data availability**: Pubdata correctly represents all state changes

### Phase 3: EXECUTE (`executeBatches`)

**What happens:**
- Batch is finalized on L1
- Cannot be reverted after this point
- L2→L1 messages become withdrawable
- Priority operations are marked as processed

**Key checks:**
```solidity
function _executeOneBatch(StoredBatchInfo memory _storedBatch, uint256 _executedBatchIdx) {
    // Must execute in order
    require(currentBatchNumber == s.totalBatchesExecuted + _executedBatchIdx + 1);

    // Must have been committed and proven
    require(_hashStoredBatchInfo(_storedBatch) == s.storedBatchHashes[currentBatchNumber]);

    // Priority ops must match
    bytes32 priorityOpsHash = _collectOperationsFromPriorityQueue(_storedBatch.numberOfLayer1Txs);
    require(priorityOpsHash == _storedBatch.priorityOperationsHash);

    // Save L2→L1 logs root for withdrawal proofs
    s.l2LogsRootHashes[currentBatchNumber] = _storedBatch.l2LogsTreeRoot;
}
```

**Crucial Invariant:**
```
totalBatchesExecuted ≤ totalBatchesVerified ≤ totalBatchesCommitted
```

You cannot execute a batch until it's proven, and you cannot prove a batch until it's committed.

---

## 3. Data Availability & EIP-4844 (Danksharding)

### The Data Availability Problem

For zkSync to be a valid rollup, anyone must be able to:
1. Observe Ethereum L1
2. Extract all published data
3. Reconstruct the complete L2 state
4. Continue operating the network even if the operator disappears

**What data must be available:**

1. **L2→L1 Logs** (88 bytes each)
   ```solidity
   struct L2Log {
       uint8 l2ShardId;
       bool isService;
       uint16 txNumberInBlock;
       address sender;
       bytes32 key;
       bytes32 value;
   }
   ```

2. **L2→L1 Messages** (arbitrary length)
   - Withdrawals, cross-chain messages

3. **Deployed Bytecodes**
   - Can be compressed or uncompressed
   - Compressed bytecodes published as L2→L1 messages

4. **State Diffs** (storage changes)
   - Most expensive component
   - Subject to aggressive compression

### Pre-4844: Calldata

Before EIP-4844, all pubdata was posted as calldata:
- ~16 gas per byte for zero bytes
- ~68 gas per byte for non-zero bytes
- Limited to ~120KB per batch (gas limits)

### Post-4844: Blob Data Availability

**EIP-4844 (Proto-Danksharding) Benefits:**
- Blobs provide cheaper data availability (~1-3 gas per byte vs 16-68)
- Each blob: 4096 field elements × 31 bytes = 126,976 bytes
- zkSync uses up to 2 blobs per batch
- Blob data not accessible to EVM, but availability is guaranteed

**How zkSync Uses Blobs:**

1. **L2 Processing:**
   ```python
   # Collect all pubdata for batch
   total_pubdata = concat([
       l2_to_l1_logs,
       l2_to_l1_messages,
       compressed_bytecodes,
       compressed_state_diffs
   ])

   # Chunk into blob-sized pieces (126,976 bytes each)
   BLOB_SIZE = 4096 * 31
   num_blobs = ceil(len(total_pubdata) / BLOB_SIZE)

   for i in range(num_blobs):
       chunk = total_pubdata[i*BLOB_SIZE : (i+1)*BLOB_SIZE]
       padded_chunk = pad_to_blob_size(chunk)
       blob_hash = keccak256(padded_chunk)

       # Publish blob hash via system log
       emit_system_log(BLOB_HASH_KEY[i], blob_hash)
   ```

2. **L1 Verification:**

   When using blobs, `pubdataCommitments` contains KZG proof data:
   ```
   [1 byte source flag] || [144 bytes per blob]:
       opening_point (16 bytes) ||
       claimed_value (32 bytes) ||
       commitment (48 bytes) ||
       proof (48 bytes)
   ```

   **Point Evaluation Precompile:**
   ```solidity
   function _verifyBlobInformation(bytes calldata _pubdataCommitments, bytes32[] memory _blobHashes) {
       for each blob commitment {
           // Get versioned hash from BLOBHASH opcode
           bytes32 versionedHash = _getBlobVersionedHash(index);

           // Extract KZG data
           bytes32 openingPoint = bytes32(uint128(commitment[0:16]));
           bytes calldata claimedValue = commitment[16:48];
           bytes calldata kzgCommitment = commitment[48:96];
           bytes calldata proof = commitment[96:144];

           // Call point evaluation precompile
           // Verifies: P(openingPoint) = claimedValue
           // where P is the polynomial committed to by kzgCommitment
           _pointEvaluationPrecompile(
               versionedHash,
               openingPoint,
               claimedValue || kzgCommitment || proof
           );

           // Compute blob commitment for circuits
           blobCommitments[index] = keccak256(
               versionedHash || openingPoint || claimedValue
           );
       }
   }
   ```

3. **Proof of Equivalence (in ZK Circuits):**

   The circuits verify:
   ```
   blob_linear_hash = keccak256(blob_preimage)
   blob_commitment = keccak256(versioned_hash || opening_point || claimed_value)

   // Prove the blob contains the same data as the state diffs
   blob_preimage == encode_for_blob(total_pubdata)

   // Prove the KZG commitment is valid
   polynomial_from_blob(blob_preimage).evaluate(opening_point) == claimed_value
   ```

**Critical Security Property:**

The combination of:
- L2 computing `blob_linear_hash = keccak256(pubdata)` and publishing via system log
- L1 verifying KZG proof via point evaluation precompile
- ZK proof verifying the blob contains the correct pubdata

...ensures data availability without the L1 EVM needing to see the actual blob data.

---

## 4. State Diff Compression

State diffs are the most expensive component of pubdata. zkSync employs sophisticated compression.

### The Enumeration Index System

**Initial Writes:**
- First time a storage slot is modified: publish `(derived_key, value)`
- `derived_key = hash(address, key)` — 32 bytes
- Assign a sequential `enumeration_index` to this slot (8 bytes max)

**Repeated Writes:**
- Subsequent modifications: publish `(enumeration_index, value)`
- Use the much shorter index instead of full 32-byte key

### Compression v1 Specification

**Value Compression:**

Instead of always publishing 32 bytes for values, compress based on operation type:

```
Compression Types:
- NoCompression: full 32 bytes
- Add: value increased (publish the delta)
- Sub: value decreased (publish the delta)
- Transform: value changed arbitrarily (publish minimal bytes)
```

**Packing Type Encoding (1 byte):**
```
[5 bits: length (0-31)] [3 bits: operation type]
```

**Format:**

```
Header:
  version (1) || total_logs_len (3) || bytes_for_enum_index (1)

Initial Writes:
  num_initial_writes (2 bytes)
  For each write:
    derived_key (32) || packing_type (1) || packed_value (0-32)

Repeated Writes:
  For each write:
    enum_index (N bytes) || packing_type (1) || packed_value (0-32)
```

**Example:**
```
// Nonce increased from 5 to 6
packing_type = 0b00001_001  // 1 byte length, Add operation
packed_value = 0x01

// Balance changed from X to 0
packing_type = 0b00000_010  // 0 bytes length, Transform operation
packed_value = <none>

// Random 32-byte value
packing_type = 0b11111_011  // 31 bytes length, NoCompression
packed_value = 0x123...789 (32 bytes)
```

**Compression Results:**
- ~75% compression for values
- ~50% overall compression for storage logs
- Most storage operations (nonces, balances) compress to 7-9 bytes total

---

## 5. How the Proof Enforces State Transitions

### The Cryptographic Binding Chain

```
Block N-1: commitment_N-1 = hash(stateRoot_N-1, ...)
             ↓
ZK Proof: "Executing transactions on stateRoot_N-1 yields stateRoot_N"
             ↓
Block N:   commitment_N = hash(stateRoot_N, stateDiffs_N, ...)
             ↓
Public Input: hash(commitment_N-1, commitment_N, vk_hashes)
             ↓
Verification: verifier.verify(publicInput, proof) == true
```

### What the ZK Circuit Proves

The circuit is the **definition** of valid state transitions. It proves:

1. **Bootloader Execution:**
   - Bootloader code matches committed hash
   - Each transaction properly loaded and executed
   - Transaction signatures valid (via account abstraction)

2. **EraVM Execution:**
   - Every instruction executed according to EraVM spec
   - Gas metering correct
   - Call frames managed correctly
   - Precompiles executed correctly

3. **System Contract Behavior:**
   - `SystemContext` correctly manages block/batch info
   - `L1Messenger` correctly aggregates L2→L1 messages
   - `ContractDeployer` correctly deploys contracts
   - `KnownCodesStorage` correctly marks bytecodes as known
   - `NonceHolder` correctly manages nonces

4. **State Tree Updates:**
   ```
   For each storage write (address, key, value):
     derived_key = hash(address, key)
     old_value = state_tree.get(derived_key)
     state_tree.set(derived_key, value)
     record_state_diff(derived_key, old_value, value)

   new_state_root = state_tree.root()
   ```

5. **Commitment Consistency:**
   - `bootloaderHeapInitialContentsHash` matches actual bootloader heap
   - `eventsQueueStateHash` matches actual events emitted
   - `stateDiffHash` matches actual state changes
   - L2→L1 logs match actual messages sent
   - Pubdata (in blobs or calldata) matches actual state diffs

6. **Enumeration Indexes:**
   - Initial writes get sequential indexes in sorted order
   - Repeated writes use existing indexes correctly

### Why Proofs Make Fraud Impossible

**Invalid state transition attempts:**

```
Malicious operator tries:
- Steal funds by modifying balances
- Execute transactions with invalid signatures
- Skip transaction execution but claim it happened
- Change state root without proper state changes
- Claim different pubdata than actual
```

**None of these can work because:**

1. **The proof generation will fail** - the prover cannot create a valid proof for an invalid computation because the circuit constraints won't be satisfied

2. **If operator submits an invalid proof** - the verifier contract will reject it:
   ```solidity
   require(s.verifier.verify(publicInput, proof), "p");
   ```

3. **If operator tries to execute without proof** - the contract enforces order:
   ```solidity
   require(newTotalBatchesExecuted <= s.totalBatchesVerified, "n");
   ```

4. **The commitment creates a dependency chain** - you can't prove batch N without the correct commitment from batch N-1

### The Security Model

**Trust Assumptions:**
- ✓ Ethereum L1 is secure (standard assumption)
- ✓ ZK proof system is sound (cryptographic assumption)
- ✓ Circuits correctly implement EraVM spec (audited implementation)
- ✗ Don't need to trust the operator (cryptographically verified)
- ✗ Don't need to trust the sequencer (can force include txs via L1)

**Operator Cannot:**
- Create invalid state transitions (proof will fail)
- Steal funds (would require invalid state change)
- Censor forever (force-include mechanism via L1 priority queue)
- Withhold data (DA is enforced via calldata/blobs)

**Operator Can (but is economically disincentivized):**
- Order transactions arbitrarily (MEV extraction)
- Temporarily censor (but not indefinitely due to priority queue)

---

## 6. The Role of Different Components

### L1 Smart Contracts (Ethereum)

**ExecutorFacet** (`Executor.sol`):
- Accepts batch commitments (`commitBatches`)
- Verifies ZK proofs (`proveBatches`)
- Finalizes batches (`executeBatches`)
- Maintains commitment chain
- Enforces data availability
- Manages priority queue (censorship resistance)

**Verifier Contract:**
- Implements Plonk/SNARK verification algorithm
- Checks proof against public inputs
- Returns true/false

**StateTransitionManager:**
- Manages multiple zkSync chains (hyperchain architecture)
- Controls protocol upgrades
- Manages shared resources

**Bridges:**
- Lock assets on L1
- Release assets on withdrawals
- Verify L2→L1 message proofs

### L2 System Contracts

**Bootloader:**
- Transaction execution coordinator
- Manages batch execution lifecycle
- Calls system contracts in correct order
- Collects and publishes pubdata

**L1Messenger:**
- Aggregates L2→L1 logs into merkle tree
- Validates pubdata compression
- Publishes commitments via system logs

**SystemContext:**
- Manages block/batch numbers and timestamps
- Stores block hashes
- Provides `block.number`, `block.timestamp` to contracts

**ContractDeployer:**
- Deploys contracts with zkSync-specific address derivation
- Manages contract code storage
- Publishes bytecodes

**KnownCodesStorage:**
- Tracks which bytecode hashes are known
- Validates bytecode publication

### Prover

- Receives execution trace from node
- Generates witnesses for circuits
- Computes ZK-SNARK proof
- Submits proof to L1

---

## 7. Complete Flow Example

### Transaction Journey

1. **User submits transaction to zkSync operator**

2. **Operator collects transactions into a batch**
   - Orders transactions (potential MEV)
   - Executes in EraVM
   - Tracks state changes
   - Records events and logs

3. **Bootloader finalizes batch on L2**
   ```yul
   // Simplified bootloader logic
   for each transaction {
       executeTransaction()
       recordStateChanges()
       collectEvents()
   }

   // Finalization
   L1Messenger.publishPubdata(stateDiffs, logs, messages, bytecodes)
   SystemContext.publishBatchHash()
   PubdataChunkPublisher.publishBlobHashes()
   ```

4. **Operator commits batch to L1**
   ```solidity
   executorFacet.commitBatches(
       lastCommittedBatch,
       [newBatchCommitment]
   )
   ```

   Commitment includes:
   - New state root: `0xabc...`
   - State diff hash: `keccak256(stateDiffs)`
   - Bootloader heap hash: `keccak256(txs)`
   - System logs with blob hashes

5. **Prover generates proof**
   - Input: execution trace, old state, new state, commitments
   - Output: SNARK proof that everything is correct
   - Time: several minutes to hours depending on batch size

6. **Operator submits proof to L1**
   ```solidity
   executorFacet.proveBatches(
       prevBatch,
       [committedBatch],
       proof
   )
   ```

   L1 verifier checks:
   ```
   verify(
       publicInput = hash(prevCommitment || newCommitment || vkHash),
       proof
   ) == true
   ```

7. **Batch is executed (finalized)**
   ```solidity
   executorFacet.executeBatches([provenBatch])
   ```

   Now:
   - State transition is finalized
   - Users can withdraw funds
   - Priority txs are processed
   - Cannot be reverted

---

## 8. Key Innovations & Technical Highlights

### Account Abstraction

zkSync has **native account abstraction** - every account is a smart contract:
- No EOA concept at protocol level
- Signature verification in account code
- Enables session keys, multi-sig, social recovery
- Gas can be paid in any token

### Efficient State Management

**Merkle Tree:**
- 256-level binary tree
- Leaves: `hash(address, key) → value`
- Flat structure (not account-based like Ethereum)
- Optimized for zkSNARK verification

**Storage Slots:**
```
slot_id = hash(address, key)
value = storage[slot_id]
```

### Recursive Proof Aggregation

The verifier params include:
```solidity
struct VerifierParams {
    bytes32 recursionNodeLevelVkHash;  // For aggregating proofs
    bytes32 recursionLeafLevelVkHash;  // For base proofs
    bytes32 recursionCircuitsSetVksHash;
}
```

This allows:
- Multiple batches proven separately
- Proofs aggregated into one
- Single L1 verification for many batches (future optimization)

### Priority Queue (Censorship Resistance)

Users can submit transactions directly to L1:
```solidity
function requestL2Transaction(
    address _contractL2,
    uint256 _l2Value,
    bytes calldata _calldata,
    ...
) external payable {
    // Add to priority queue
    // Operator MUST include within timeframe or batch can be reverted
}
```

Guarantees:
- Cannot be censored forever
- L1→L2 messages always processable
- Emergency withdrawals always possible

---

## 9. Relationship to Full Danksharding

**Current (Proto-Danksharding/EIP-4844):**
- 2-6 blobs per Ethereum block
- ~0.25-0.75 MB of DA per block
- Blob data pruned after ~18 days
- Point evaluation precompile for verification

**Future (Full Danksharding):**
- 64+ blobs per block (target)
- ~16 MB of DA per block
- Data Availability Sampling (DAS)
- zkSync can use up to 16 blobs (circuits already support)

**Benefits for zkSync:**
- Lower transaction costs (10-100x cheaper)
- Higher throughput (more txs per batch)
- Same security guarantees
- Easier state reconstruction

---

## 10. Security Considerations

### Attack Vectors

1. **Malicious Operator** ✓ Mitigated
   - Cannot create invalid proofs
   - Cannot steal funds
   - Can censor temporarily but not permanently (priority queue)

2. **Data Withholding** ✓ Mitigated
   - All state diffs published to L1
   - Calldata is permanent
   - Blobs ensure availability (although pruned, enough time to sync)

3. **Sequencer Centralization** ⚠️ Current Risk
   - Single operator currently
   - Roadmap includes decentralization

4. **Circuit Bugs** ⚠️ Low Risk
   - Extensive audits
   - Bug bounty program
   - Formal verification efforts

5. **Verifier Implementation** ⚠️ Low Risk
   - Complex cryptography
   - Relies on soundness of SNARK system
   - Multiple audits

### Upgrade Mechanism

Governed upgrades can:
- Change system contracts
- Update circuits
- Modify fee structure
- Add features

Protected by:
- Timelock (delay before execution)
- Governance multi-sig
- Security council (emergency response)

---

## 11. Comparison to Other Systems

### vs Optimistic Rollups (Arbitrum, Optimism)

**zkSync (Validity Proof):**
- ✓ Instant finality once proven (~1-4 hours)
- ✓ No challenge period
- ✓ Smaller state commitments
- ✗ Higher computational overhead (proof generation)
- ✗ More complex (circuits, cryptography)

**Optimistic Rollups:**
- ✓ Simpler implementation (basically run EVM)
- ✓ Lower computational requirements
- ✗ 7-day withdrawal delay (challenge period)
- ✗ Potential for invalid state if fraud proof fails
- ✗ Larger data requirements

### vs Other ZK-Rollups (StarkNet, Polygon zkEVM)

**zkSync Era:**
- Custom VM (EraVM) optimized for zkSNARKs
- Account abstraction native
- SNARK-based (smaller proofs)

**StarkNet:**
- Cairo VM, STARK-based (transparent, quantum-resistant)
- Larger proofs but faster generation

**Polygon zkEVM:**
- EVM-equivalent (full bytecode compatibility)
- More complex circuits

---

## 12. Conclusion

The zkSync Era proof mechanism is a sophisticated system that:

1. **Enforces correct state transitions** through ZK-SNARK proofs that cryptographically verify execution
2. **Ensures data availability** through Ethereum calldata or blobs (EIP-4844)
3. **Maintains a commitment chain** linking batches cryptographically
4. **Compresses state diffs** aggressively to minimize costs
5. **Provides instant finality** once proofs are verified on L1

The key insight is that **the proof IS the enforcement mechanism**. You cannot create a valid proof for an invalid state transition. The circuits define the rules of state changes, the prover generates proofs of compliance, and L1 verifies those proofs. This creates a trustless system where:

- State transitions are **mathematically guaranteed** to be correct
- Data availability is **cryptographically ensured**
- Users don't need to trust the operator
- Ethereum provides the security and DA, zkSync provides the scalability

The integration with EIP-4844/Danksharding makes this economically viable by drastically reducing data costs while maintaining the same security properties through KZG commitments and point evaluation.
