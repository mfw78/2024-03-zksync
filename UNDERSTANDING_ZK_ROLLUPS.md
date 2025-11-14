# Understanding ZK-Rollups: A Complete Guide

## Table of Contents

1. [What is a ZK-Rollup?](#what-is-a-zk-rollup)
2. [Core Concepts](#core-concepts)
3. [Building from First Principles](#building-from-first-principles)
4. [Common Pitfalls](#common-pitfalls)
5. [Simple Mental Models](#simple-mental-models)
6. [Design Evolution](#design-evolution)
7. [Security Checklist](#security-checklist)

---

## What is a ZK-Rollup?

### The Simple Explanation

Imagine you're running a ledger of who has how much money:

**Normal blockchain (Ethereum L1):**
```
Everyone sees every transaction
Everyone verifies every transaction
Everyone stores the full ledger
Result: Secure but slow and expensive
```

**ZK-Rollup:**
```
One operator processes transactions off-chain
Operator generates a mathematical proof: "I processed these correctly"
Ethereum verifies the proof (cheap!)
Ethereum stores just the final balances (data availability)
Result: Fast, cheap, still secure
```

### The Key Insight

**You don't need to re-execute transactions to verify them - you can verify a proof instead!**

```
Without ZK:
  Transaction → Execute → Verify (expensive!)

With ZK:
  Transaction → Execute off-chain → Generate proof → Verify proof (cheap!)
```

---

## Core Concepts

### 1. State Root

**What it is:** A single hash that represents the entire state.

```
State:
  alice: 100 ETH
  bob: 50 ETH
  charlie: 75 ETH

Merkle Tree:
         ROOT
        /    \
    H(alice)  H(bob+charlie)
                /      \
            H(bob)   H(charlie)

State Root = ROOT hash = 0xabc...def

Change anything → Different root!
```

**Why it matters:**
- Ethereum only stores the root (32 bytes)
- Not all balances (potentially millions of entries)
- Can prove any balance with a Merkle proof

### 2. Zero-Knowledge Proof

**What it is:** A mathematical proof that something is true without revealing why.

**Simple analogy:**
```
You: "I know the password to this account"
Verifier: "Prove it"

Without ZK:
  You: "The password is 'hunter2'"
  Verifier: Checks password
  Problem: Now verifier knows password!

With ZK:
  You: Generates proof using password
  Verifier: Checks proof (without seeing password)
  Result: Verified, password still secret!
```

**For rollups:**
```
Operator: "I executed these 1000 transactions correctly"
Ethereum: "Prove it"

Without ZK:
  Operator: Sends all 1000 transactions
  Ethereum: Re-executes all 1000 (expensive!)

With ZK:
  Operator: Generates proof
  Ethereum: Verifies proof (cheap!)
  Result: Same security, much cheaper!
```

### 3. Data Availability

**The problem:**
```
If Ethereum only stores state roots:
  How do we know what the actual state is?
  How can we reconstruct balances?
  What if operator disappears?
```

**The solution:** Publish all state changes (pubdata)
```
L1 stores:
  - State root (32 bytes)
  - State changes (compressed, in blob)

Anyone can:
  - Download state changes from L1
  - Replay them to reconstruct full state
  - Continue operating the rollup
```

**Why it's critical:**
```
Without data availability:
  Operator stops → State is lost → Funds locked forever

With data availability:
  Operator stops → Anyone can reconstruct state → New operator takes over
```

### 4. The Three-Phase Commit

```
COMMIT
  ↓
PROVE
  ↓
EXECUTE
```

**Why three phases?**

1. **COMMIT**: "I claim this is the new state"
   - Operator posts commitment to L1
   - Not yet proven
   - Can be challenged/reverted

2. **PROVE**: "Here's proof the state transition is correct"
   - Operator submits ZK proof
   - L1 verifies proof
   - Cryptographic certainty achieved

3. **EXECUTE**: "Finalize this state"
   - State is now final
   - Cannot be reverted
   - Withdrawals become available

**Why not commit+prove in one step?**
- Proof generation takes time (minutes to hours)
- Commit is fast (immediate)
- Users see "soft confirmation" after commit
- "Hard confirmation" after proof

---

## Building from First Principles

### Level 0: Just Balances (Simplest Possible)

```solidity
// L2 State (off-chain)
mapping(address => uint256) balances;

// L1 Contract
bytes32 stateRoot;  // Merkle root of balances

function deposit() payable {
    // Add to priority queue
}

function commitBatch(bytes32 newRoot) {
    stateRoot = newRoot;
}
```

**What's wrong?**
- ❌ No proof! Operator can claim any state
- ❌ No accounting! Can inflate balances
- ❌ No data availability! Can't reconstruct state

### Level 1: Add ZK Proof

```solidity
function commitBatch(
    bytes32 prevRoot,
    bytes32 newRoot,
    bytes proof
) {
    require(prevRoot == stateRoot, "Wrong prev state");
    require(verifier.verify([prevRoot, newRoot], proof), "Invalid proof");
    stateRoot = newRoot;
}
```

**What's better:**
- ✓ Proof required! Can't fake state transitions
- ❌ Still no accounting validation
- ❌ Still no data availability

### Level 2: Add Accounting Invariants

```solidity
struct BatchCommit {
    bytes32 newRoot;
    uint256 totalL2Balances;  // Sum of all L2 balances
    bytes proof;
}

uint256 public totalDeposited;
uint256 public totalWithdrawn;

function commitBatch(BatchCommit calldata batch) {
    // Verify proof includes accounting
    require(verifier.verify([
        stateRoot,
        batch.newRoot,
        batch.totalL2Balances  // Proven by circuit!
    ], batch.proof));

    // Verify conservation of value
    require(
        batch.totalL2Balances ==
        totalDeposited - totalWithdrawn
    );

    stateRoot = batch.newRoot;
}
```

**What's better:**
- ✓ Proof required
- ✓ Accounting enforced! Can't inflate balances
- ❌ Still no data availability

### Level 3: Add Data Availability

```solidity
function commitBatch(
    BatchCommit calldata batch,
    bytes calldata pubdata  // State changes
) {
    require(keccak256(pubdata) == batch.pubdataHash);

    // Verify proof
    require(verifier.verify([...], batch.proof));

    // Verify accounting
    require(batch.totalL2Balances == totalDeposited - totalWithdrawn);

    // Store pubdata on L1 (expensive!)
    // OR: Store in blob (cheap!)

    stateRoot = batch.newRoot;
}
```

**What's better:**
- ✓ Proof required
- ✓ Accounting enforced
- ✓ Data availability! Can reconstruct state from L1

**Problem:** Calldata is expensive (~16-68 gas/byte)

### Level 4: Use EIP-4844 Blobs

```solidity
function commitBatch(
    BatchCommit calldata batch,
    bytes calldata blobProof  // KZG proof
) {
    // Verify blob via point evaluation precompile
    _verifyBlobCommitment(batch.blobHash, blobProof);

    // Rest same as before...
}

function _verifyBlobCommitment(bytes32 blobHash, bytes calldata proof) {
    bytes32 versionedHash = BLOBHASH(0);  // From transaction

    // Point evaluation precompile verifies:
    // 1. Blob contains data matching blobHash
    // 2. KZG commitment is valid
    (bool success, ) = POINT_EVAL_PRECOMPILE.call(proof);
    require(success);
}
```

**What's better:**
- ✓ Proof required
- ✓ Accounting enforced
- ✓ Data availability via blobs (10-100x cheaper!)

### Level 5: Add L1 State Anchoring

```solidity
function commitBatch(
    BatchCommit calldata batch,
    bytes calldata accountProof  // Merkle proof of L1 balance
) {
    // Verify L1 block is canonical
    require(blockhash(batch.l1Block) == batch.l1BlockHash);

    // Verify account proof shows contract balance at that block
    bytes memory accountRLP = MerklePatricia.verify(
        accountProof,
        batch.l1StateRoot,
        keccak256(address(this))
    );

    (, uint256 balance, ,) = decodeAccount(accountRLP);
    require(balance == batch.l1BalanceAtBlock);

    // NOW accounting check uses proven L1 balance
    require(
        batch.totalL2Balances ==
        batch.l1BalanceAtBlock + depositsInBatch
    );

    // Rest of verification...
}
```

**What's better:**
- ✓ Proof required
- ✓ Accounting enforced with L1 proof
- ✓ Data availability
- ✓ Temporal consistency! No timing attacks

**This is a complete, secure ZK-rollup!**

---

## Common Pitfalls

### Pitfall 1: No Accounting Validation

**The mistake:**
```solidity
function commitBatch(bytes32 newRoot, bytes proof) {
    require(verifier.verify([stateRoot, newRoot], proof));
    stateRoot = newRoot;
}
```

**What's wrong:**
- Operator can claim totalL2Balances = 1,000,000 ETH
- Proof verifies state transition is valid
- But doesn't verify TOTAL balances match deposits!

**The fix:**
```solidity
function commitBatch(BatchCommit calldata batch) {
    // Proof must include total balances as public input
    require(verifier.verify([
        stateRoot,
        batch.newRoot,
        batch.totalL2Balances  // ← Critical!
    ], batch.proof));

    // Verify against actual deposits
    require(batch.totalL2Balances <= totalDeposited - totalWithdrawn);
}
```

**Why it matters:**
Without this, operator can print money by inflating balances.

### Pitfall 2: No Data Availability

**The mistake:**
```solidity
function commitBatch(bytes32 newRoot, bytes proof) {
    // Just stores state root
    stateRoot = newRoot;
}
```

**What's wrong:**
- State root is stored
- But how do we know alice has 100 ETH?
- If operator disappears, state is lost forever!

**The fix:**
```solidity
function commitBatch(BatchCommit calldata batch, bytes calldata pubdata) {
    // Verify pubdata matches commitment
    require(keccak256(pubdata) == batch.pubdataHash);

    // Store pubdata on L1 (or in blob)
    // Now anyone can reconstruct state
}
```

**Why it matters:**
Without this, rollup becomes a custodial system. Operator controls access to state.

### Pitfall 3: Timing Attacks (No L1 Anchoring)

**The mistake:**
```solidity
function commitBatch(BatchCommit calldata batch) {
    // Check against current state
    require(batch.totalDeposited == totalDeposited);  // ← Problem!
}
```

**The attack:**
```
Time T0: Operator builds batch, totalDeposited = 1000
Time T1: New deposits arrive, totalDeposited = 1500
Time T2: Operator commits batch
         batch.totalDeposited = 1000
         contract.totalDeposited = 1500
         Check fails! But batch was correct at T0

OR WORSE:
Time T0: Operator builds batch with fake 500 ETH
Time T1: Real 500 ETH deposit arrives
Time T2: Commit succeeds! (1500 == 1500)
```

**The fix:**
```solidity
function commitBatch(
    BatchCommit calldata batch,
    bytes calldata accountProof
) {
    // Anchor to specific L1 block
    require(blockhash(batch.l1Block) == batch.l1BlockHash);

    // Prove balance at that block
    uint256 balanceAtBlock = verifyAccountProof(accountProof, ...);

    // Check against proven historical balance
    require(batch.totalL2Balances == balanceAtBlock + depositsInBatch);
}
```

**Why it matters:**
Without this, operator can exploit race conditions between batch creation and commitment.

### Pitfall 4: No Withdrawal Authorization

**The mistake:**
```solidity
function executeWithdrawal(
    uint256 batchNumber,
    address recipient,
    uint256 amount,
    bytes32[] proof
) {
    // Anyone can call for any recipient!
    bytes32 leaf = keccak256(abi.encode(recipient, amount));
    require(verifyMerkleProof(leaf, proof, withdrawalsRoot));

    recipient.transfer(amount);  // ← Problem!
}
```

**The attack:**
```
Alice withdraws 100 ETH to alice_L1
Withdrawal committed: {recipient: alice_L1, amount: 100}

Bob calls executeWithdrawal(batch, alice_L1, 100, proof)
  → Sends to alice_L1
  → Alice gets money (good)

Bob calls executeWithdrawal again with different recipient:
  → Can't! Merkle proof won't verify for different recipient

BUT: Bob could front-run Alice's withdrawal call
  → Bob sees Alice's tx in mempool
  → Bob submits same tx with higher gas
  → Bob's tx executes first
  → Alice's tx reverts (already withdrawn)
  → Griefing attack!
```

**The fix:**
```solidity
function executeWithdrawal(...) {
    require(msg.sender == recipient, "Only recipient can claim");
    // Rest of verification...
}
```

**Why it matters:**
Only the designated recipient should be able to claim their withdrawal.

### Pitfall 5: Deposit Ordering Assumptions

**The mistake:**
```solidity
function commitBatch(BatchCommit calldata batch) {
    // Process "next N deposits"
    for (uint i = 0; i < batch.numDeposits; i++) {
        Deposit memory dep = depositQueue[queueHead + i];
        // Process deposit...
    }
    queueHead += batch.numDeposits;
}
```

**What's wrong:**
- Assumes deposits processed in strict queue order
- What if operator wants to skip a deposit?
- What if deposits arrive out of order due to reorgs?

**The fix:**
```solidity
function commitBatch(BatchCommit calldata batch) {
    // Explicit deposit IDs
    require(batch.firstDepositId == lastProcessedId);

    // Verify all deposits in range
    bytes32 expectedHash = keccak256("");
    for (uint i = 0; i < batch.numDeposits; i++) {
        Deposit memory dep = deposits[batch.firstDepositId + i];
        expectedHash = keccak256(abi.encode(expectedHash, dep));
    }

    require(expectedHash == batch.depositsHash);
}
```

**Why it matters:**
Explicit deposit IDs prevent skipping and ensure correct ordering.

### Pitfall 6: No Double-Withdrawal Prevention

**The mistake:**
```solidity
function executeWithdrawal(uint256 batch, uint256 index, ...) {
    // Verify merkle proof
    require(verifyMerkleProof(...));

    // Transfer funds (no tracking!)
    recipient.transfer(amount);
}
```

**The attack:**
```
Alice withdraws 100 ETH
Merkle proof valid

Call executeWithdrawal(batch, index, alice, 100)
  → Transfer 100 ETH to Alice ✓

Call executeWithdrawal(batch, index, alice, 100) AGAIN
  → Merkle proof still valid!
  → Transfer another 100 ETH to Alice ✓

Repeat until contract drained!
```

**The fix:**
```solidity
mapping(bytes32 => bool) public withdrawalExecuted;

function executeWithdrawal(...) {
    bytes32 withdrawalId = keccak256(abi.encode(batch, index));
    require(!withdrawalExecuted[withdrawalId], "Already withdrawn");

    // Verify and transfer...

    withdrawalExecuted[withdrawalId] = true;
}
```

**Why it matters:**
Without tracking, same withdrawal can be executed multiple times.

### Pitfall 7: Blob Data Not Verified

**The mistake:**
```solidity
function commitBatch(BatchCommit calldata batch) {
    // Just check blob hash matches
    require(batch.blobHash != 0);

    // Don't verify blob actually contains this data!
    stateRoot = batch.newRoot;
}
```

**What's wrong:**
- Blob could contain garbage
- Blob could contain different data than claimed
- Can't reconstruct state from blob

**The fix:**
```solidity
function commitBatch(
    BatchCommit calldata batch,
    bytes calldata kzgProof
) {
    // Get blob versioned hash
    bytes32 versionedHash = BLOBHASH(0);

    // Verify via point evaluation precompile
    // This proves blob contains data matching commitment
    (bool success, ) = POINT_EVAL_PRECOMPILE.call(
        abi.encodePacked(versionedHash, kzgProof)
    );
    require(success, "Blob verification failed");

    // Also verify in ZK circuit that pubdata matches blob
}
```

**Why it matters:**
Without verification, data availability is not guaranteed.

### Pitfall 8: Missing Invariant Checks

**The mistake:**
```solidity
function executeWithdrawal(...) {
    withdrawalExecuted[id] = true;
    totalWithdrawn += amount;
    recipient.transfer(amount);  // Could fail!
}
```

**What's wrong:**
- Contract balance might be insufficient
- Invariant could be violated: `balance != deposits - withdrawn`

**The fix:**
```solidity
function executeWithdrawal(...) {
    // Verify invariant before
    require(address(this).balance >= amount, "Insufficient balance");

    // Verify invariant after
    require(
        address(this).balance - amount ==
        totalDeposited - totalWithdrawn - amount,
        "Would violate invariant"
    );

    withdrawalExecuted[id] = true;
    totalWithdrawn += amount;

    (bool success, ) = recipient.call{value: amount}("");
    require(success, "Transfer failed");
}
```

**Why it matters:**
Invariant violations indicate accounting errors or potential exploits.

---

## Simple Mental Models

### Mental Model 1: Rollup as a Notary

```
Normal blockchain:
  Everyone is a notary
  Everyone witnesses every transaction
  Slow but everyone agrees

ZK-Rollup:
  One notary (operator) witnesses all transactions
  Notary creates a stamped certificate (proof)
  Everyone verifies the stamp (cheap!)
  Fast and still secure
```

### Mental Model 2: State Root as a Fingerprint

```
State = All balances

State Root = Fingerprint of state

Change any balance → Fingerprint changes completely

Like a hash:
  hash("alice: 100") = 0xabc...
  hash("alice: 101") = 0x789...  (completely different!)

Can't fake fingerprint without knowing full state
Can prove any balance with Merkle proof
```

### Mental Model 3: Data Availability as a Backup

```
L1 Stores:
  - State root (the fingerprint)
  - State changes (the diff)

Like Git:
  - Current commit hash (state root)
  - Commit history (state changes)

Can reconstruct full state from:
  - Genesis state (empty)
  - All state changes (from L1)

Even if operator disappears!
```

### Mental Model 4: Three-Phase Commit as Escrow

```
COMMIT = "I put money in escrow"
  - Money set aside
  - Not yet transferred
  - Can still back out

PROVE = "I show proof of purchase"
  - Verified product is real
  - Verified price is correct
  - Still in escrow

EXECUTE = "Release funds"
  - Proof verified
  - Transfer is final
  - Cannot reverse
```

### Mental Model 5: ZK Proof as Sealed Envelope

```
Normal verification:
  "Here's my work, check it"
  Verifier re-does all work
  Expensive!

ZK proof:
  "Here's a sealed envelope with cryptographic seal"
  Verifier checks seal (cheap!)
  Seal can only be created if work is correct
  Don't need to see the work, just verify seal
```

---

## Design Evolution

### Phase 1: Trust (Sidechains)

```
L1: Ethereum
L2: Separate chain with own validators

Problem: Must trust L2 validators
```

**Security:** Trust-based (weak)

### Phase 2: Fraud Proofs (Optimistic Rollups)

```
L1: Ethereum
L2: Operator proposes state
Anyone: Can challenge with fraud proof

Problem: 7-day withdrawal delay
```

**Security:** Economic (good)

### Phase 3: Validity Proofs (ZK-Rollups)

```
L1: Ethereum
L2: Operator proposes state + proof
L1: Verifies proof immediately

Benefit: Instant finality
```

**Security:** Cryptographic (best)

### Phase 4: Data Availability (Current)

```
Without DA:
  State root on L1
  Full state controlled by operator

With DA (calldata):
  State root + state changes on L1
  Anyone can reconstruct
  Expensive! (~$1 per tx)

With DA (blobs):
  State root + state changes in blob
  Anyone can reconstruct
  Cheap! (~$0.01 per tx)
```

**Security:** Cryptographic + Decentralized (best)

---

## Security Checklist

### Before Launch

- [ ] **Accounting invariants enforced**
  - [ ] Total L2 balances proven in circuit
  - [ ] Invariant: L2_total + pending = deposits - withdrawn
  - [ ] Contract balance verified via L1 proof

- [ ] **Data availability guaranteed**
  - [ ] State diffs published (calldata or blob)
  - [ ] Blob commitments verified via point evaluation
  - [ ] Can reconstruct full state from L1 data

- [ ] **Deposit handling correct**
  - [ ] Priority queue for censorship resistance
  - [ ] Explicit deposit IDs (not queue positions)
  - [ ] Deposit range verified against L1 block

- [ ] **Withdrawal security**
  - [ ] Only recipient can claim (msg.sender check)
  - [ ] Double-withdrawal prevented (executed tracking)
  - [ ] Merkle proof binds recipient to amount

- [ ] **L1 state anchoring**
  - [ ] Batch anchored to specific L1 block
  - [ ] Account proof verifies contract balance
  - [ ] Block verified via blockhash or light client

- [ ] **Proof verification**
  - [ ] Public inputs include all critical values
  - [ ] Verifier contract audited
  - [ ] Cannot skip proof verification

- [ ] **Circuit correctness**
  - [ ] All state transitions enforced
  - [ ] Signature verification included
  - [ ] Nonce replay protection
  - [ ] Balance underflow checks

- [ ] **Emergency procedures**
  - [ ] Invariant checking functions
  - [ ] Circuit upgrade mechanism
  - [ ] Forced exit for users

### Ongoing Monitoring

- [ ] Invariant checks after each batch
- [ ] Data availability monitoring
- [ ] Proof generation time tracking
- [ ] Circuit utilization metrics

---

## Summary

### What Makes a Secure ZK-Rollup?

1. **ZK Proofs** → Can't fake state transitions
2. **Accounting Validation** → Can't inflate balances
3. **Data Availability** → Can't lose state
4. **L1 Anchoring** → Can't exploit timing
5. **Withdrawal Security** → Can't steal funds

### The Complete Picture

```
┌─────────────────────────────────────────────────────────┐
│                    L1 (Ethereum)                         │
│                                                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Rollup Contract                                  │  │
│  │  - Stores state roots                             │  │
│  │  - Verifies ZK proofs                            │  │
│  │  - Enforces accounting: L2_total = deposits - w  │  │
│  │  - Verifies L1 proofs: balance at block N       │  │
│  │  - Manages deposits/withdrawals                  │  │
│  └──────────────────────────────────────────────────┘  │
│                                                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Blob Storage (EIP-4844)                         │  │
│  │  - Stores compressed state diffs                 │  │
│  │  - Temporary (~18 days)                          │  │
│  │  - Enables state reconstruction                  │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                           ↕
              ZK Proofs + Data Availability
                           ↕
┌─────────────────────────────────────────────────────────┐
│                    L2 (Rollup)                           │
│                                                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Operator                                         │  │
│  │  - Collects transactions                          │  │
│  │  - Executes in EVM/VM                            │  │
│  │  - Builds batches                                 │  │
│  │  - Generates proofs                              │  │
│  └──────────────────────────────────────────────────┘  │
│                                                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │  State                                            │  │
│  │  - Full state (all balances)                     │  │
│  │  - Merkle tree representation                    │  │
│  │  - State root = commitment                       │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### Key Takeaways

1. **Proofs ensure correctness** - Can't fake state transitions
2. **Accounting ensures conservation** - Can't print money
3. **Data availability ensures liveness** - Can't lock funds
4. **L1 anchoring ensures consistency** - Can't exploit timing
5. **All together** - Secure, scalable, decentralized rollup

---

## Further Reading

See the accompanying documents for detailed implementations:

1. `PROOF_MECHANISM_ANALYSIS.md` - How zkSync Era's proof system works
2. `MINIMAL_ROLLUP_DESIGN.md` - Building a rollup from scratch
3. `MINIMAL_ROLLUP_WITH_ACCOUNTING.md` - Adding accounting invariants
4. `ROLLUP_WITH_L1_ANCHORING.md` - Snapshot-based L1 anchoring
5. `SIMPLE_L1_ANCHORING.md` - Proof-based L1 anchoring (recommended)

Each document builds on the previous, showing the evolution from a simple design to a production-ready ZK-rollup.
