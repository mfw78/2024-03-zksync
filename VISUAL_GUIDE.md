# Visual Guide to ZK-Rollups

## Table of Contents

1. [Architecture Diagrams](#architecture-diagrams)
2. [Flow Diagrams](#flow-diagrams)
3. [State Transitions](#state-transitions)
4. [Security Mechanisms](#security-mechanisms)
5. [Common Scenarios](#common-scenarios)

---

## Architecture Diagrams

### High-Level Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                         Users                                   │
│  (Send transactions, deposit, withdraw)                         │
└──────────────┬─────────────────────────────┬───────────────────┘
               │                             │
               │ L2 Transactions             │ L1 Transactions
               │                             │ (Deposits)
               ↓                             ↓
┌──────────────────────────────┐  ┌─────────────────────────────┐
│     L2 (Off-Chain)           │  │    L1 (Ethereum)            │
│                              │  │                             │
│  ┌────────────────────────┐ │  │  ┌───────────────────────┐ │
│  │  Sequencer/Operator    │ │  │  │  Rollup Contract      │ │
│  │  - Collects txs        │ │  │  │  - Stores roots       │ │
│  │  - Orders txs          │ │  │  │  - Verifies proofs    │ │
│  │  - Executes in VM      │ │  │  │  - Manages deposits   │ │
│  │  - Builds batches      │ │  │  │  - Handles withdrawals│ │
│  └────────────────────────┘ │  │  └───────────────────────┘ │
│               │              │  │            ↑               │
│               ↓              │  │            │               │
│  ┌────────────────────────┐ │  │            │ Commitments  │
│  │  State (Full)          │ │  │            │ + Proofs     │
│  │  alice: 100 ETH        │ │  │  ┌─────────┴─────────────┐ │
│  │  bob: 50 ETH           │ │  │  │  Blob Storage         │ │
│  │  charlie: 75 ETH       │ │  │  │  (EIP-4844)           │ │
│  │  ...                   │ │  │  │  - State diffs        │ │
│  └────────────────────────┘ │  │  │  - Compressed         │ │
│               │              │  │  │  - Temporary (~18d)   │ │
│               ↓              │  │  └───────────────────────┘ │
│  ┌────────────────────────┐ │  │                             │
│  │  State Root            │ │  │  ┌───────────────────────┐ │
│  │  0xabc...def           │───────→│  Light Client         │ │
│  └────────────────────────┘ │  │  │  - Verifies blocks    │ │
│               │              │  │  │  - Beacon chain sync  │ │
│               ↓              │  │  └───────────────────────┘ │
│  ┌────────────────────────┐ │  │                             │
│  │  Prover                │ │  └─────────────────────────────┘
│  │  - Generates ZK proofs │ │
│  │  - Takes hours         │ │
│  │  - Expensive compute   │ │
│  └────────────────────────┘ │
│               │              │
│               │ Proof        │
│               └──────────────┼─────────────→ (Submit to L1)
└──────────────────────────────┘
```

### Data Flow

```
USER TX FLOW:
─────────────

1. Submit     2. Sequence    3. Execute     4. State Change
   ┌─────┐       ┌─────┐        ┌─────┐        ┌─────┐
   │User │──────→│ Seq │───────→│ VM  │───────→│State│
   └─────┘       └─────┘        └─────┘        └─────┘
     │             │              │              │
     │             │              │              ↓
     │             │              │         ┌─────────┐
     │             │              │         │ Root    │
     │             │              │         │ Changes │
     │             │              │         └─────────┘
     │             │              │              │
     │             │              │              ↓
     │             │              │         ┌─────────┐
     │             │              └────────→│ Pubdata │
     │             │                        └─────────┘
     │             │                             │
     │             │                             ↓
     │             │                        ┌─────────┐
     │             └───────────────────────→│ Batch   │
     │                                      └─────────┘
     │                                           │
     │                                           ↓
     │                                      ┌─────────┐
     │                                      │ Prover  │
     │                                      └─────────┘
     │                                           │
     │                                           ↓ Proof
     │                                      ┌─────────┐
     └─────────────────────────────────────→│   L1    │
                                            └─────────┘
                                         (Verify & Finalize)
```

---

## Flow Diagrams

### Complete Transaction Lifecycle

```
TIME ──────────────────────────────────────────────────────────→

┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│  Submit  │  │  Batch   │  │  Commit  │  │  Prove   │  │  Execute │
│    TX    │→ │  Build   │→ │  on L1   │→ │  on L1   │→ │  on L1   │
└──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘
     │             │             │             │             │
     │ <1 sec      │ ~1 min      │ ~1 min      │ ~1 hour     │ ~1 min
     │             │             │             │             │
     ↓             ↓             ↓             ↓             ↓
  Pending      Sequenced     Committed      Proven       Finalized
                             (soft          (verified)   (cannot
                             confirm)                    revert)

What user can do:
  Pending:    See TX in mempool
  Sequenced:  See TX in batch
  Committed:  Use funds on L2 (with risk)
  Proven:     Use funds on L2 (safe)
  Finalized:  Withdraw to L1
```

### Deposit Flow

```
L1 (Ethereum)                           L2 (Rollup)
─────────────                           ───────────

 User
   │
   │ deposit(recipient)
   │ {value: 100 ETH}
   ↓
┌─────────────────┐
│ Rollup Contract │
│                 │
│ balance += 100  │
│ deposits.push() │
│ totalDep += 100 │
└────────┬────────┘
         │
         │ Event: DepositQueued
         │
         ↓
    ┌─────────┐
    │Priority │
    │ Queue   │
    └────┬────┘
         │
         │ Operator monitors
         │
         ↓                              Operator
                                           │
                                           │ Includes in batch
                                           ↓
                                    ┌─────────────┐
                                    │  Execute    │
                                    │  Deposit    │
                                    │             │
                                    │ state[r]    │
                                    │  += 100     │
                                    └──────┬──────┘
                                           │
                                           │ Update root
                                           ↓
                                    ┌─────────────┐
                                    │ New State   │
                                    │ Root        │
                                    └──────┬──────┘
                                           │
                                           │ Build batch
                                           │
         ┌─────────────────────────────────┘
         │
         │ commitBatch(batch + proof)
         ↓
┌─────────────────┐
│ Rollup Contract │
│                 │
│ ✓ Verify proof  │
│ ✓ Check deposits│
│ ✓ Store root    │
└─────────────────┘
         │
         │ After execution
         ↓
    Deposit complete!
    (User has 100 ETH on L2)
```

### Withdrawal Flow

```
L2 (Rollup)                             L1 (Ethereum)
───────────                             ─────────────

  User
    │
    │ withdraw(amount: 50)
    │ {signature}
    ↓
┌─────────────┐
│   Execute   │
│             │
│ state[user] │
│   -= 50     │
└──────┬──────┘
       │
       │ Add to withdrawal list
       ↓
┌─────────────┐
│ Withdrawals │
│   List      │
│             │
│ [{user, 50, │
│   index: 0}]│
└──────┬──────┘
       │
       │ Build Merkle tree
       ↓
┌─────────────┐
│ Withdrawals │
│   Root      │
│  0xdef...   │
└──────┬──────┘
       │
       │ Include in batch
       │
       │ commitBatch(batch)
       ↓                              ┌─────────────────┐
       ────────────────────────────→  │ Rollup Contract │
                                      │                 │
                                      │ ✓ Verify proof  │
                                      │ Store w_root    │
                                      │ pending += 50   │
                                      └────────┬────────┘
                                               │
                                               │ After execution
                                               │
                                        Withdrawal committed
                                        (but not executed)
                                               │
                                               │
  User                                         │
    │                                          │
    │ executeWithdrawal(                       │
    │   batch: 100,                            │
    │   index: 0,                              │
    │   recipient: user_L1,                    │
    │   amount: 50,                            │
    │   merkleProof: [...]                     │
    │ )                                        │
    └────────────────────────────────────────→ │
                                               ↓
                                      ┌─────────────────┐
                                      │ Rollup Contract │
                                      │                 │
                                      │ ✓ msg.sender == │
                                      │   recipient     │
                                      │ ✓ Merkle proof  │
                                      │ ✓ Not executed  │
                                      │                 │
                                      │ withdrawn += 50 │
                                      │ pending -= 50   │
                                      │                 │
                                      │ Transfer 50 ETH │
                                      └────────┬────────┘
                                               │
                                               ↓
                                          user_L1.call
                                          {value: 50}
                                               │
                                               ↓
                                        Withdrawal complete!
                                        (User has 50 ETH on L1)
```

---

## State Transitions

### Merkle Tree State Updates

```
BEFORE TRANSACTION:
───────────────────

         Root
      0xabc...def
        /      \
       /        \
   H(alice)   H(bob+charlie)
   [100]        /        \
             H(bob)    H(charlie)
             [50]       [75]

Alice: 100 ETH
Bob: 50 ETH
Charlie: 75 ETH


TRANSACTION:
────────────
Transfer: alice → bob (25 ETH)


AFTER TRANSACTION:
──────────────────

         Root
      0x123...456  ← Changed!
        /      \
       /        \
   H(alice)   H(bob+charlie)  ← Changed!
   [75]←         /        \
             H(bob)    H(charlie)
             [75]←      [75]

Alice: 75 ETH   ← Changed
Bob: 75 ETH     ← Changed
Charlie: 75 ETH (unchanged)


MERKLE PROOF for Bob:
─────────────────────

To prove Bob has 75 ETH:

Proof = [H(charlie), H(alice)]

Verification:
1. Compute H(bob) = hash(75)
2. Combine with H(charlie): H(bob+charlie)
3. Combine with H(alice): Root
4. Check Root == 0x123...456 ✓

Only need 2 hashes to prove, not entire tree!
```

### Batch State Progression

```
GENESIS STATE:
──────────────
State Root: 0x000...000
Total L2 Balances: 0 ETH
Deposits: 0 ETH
Withdrawn: 0 ETH

Invariant: 0 + 0 = 0 - 0 ✓


BATCH 1: Alice deposits 100 ETH
───────────────────────────────

L1 Action:
  Alice → deposit(alice) {value: 100}
  Contract balance: 100 ETH
  totalDeposited: 100 ETH

L2 Processing:
  state[alice] = 0 + 100 = 100
  newRoot = compute_merkle_root({alice: 100})

Commitment:
  prevRoot: 0x000...000
  newRoot: 0xabc...def
  totalL2Balances: 100
  depositsInBatch: 100

Verification:
  ✓ Proof valid for state transition
  ✓ 100 + 0 = 0 + 100 - 0
  ✓ Invariant holds

After Execution:
  State Root: 0xabc...def
  Total L2 Balances: 100 ETH
  Deposits: 100 ETH
  Withdrawn: 0 ETH

Invariant: 100 + 0 = 100 - 0 ✓


BATCH 2: Bob deposits 50, Alice → Bob (25)
───────────────────────────────────────────

L1 Action:
  Bob → deposit(bob) {value: 50}
  Contract balance: 150 ETH
  totalDeposited: 150 ETH

L2 Processing:
  # Process deposit
  state[bob] = 0 + 50 = 50

  # Process transfer
  state[alice] = 100 - 25 = 75
  state[bob] = 50 + 25 = 75

  newRoot = compute_merkle_root({
    alice: 75,
    bob: 75
  })

Commitment:
  prevRoot: 0xabc...def
  newRoot: 0x123...456
  totalL2Balances: 150
  depositsInBatch: 50

Verification:
  ✓ Proof valid
  ✓ 150 + 0 = 100 + 50 - 0
  ✓ Invariant holds

After Execution:
  State Root: 0x123...456
  Total L2 Balances: 150 ETH
  Deposits: 150 ETH
  Withdrawn: 0 ETH

Invariant: 150 + 0 = 150 - 0 ✓


BATCH 3: Alice withdraws 30
───────────────────────────

L2 Processing:
  # Withdrawal
  state[alice] = 75 - 30 = 45
  withdrawals = [{alice_L1, 30, 0}]

  newRoot = compute_merkle_root({
    alice: 45,
    bob: 75
  })

Commitment:
  prevRoot: 0x123...456
  newRoot: 0x789...abc
  totalL2Balances: 120
  pendingWithdrawals: 30
  withdrawalsRoot: merkle_root(withdrawals)

Verification:
  ✓ Proof valid
  ✓ 120 + 30 = 150 - 0
  ✓ Invariant holds

After Execution:
  State Root: 0x789...abc
  Total L2 Balances: 120 ETH
  Deposits: 150 ETH
  Pending Withdrawals: 30 ETH
  Withdrawn: 0 ETH

Invariant: 150 = 120 + 30 + 0 ✓


WITHDRAWAL EXECUTION:
─────────────────────

L1 Action:
  Alice → executeWithdrawal(batch: 3, ...)

Verification:
  ✓ Merkle proof valid
  ✓ msg.sender == alice_L1
  ✓ Not already executed

Updates:
  totalWithdrawn: 30 ETH
  pendingWithdrawals: 0 ETH
  Contract balance: 150 - 30 = 120 ETH

After Withdrawal:
  State Root: 0x789...abc (unchanged)
  Total L2 Balances: 120 ETH
  Deposits: 150 ETH
  Pending Withdrawals: 0 ETH
  Withdrawn: 30 ETH

Invariant: 120 = 150 - 30 ✓
Contract balance: 120 = 150 - 30 ✓
```

---

## Security Mechanisms

### ZK Proof Verification

```
CIRCUIT CONSTRAINTS:
────────────────────

Input State:
  prev_root: 0xabc...
  state = {alice: 100, bob: 50}

Transaction:
  alice → bob (25)
  signature: 0x123...

CIRCUIT MUST VERIFY:
┌────────────────────────────────────┐
│ 1. Signature Valid                 │
│    ecrecover(hash(tx), sig)        │
│    == alice ✓                      │
├────────────────────────────────────┤
│ 2. Nonce Correct                   │
│    nonce[alice] == tx.nonce ✓      │
├────────────────────────────────────┤
│ 3. Sufficient Balance              │
│    state[alice] >= 25 ✓            │
│    100 >= 25 ✓                     │
├────────────────────────────────────┤
│ 4. State Update Correct            │
│    new_state[alice] = 100 - 25     │
│    new_state[bob] = 50 + 25        │
├────────────────────────────────────┤
│ 5. Merkle Root Correct             │
│    compute_root(new_state)         │
│    == new_root ✓                   │
├────────────────────────────────────┤
│ 6. Conservation                    │
│    sum(prev_state) == sum(new_state)│
│    150 == 150 ✓                    │
└────────────────────────────────────┘

If ANY constraint fails:
  → Proof generation FAILS
  → Cannot create valid proof
  → Cannot submit to L1

This is why fraud is impossible!
```

### Accounting Enforcement

```
DEPOSIT FLOW:
─────────────

L1 State Before:
  contract.balance = 1000 ETH
  totalDeposited = 1000 ETH

User deposits 100 ETH:
  contract.balance = 1100 ETH ✓
  totalDeposited = 1100 ETH ✓

Batch Processing:
  L2_balances_before = 1000
  deposits_in_batch = 100
  L2_balances_after = 1100

  Circuit proves:
    L2_balances_after = L2_balances_before + deposits
    1100 = 1000 + 100 ✓

L1 Verification:
  Check: L2_balances == totalDeposited - totalWithdrawn
  1100 == 1100 - 0 ✓

  If operator tried to inflate:
    L2_balances_after = 1200  (fraud!)
    Check: 1200 == 1100 - 0  ✗ FAILS


WITHDRAWAL FLOW:
────────────────

L2 State:
  alice: 100 ETH

Alice withdraws 30:
  state[alice] = 70
  pending_withdrawals += 30

  Circuit proves:
    70 + 30 = 100 ✓

L1 Verification:
  Check: L2_total + pending == deposits - withdrawn
  970 + 30 == 1100 - 100 ✓

Withdrawal Execution:
  totalWithdrawn += 30
  pending -= 30
  contract.balance -= 30

  Check: 970 + 0 == 1100 - 130 ✓
  Contract balance: 970 == 1100 - 130 ✓


INVARIANT ALWAYS HOLDS:
───────────────────────

contract.balance = totalDeposited - totalWithdrawn
L2_total + pending = totalDeposited - totalWithdrawn

Therefore:
contract.balance = L2_total + pending

This is enforced:
  - By circuit (proves L2_total)
  - By L1 contract (checks invariant)
  - Cryptographically impossible to break!
```

### L1 State Anchoring

```
TIMING ATTACK PREVENTED:
────────────────────────

Block 1000:
┌─────────────────────────────┐
│ L1 State                    │
│ - blockhash: 0xabc...       │
│ - stateRoot: 0xdef...       │
│ - contract.balance: 1000    │
│                             │
│ Account Proof:              │
│   [0x123, 0x456, ...]       │
│   ↓                         │
│   proves balance = 1000     │
└─────────────────────────────┘
          │
          │ Operator uses this
          ↓
    ┌──────────────┐
    │ Build Batch  │
    │              │
    │ Anchor:      │
    │  block: 1000 │
    │  hash: 0xabc │
    │  balance:1000│
    └──────────────┘
          │
          │ Time passes...
          ↓
Block 1050:
          │ New deposits arrive
          │ balance now = 1500
          │
          ↓ Commit batch
    ┌──────────────┐
    │ L1 Contract  │
    │              │
    │ Verify:      │
    │ ✓ blockhash  │
    │   (1000)     │
    │ ✓ account    │
    │   proof      │
    │ ✓ balance at │
    │   block 1000 │
    │   = 1000     │
    │              │
    │ Check:       │
    │ L2_total ==  │
    │ 1000 + deps  │
    └──────────────┘

Operator CANNOT:
  - Claim balance = 1500 at block 1000
    (account proof won't verify)

  - Use current balance without anchor
    (would create timing window)

  - Exploit race conditions
    (anchored to specific historical state)
```

---

## Common Scenarios

### Scenario 1: Normal Operation

```
Day 1, 9:00 AM - Alice deposits
─────────────────────────────────
L1: Alice → deposit(100 ETH)
    ✓ Funds locked in contract
    ✓ Event emitted

L2: Operator includes in next batch
    ✓ state[alice] += 100
    ✓ Batch built within 1 minute

L1: Operator commits batch
    ✓ Proof verified
    ✓ State root updated
    ✓ Alice can use funds on L2

Status: COMPLETE (< 2 minutes)


Day 1, 3:00 PM - Alice sends to Bob
────────────────────────────────────
L2: Alice → transfer(bob, 25)
    ✓ Signature verified
    ✓ Balance checked
    ✓ State updated
    ✓ Included in batch

L1: Batch committed + proven
    ✓ Bob receives funds on L2

Status: COMPLETE (< 5 minutes)


Day 2, 10:00 AM - Bob withdraws
────────────────────────────────
L2: Bob → withdraw(50)
    ✓ Balance deducted
    ✓ Withdrawal committed in batch

L1: Batch executed
    ✓ Withdrawal becomes claimable

L1: Bob → executeWithdrawal()
    ✓ Merkle proof verified
    ✓ 50 ETH sent to Bob's L1 address

Status: COMPLETE (< 1 hour total)
```

### Scenario 2: Operator Goes Offline

```
Time: Day 1, 12:00 PM
─────────────────────
Operator: OFFLINE (server crashed)

Pending transactions:
  - Alice → Bob (10 ETH)
  - Charlie → Dave (20 ETH)
  - 50 more transactions...


Hour 1 (12:00-1:00 PM)
──────────────────────
Users: Notice transactions not processing
Action: Wait (operator might recover)


Hour 2 (1:00-2:00 PM)
─────────────────────
Users: Still stuck
Action: Submit transactions via L1 priority queue

L1: User → forceIncludeTransaction(tx)
    ✓ TX added to priority queue
    ✓ MUST be processed within N batches


Hour 3 (2:00-3:00 PM)
─────────────────────
Operator: Still offline
Users: Full state is available on L1!
        (All batches have pubdata in blobs)

New Operator:
  1. Download all blobs from L1
  2. Reconstruct full L2 state
  3. Start processing transactions
  4. Include priority queue transactions

Result: Liveness restored!
        No funds lost!
        Decentralized continuation!
```

### Scenario 3: Malicious Operator Attempts

```
ATTACK 1: Steal Funds
─────────────────────

Operator tries:
  state[operator] += 1000 ETH  (no deposit!)

Circuit verification:
  ✗ No deposit for 1000 ETH
  ✗ Proof generation FAILS

Result: Cannot submit to L1
        Attack prevented ✓


ATTACK 2: Fake Deposit
──────────────────────

Operator tries:
  Include fake deposit in batch
  depositsHash = hash([fake_deposit])

L1 verification:
  expected = hash(actual_priority_queue)
  require(depositsHash == expected)
  ✗ FAILS (hashes don't match)

Result: commitBatch() reverts
        Attack prevented ✓


ATTACK 3: Double Withdrawal
────────────────────────────

User withdraws 100 ETH:
  L2: state[user] -= 100
  L1: Batch committed with withdrawal

Operator tries to execute withdrawal twice:

First execution:
  ✓ Merkle proof valid
  ✓ Not yet executed
  ✓ Transfer 100 ETH
  ✓ Mark as executed

Second execution:
  ✓ Merkle proof valid (still!)
  ✗ Already executed
  ✗ Transaction REVERTS

Result: Attack prevented ✓


ATTACK 4: Timing Attack
───────────────────────

Block 1000: Operator builds batch
            totalDeposited = 1000

Operator inflates L2 by 100 ETH

Block 1010: New deposit arrives (+100 ETH)
            totalDeposited = 1100

Block 1015: Operator commits:
            L2_total = 1100 (includes fake 100)
            totalDeposited = 1100

OLD CONTRACT (vulnerable):
  Check: 1100 == 1100 ✓
  Attack succeeds ✗

NEW CONTRACT (with anchoring):
  Anchor block: 1000
  Account proof: balance = 1000 at block 1000
  Check: 1100 == 1000 + 0
  ✗ FAILS

Result: Attack prevented ✓
```

### Scenario 4: Emergency Exit

```
Situation: Critical bug found in ZK circuit
───────────────────────────────────────────

Time: Day 1, 8:00 AM
────────────────────
Discovery: Circuit allows double-spending

Action: FREEZE CONTRACT

L1 Contract:
  function emergencyFreeze() onlyOwner {
      frozen = true;
  }

Effects:
  ✗ No new batches can be committed
  ✗ No new withdrawals can be executed
  ✓ Existing funds safe (locked)


Time: Day 1, 9:00 AM - Investigation
─────────────────────────────────────
Team:
  1. Analyze bug
  2. Determine affected batches
  3. Calculate actual valid state
  4. Prepare fix


Time: Day 1, 12:00 PM - Fix Deployed
─────────────────────────────────────
Actions:
  1. Deploy new circuit
  2. Deploy new verifier contract
  3. Revert invalid batches
  4. Set correct state root

L1 Contract:
  function emergencyRecover(
      uint256 validBatchNumber,
      bytes32 validStateRoot
  ) onlyOwner {
      // Revert to last valid state
      currentBatch = validBatchNumber;
      stateRoot = validStateRoot;

      // Update verifier
      verifier = newVerifier;

      // Unfreeze
      frozen = false;
  }


Time: Day 1, 1:00 PM - Resume
──────────────────────────────
Status: Normal operation resumed
Users: Can continue using rollup
Funds: All safe

Lesson: Emergency procedures critical!
```

---

## Putting It All Together

### The Complete Security Picture

```
┌─────────────────────────────────────────────────────────────┐
│                    SECURITY LAYERS                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Layer 1: ZK Proof                                          │
│  ─────────────────                                          │
│  ✓ Circuit enforces all state transition rules             │
│  ✓ Cannot create proof for invalid execution               │
│  ✓ Cryptographic guarantee (SNARK soundness)               │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Layer 2: Accounting Invariants                             │
│  ───────────────────────────                                │
│  ✓ Total L2 balances proven in circuit                     │
│  ✓ Invariant checked on L1: L2 + pending = deps - w        │
│  ✓ Cannot inflate balances beyond deposits                 │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Layer 3: L1 State Anchoring                                │
│  ────────────────────────                                   │
│  ✓ Batch anchored to specific L1 block                     │
│  ✓ Balance proven via Merkle proof                         │
│  ✓ Block verified via blockhash/light client               │
│  ✓ No timing attacks possible                              │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Layer 4: Data Availability                                 │
│  ───────────────────────                                    │
│  ✓ State diffs published to L1 (blobs)                     │
│  ✓ Blob verified via point evaluation                      │
│  ✓ Anyone can reconstruct full state                       │
│  ✓ Decentralized liveness guarantee                        │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Layer 5: Withdrawal Security                               │
│  ─────────────────────────                                  │
│  ✓ Only recipient can claim (msg.sender check)             │
│  ✓ Merkle proof binds recipient to amount                  │
│  ✓ Double-withdrawal prevented (tracking)                  │
│  ✓ Amount deducted from L2 before claimable                │
│                                                             │
└─────────────────────────────────────────────────────────────┘

Result: Defense in depth
        Multiple layers must all fail for exploit
        Cryptographic + Economic + Social security
```

### Quick Reference: What Prevents What

```
╔════════════════════════════╦═══════════════════════════════════╗
║ ATTACK                     ║ PREVENTION MECHANISM              ║
╠════════════════════════════╬═══════════════════════════════════╣
║ Steal funds                ║ ZK proof + Accounting invariant   ║
║ Inflate balances           ║ Circuit proves totals + L1 check  ║
║ Fake deposits              ║ Priority queue verification       ║
║ Skip deposits              ║ Explicit deposit IDs + range check║
║ Timing attack              ║ L1 block anchoring + account proof║
║ Fake L1 state              ║ Blockhash / light client verify   ║
║ Wrong withdrawal recipient ║ msg.sender check + Merkle binding ║
║ Double withdrawal          ║ Executed tracking mapping         ║
║ Withhold state             ║ Data availability (blobs)         ║
║ Censor forever             ║ Priority queue + forced inclusion ║
║ Invalid state transition   ║ ZK circuit constraints            ║
║ Wrong state root           ║ Circuit computes + L1 stores      ║
╚════════════════════════════╩═══════════════════════════════════╝
```

---

## Summary

The key to understanding ZK-rollups:

1. **State** is represented as a Merkle root
2. **Proofs** verify state transitions are valid
3. **Accounting** ensures no funds created from thin air
4. **Anchoring** prevents timing exploits
5. **Data availability** enables decentralized reconstruction
6. **All together** creates a secure, scalable system

Each layer builds on the previous, creating defense in depth that makes the system trustless and secure.
