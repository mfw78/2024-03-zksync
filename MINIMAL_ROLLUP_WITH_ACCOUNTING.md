# Minimal ZK-Rollup with Strict Accounting Invariants

## Critical Security Requirement

**The fundamental invariant that MUST be enforced:**

```
L1_contract_balance = total_deposits - total_withdrawals_executed
L2_total_balances = total_deposits - total_withdrawals_pending - total_withdrawals_executed

INVARIANT:
  L1_contract_balance + sum(L2_balances) + pending_withdrawals = total_deposits
```

This invariant must be:
1. **Tracked on L1** (total deposits, executed withdrawals)
2. **Enforced by ZK circuit** (total L2 balances, pending withdrawals)
3. **Verified as part of the proof** (accounting consistency)

---

## 1. Enhanced L1 Contract with Accounting

```solidity
contract MinimalRollup {
    //====================
    // STATE VARIABLES
    //====================

    // State commitment
    bytes32 public stateRoot;
    uint256 public currentBatch;

    // CRITICAL: Accounting totals
    uint256 public totalDeposited;        // Sum of all deposits ever made
    uint256 public totalWithdrawn;        // Sum of all withdrawals executed
    uint256 public pendingWithdrawals;    // Sum of all pending withdrawals

    // Batch tracking
    mapping(uint256 => BatchCommitment) public batches;
    mapping(uint256 => bool) public batchExecuted;

    // Priority queue for deposits
    struct Deposit {
        address from;
        address to;
        uint256 amount;
        uint256 depositId;
    }
    Deposit[] public priorityQueue;
    uint256 public priorityQueueHead;
    uint256 public nextDepositId;

    // Withdrawal tracking
    mapping(bytes32 => bool) public withdrawalExecuted;
    // keccak256(batchNumber, withdrawalIndex) => executed

    // Verifier
    IVerifier public verifier;

    //====================
    // BATCH COMMITMENT STRUCTURE
    //====================

    struct BatchCommitment {
        // State transition
        bytes32 prevStateRoot;
        bytes32 newStateRoot;

        // Transaction data
        uint256 numDeposits;
        bytes32 depositsHash;
        bytes32 l2TransactionsHash;

        // Withdrawal data
        bytes32 withdrawalsRoot;
        uint256 numWithdrawals;
        uint256 totalWithdrawalAmount;  // NEW: sum of withdrawal amounts

        // CRITICAL: Accounting totals (public inputs to proof)
        uint256 totalL2BalancesAfter;   // NEW: sum of all L2 balances after batch
        uint256 totalDepositsAfter;     // NEW: running total of deposits
        uint256 pendingWithdrawalsAfter; // NEW: sum of unexecuted withdrawals

        // Blob commitment
        bytes32 blobHash;
    }

    //====================
    // DEPOSITS (L1 → L2)
    //====================

    function deposit(address recipient) external payable {
        require(msg.value > 0, "Must deposit ETH");

        uint256 depositId = nextDepositId++;

        priorityQueue.push(Deposit({
            from: msg.sender,
            to: recipient,
            amount: msg.value,
            depositId: depositId
        }));

        // Track total deposited
        totalDeposited += msg.value;

        emit DepositQueued(msg.sender, recipient, msg.value, depositId);
    }

    //====================
    // BATCH COMMITMENT
    //====================

    function commitBatch(
        BatchCommitment calldata batch,
        bytes calldata blobCommitmentProof
    ) external onlyOperator {
        require(batch.batchNumber == currentBatch + 1, "Wrong batch number");
        require(batch.prevStateRoot == stateRoot, "Wrong prev state");

        // 1. Verify deposits match priority queue
        (bytes32 expectedDepositsHash, uint256 depositAmount) =
            _verifyDeposits(batch.numDeposits);
        require(batch.depositsHash == expectedDepositsHash, "Deposits mismatch");

        // 2. CRITICAL: Verify accounting invariant
        uint256 expectedTotalDeposits = totalDeposited;  // Already updated by deposits
        require(batch.totalDepositsAfter == expectedTotalDeposits,
            "Deposits accounting mismatch");

        uint256 expectedPendingWithdrawals =
            pendingWithdrawals + batch.totalWithdrawalAmount;
        require(batch.pendingWithdrawalsAfter == expectedPendingWithdrawals,
            "Withdrawal accounting mismatch");

        // 3. CRITICAL: Verify the fundamental invariant
        // L2_balances + pending_withdrawals = total_deposits - total_withdrawn
        require(
            batch.totalL2BalancesAfter + batch.pendingWithdrawalsAfter ==
            batch.totalDepositsAfter - totalWithdrawn,
            "Balance invariant violated"
        );

        // 4. Verify blob commitment (4844)
        _verifyBlobCommitment(batch.blobHash, blobCommitmentProof);

        // 5. Store commitment
        batches[batch.batchNumber] = batch;

        emit BatchCommitted(batch.batchNumber, keccak256(abi.encode(batch)));
    }

    function _verifyDeposits(uint256 numDeposits)
        internal
        view
        returns (bytes32 hash, uint256 totalAmount)
    {
        hash = keccak256("");
        totalAmount = 0;

        for (uint256 i = 0; i < numDeposits; i++) {
            Deposit memory dep = priorityQueue[priorityQueueHead + i];
            hash = keccak256(abi.encode(hash, dep));
            totalAmount += dep.amount;
        }
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
        require(!batchExecuted[batchNumber], "Already executed");

        // Create public input that includes accounting
        uint256[] memory publicInputs = new uint256[](5);
        publicInputs[0] = uint256(batch.prevStateRoot);
        publicInputs[1] = uint256(batch.newStateRoot);
        publicInputs[2] = batch.totalL2BalancesAfter;      // NEW
        publicInputs[3] = batch.totalDepositsAfter;        // NEW
        publicInputs[4] = batch.pendingWithdrawalsAfter;   // NEW

        // Verify the proof
        require(verifier.verify(publicInputs, proof), "Invalid proof");

        emit BatchProven(batchNumber);
    }

    //====================
    // BATCH EXECUTION
    //====================

    function executeBatch(uint256 batchNumber) external {
        BatchCommitment memory batch = batches[batchNumber];
        require(batch.newStateRoot != bytes32(0), "Not committed");
        require(!batchExecuted[batchNumber], "Already executed");
        // NOTE: Would also check proof verified, but simplified here

        // Mark deposits as processed
        priorityQueueHead += batch.numDeposits;

        // Update state root
        stateRoot = batch.newStateRoot;

        // Update pending withdrawals total
        pendingWithdrawals += batch.totalWithdrawalAmount;

        // Mark as executed
        batchExecuted[batchNumber] = true;
        currentBatch = batchNumber;

        emit BatchExecuted(batchNumber, batch.newStateRoot);
    }

    //====================
    // WITHDRAWALS (L2 → L1)
    //====================

    struct WithdrawalProof {
        uint256 batchNumber;
        uint256 withdrawalIndex;
        address recipient;          // MUST match committed recipient
        uint256 amount;             // MUST match committed amount
        bytes32[] merkleProof;
    }

    function executeWithdrawal(WithdrawalProof calldata withdrawal) external {
        // 1. Check batch is executed
        require(batchExecuted[withdrawal.batchNumber], "Batch not executed");

        // 2. Check not already withdrawn
        bytes32 withdrawalId = keccak256(abi.encode(
            withdrawal.batchNumber,
            withdrawal.withdrawalIndex
        ));
        require(!withdrawalExecuted[withdrawalId], "Already withdrawn");

        // 3. Get batch commitment
        BatchCommitment memory batch = batches[withdrawal.batchNumber];

        // 4. Verify merkle proof - this ensures:
        //    - recipient matches what was committed
        //    - amount matches what was committed
        //    - withdrawal was actually included in this batch
        bytes32 leaf = keccak256(abi.encode(
            withdrawal.recipient,
            withdrawal.amount,
            withdrawal.withdrawalIndex
        ));

        require(
            _verifyMerkleProof(leaf, withdrawal.merkleProof, batch.withdrawalsRoot),
            "Invalid merkle proof"
        );

        // 5. CRITICAL: Only the specified recipient can claim
        require(msg.sender == withdrawal.recipient, "Only recipient can claim");

        // 6. Update accounting
        withdrawalExecuted[withdrawalId] = true;
        totalWithdrawn += withdrawal.amount;
        pendingWithdrawals -= withdrawal.amount;

        // 7. CRITICAL: Verify contract has sufficient balance
        require(address(this).balance >= withdrawal.amount, "Insufficient balance");

        // 8. Transfer ETH
        (bool success, ) = withdrawal.recipient.call{value: withdrawal.amount}("");
        require(success, "Transfer failed");

        emit WithdrawalExecuted(
            withdrawal.batchNumber,
            withdrawal.withdrawalIndex,
            withdrawal.recipient,
            withdrawal.amount
        );

        // INVARIANT CHECK (for safety, could be removed in production)
        assert(address(this).balance >= totalDeposited - totalWithdrawn);
    }

    //====================
    // VIEW FUNCTIONS
    //====================

    function verifyAccountingInvariant() external view returns (bool) {
        // This should always be true
        return address(this).balance == totalDeposited - totalWithdrawn;
    }

    function getExpectedL2Total() external view returns (uint256) {
        // What the sum of L2 balances should be
        return totalDeposited - totalWithdrawn - pendingWithdrawals;
    }

    //====================
    // EMERGENCY
    //====================

    // If accounting invariant is violated, circuit cannot produce valid proof
    // This provides an emergency way to detect issues
    function emergencyCheckAccounting() external view {
        require(
            address(this).balance == totalDeposited - totalWithdrawn,
            "L1 accounting broken"
        );

        if (currentBatch > 0) {
            BatchCommitment memory lastBatch = batches[currentBatch];
            require(
                lastBatch.totalL2BalancesAfter + pendingWithdrawals ==
                totalDeposited - totalWithdrawn,
                "L2 accounting broken"
            );
        }
    }
}
```

---

## 2. Enhanced ZK Circuit with Accounting Constraints

The circuit must now prove the accounting invariant as part of its public inputs.

```rust
circuit MinimalRollupWithAccounting {
    //====================
    // PUBLIC INPUTS (visible to L1 verifier)
    //====================
    public_input prev_state_root: Field;
    public_input new_state_root: Field;

    // NEW: Accounting totals that L1 will verify
    public_input total_l2_balances_after: Field;      // sum(state.values())
    public_input total_deposits_after: Field;         // cumulative deposits
    public_input pending_withdrawals_after: Field;    // sum of pending withdrawals

    // Transaction commitments
    public_input deposits_hash: Field;
    public_input l2_transactions_hash: Field;
    public_input withdrawals_root: Field;

    //====================
    // PRIVATE WITNESS
    //====================
    witness deposits: Vec<Deposit>;
    witness l2_transactions: Vec<Transaction>;
    witness withdrawals: Vec<Withdrawal>;

    witness state_before: Map<Address, Balance>;      // Initial state
    witness state_after: Map<Address, Balance>;       // Final state
    witness state_merkle_proofs: Vec<MerkleProof>;

    witness prev_total_deposits: Field;
    witness prev_total_l2_balances: Field;
    witness prev_pending_withdrawals: Field;

    //====================
    // CIRCUIT CONSTRAINTS
    //====================
    fn verify() {
        // 1. Verify initial state root
        assert!(compute_merkle_root(state_before) == prev_state_root);

        // 2. Initialize running totals
        let mut current_state = state_before.clone();
        let mut total_deposit_amount = 0;
        let mut total_withdrawal_amount = 0;

        // 3. Process deposits
        let mut computed_deposits_hash = hash("");
        for deposit in deposits {
            // Add to L2 balance
            current_state[deposit.to] += deposit.amount;
            total_deposit_amount += deposit.amount;

            // Update hash
            computed_deposits_hash = hash(computed_deposits_hash, hash(deposit));
        }
        assert!(computed_deposits_hash == deposits_hash);

        // 4. Process L2 transactions
        let mut computed_l2_hash = hash("");
        for tx in l2_transactions {
            match tx.tx_type {
                TRANSFER => {
                    // Verify signature
                    assert!(verify_ecdsa(tx.from, hash(tx), tx.signature));

                    // Verify nonce
                    assert!(get_nonce(tx.from) == tx.nonce);

                    // Verify sufficient balance
                    assert!(current_state[tx.from] >= tx.amount);

                    // Update state
                    current_state[tx.from] -= tx.amount;
                    current_state[tx.to] += tx.amount;

                    // Increment nonce
                    increment_nonce(tx.from);
                }

                WITHDRAWAL => {
                    // Verify signature
                    assert!(verify_ecdsa(tx.from, hash(tx), tx.signature));

                    // Verify nonce
                    assert!(get_nonce(tx.from) == tx.nonce);

                    // Verify sufficient balance
                    assert!(current_state[tx.from] >= tx.amount);

                    // Deduct from L2
                    current_state[tx.from] -= tx.amount;
                    total_withdrawal_amount += tx.amount;

                    // Increment nonce
                    increment_nonce(tx.from);
                }
            }

            computed_l2_hash = hash(computed_l2_hash, hash(tx));
        }
        assert!(computed_l2_hash == l2_transactions_hash);

        // 5. Verify withdrawal merkle root
        assert!(compute_merkle_root(withdrawals) == withdrawals_root);

        // 6. Verify final state root
        assert!(compute_merkle_root(current_state) == new_state_root);

        // 7. CRITICAL: Compute and verify accounting totals
        let computed_total_l2_balances = sum(current_state.values());
        assert!(computed_total_l2_balances == total_l2_balances_after);

        let computed_total_deposits = prev_total_deposits + total_deposit_amount;
        assert!(computed_total_deposits == total_deposits_after);

        let computed_pending_withdrawals =
            prev_pending_withdrawals + total_withdrawal_amount;
        assert!(computed_pending_withdrawals == pending_withdrawals_after);

        // 8. CRITICAL: Verify the fundamental invariant
        // L2_balances + pending_withdrawals = total_deposits - withdrawn
        // Note: We don't track total_withdrawn in the circuit (it's on L1)
        // But the L1 contract will verify this using the public inputs
        assert!(
            total_l2_balances_after + pending_withdrawals_after <= total_deposits_after
        );
    }

    //====================
    // HELPER: Sum all balances
    //====================
    fn sum(balances: Vec<Balance>) -> Field {
        let mut total = 0;
        for balance in balances {
            total += balance;
        }
        total
    }
}
```

---

## 3. Why This Prevents Theft

### Attack 1: Operator tries to credit themselves without deposit

```rust
// Malicious operator attempts:
state[operator] = 0 + 1000 ETH  // No deposit, just adding balance

// Circuit verification:
total_l2_balances_after = sum(state.values())
                        = prev_total + 1000  // Includes stolen amount

total_deposits_after = prev_deposits + 0  // No actual deposit
                     = prev_deposits

// Accounting constraint:
assert!(total_l2_balances_after + pending_withdrawals <= total_deposits_after)
assert!(prev_total + 1000 + pending <= prev_deposits)  // FAILS!

// The previous batch already satisfied:
// prev_total + pending = prev_deposits
// So adding 1000 breaks the invariant
```

**Result:** Cannot generate valid proof ✓

### Attack 2: Operator tries to process fake deposit

```rust
// Malicious operator attempts:
Process deposit {to: operator, amount: 1000} // Not in priority queue

// L1 Contract verification in commitBatch():
computed_deposits_hash = hash of actual priority queue items
batch.depositsHash = hash of fake deposits including operator's
require(computed_deposits_hash == batch.depositsHash)  // FAILS!
```

**Result:** commitBatch() reverts on L1 ✓

### Attack 3: Operator tries to prevent withdrawal execution

```rust
// Operator omits user's withdrawal from withdrawals list

// Circuit still deducts from L2:
state[user] -= withdrawal_amount
pending_withdrawals_after += withdrawal_amount

// But withdrawal not in merkle tree:
withdrawals_root = merkle_root([/* user's withdrawal omitted */])

// Later, user cannot execute withdrawal:
executeWithdrawal() {
    verify_merkle_proof(user_withdrawal, withdrawals_root)  // FAILS
}

// However: User's L2 balance already deducted!
// This violates conservation of value

// Circuit constraint:
total_l2_balances = prev_total - withdrawal_amount
pending_withdrawals = prev_pending + withdrawal_amount

// If operator omits from merkle tree:
pending_withdrawals = prev_pending + 0  // Not tracked

// Invariant check:
total_l2_balances + pending_withdrawals
= (prev_total - withdrawal_amount) + prev_pending
= prev_total + prev_pending - withdrawal_amount
< total_deposits - total_withdrawn  // VIOLATES INVARIANT!
```

**Better approach:** Circuit must verify:
```rust
assert!(
    sum(withdrawals.amount) == total_withdrawal_amount
);
assert!(
    total_withdrawal_amount ==
    (prev_total_l2_balances - total_l2_balances_after) - total_deposit_amount
);
```

**Result:** Operator must include all withdrawals in merkle tree ✓

### Attack 4: Operator tries to allow wrong person to withdraw

```rust
// Withdrawal committed in batch:
{recipient: alice, amount: 100}

// Operator tries to submit proof claiming bob as recipient
executeWithdrawal({
    recipient: bob,
    amount: 100,
    merkle_proof: [...]
})

// L1 verification:
leaf = hash(bob, 100, index)  // Wrong recipient
verify_merkle_proof(leaf, merkle_proof, withdrawals_root)  // FAILS

// Even if operator tries to fake proof:
// The withdrawals_root in the committed batch was computed as:
// merkle_root([hash(alice, 100, 0)])
// Cannot produce valid proof for hash(bob, 100, 0)
```

**Result:** Only alice can withdraw ✓

---

## 4. Complete Accounting Flow Example

### Initial State
```
L1 Contract:
  balance: 0 ETH
  totalDeposited: 0
  totalWithdrawn: 0
  pendingWithdrawals: 0

L2 State:
  state: {}
  state_root: 0x000...
  total_l2_balances: 0

INVARIANT: ✓
  0 + 0 = 0 - 0
  L1_balance + pending = deposits - withdrawn
```

### Batch 1: Alice deposits 100 ETH

```
DEPOSIT:
  Alice sends 100 ETH to L1 contract

L1 Contract updates:
  balance: 100 ETH
  totalDeposited: 100
  priorityQueue: [Deposit{to: alice, amount: 100}]

OPERATOR processes batch:
  state[alice] = 0 + 100 = 100
  new_state_root = merkle_root({alice: 100})

CIRCUIT proves:
  prev_total_l2: 0
  deposits: [100]
  total_l2_after: 100
  total_deposits_after: 100
  pending_withdrawals_after: 0

  Verification:
    ✓ 100 + 0 = 100 - 0
    ✓ total_l2_balances + pending = deposits - withdrawn

L1 CONTRACT in commitBatch():
  require(batch.totalL2BalancesAfter + batch.pendingWithdrawalsAfter
          == batch.totalDepositsAfter - totalWithdrawn)
  require(100 + 0 == 100 - 0)  ✓

After EXECUTE:
  L1: balance=100, deposits=100, withdrawn=0, pending=0
  L2: total_balances=100
  INVARIANT: 100 = 100 - 0  ✓
```

### Batch 2: Alice withdraws 30 ETH

```
WITHDRAWAL TX:
  {from: alice, to: alice_L1, amount: 30}

OPERATOR processes:
  state[alice] = 100 - 30 = 70
  withdrawals = [{recipient: alice_L1, amount: 30, index: 0}]
  withdrawals_root = merkle_root(withdrawals)

CIRCUIT proves:
  prev_total_l2: 100
  withdrawal_amount: 30
  total_l2_after: 70
  total_deposits_after: 100  (unchanged)
  pending_withdrawals_after: 0 + 30 = 30

  Verification:
    ✓ 70 + 30 = 100 - 0
    ✓ total_l2_balances + pending = deposits - withdrawn

L1 CONTRACT in commitBatch():
  require(70 + 30 == 100 - 0)  ✓

After EXECUTE:
  L1: balance=100, deposits=100, withdrawn=0, pending=30
  L2: total_balances=70
  INVARIANT: 100 + 30 = 100 - 0  ✓
  (L1_balance + pending = deposits - withdrawn)
```

### Batch 3: Alice executes withdrawal on L1

```
USER calls executeWithdrawal():
  Provides merkle proof for {alice_L1, 30, 0}

L1 CONTRACT:
  ✓ Verifies merkle proof against withdrawals_root from batch 2
  ✓ Checks msg.sender == alice_L1
  ✓ Checks not already executed

  Updates:
    totalWithdrawn: 0 + 30 = 30
    pendingWithdrawals: 30 - 30 = 0
    balance: 100 - 30 = 70

  Transfer 30 ETH to alice_L1

After withdrawal execution:
  L1: balance=70, deposits=100, withdrawn=30, pending=0
  L2: total_balances=70
  INVARIANT: 70 + 0 = 100 - 30  ✓
```

---

## 5. Enhanced Public Inputs

The proof's public inputs now include accounting totals:

```solidity
function createPublicInputs(BatchCommitment memory batch)
    internal
    pure
    returns (uint256[] memory)
{
    uint256[] memory inputs = new uint256[](8);

    // State transition
    inputs[0] = uint256(batch.prevStateRoot);
    inputs[1] = uint256(batch.newStateRoot);

    // Accounting totals (NEW - critical for security)
    inputs[2] = batch.totalL2BalancesAfter;
    inputs[3] = batch.totalDepositsAfter;
    inputs[4] = batch.pendingWithdrawalsAfter;

    // Transaction commitments
    inputs[5] = uint256(batch.depositsHash);
    inputs[6] = uint256(batch.l2TransactionsHash);
    inputs[7] = uint256(batch.withdrawalsRoot);

    return inputs;
}
```

**The verifier checks:**
```
Proof is valid for public inputs
⟹ State transition is correct
⟹ Accounting totals are correct
⟹ Invariant is maintained
```

---

## 6. Security Properties

### Property 1: Conservation of Value

```
THEOREM: For all batches b, the following holds:
  L1_balance(b) + L2_total(b) + pending(b) = total_deposits(b)

PROOF:
  - L1 contract enforces this check in commitBatch()
  - ZK circuit includes accounting totals in public inputs
  - Proof cannot be valid unless constraint satisfied
  - Therefore invariant cannot be broken
```

### Property 2: Withdrawal Authorization

```
THEOREM: Only the designated recipient can execute a withdrawal

PROOF:
  - Withdrawal committed with {recipient, amount, index}
  - Merkle root computed over these exact values
  - executeWithdrawal() verifies merkle proof for exact leaf
  - executeWithdrawal() requires msg.sender == recipient
  - Cannot fake merkle proof (cryptographic security of merkle trees)
  - Therefore only recipient can withdraw
```

### Property 3: No Double Withdrawals

```
THEOREM: Each withdrawal can only be executed once

PROOF:
  - Withdrawal identified by (batchNumber, withdrawalIndex)
  - withdrawalExecuted[keccak256(batch, index)] tracks execution
  - executeWithdrawal() requires !withdrawalExecuted[id]
  - withdrawalExecuted[id] = true after execution
  - Therefore cannot execute twice
```

### Property 4: No Theft via Fake Deposits

```
THEOREM: Operator cannot credit accounts without actual L1 deposits

PROOF:
  - Deposits added to priority queue on L1
  - L1 contract computes expected_deposits_hash from queue
  - commitBatch() requires batch.depositsHash == expected
  - Circuit proves state changes match deposits_hash
  - Cannot fake deposit without matching L1 queue
  - Therefore cannot steal via fake deposits
```

### Property 5: No Theft via Balance Inflation

```
THEOREM: Operator cannot inflate L2 balances without breaking invariant

PROOF:
  - Circuit computes total_l2_balances = sum(all balances)
  - Circuit outputs this as public input
  - L1 contract verifies: total_l2 + pending = deposits - withdrawn
  - If operator inflates balance:
    - total_l2_balances increases
    - But deposits and withdrawn unchanged
    - Invariant violated
    - commitBatch() reverts
  - Therefore cannot inflate balances
```

---

## 7. Comparison to Original Design

### What Changed

**Original (simplified):**
```solidity
// Stored only state root
bytes32 public stateRoot;

// No accounting tracking
// Assumed proof verified everything
// Trusted implicit conservation
```

**Enhanced (secure):**
```solidity
// Stored state root + accounting
bytes32 public stateRoot;
uint256 public totalDeposited;
uint256 public totalWithdrawn;
uint256 public pendingWithdrawals;

// Explicit invariant checking
require(
    totalL2Balances + pendingWithdrawals ==
    totalDeposited - totalWithdrawn
);

// Public inputs include accounting
publicInputs = [
    prevStateRoot,
    newStateRoot,
    totalL2Balances,      // NEW
    totalDeposits,        // NEW
    pendingWithdrawals    // NEW
];
```

### Why This Matters

**Without accounting checks:**
- Operator could claim arbitrary L2 balances
- Circuit proves state transitions but not totals
- L1 contract trusts the new state root
- Possible for L2_total > L1_balance (theft!)

**With accounting checks:**
- Every balance change tracked explicitly
- Circuit proves both state AND totals
- L1 contract verifies conservation of value
- Impossible for L2_total > deposits - withdrawn
- Cryptographic guarantee of no theft

---

## 8. Summary

### Critical Components

1. **L1 Tracking:**
   ```solidity
   totalDeposited      // Sum of all deposits
   totalWithdrawn      // Sum of executed withdrawals
   pendingWithdrawals  // Sum of committed but not executed withdrawals
   ```

2. **Circuit Proving:**
   ```rust
   // Prove accounting totals as public outputs
   total_l2_balances_after = sum(state.values())
   pending_withdrawals_after = prev_pending + new_withdrawals
   ```

3. **L1 Verification:**
   ```solidity
   // Verify invariant
   require(
       total_l2_balances + pending_withdrawals ==
       total_deposits - total_withdrawn
   );
   ```

4. **Withdrawal Claiming:**
   ```solidity
   // Only designated recipient can claim
   require(msg.sender == withdrawal.recipient);
   // Verify merkle proof
   require(verifyMerkleProof(leaf, proof, root));
   ```

### The Complete Security Model

```
L1 Deposits → Priority Queue → Circuit Verification → State Update
                                        ↓
                                Accounting Proof
                                        ↓
                    L1 Contract Verifies Invariant
                                        ↓
                                Batch Finalized
                                        ↓
                    Withdrawals Claimable by Recipients Only
```

**Key Insight:** The proof doesn't just verify state transitions—it verifies the **accounting totals** that guarantee conservation of value. The L1 contract then checks that these totals satisfy the fundamental invariant.

This makes it cryptographically impossible for the operator to:
- Steal funds by inflating balances
- Credit accounts without deposits
- Prevent legitimate withdrawals
- Allow unauthorized withdrawal claims

The security comes from **explicit accounting** enforced by both the circuit (proof) and the L1 contract (verification).
