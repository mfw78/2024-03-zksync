# Minimal ZK-Rollup Design: Account-Based System

## System Overview

A simple rollup with only:
- **Accounts** (address → balance mapping)
- **Deposits** (L1 → L2)
- **Transfers** (L2 → L2)
- **Withdrawals** (L2 → L1)

Secured by Ethereum using ZK-SNARKs and EIP-4844 blobs.

---

## 1. State Representation

### L2 State

The entire L2 state is a simple mapping:
```
State = Map<Address, Balance>
  where Address = bytes20 (Ethereum address)
        Balance = uint256
```

**State Root:**
```
StateRoot = MerkleRoot(sorted([
  hash(address_1, balance_1),
  hash(address_2, balance_2),
  ...
]))
```

Use a **sparse Merkle tree** of depth 160 (one level per address bit):
- Leaf at position `address`: `hash(balance)`
- Empty leaves: `hash(0)`
- Root: commitment to entire state

**Why sparse Merkle tree?**
- Efficient ZK circuit verification
- Constant-size proofs (160 siblings)
- Easy to prove non-membership (account doesn't exist)

---

## 2. Transaction Types

### Deposit (L1 → L2)

```solidity
// L1 Contract
function deposit(address recipient) external payable {
    require(msg.value > 0, "Must deposit something");

    // Add to priority queue
    bytes32 depositHash = keccak256(abi.encode(
        DEPOSIT_TX_TYPE,
        msg.sender,      // depositor (L1 address)
        recipient,       // L2 recipient
        msg.value,       // amount
        depositNonce++   // unique ID
    ));

    priorityQueue.push(depositHash);
    emit Deposit(msg.sender, recipient, msg.value, depositNonce);
}
```

**L2 Processing:**
```python
def process_deposit(tx):
    # No signature needed - already authorized on L1
    state[tx.recipient] += tx.amount
    # No sender deduction - funds came from L1
```

### Transfer (L2 → L2)

```python
struct Transfer {
    from: Address,
    to: Address,
    amount: uint256,
    nonce: uint256,     # replay protection
    signature: Signature
}

def process_transfer(tx):
    # 1. Verify signature
    assert verify_signature(tx.from, tx, tx.signature)

    # 2. Check nonce
    assert nonces[tx.from] == tx.nonce
    nonces[tx.from] += 1

    # 3. Check balance
    assert state[tx.from] >= tx.amount

    # 4. Update state
    state[tx.from] -= tx.amount
    state[tx.to] += tx.amount
```

### Withdrawal (L2 → L1)

```python
struct Withdrawal {
    from: Address,
    to: Address,      # L1 recipient
    amount: uint256,
    nonce: uint256,
    signature: Signature
}

def process_withdrawal(tx):
    # 1. Verify signature
    assert verify_signature(tx.from, tx, tx.signature)

    # 2. Check nonce
    assert nonces[tx.from] == tx.nonce
    nonces[tx.from] += 1

    # 3. Check balance
    assert state[tx.from] >= tx.amount

    # 4. Deduct from L2
    state[tx.from] -= tx.amount

    # 5. Queue for L1 withdrawal
    emit_l2_to_l1_message(WITHDRAWAL, tx.to, tx.amount)
```

---

## 3. L1 Smart Contract

```solidity
contract MinimalRollup {
    // State commitments
    bytes32 public stateRoot;
    uint256 public currentBatch;

    // Batch tracking
    mapping(uint256 => bytes32) public batchCommitments;
    mapping(uint256 => bool) public batchExecuted;

    // Priority queue for deposits
    struct Deposit {
        address from;
        address to;
        uint256 amount;
        uint256 nonce;
    }
    Deposit[] public priorityQueue;
    uint256 public priorityQueueHead;

    // Withdrawal tracking
    mapping(uint256 => mapping(uint256 => bool)) public withdrawalExecuted;
    // batch => withdrawal_index => executed

    // Verifier
    IVerifier public verifier;

    //====================
    // DEPOSITS (L1 → L2)
    //====================

    function deposit(address recipient) external payable {
        require(msg.value > 0, "Must deposit ETH");

        priorityQueue.push(Deposit({
            from: msg.sender,
            to: recipient,
            amount: msg.value,
            nonce: priorityQueue.length
        }));

        emit DepositQueued(msg.sender, recipient, msg.value, priorityQueue.length - 1);
    }

    //====================
    // BATCH COMMITMENT
    //====================

    struct BatchCommitment {
        uint256 batchNumber;
        bytes32 prevStateRoot;
        bytes32 newStateRoot;
        uint256 numDeposits;           // # priority txs processed
        bytes32 depositsHash;          // hash of deposits processed
        bytes32 transactionsHash;      // hash of L2 transactions
        bytes32 withdrawalsRoot;       // Merkle root of withdrawals
        uint256 numWithdrawals;
        bytes32 blobHash;              // Hash of blob data (for 4844)
    }

    function commitBatch(
        BatchCommitment calldata batch,
        bytes calldata blobCommitmentProof  // KZG proof data
    ) external onlyOperator {
        require(batch.batchNumber == currentBatch + 1, "Wrong batch number");
        require(batch.prevStateRoot == stateRoot, "Wrong prev state");

        // Verify deposits processed
        bytes32 expectedDepositsHash = _verifyDeposits(batch.numDeposits);
        require(batch.depositsHash == expectedDepositsHash, "Deposits mismatch");

        // Verify blob commitment (4844)
        _verifyBlobCommitment(batch.blobHash, blobCommitmentProof);

        // Create batch commitment
        bytes32 commitment = keccak256(abi.encode(batch));
        batchCommitments[batch.batchNumber] = commitment;

        emit BatchCommitted(batch.batchNumber, commitment);
    }

    function _verifyDeposits(uint256 numDeposits) internal returns (bytes32) {
        bytes32 hash = keccak256("");

        for (uint256 i = 0; i < numDeposits; i++) {
            Deposit memory dep = priorityQueue[priorityQueueHead + i];
            hash = keccak256(abi.encode(hash, dep));
        }

        return hash;
    }

    //====================
    // BATCH PROVING
    //====================

    function proveBatch(
        uint256 batchNumber,
        bytes calldata proof
    ) external {
        require(batchCommitments[batchNumber] != bytes32(0), "Batch not committed");
        require(!batchExecuted[batchNumber], "Already executed");

        // Public input for ZK proof
        uint256 publicInput = uint256(batchCommitments[batchNumber]);

        // Verify the proof
        require(verifier.verify([publicInput], proof), "Invalid proof");

        emit BatchProven(batchNumber);
    }

    //====================
    // BATCH EXECUTION
    //====================

    function executeBatch(
        uint256 batchNumber,
        BatchCommitment calldata batch
    ) external {
        require(batchCommitments[batchNumber] != bytes32(0), "Not committed");
        require(!batchExecuted[batchNumber], "Already executed");
        require(keccak256(abi.encode(batch)) == batchCommitments[batchNumber], "Commitment mismatch");

        // Mark deposits as processed
        priorityQueueHead += batch.numDeposits;

        // Update state root
        stateRoot = batch.newStateRoot;

        // Mark as executed
        batchExecuted[batchNumber] = true;
        currentBatch = batchNumber;

        emit BatchExecuted(batchNumber, batch.newStateRoot);
    }

    //====================
    // WITHDRAWALS (L2 → L1)
    //====================

    struct WithdrawalProof {
        address recipient;
        uint256 amount;
        uint256 withdrawalIndex;
        bytes32[] merkleProof;
    }

    function executeWithdrawal(
        uint256 batchNumber,
        WithdrawalProof calldata withdrawal
    ) external {
        require(batchExecuted[batchNumber], "Batch not executed");
        require(!withdrawalExecuted[batchNumber][withdrawal.withdrawalIndex], "Already withdrawn");

        // Get withdrawal root from batch
        BatchCommitment memory batch = _getBatchCommitment(batchNumber);

        // Verify Merkle proof
        bytes32 leaf = keccak256(abi.encode(
            withdrawal.recipient,
            withdrawal.amount,
            withdrawal.withdrawalIndex
        ));

        require(
            _verifyMerkleProof(leaf, withdrawal.merkleProof, batch.withdrawalsRoot),
            "Invalid proof"
        );

        // Mark as executed
        withdrawalExecuted[batchNumber][withdrawal.withdrawalIndex] = true;

        // Transfer ETH
        (bool success, ) = withdrawal.recipient.call{value: withdrawal.amount}("");
        require(success, "Transfer failed");

        emit WithdrawalExecuted(batchNumber, withdrawal.withdrawalIndex, withdrawal.recipient, withdrawal.amount);
    }

    //====================
    // BLOB VERIFICATION (EIP-4844)
    //====================

    function _verifyBlobCommitment(
        bytes32 blobHash,
        bytes calldata proofData
    ) internal view {
        // Extract KZG proof components
        // proofData = opening_point (16) || claimed_value (32) || commitment (48) || proof (48)

        bytes32 openingPoint = bytes32(uint256(uint128(bytes16(proofData[0:16]))));

        // Get versioned hash from BLOBHASH opcode
        bytes32 versionedHash = _getBlobVersionedHash(0);
        require(versionedHash != bytes32(0), "No blob");

        // Verify via point evaluation precompile
        bytes memory precompileInput = abi.encodePacked(
            versionedHash,
            openingPoint,
            proofData[16:144]  // claimed_value || commitment || proof
        );

        (bool success, bytes memory data) = address(0x0A).staticcall(precompileInput);
        require(success, "Point eval failed");

        (, uint256 result) = abi.decode(data, (uint256, uint256));
        require(result == BLS_MODULUS, "Invalid result");

        // Verify blob hash matches commitment
        bytes32 computedBlobHash = keccak256(abi.encodePacked(
            versionedHash,
            openingPoint,
            bytes32(proofData[16:48])  // claimed value
        ));

        require(computedBlobHash == blobHash, "Blob hash mismatch");
    }

    //====================
    // HELPERS
    //====================

    function _getBlobVersionedHash(uint256 index) internal view returns (bytes32) {
        // Call BlobHashRetriever contract (Yul implementation)
        (bool success, bytes memory data) = blobHashRetriever.staticcall(abi.encode(index));
        require(success, "Blob hash retrieval failed");
        return abi.decode(data, (bytes32));
    }

    function _verifyMerkleProof(
        bytes32 leaf,
        bytes32[] memory proof,
        bytes32 root
    ) internal pure returns (bool) {
        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {
            if (computedHash < proof[i]) {
                computedHash = keccak256(abi.encodePacked(computedHash, proof[i]));
            } else {
                computedHash = keccak256(abi.encodePacked(proof[i], computedHash));
            }
        }

        return computedHash == root;
    }
}
```

---

## 4. L2 Execution (Off-Chain)

### Batch Builder

```python
class BatchBuilder:
    def __init__(self):
        self.state = {}  # address => balance
        self.nonces = {}  # address => nonce
        self.state_root = compute_merkle_root(self.state)

    def build_batch(self, priority_deposits, user_transactions):
        """Build a batch from deposits and user transactions."""

        prev_state_root = self.state_root
        transactions = []
        withdrawals = []
        state_diffs = []

        # 1. Process priority deposits first (must process in order)
        for deposit in priority_deposits:
            self._process_deposit(deposit)
            transactions.append(deposit)
            state_diffs.append({
                'address': deposit.to,
                'old_balance': self.state.get(deposit.to, 0) - deposit.amount,
                'new_balance': self.state.get(deposit.to, 0)
            })

        # 2. Process user transactions
        for tx in user_transactions:
            if isinstance(tx, Transfer):
                if self._can_process_transfer(tx):
                    self._process_transfer(tx)
                    transactions.append(tx)
                    state_diffs.append({
                        'address': tx.from_,
                        'old_balance': self.state[tx.from_] + tx.amount,
                        'new_balance': self.state[tx.from_]
                    })
                    state_diffs.append({
                        'address': tx.to,
                        'old_balance': self.state[tx.to] - tx.amount,
                        'new_balance': self.state[tx.to]
                    })

            elif isinstance(tx, Withdrawal):
                if self._can_process_withdrawal(tx):
                    self._process_withdrawal(tx)
                    transactions.append(tx)
                    withdrawals.append({
                        'recipient': tx.to,
                        'amount': tx.amount,
                        'index': len(withdrawals)
                    })
                    state_diffs.append({
                        'address': tx.from_,
                        'old_balance': self.state[tx.from_] + tx.amount,
                        'new_balance': self.state[tx.from_]
                    })

        new_state_root = compute_merkle_root(self.state)

        return {
            'prev_state_root': prev_state_root,
            'new_state_root': new_state_root,
            'transactions': transactions,
            'withdrawals': withdrawals,
            'state_diffs': state_diffs
        }

    def _process_deposit(self, deposit):
        if deposit.to not in self.state:
            self.state[deposit.to] = 0
        self.state[deposit.to] += deposit.amount

    def _process_transfer(self, tx):
        assert self.nonces[tx.from_] == tx.nonce
        assert self.state[tx.from_] >= tx.amount
        assert verify_signature(tx.from_, tx, tx.signature)

        self.state[tx.from_] -= tx.amount
        if tx.to not in self.state:
            self.state[tx.to] = 0
        self.state[tx.to] += tx.amount
        self.nonces[tx.from_] += 1

    def _process_withdrawal(self, tx):
        assert self.nonces[tx.from_] == tx.nonce
        assert self.state[tx.from_] >= tx.amount
        assert verify_signature(tx.from_, tx, tx.signature)

        self.state[tx.from_] -= tx.amount
        self.nonces[tx.from_] += 1
```

---

## 5. ZK Circuit Design

The circuit proves: **"Executing these transactions on prev_state_root produces new_state_root"**

### Circuit Constraints

```rust
// Pseudo-circuit code
circuit MinimalRollup {
    // Public inputs
    public_input prev_state_root: Field;
    public_input new_state_root: Field;
    public_input transactions_hash: Field;
    public_input withdrawals_root: Field;
    public_input deposits_hash: Field;

    // Private witness
    witness transactions: Vec<Transaction>;
    witness state_proofs: Vec<MerkleProof>;
    witness signatures: Vec<Signature>;
    witness state_diffs: Vec<StateDiff>;

    fn verify() {
        let mut current_state_root = prev_state_root;
        let mut computed_tx_hash = hash("");
        let mut withdrawals = Vec::new();

        for tx in transactions {
            match tx.tx_type {
                DEPOSIT => {
                    // No signature check needed
                    current_state_root = apply_deposit(
                        current_state_root,
                        tx,
                        get_merkle_proof(tx)
                    );
                }

                TRANSFER => {
                    // Verify signature
                    assert!(verify_ecdsa(
                        tx.from,
                        hash(tx),
                        tx.signature
                    ));

                    // Verify nonce
                    assert!(get_nonce(tx.from) == tx.nonce);

                    // Verify and update balances
                    current_state_root = apply_transfer(
                        current_state_root,
                        tx,
                        get_merkle_proof(tx.from),
                        get_merkle_proof(tx.to)
                    );
                }

                WITHDRAWAL => {
                    // Verify signature
                    assert!(verify_ecdsa(
                        tx.from,
                        hash(tx),
                        tx.signature
                    ));

                    // Verify nonce
                    assert!(get_nonce(tx.from) == tx.nonce);

                    // Deduct from L2
                    current_state_root = apply_withdrawal(
                        current_state_root,
                        tx,
                        get_merkle_proof(tx.from)
                    );

                    // Add to withdrawals list
                    withdrawals.push(Withdrawal {
                        recipient: tx.to,
                        amount: tx.amount,
                        index: withdrawals.len()
                    });
                }
            }

            // Update rolling hash
            computed_tx_hash = hash(computed_tx_hash, hash(tx));
        }

        // Final assertions
        assert!(current_state_root == new_state_root);
        assert!(computed_tx_hash == transactions_hash);
        assert!(compute_merkle_root(withdrawals) == withdrawals_root);
    }

    fn apply_deposit(
        state_root: Field,
        tx: Deposit,
        proof: MerkleProof
    ) -> Field {
        // 1. Get current balance (or 0 if new account)
        let old_balance = get_balance_with_proof(state_root, tx.to, proof);

        // 2. Compute new balance
        let new_balance = old_balance + tx.amount;

        // 3. Update merkle tree and return new root
        update_merkle_tree(state_root, tx.to, new_balance, proof)
    }

    fn apply_transfer(
        state_root: Field,
        tx: Transfer,
        from_proof: MerkleProof,
        to_proof: MerkleProof
    ) -> Field {
        // 1. Check sender balance
        let from_balance = get_balance_with_proof(state_root, tx.from, from_proof);
        assert!(from_balance >= tx.amount);

        // 2. Update sender
        let new_from_balance = from_balance - tx.amount;
        state_root = update_merkle_tree(state_root, tx.from, new_from_balance, from_proof);

        // 3. Update recipient
        let to_balance = get_balance_with_proof(state_root, tx.to, to_proof);
        let new_to_balance = to_balance + tx.amount;
        state_root = update_merkle_tree(state_root, tx.to, new_to_balance, to_proof);

        state_root
    }
}
```

### Circuit Components

**Key operations that must be proven in circuit:**

1. **ECDSA Signature Verification**
   - Expensive in circuit (lots of constraints)
   - Verify `ecrecover(hash(tx), signature) == tx.from`

2. **Merkle Tree Updates**
   - Prove old balance at address
   - Prove new root after update
   - Each update: 160 hash operations (depth of sparse tree)

3. **Balance Arithmetic**
   - Addition: `new_balance = old_balance + amount`
   - Subtraction with underflow check: `assert old_balance >= amount`

4. **Hash Computations**
   - Transaction hashing
   - Merkle root computations
   - Withdrawal root

---

## 6. Data Availability with EIP-4844

### Pubdata Format

Everything that must be published for state reconstruction:

```python
pubdata = encode([
    # Header
    version: 1 byte,
    num_deposits: 2 bytes,
    num_transfers: 2 bytes,
    num_withdrawals: 2 bytes,

    # Deposits (already committed on L1, just include count)
    # No data needed - can be read from L1 events

    # Transfers
    for each transfer:
        from: 20 bytes,
        to: 20 bytes,
        amount: 32 bytes,
        nonce: 8 bytes,
        # signature: 65 bytes  (NOT needed in pubdata - verified in circuit)
    # = 80 bytes per transfer

    # Withdrawals
    for each withdrawal:
        from: 20 bytes,
        to: 20 bytes,
        amount: 32 bytes,
        nonce: 8 bytes,
        # signature: 65 bytes  (NOT needed in pubdata - verified in circuit)
    # = 80 bytes per withdrawal

    # State diffs (for full reconstruction)
    num_state_diffs: 2 bytes,
    for each diff:
        address: 20 bytes,
        old_balance: 32 bytes,  # needed for merkle proof
        new_balance: 32 bytes,
    # = 84 bytes per state diff
])
```

**Optimization:** State diffs can be compressed:
```python
# Instead of full 32-byte balances
for diff in state_diffs:
    address: 20 bytes,
    balance_change: variable (1-32 bytes),  # encode delta
    operation: 1 byte  # ADD or SUB
```

### Using EIP-4844 Blobs

```python
def prepare_blob_data(pubdata):
    """Prepare pubdata for blob submission."""

    # 1. Pad to blob size
    BLOB_SIZE = 4096 * 31  # 126,976 bytes

    if len(pubdata) > BLOB_SIZE:
        # Use multiple blobs
        num_blobs = (len(pubdata) + BLOB_SIZE - 1) // BLOB_SIZE
        blobs = []
        for i in range(num_blobs):
            chunk = pubdata[i*BLOB_SIZE : (i+1)*BLOB_SIZE]
            padded = chunk.ljust(BLOB_SIZE, b'\x00')
            blobs.append(padded)
    else:
        # Single blob
        padded = pubdata.ljust(BLOB_SIZE, b'\x00')
        blobs = [padded]

    # 2. Compute blob hashes
    blob_hashes = [keccak256(blob) for blob in blobs]

    # 3. Encode for Ethereum blob format
    encoded_blobs = [encode_blob_for_ethereum(blob) for blob in blobs]

    return encoded_blobs, blob_hashes

def encode_blob_for_ethereum(data):
    """Convert 31-byte chunks to 32-byte field elements."""
    assert len(data) == 4096 * 31

    field_elements = []
    for i in range(4096):
        chunk = data[i*31 : (i+1)*31]
        # Prepend 0x00 to make 32 bytes (ensures < BLS_MODULUS)
        field_element = b'\x00' + chunk
        field_elements.append(field_element)

    return field_elements
```

### L1 Commitment Process

```python
def commit_batch_with_blob(batch, blob):
    """Commit batch to L1 with blob."""

    # 1. Submit transaction with blob
    tx = {
        'to': rollup_contract,
        'data': encode_function_call('commitBatch', [
            batch.number,
            batch.prev_state_root,
            batch.new_state_root,
            batch.deposits_hash,
            batch.transactions_hash,
            batch.withdrawals_root,
            blob_commitment_proof  # KZG proof
        ]),
        'blobs': [blob],  # EIP-4844 blob
        'blob_versioned_hashes': [compute_versioned_hash(blob)]
    }

    # 2. Contract verifies blob
    # - Uses BLOBHASH opcode to get versioned hash
    # - Calls point evaluation precompile with KZG proof
    # - Stores commitment for circuit verification
```

### State Reconstruction

Anyone can reconstruct L2 state from L1:

```python
def reconstruct_state_from_l1():
    """Reconstruct complete L2 state from L1 data."""

    state = {}
    nonces = {}

    # 1. Get all committed batches from L1
    batches = get_committed_batches_from_l1()

    for batch in batches:
        # 2. Get blob data
        blob = fetch_blob_data(batch.blob_versioned_hash)
        pubdata = decode_blob(blob)

        # 3. Parse transactions
        deposits, transfers, withdrawals = parse_pubdata(pubdata)

        # 4. Replay transactions
        for deposit in deposits:
            state[deposit.to] = state.get(deposit.to, 0) + deposit.amount

        for transfer in transfers:
            state[transfer.from_] -= transfer.amount
            state[transfer.to] = state.get(transfer.to, 0) + transfer.amount
            nonces[transfer.from_] = transfer.nonce + 1

        for withdrawal in withdrawals:
            state[withdrawal.from_] -= withdrawal.amount
            nonces[withdrawal.from_] = withdrawal.nonce + 1

        # 5. Verify state root matches
        computed_root = compute_merkle_root(state)
        assert computed_root == batch.new_state_root

    return state
```

**Key Property:** Even though blobs are pruned after ~18 days:
- Full nodes can sync and store the data
- Blob retrievers can reconstruct state while blobs exist
- After pruning, new nodes trust the state root (backed by ZK proof)

---

## 7. Complete Flow Example

### User Deposits 10 ETH

```
1. USER → L1 Contract
   call deposit(alice) with 10 ETH

2. L1 CONTRACT
   - Adds to priority queue
   - Emits DepositQueued event

3. OPERATOR
   - Monitors L1 events
   - Includes deposit in next batch

4. L2 EXECUTION
   - state[alice] += 10 ETH
   - Update state merkle tree
   - new_state_root = 0xabc...

5. BATCH COMMITMENT
   - Create pubdata (includes state diffs)
   - Chunk into blob
   - Compute KZG commitment
   - Submit commitBatch() with blob

6. L1 CONTRACT
   - Verifies blob via point evaluation
   - Stores batch commitment
   - Stores blob hash

7. PROVER
   - Generates proof that:
     * Deposit was valid
     * Balance updated correctly
     * New state root is correct

8. OPERATOR → L1
   - Submit proveBatch(proof)

9. L1 VERIFIER
   - Checks proof against commitment
   - Returns true

10. OPERATOR → L1
    - Submit executeBatch()

11. L1 CONTRACT
    - Updates state root to 0xabc...
    - Marks deposit as processed
    - FINALIZED - cannot revert
```

### User Transfers 3 ETH

```
1. USER → L2 NODE
   Transfer { from: alice, to: bob, amount: 3, nonce: 0, signature }

2. L2 MEMPOOL
   - Validates signature
   - Validates nonce
   - Checks balance >= 3

3. BATCH BUILDER
   - Includes in next batch
   - state[alice] -= 3
   - state[bob] += 3
   - Update merkle tree

4. PUBDATA
   [
     transfer: alice → bob, 3 ETH,
     state_diff: alice: 10 → 7,
     state_diff: bob: 0 → 3
   ]

5. COMMIT/PROVE/EXECUTE (same as deposit)
   - Proof verifies signature in circuit
   - Proof verifies balance updates
   - Proof verifies new state root
```

### User Withdraws 5 ETH to L1

```
1. USER → L2 NODE
   Withdrawal { from: alice, to: alice_L1, amount: 5, nonce: 1, signature }

2. L2 EXECUTION
   - state[alice] -= 5  (now has 2 ETH)
   - Add to withdrawals list

3. WITHDRAWALS MERKLE TREE
   withdrawals = [
     { recipient: alice_L1, amount: 5, index: 0 }
   ]
   withdrawals_root = merkle_root(withdrawals)

4. COMMIT/PROVE/EXECUTE
   - Batch includes withdrawals_root
   - After execution, withdrawal is available

5. USER → L1 CONTRACT
   executeWithdrawal(
     batch_number: 100,
     proof: {
       recipient: alice_L1,
       amount: 5,
       index: 0,
       merkle_proof: [0xabc, 0xdef, ...]
     }
   )

6. L1 CONTRACT
   - Verifies merkle proof against withdrawals_root
   - Transfers 5 ETH to alice_L1
   - Marks withdrawal as executed
```

---

## 8. Key Properties & Security

### Invariants

```
L1_deposits = sum(deposits)
L2_balances = sum(state.values())
L1_withdrawals = sum(executed_withdrawals)

INVARIANT:
  L1_deposits - L1_withdrawals == L2_balances

This must hold at all times and is enforced by:
- ZK proof (correct execution)
- L1 contract (correct accounting)
```

### What Operator Cannot Do

**Steal funds:**
```
// Operator tries: state[operator] += 1000 ETH
// Proof generation FAILS because:
// - No corresponding deposit/transfer
// - Cannot create valid merkle proof
// - Circuit constraints not satisfied
```

**Create fake deposits:**
```
// Operator tries: process deposit without L1 queue
// L1 contract REJECTS because:
// - deposits_hash won't match priority queue
// - commitBatch() checks expected deposits
```

**Block withdrawals:**
```
// Operator tries: skip withdrawal transaction
// User can:
// - Wait for different operator
// - Force include via L1 (priority queue)
// - If operator stops: anyone can take over with state from L1
```

### What Operator Can Do

- **Order transactions** (MEV)
- **Choose which L2 txs to include** (temporary censorship)
- **Delay batch creation** (liveness issue, not safety)

**Mitigation:**
```solidity
// Force-include mechanism
function forceIncludeTransaction(
    address from,
    address to,
    uint256 amount,
    uint256 nonce,
    bytes signature
) external {
    // Add to priority queue with higher priority
    // Operator MUST include within N batches or batch is invalid
}
```

---

## 9. Cost Analysis

### Per Transaction Costs

**Deposit (L1 → L2):**
- L1 gas: ~50k (queue insertion)
- L2 gas: free (forced inclusion)
- Proof cost: ~10k constraints (merkle update)

**Transfer (L2 → L2):**
- L1 gas: 0 (only in pubdata via blob)
- L2 gas: ~5k virtual
- Pubdata: 80 bytes → ~$0.0001 (with blobs)
- Proof cost: ~100k constraints (signature + 2x merkle updates)

**Withdrawal (L2 → L1):**
- L1 gas: ~80k (merkle proof verification + ETH transfer)
- L2 gas: ~5k virtual
- Pubdata: 80 bytes
- Proof cost: ~60k constraints (signature + merkle update)

### Batch Economics (with EIP-4844)

```
Assumptions:
- 1000 transfers per batch
- 1 blob used
- Blob gas: ~0.001 ETH

Costs per batch:
- Commit: 200k gas (~$5)
- Prove: 300k gas (~$7.50)
- Execute: 100k gas (~$2.50)
- Blob: 0.001 ETH (~$2)
- Prover compute: ~$10

Total: ~$27 per batch
Per transaction: $0.027

Compare to:
- Ethereum L1: ~$5 per transfer
- Optimistic rollup: ~$0.10 per transfer
- zkRollup without blobs: ~$0.30 per transfer
```

---

## 10. Comparison to Full Systems

### vs zkSync Era

**This minimal system:**
- ✓ Same core security model
- ✓ Same ZK proof verification
- ✓ Same blob data availability
- ✗ No smart contracts
- ✗ No EVM compatibility
- ✗ Simpler state (just balances)

**zkSync adds:**
- Contract deployment & execution
- Storage (key-value for contracts)
- System contracts
- Account abstraction
- Gas metering
- Precompiles

### vs Payment-Only Rollups (e.g., ZKP2P concepts)

**This is essentially a ZK payment rollup**, similar to:
- Aztec Connect (before v3)
- Hermez (now Polygon zkEVM)
- Loopring (payment mode)

### Extending the Design

**To add smart contracts:**
1. Change state from `Map<Address, Balance>` to `Map<Address, Account>`
   ```rust
   struct Account {
       balance: uint256,
       nonce: uint256,
       code_hash: bytes32,
       storage_root: bytes32  // merkle root of storage
   }
   ```

2. Add transaction type: `ContractCall`
   ```rust
   struct ContractCall {
       from: Address,
       to: Address,
       data: bytes,
       gas_limit: uint256,
       signature: Signature
   }
   ```

3. Expand circuit to include:
   - VM execution (opcodes)
   - Storage access (SLOAD/SSTORE)
   - Contract creation
   - Gas accounting

This is the path from minimal rollup → full zkEVM.

---

## Summary

This minimal rollup demonstrates the core ZK-rollup principles:

1. **State commitments** (merkle roots) go on L1
2. **Execution happens off-chain** (operator builds batches)
3. **ZK proofs enforce correctness** (cannot fake state transitions)
4. **Data availability via blobs** (anyone can reconstruct state)
5. **L1 finalizes** (execute makes it permanent)

**The magic:** A malicious operator CANNOT create a valid proof for an invalid state transition. The circuits define the rules, and the proof system enforces them cryptographically.

**With EIP-4844:** Data costs drop 10-100x, making the rollup economically viable for high-throughput applications.

This is the foundation that zkSync Era builds upon, adding EVM execution, account abstraction, and a rich contract environment on top of these same core mechanisms.
