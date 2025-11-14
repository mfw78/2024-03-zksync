# Blob Versioned Hashes Explained (EIP-4844)

## What is a Versioned Hash?

A **versioned hash** is a commitment to blob data that includes a version byte for forward compatibility.

### Simple Definition

```
Versioned Hash = [version_byte || hash(blob_commitment)]
                 └── 1 byte ──┘ └───── 31 bytes ──────┘
                           32 bytes total
```

**Purpose:**
- Identifies which blob format/version is being used
- Commits to the blob's KZG commitment
- Links execution layer (EVM) to consensus layer (blob storage)

---

## The Problem It Solves

### Without Versioned Hashes

```
Transaction includes blob
↓
How does execution layer reference the blob?
↓
Problem: Blob lives on consensus layer
         EVM can't directly access blob data
         Need a way to prove blob contains correct data
```

### With Versioned Hashes

```
Transaction includes blob
↓
Beacon chain computes: versioned_hash = sha256(kzg_commitment)
↓
Execution layer can access versioned_hash via BLOBHASH opcode
↓
Smart contract verifies blob data matches commitment
```

---

## How It Works

### Transaction with Blob

```
User creates transaction:
┌─────────────────────────────────────┐
│ Regular EIP-1559 Transaction        │
│ - to: rollup_contract               │
│ - data: commitBatch(...)            │
│ - maxFeePerGas: ...                 │
│ - maxPriorityFeePerGas: ...         │
│                                     │
│ NEW (EIP-4844):                     │
│ - maxFeePerBlobGas: ...            │
│ - blobVersionedHashes: [           │
│     0x01abc...,  ← Points to blob 0│
│     0x01def...,  ← Points to blob 1│
│   ]                                 │
│                                     │
│ Blobs (separate):                   │
│ - blob[0]: [pubdata chunk 1]       │
│ - blob[1]: [pubdata chunk 2]       │
└─────────────────────────────────────┘
```

### Versioned Hash Computation

```
For each blob:

1. Blob data (4096 field elements × 32 bytes each)
   ↓
2. Create KZG commitment to blob
   commitment = KZG.commit(blob)
   (48 bytes)
   ↓
3. Hash the commitment
   hash = sha256(commitment)
   (32 bytes)
   ↓
4. Prepend version byte
   versioned_hash = BLOB_COMMITMENT_VERSION_KZG || hash
                  = 0x01 || hash
   (1 + 31 = 32 bytes)
```

**Version byte values:**
- `0x01`: KZG commitment (current version)
- `0x02`, `0x03`, ...: Future commitment schemes

---

## Using BLOBHASH Opcode

### In Smart Contract

```solidity
contract RollupContract {
    function commitBatch(
        BatchCommit calldata batch,
        bytes calldata kzgProof
    ) external {
        // Get versioned hash from transaction
        bytes32 versionedHash = blobhash(0);  // First blob
        //                      └─ blob index (0, 1, 2, ...)

        require(versionedHash != 0, "No blob attached");

        // Verify this matches what we expect
        require(versionedHash == batch.expectedBlobHash, "Wrong blob");

        // Use for verification...
    }
}
```

### BLOBHASH Opcode Behavior

```
blobhash(index):
  if index < number_of_blobs_in_transaction:
    return versioned_hashes[index]
  else:
    return 0x000...000

Examples:
  Transaction with 2 blobs:
    blobhash(0) → 0x01abc...  ✓
    blobhash(1) → 0x01def...  ✓
    blobhash(2) → 0x000...    (no third blob)
```

---

## Point Evaluation Precompile

The versioned hash is used to verify blob data via the point evaluation precompile.

### The Verification Process

```
INPUT to precompile (192 bytes):
┌──────────────────────────────┐
│ versioned_hash    (32 bytes) │ ← From BLOBHASH opcode
│ evaluation_point  (32 bytes) │ ← Where to evaluate polynomial
│ expected_value    (32 bytes) │ ← Expected result
│ commitment        (48 bytes) │ ← KZG commitment to blob
│ proof             (48 bytes) │ ← KZG proof
└──────────────────────────────┘
        ↓
   Precompile verifies:
   1. sha256(commitment)[1:] == versioned_hash[1:]
      (commitment matches versioned hash)
   2. version_byte == 0x01
      (using KZG commitment scheme)
   3. KZG.verify(commitment, point, value, proof)
      (polynomial evaluates to value at point)
        ↓
   OUTPUT (64 bytes):
┌──────────────────────────────┐
│ FIELD_ELEMENTS_PER_BLOB      │ ← 4096
│ BLS_MODULUS                  │ ← 0x73eda753299d7d...
└──────────────────────────────┘

If second value == BLS_MODULUS:
  ✓ Verification successful!
```

### Why This Works

```
The versioned hash links everything together:

Transaction
    ↓ includes
Versioned Hash
    ↓ computed from
KZG Commitment
    ↓ commits to
Blob Data
    ↓ stored on
Consensus Layer

Smart contract:
  1. Gets versioned_hash via BLOBHASH
  2. Verifies commitment matches versioned_hash
  3. Verifies blob contains expected data
  4. All without accessing blob directly!
```

---

## Concrete Example

### Rollup Commits Batch with Blob

```javascript
// OFF-CHAIN: Operator prepares blob

// 1. Create pubdata
const pubdata = encodePubdata(stateDiffs);
// 126,976 bytes (4096 × 31)

// 2. Encode as blob
const blob = encodeForBlob(pubdata);
// 4096 field elements × 32 bytes each

// 3. Compute KZG commitment
const commitment = KZG.commit(blob);
// 48 bytes: 0x8a3f2b...

// 4. Compute versioned hash
const hash = sha256(commitment);
const versionedHash = concat([0x01, hash.slice(0, 31)]);
// 32 bytes: 0x01abc123...

// 5. Compute opening proof
const openingPoint = computeOpeningPoint(pubdata);
const claimedValue = evaluatePolynomial(blob, openingPoint);
const proof = KZG.prove(blob, openingPoint);

// 6. Create transaction
const tx = {
    to: rollupContract,
    data: encodeFunctionCall('commitBatch', [
        batch,
        concat([
            openingPoint,    // 16 bytes
            claimedValue,    // 32 bytes
            commitment,      // 48 bytes
            proof           // 48 bytes
        ])
    ]),
    blobs: [blob],
    blobVersionedHashes: [versionedHash]
};
```

### ON-CHAIN: Contract Verifies

```solidity
function commitBatch(
    BatchCommit calldata batch,
    bytes calldata kzgProof  // 144 bytes
) external {
    // 1. Get versioned hash from transaction
    bytes32 versionedHash = blobhash(0);
    require(versionedHash != 0, "No blob");

    // 2. Extract KZG proof components
    bytes16 openingPoint = bytes16(kzgProof[0:16]);
    bytes32 claimedValue = bytes32(kzgProof[16:48]);
    bytes48 commitment = bytes48(kzgProof[48:96]);
    bytes48 proof = bytes48(kzgProof[96:144]);

    // 3. Call point evaluation precompile
    bytes memory input = abi.encodePacked(
        versionedHash,  // From BLOBHASH
        bytes32(openingPoint),  // Padded to 32 bytes
        claimedValue,
        commitment,
        proof
    );

    (bool success, bytes memory output) =
        POINT_EVAL_PRECOMPILE.staticcall(input);

    require(success, "Point eval failed");

    // 4. Verify output
    (, uint256 modulus) = abi.decode(output, (uint256, uint256));
    require(modulus == BLS_MODULUS, "Invalid proof");

    // 5. Verify blob hash matches our expectation
    bytes32 expectedBlobHash = keccak256(abi.encodePacked(
        versionedHash,
        openingPoint,
        claimedValue
    ));
    require(expectedBlobHash == batch.blobHash, "Blob mismatch");

    // Now we know:
    // ✓ Blob is attached to transaction
    // ✓ Blob commits to claimed data
    // ✓ Opening proof is valid
    // ✓ Blob contains the pubdata we expect
}
```

---

## Why Versioned?

### Forward Compatibility

```
Version 0x01 (current):
  - Uses KZG commitments
  - Requires trusted setup
  - Efficient for current needs

Future versions might use:
  - Version 0x02: Different polynomial commitment scheme
  - Version 0x03: Post-quantum secure commitments
  - Version 0x04: More efficient encoding

Smart contracts can check version:
  bytes1 version = versioned_hash[0];
  if (version == 0x01) {
      // Use KZG verification
  } else if (version == 0x02) {
      // Use new scheme
  } else {
      revert("Unsupported version");
  }
```

### Why Not Just Use KZG Commitment Directly?

```
Option 1: Use commitment directly
  - commitment = 48 bytes
  - Doesn't fit in bytes32
  - Can't use as mapping key easily

Option 2: Hash commitment
  - hash(commitment) = 32 bytes ✓
  - But loses version information

Option 3: Versioned hash (chosen!)
  - version || hash(commitment)[1:] = 32 bytes ✓
  - Includes version for future proofing ✓
  - Standard bytes32 size ✓
```

---

## The Complete Picture

### Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│                      CONSENSUS LAYER                         │
│                      (Beacon Chain)                          │
│                                                              │
│  ┌────────────────────────────────────────────────────┐    │
│  │ Blob Storage (temporary, ~18 days)                 │    │
│  │                                                     │    │
│  │  Blob 0: [field_element_0, field_element_1, ...]  │    │
│  │          (4096 elements × 32 bytes)                │    │
│  │                                                     │    │
│  │  KZG Commitment: 0x8a3f2b... (48 bytes)           │    │
│  │          ↓                                          │    │
│  │  Hash: sha256(commitment)                          │    │
│  │          ↓                                          │    │
│  │  Versioned Hash: 0x01 || hash[0:31]               │    │
│  │                  = 0x01abc123... (32 bytes)        │    │
│  └────────────────────────────────────────────────────┘    │
│                          ↓ Included in beacon block         │
└─────────────────────────┼────────────────────────────────────┘
                          ↓
┌─────────────────────────┼────────────────────────────────────┐
│                   EXECUTION LAYER                             │
│                   (Ethereum L1)                               │
│                          ↓                                    │
│  ┌────────────────────────────────────────────────────┐     │
│  │ Transaction                                         │     │
│  │                                                     │     │
│  │  blobVersionedHashes: [0x01abc123...]             │     │
│  │                             ↑                       │     │
│  │                             │                       │     │
│  │                             │ BLOBHASH(0)          │     │
│  │                             │                       │     │
│  │  ┌──────────────────────────┼──────────────────┐  │     │
│  │  │ Smart Contract           │                  │  │     │
│  │  │                          ↓                  │  │     │
│  │  │  bytes32 vh = blobhash(0);                 │  │     │
│  │  │  // vh = 0x01abc123...                     │  │     │
│  │  │                                             │  │     │
│  │  │  Call point_eval_precompile(               │  │     │
│  │  │    versionedHash: vh,                      │  │     │
│  │  │    point: 0x1234,                          │  │     │
│  │  │    value: 0x5678,                          │  │     │
│  │  │    commitment: 0x8a3f...,                  │  │     │
│  │  │    proof: 0x9b2c...                        │  │     │
│  │  │  )                                          │  │     │
│  │  │                                             │  │     │
│  │  │  ✓ Verifies commitment matches vh          │  │     │
│  │  │  ✓ Verifies polynomial(point) == value     │  │     │
│  │  │                                             │  │     │
│  │  │  Result: Blob proven to contain            │  │     │
│  │  │          expected data!                    │  │     │
│  │  └─────────────────────────────────────────────┘  │     │
│  └────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────┘
```

### Security Guarantees

```
1. Versioned hash binds transaction to blob
   → Can't swap blob without changing hash
   → Can't use wrong blob

2. Point evaluation proves blob contents
   → Can't claim blob contains different data
   → Cryptographically verified

3. Version byte enables upgrades
   → Future-proof commitment scheme
   → Smooth migration path

4. Hash is commitment to commitment
   → Can't fake KZG commitment
   → Must match blob data exactly
```

---

## Common Questions

### Q: Why hash the commitment instead of using it directly?

**A:**
- KZG commitment is 48 bytes (G1 point on BLS12-381 curve)
- Ethereum uses bytes32 extensively (mapping keys, storage, etc.)
- Hashing to 32 bytes + version byte = standard size
- Easier to work with in EVM

### Q: Why SHA256 instead of keccak256?

**A:**
- SHA256 is used by consensus layer (beacon chain)
- Consistency between layers
- SHA256 is the standard for BLS12-381 curve operations

### Q: Can I access the blob data directly in my contract?

**A:**
```solidity
// NO - This doesn't work:
bytes memory blobData = getBlob(0);  // ✗ No such opcode

// YES - This works:
bytes32 vh = blobhash(0);  // ✓ Get versioned hash

// Then prove blob contains what you expect
// via point evaluation precompile
```

Blobs are **not accessible** to EVM execution!
- Blobs live on consensus layer
- EVM only gets versioned hash
- Must use proof to verify blob contents

### Q: What happens if I call blobhash for a non-existent blob?

**A:**
```solidity
// Transaction has 2 blobs (indices 0 and 1)

bytes32 vh0 = blobhash(0);  // Returns versioned hash ✓
bytes32 vh1 = blobhash(1);  // Returns versioned hash ✓
bytes32 vh2 = blobhash(2);  // Returns 0x000...000 ✗

require(vh2 != 0);  // Would fail!
```

This is how you check how many blobs are attached:
```solidity
function countBlobs() internal view returns (uint256) {
    uint256 count = 0;
    while (blobhash(count) != 0) {
        count++;
    }
    return count;
}
```

### Q: Can someone submit transaction without the blob?

**A:**
```
Transaction includes:
  - blobVersionedHashes: [0x01abc...]
  - blobs: [blob_data]

If blobs missing:
  → Transaction is INVALID
  → Rejected by consensus layer
  → Never included in block

If blobVersionedHashes missing:
  → Transaction type is regular EIP-1559
  → No blobs attached
  → blobhash() returns 0
```

### Q: How do I verify the opening point and claimed value?

**A:**
```solidity
// These values are chosen by the operator
// Point evaluation precompile verifies:
//   polynomial(openingPoint) == claimedValue
//
// But you also need to verify these match your pubdata:

function verifyBlobCommitment(
    bytes32 versionedHash,
    bytes16 openingPoint,
    bytes32 claimedValue,
    bytes memory expectedPubdata
) internal view {
    // 1. Compute what the opening point should be
    bytes16 expectedPoint = computeOpeningPoint(expectedPubdata);
    require(openingPoint == expectedPoint, "Wrong point");

    // 2. Compute what the value should be
    bytes32 expectedValue = computeEvaluation(expectedPubdata, openingPoint);
    require(claimedValue == expectedValue, "Wrong value");

    // 3. Verify via precompile
    // (This checks the KZG proof)
    ...
}
```

Or more commonly, just verify the final result:
```solidity
// Verify blob commitment matches expected
bytes32 computedHash = keccak256(abi.encodePacked(
    versionedHash,
    openingPoint,
    claimedValue
));

require(computedHash == batch.expectedBlobHash);
```

---

## Summary

### What Versioned Hash Is

- **32-byte identifier** for a blob
- **Version byte** (0x01) + **hash of KZG commitment** (31 bytes)
- **Accessible in EVM** via `blobhash(index)` opcode
- **Links execution layer to consensus layer** blob storage

### What It Enables

- ✓ Smart contracts can reference blobs
- ✓ Verify blob contents via proofs (point evaluation)
- ✓ Cannot fake or swap blobs
- ✓ Forward compatible (version byte)

### How It's Used in Rollups

```
1. Operator: Create blob with state diffs
2. Operator: Compute KZG commitment
3. Operator: Compute versioned hash
4. Operator: Submit transaction with blob
5. Contract: Get versioned hash via blobhash()
6. Contract: Verify proof via precompile
7. Contract: Accept batch if proof valid

Result: Cheap data availability!
        Only ~$0.001 per transaction
        10-100x cheaper than calldata
```

The versioned hash is the **bridge** between the EVM (which can't see blobs) and the consensus layer (where blobs live), enabling cheap data availability while maintaining security through cryptographic proofs.
