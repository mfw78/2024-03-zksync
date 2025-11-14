# ZK-Rollup Documentation Suite

A comprehensive guide to understanding and building ZK-rollups, with detailed analysis of zkSync Era's proof mechanism.

## 📚 Document Guide

### Start Here

**[UNDERSTANDING_ZK_ROLLUPS.md](UNDERSTANDING_ZK_ROLLUPS.md)** - *Main conceptual guide*
- What is a ZK-rollup in simple terms?
- Core concepts explained with analogies
- **8 major pitfalls** and how to avoid them
- Simple mental models
- Design evolution from basic to production
- Complete security checklist

**Best for:** Getting a solid conceptual understanding before diving into code.

---

### Visual Learning

**[VISUAL_GUIDE.md](VISUAL_GUIDE.md)** - *Diagrams and flows*
- ASCII art architecture diagrams
- Complete transaction flows
- State transition visualizations
- Attack scenarios and prevention
- Step-by-step common scenarios
- Quick reference tables

**Best for:** Visual learners who want to see how everything connects.

---

### Building from Scratch

**[MINIMAL_ROLLUP_DESIGN.md](MINIMAL_ROLLUP_DESIGN.md)** - *First implementation*
- Simple rollup with just deposits, transfers, withdrawals
- Complete L1 contract code
- ZK circuit design
- EIP-4844 blob integration
- Cost analysis
- No extra security features (shows baseline)

**Best for:** Understanding the absolute minimum requirements.

**[MINIMAL_ROLLUP_WITH_ACCOUNTING.md](MINIMAL_ROLLUP_WITH_ACCOUNTING.md)** - *Adding security*
- Builds on minimal design
- **Strict accounting invariants**
- Prevents balance inflation
- Conservation of value enforcement
- Proof includes total balances
- L1 verification of accounting

**Best for:** Understanding why accounting validation is critical.

**[ROLLUP_WITH_L1_ANCHORING.md](ROLLUP_WITH_L1_ANCHORING.md)** - *Snapshot approach*
- Adds temporal consistency
- Snapshot system for L1 state
- Blockhash verification
- Prevents timing attacks
- More complex, more state

**Best for:** Understanding one approach to L1 anchoring (but see next doc for better approach).

**[SIMPLE_L1_ANCHORING.md](SIMPLE_L1_ANCHORING.md)** - *Proof approach* ⭐ **RECOMMENDED**
- **Simpler and better than snapshots**
- Uses `eth_getProof` for L1 state
- Merkle proof verification
- Light client for old blocks
- No snapshot transactions needed
- Less on-chain state

**Best for:** The practical, production-ready approach to L1 anchoring.

---

### Deep Dives

**[PROOF_MECHANISM_ANALYSIS.md](PROOF_MECHANISM_ANALYSIS.md)** - *zkSync Era analysis*
- How zkSync Era actually works
- Three-phase commit (commit → prove → execute)
- Integration with EIP-4844/Danksharding
- State diff compression
- How proofs enforce state transitions
- Complete technical breakdown

**Best for:** Understanding a production ZK-rollup in detail.

**[BLOB_VERSIONED_HASHES_EXPLAINED.md](BLOB_VERSIONED_HASHES_EXPLAINED.md)** - *EIP-4844 deep dive*
- What are versioned hashes?
- Why they exist
- How BLOBHASH opcode works
- Point evaluation precompile
- Concrete code examples
- Complete data flow
- Common questions answered

**Best for:** Understanding the blob data availability mechanism.

---

## 🎯 Learning Paths

### Path 1: Complete Beginner
```
1. UNDERSTANDING_ZK_ROLLUPS.md (concepts)
2. VISUAL_GUIDE.md (see it in action)
3. MINIMAL_ROLLUP_DESIGN.md (simple implementation)
4. PROOF_MECHANISM_ANALYSIS.md (production system)
```

### Path 2: Want to Build
```
1. MINIMAL_ROLLUP_DESIGN.md (start simple)
2. MINIMAL_ROLLUP_WITH_ACCOUNTING.md (add security)
3. SIMPLE_L1_ANCHORING.md (add L1 proofs)
4. BLOB_VERSIONED_HASHES_EXPLAINED.md (add data availability)
```

### Path 3: Security Focused
```
1. UNDERSTANDING_ZK_ROLLUPS.md (read "Common Pitfalls" section)
2. MINIMAL_ROLLUP_WITH_ACCOUNTING.md (accounting attacks)
3. SIMPLE_L1_ANCHORING.md (timing attacks)
4. VISUAL_GUIDE.md (see attack scenarios)
```

### Path 4: zkSync Era Specific
```
1. PROOF_MECHANISM_ANALYSIS.md (how zkSync works)
2. BLOB_VERSIONED_HASHES_EXPLAINED.md (data availability)
3. UNDERSTANDING_ZK_ROLLUPS.md ("Design Evolution" section)
```

---

## 🔑 Key Concepts Covered

### Security Invariants
- **Accounting:** `L2_balances + pending = deposits - withdrawn`
- **Conservation:** Cannot create funds from thin air
- **Authorization:** Only recipient can claim withdrawals
- **Double-spend prevention:** Withdrawal tracking
- **Data availability:** State reconstructable from L1

### Critical Components
- **State root:** Merkle commitment to entire L2 state
- **ZK proof:** Cryptographic guarantee of valid execution
- **Public inputs:** Values proven by circuit and checked by L1
- **Account proofs:** Prove L1 state at specific block
- **Versioned hashes:** Link to blob data
- **Light client:** Verify old L1 blocks

### Attack Vectors Prevented
- ✓ Balance inflation (accounting invariants)
- ✓ Fake deposits (priority queue verification)
- ✓ Timing attacks (L1 anchoring)
- ✓ Wrong withdrawals (merkle proof binding)
- ✓ Double withdrawals (execution tracking)
- ✓ Data withholding (blob verification)
- ✓ Invalid transitions (ZK circuit constraints)
- ✓ Missing invariants (explicit checks)

---

## 📊 Quick Reference

### The Three-Phase Commit
```
COMMIT  → Post commitment to L1 (fast, ~1 min)
  ↓
PROVE   → Submit ZK proof (slow, ~1 hour)
  ↓
EXECUTE → Finalize state (fast, ~1 min)
```

### Data Availability Options
```
Calldata: ~$1 per tx (expensive)
Blobs:    ~$0.01 per tx (10-100x cheaper!)
```

### Blob Verification
```
1. Get versioned hash via BLOBHASH opcode
2. Verify KZG proof via point evaluation precompile
3. Check blob commitment in circuit
Result: Proven data availability
```

### Essential Checks
```
L1 Contract:
  ✓ Proof verification
  ✓ Accounting invariant
  ✓ L1 state proof
  ✓ Blob commitment
  ✓ Deposit queue

ZK Circuit:
  ✓ Signature verification
  ✓ Nonce checks
  ✓ Balance checks
  ✓ State root computation
  ✓ Total balances computation
```

---

## 🛡️ Security Checklist Summary

Before deploying a rollup:

**Proof System**
- [ ] Circuit enforces all invariants
- [ ] Public inputs include accounting totals
- [ ] Verifier contract audited
- [ ] Cannot bypass proof verification

**Accounting**
- [ ] Total L2 balances proven
- [ ] Invariant enforced: L2 + pending = deposits - withdrawn
- [ ] L1 balance verified via proof
- [ ] No balance inflation possible

**Data Availability**
- [ ] State diffs published (calldata or blobs)
- [ ] Blob verified via point evaluation
- [ ] State reconstructable from L1
- [ ] Liveness guaranteed

**L1 Anchoring**
- [ ] Batches anchor to specific L1 block
- [ ] Account proof verifies balance
- [ ] Blockhash or light client verification
- [ ] No timing attack vectors

**Withdrawals**
- [ ] Recipient authorization required
- [ ] Merkle proof binds recipient to amount
- [ ] Double-withdrawal prevented
- [ ] Amount deducted before claimable

---

## 💡 Common Questions

**Q: What's the simplest secure rollup design?**

A: See `SIMPLE_L1_ANCHORING.md` - it combines:
- ZK proofs for validity
- Accounting invariants for conservation
- Account proofs for L1 anchoring
- Blobs for cheap data availability

**Q: What's the biggest security risk?**

A: Not enforcing accounting invariants. Without explicit checks, operator can inflate balances. See pitfall #1 in `UNDERSTANDING_ZK_ROLLUPS.md`.

**Q: How does data availability work?**

A: State diffs published in blobs. Anyone can download and reconstruct full state. See `BLOB_VERSIONED_HASHES_EXPLAINED.md` for details.

**Q: What happens if operator disappears?**

A: Anyone can take over using data from L1. See "Operator Goes Offline" scenario in `VISUAL_GUIDE.md`.

**Q: Why use blobs instead of calldata?**

A: 10-100x cheaper! ~$0.01 per tx vs ~$1 per tx. See cost analysis in `MINIMAL_ROLLUP_DESIGN.md`.

---

## 📖 Related Resources

### External Documentation
- [zkSync Era Docs](https://era.zksync.io/docs/)
- [EIP-4844 Specification](https://eips.ethereum.org/EIPS/eip-4844)
- [Ethereum Data Availability](https://ethereum.org/en/developers/docs/data-availability/)

### Code References
- [zkSync Era Contracts](https://github.com/matter-labs/era-contracts)
- [zkSync Era ZK Circuits](https://github.com/matter-labs/era-zkevm_circuits)

---

## 🚀 Next Steps

1. **Read:** Start with `UNDERSTANDING_ZK_ROLLUPS.md`
2. **Visualize:** Review diagrams in `VISUAL_GUIDE.md`
3. **Build:** Follow progression in minimal rollup docs
4. **Study:** Analyze zkSync Era in `PROOF_MECHANISM_ANALYSIS.md`
5. **Deploy:** Use security checklist before launch

---

## 📝 Document Stats

| Document | Lines | Focus | Difficulty |
|----------|-------|-------|------------|
| UNDERSTANDING_ZK_ROLLUPS.md | ~1200 | Concepts & Pitfalls | Beginner |
| VISUAL_GUIDE.md | ~1400 | Diagrams & Flows | Beginner |
| MINIMAL_ROLLUP_DESIGN.md | ~1150 | Basic Implementation | Intermediate |
| MINIMAL_ROLLUP_WITH_ACCOUNTING.md | ~950 | Security Layer 1 | Intermediate |
| ROLLUP_WITH_L1_ANCHORING.md | ~850 | Security Layer 2 (snapshots) | Advanced |
| SIMPLE_L1_ANCHORING.md | ~750 | Security Layer 2 (proofs) | Advanced |
| PROOF_MECHANISM_ANALYSIS.md | ~850 | Production System | Advanced |
| BLOB_VERSIONED_HASHES_EXPLAINED.md | ~700 | Data Availability | Intermediate |

**Total:** ~8,000 lines of comprehensive documentation

---

## 🎓 What You'll Learn

By reading these documents, you'll understand:

✓ How ZK-rollups achieve scalability without sacrificing security
✓ Why proofs are better than fraud proofs (validity vs optimistic)
✓ How EIP-4844 makes rollups 10-100x cheaper
✓ What can go wrong and how to prevent it
✓ How to build a secure rollup from scratch
✓ How production systems like zkSync Era work
✓ The complete security model and attack prevention

---

## 🤝 Contributing

Found an error or want to improve these docs?
1. These documents are educational and explanatory
2. They build understanding from first principles
3. Security is emphasized throughout
4. Examples are simplified but correct

---

## ⚖️ License

This documentation is provided for educational purposes. The zkSync Era code itself has its own license - see the main repository.

---

**Remember:** Building a secure ZK-rollup requires deep understanding. These documents provide that foundation. Take time to understand each layer before moving to the next!
