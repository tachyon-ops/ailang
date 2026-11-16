---
name: lockfree-atomic-protocol-verifier
description: >-
  Formally verify lock-free AtomicU64 compare-and-swap (CAS) state machines,
  token-bucket rate limiters, and sharded financial reserve ledgers using Z3
  inductive protocol proofs and AIL atomic_protocol declarations. Proves
  conservation invariants across arbitrary thread interleavings and compiles to
  native LLVM / ARMv8.1 atomics.
---

# Lock-Free Atomic Protocol & CAS Interleaving Verifier

Concurrency bugs in lock-free `AtomicU64` / `compare_exchange` loops — double
spends under race conditions, `u64` subtraction underflow when two threads pass a
stale balance check, or leaked in-flight reservations — cannot be caught reliably
by stress tests.

This skill proves **inductive conservation invariants across arbitrary thread
interleavings** in milliseconds using Z3 and compiles verified CAS loops via AIL.

## Included Verified Assets

- `scripts/verify_cas_interleavings.py` — Standalone Z3 inductive transition &
  multi-thread interleaving prover (`uv run --with z3-solver scripts/verify_cas_interleavings.py --demo`).
  Checks:
  1. Initial state satisfies global invariant $I(s_0)$.
  2. Every guarded atomic step preserves $I(s) \land G(s, a) \implies I(s')$ without
     64-bit overflow or underflow.
  3. Bounded $K$-step arbitrary thread interleavings never violate $I$ or allow
     stale-read double-withdrawal when CAS retry semantics are enforced vs naive
     non-atomic `load` + `fetch_sub` (automatically demonstrating the race witness!).
- `references/sharded_escrow_ledger.ail` — Proven 4-field Verus/IronSync-style
  `atomic_protocol` (`EscrowLedger`: `available + locked + settled == total_supply`)
  covering `lock_escrow`, `settle_escrow`, and `refund_escrow` transitions.

## Mandatory Lock-Free Synthesis Rules

1. **Never Separate Guard Check from State Mutation (`load` + `fetch_sub` Race)**
   Reading an atomic balance (`load`) and then unconditionally subtracting (`fetch_sub`)
   allows two concurrent threads with `req = 60` against `balance = 100` to both pass
   `req <= balance` and wrap `u64` to `18446744073709551596`! Every bounded transition
   MUST use a compare-and-swap (`compare_exchange`) retry loop re-checking `req <= observed`
   on every retry.

2. **Encode Conservation Laws Explicitly**
   Track conserved totals across states (e.g., `available + reserved + disbursed == cap`)
   so Z3 proves neither value creation nor value destruction on every step.

3. **Bound Step Parameters by State Variables**
   In AIL `(atomic_protocol ...)`, constrain transition parameters directly against
   live protocol fields (e.g., `(req u64[0..available])`) so Z3 proves zero `u64`
   underflow and zero `u64` overflow across `0..U64_MAX`.

## Step-by-Step Workflow

1. **Model & Prove CAS Protocol Invariants with Z3**
   ```bash
   uv run --with z3-solver scripts/verify_cas_interleavings.py --demo
   ```
   Or supply `--protocol-json my_protocol.json` to prove custom state variables,
   conservation invariants, and transitions before writing Rust/C++/Go atomics.

2. **Verify & Compile Hardware CAS Loops with AIL**
   ```bash
   uvx --from git+https://github.com/tachyon-ops/ailang.git ail check \
     references/sharded_escrow_ledger.ail
   uvx --from git+https://github.com/tachyon-ops/ailang.git ail build \
     --target llvm references/sharded_escrow_ledger.ail -o build/escrow_native
   ```
   Lowers verified `atomic_cas` transitions directly to LLVM `cmpxchg` / ARMv8.1
   `casal` instructions with zero UB.
