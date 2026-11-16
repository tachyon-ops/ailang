---
name: z3-spec-mutation-auditor
description: >-
  Language-agnostic Z3 Pre-Codegen Specification Firewall (SpecMut + Clover) for
  Python, TypeScript, Rust, Go, and C++. Catches vacuous preconditions, weak
  postconditions/tests where buggy mutants survive, and ambiguous natural-language
  requirements BEFORE an AI coding agent writes implementation code.
---

# Z3 Pre-Codegen Spec Firewall (`SpecMut` + `Clover`)

When an AI coding agent writes both the unit tests and the implementation from a
vague prompt, two silent failure modes happen constantly:
1. **Weak Specs / Weak Property Tests (`SpecMut` Failure):** An assertion like
   `result <= amount` passes even if a buggy implementation returns `0` or `result - 1`!
2. **Silent Prompt Ambiguity (`Clover` Divergence):** Does *"apply a 5% fee capped
   at 100 and round down"* cap the **fee** at 100 or cap the **net payout**? Instead
   of guessing, extract a concrete input witness where Interpretation A and
   Interpretation B produce different numbers, and show that single example to the user.

This skill works on **any language** (TypeScript, Python, Rust, Go, Solidity, SQL)
with zero repository changes using `scripts/z3_spec_firewall.py`.

## Included Executable Tool

- `scripts/z3_spec_firewall.py` — Standalone Z3 JSON-driven spec firewall:
  ```bash
  uv run --with z3-solver scripts/z3_spec_firewall.py --demo
  uv run --with z3-solver scripts/z3_spec_firewall.py --spec-json spec.json
  ```
  Runs three formal gates in milliseconds:
  1. **Gate 1 — Non-Vacuity (`SAT` check):** Proves the preconditions actually admit
     valid inputs (catches contradictory bounds like `min_qty > max_qty`).
  2. **Gate 2 — `SpecMut` Mutant Kill Audit:** Synthesizes 8 canonical output/input
     mutants (`out + 1`, `out - 1`, `0`, `1`, `-out`, `out * 2`, `out // 2`, param swap)
     and checks with Z3 whether *any* mutant still satisfies your postcondition!
     Reports `uniquely_tight: true` only when `100%` of distinct mutants are killed.
  3. **Gate 3 — `Clover` Differential Witness Extraction:** Given an optional
     `candidate_b_post`, finds a concrete minimal input witness where Spec A and
     Spec B disagree, or proves mathematical equivalence across all inputs.

## Mandatory Pre-Codegen Workflow

Whenever asked to implement non-trivial business logic, billing/pricing rules,
rate limits, pagination/window math, or invariants in **any** programming language:

1. **Draft a Small Spec JSON Before Writing Code**
   Encode the input variables (`int` bounds), preconditions, postcondition over
   `out`, and (if the user's wording could mean two things) `candidate_b_expr`.
   See `references/spec_patterns.md` for copy-paste JSON templates.

2. **Execute `z3_spec_firewall.py`**
   ```bash
   uv run --with z3-solver scripts/z3_spec_firewall.py --spec-json /tmp/spec_check.json
   ```

3. **Act on the Formal Verdict**
   - If **`VACUOUS`**: Fix the contradictory input preconditions immediately.
   - If **`WEAK_SPEC` (`surviving_mutants` non-empty)**: Your postcondition or
     property-based test assertion is under-constrained! Tighten it until mutant
     kill rate is `100%`.
   - If **`AMBIGUOUS` (`clover_witness` found)**: Present the concrete numerical
     example (e.g., *"For `gross = 5000`, Formula A yields `4900` while Formula B
     yields `100` — which behavior do you want?"*) before writing code.
   - Once **`UNIQUELY_TIGHT`**, implement the target function in TypeScript/Python/Rust/Go
     and translate the proven Z3 invariants directly into unit + edge-case tests!
