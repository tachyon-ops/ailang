# `z3_spec_firewall.py` JSON Templates & Failure Patterns

## 1. Catching a Weak Postcondition (`WEAK_SPEC`)

Suppose an agent writes a property test asserting only `out <= gross` for a discount
calculator:

```json
{
  "function_name": "weak_discount_spec",
  "params": {
    "gross": [0, 100000],
    "discount_bps": [0, 5000]
  },
  "preconditions": [],
  "reference_expr": "gross - (gross * discount_bps) // 10000",
  "postcondition": "out >= 0 and out <= gross"
}
```

Running `z3_spec_firewall.py` immediately flags `verdict: "WEAK_SPEC"` because
`const_zero` (`return 0`), `halved` (`return out // 2`), and `off_by_minus_1` all
satisfy `0 <= out <= gross`! Tightening `"postcondition"` to exact equivalence
kills 100% of mutants.

## 2. Disambiguating Natural-Language Prompts (`Clover`)

When a user says *"charge `fee_bps` up to `fee_cap` on `gross`"*, pass both
plausible interpretations (`reference_expr` vs `candidate_b_expr`) to extract a
single concrete test case before writing code:

```json
{
  "function_name": "capped_fee_payout",
  "params": {
    "gross": [1000, 100000],
    "fee_bps": [100, 2000],
    "fee_cap": [50, 500]
  },
  "preconditions": [],
  "reference_expr": "gross - min((gross * fee_bps) // 10000, fee_cap)",
  "postcondition": "out == gross - min((gross * fee_bps) // 10000, fee_cap)",
  "candidate_b_expr": "min(gross - (gross * fee_bps) // 10000, fee_cap)"
}
```
