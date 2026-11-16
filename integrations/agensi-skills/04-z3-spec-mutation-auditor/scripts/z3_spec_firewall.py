#!/usr/bin/env python3
"""Language-Agnostic Z3 Pre-Codegen Specification Firewall (SpecMut + Clover).

Audits function specifications encoded in safe arithmetic JSON before code generation:
  - Gate 1: Non-Vacuity (do valid inputs exist?)
  - Gate 2: SpecMut Mutant Kill Rate (do off-by-one / zero / scale mutants survive?)
  - Gate 3: Clover Differential Disambiguation (concrete witness between 2 interpretations)

Run via:
  uv run --with z3-solver scripts/z3_spec_firewall.py --demo
  uv run --with z3-solver scripts/z3_spec_firewall.py --spec-json path/to/spec.json
"""

from __future__ import annotations
import ast
import argparse
import json
from pathlib import Path
import sys
import z3

DEMO_SPEC = {
    "function_name": "net_payout_after_capped_fee",
    "params": {
        "gross": [0, 10_000_000],
        "fee_bps": [0, 5000],
        "fee_cap": [0, 1_000_000],
    },
    "preconditions": [
        "fee_cap >= 100",
    ],
    "reference_expr": "gross - min((gross * fee_bps) // 10000, fee_cap)",
    "postcondition": "out == gross - min((gross * fee_bps) // 10000, fee_cap)",
    "candidate_b_expr": "min(gross - (gross * fee_bps) // 10000, fee_cap)",
}


def _z3_min(a: z3.ArithRef, b: z3.ArithRef) -> z3.ArithRef:
    return z3.If(a <= b, a, b)


def _z3_max(a: z3.ArithRef, b: z3.ArithRef) -> z3.ArithRef:
    return z3.If(a >= b, a, b)


def _z3_abs(a: z3.ArithRef) -> z3.ArithRef:
    return z3.If(a >= 0, a, -a)


class SafeZ3Evaluator(ast.NodeVisitor):
    """Evaluates pure arithmetic/boolean Python AST expressions into Z3 formulas safely."""

    def __init__(self, env: dict[str, z3.ArithRef]) -> None:
        self.env = env

    def visit_Expression(self, node: ast.Expression):
        return self.visit(node.body)

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, bool):
            return z3.BoolVal(node.value)
        if isinstance(node.value, int):
            return z3.IntVal(node.value)
        raise ValueError(f"Unsupported constant: {node.value!r}")

    def visit_Name(self, node: ast.Name):
        if node.id in self.env:
            return self.env[node.id]
        raise ValueError(f"Unknown identifier in spec expression: {node.id}")

    def visit_UnaryOp(self, node: ast.UnaryOp):
        val = self.visit(node.operand)
        if isinstance(node.op, ast.USub):
            return -val
        if isinstance(node.op, ast.Not):
            return z3.Not(val)
        raise ValueError(f"Unsupported unary op: {type(node.op).__name__}")

    def visit_BinOp(self, node: ast.BinOp):
        left = self.visit(node.left)
        right = self.visit(node.right)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.FloorDiv):
            return left / right
        if isinstance(node.op, ast.Mod):
            return left % right
        raise ValueError(f"Unsupported binary op: {type(node.op).__name__} (use // for integer division)")

    def visit_BoolOp(self, node: ast.BoolOp):
        vals = [self.visit(v) for v in node.values]
        if isinstance(node.op, ast.And):
            return z3.And(*vals)
        if isinstance(node.op, ast.Or):
            return z3.Or(*vals)
        raise ValueError(f"Unsupported bool op: {type(node.op).__name__}")

    def visit_Compare(self, node: ast.Compare):
        left = self.visit(node.left)
        clauses = []
        cur = left
        for op, comp in zip(node.ops, node.comparators):
            nxt = self.visit(comp)
            if isinstance(op, ast.Eq):
                clauses.append(cur == nxt)
            elif isinstance(op, ast.NotEq):
                clauses.append(cur != nxt)
            elif isinstance(op, ast.Lt):
                clauses.append(cur < nxt)
            elif isinstance(op, ast.LtE):
                clauses.append(cur <= nxt)
            elif isinstance(op, ast.Gt):
                clauses.append(cur > nxt)
            elif isinstance(op, ast.GtE):
                clauses.append(cur >= nxt)
            else:
                raise ValueError(f"Unsupported comparison: {type(op).__name__}")
            cur = nxt
        return clauses[0] if len(clauses) == 1 else z3.And(*clauses)

    def visit_IfExp(self, node: ast.IfExp):
        return z3.If(self.visit(node.test), self.visit(node.body), self.visit(node.orelse))

    def visit_Call(self, node: ast.Call):
        if not isinstance(node.func, ast.Name):
            raise ValueError("Only direct helper calls min(), max(), abs() are allowed")
        fn = node.func.id
        args = [self.visit(a) for a in node.args]
        if fn == "min" and len(args) == 2:
            return _z3_min(args[0], args[1])
        if fn == "max" and len(args) == 2:
            return _z3_max(args[0], args[1])
        if fn == "abs" and len(args) == 1:
            return _z3_abs(args[0])
        raise ValueError(f"Unsupported call: {fn}()")

    def generic_visit(self, node: ast.AST):
        raise ValueError(f"Disallowed AST construct in spec: {type(node).__name__}")


def parse_z3_expr(expr_src: str, env: dict[str, z3.ArithRef]):
    tree = ast.parse(expr_src, mode="eval")
    return SafeZ3Evaluator(env).visit(tree)


def audit_spec_dict(spec: dict) -> dict:
    params_cfg: dict[str, list[int]] = spec["params"]
    env: dict[str, z3.ArithRef] = {}
    pre: list[z3.BoolRef] = []

    for pname, bounds in params_cfg.items():
        lo, hi = int(bounds[0]), int(bounds[1])
        v = z3.Int(pname)
        env[pname] = v
        pre.extend([v >= lo, v <= hi])

    for p_expr in spec.get("preconditions", []):
        pre.append(parse_z3_expr(p_expr, env))

    # Gate 1: Non-vacuity
    s_vac = z3.Solver()
    s_vac.set("timeout", 4000)
    s_vac.add(*pre)
    non_vacuous = s_vac.check() == z3.sat
    if not non_vacuous:
        return {
            "function": spec.get("function_name", "unknown"),
            "verdict": "VACUOUS",
            "non_vacuous": False,
            "message": "Preconditions are contradictory; zero valid inputs exist.",
        }

    ref_z3 = parse_z3_expr(spec["reference_expr"], env)
    out_var = z3.Int("out")
    post_env = dict(env, out=out_var)
    post_z3 = parse_z3_expr(spec["postcondition"], post_env)

    # Gate 2: SpecMut mutant kill rate
    mutants: dict[str, z3.ArithRef] = {
        "off_by_plus_1": ref_z3 + 1,
        "off_by_minus_1": ref_z3 - 1,
        "const_zero": z3.IntVal(0),
        "const_one": z3.IntVal(1),
        "negated": -ref_z3,
        "doubled": ref_z3 * 2,
        "halved": ref_z3 / 2,
    }
    pnames = list(params_cfg.keys())
    if len(pnames) >= 2:
        swapped_env = dict(env)
        swapped_env[pnames[0]], swapped_env[pnames[1]] = env[pnames[1]], env[pnames[0]]
        mutants[f"swap_{pnames[0]}_{pnames[1]}"] = parse_z3_expr(spec["reference_expr"], swapped_env)

    killed = 0
    total_distinct = 0
    surviving: list[dict] = []

    for mname, mexpr in mutants.items():
        # Check if mutant differs from reference on at least one valid input
        s_diff = z3.Solver()
        s_diff.set("timeout", 3000)
        s_diff.add(*pre, mexpr != ref_z3)
        if s_diff.check() != z3.sat:
            continue
        total_distinct += 1

        # A mutant SURVIVES if for ALL valid inputs where mexpr != ref_z3, wait:
        # In implementation mutation testing, a mutant program M(x) survives the spec Post(x, out)
        # iff ∀x. Pre(x) => Post(x, M(x)). Equivalently, it is KILLED iff ∃x. Pre(x) ∧ ¬Post(x, M(x)).
        mut_post = z3.substitute(post_z3, (out_var, mexpr))
        s_kill = z3.Solver()
        s_kill.set("timeout", 3000)
        s_kill.add(*pre, z3.Not(mut_post))
        if s_kill.check() == z3.sat:
            killed += 1
        else:
            surviving.append({"mutant": mname})

    uniquely_tight = len(surviving) == 0

    # Check universal uniqueness: does there exist x, y1 != y2 both satisfying Post(x, y)?
    y1, y2 = z3.Int("y1"), z3.Int("y2")
    s_uniq = z3.Solver()
    s_uniq.set("timeout", 3000)
    s_uniq.add(
        *pre,
        y1 != y2,
        z3.substitute(post_z3, (out_var, y1)),
        z3.substitute(post_z3, (out_var, y2)),
    )
    exact_functional = s_uniq.check() == z3.unsat

    # Gate 3: Clover Differential Witness (optional candidate_b_expr)
    clover = None
    if "candidate_b_expr" in spec and spec["candidate_b_expr"]:
        cand_b = parse_z3_expr(spec["candidate_b_expr"], env)
        s_clover = z3.Solver()
        s_clover.set("timeout", 4000)
        s_clover.add(*pre, ref_z3 != cand_b)
        if s_clover.check() == z3.sat:
            m = s_clover.model()
            inputs = {k: int(str(m.evaluate(v, model_completion=True))) for k, v in env.items()}
            clover = {
                "equivalent": False,
                "distinguishing_inputs": inputs,
                "spec_a_output": int(str(m.evaluate(ref_z3, model_completion=True))),
                "spec_b_output": int(str(m.evaluate(cand_b, model_completion=True))),
            }
        else:
            clover = {"equivalent": True, "distinguishing_inputs": None}

    verdict = "UNIQUELY_TIGHT" if (uniquely_tight and exact_functional) else "WEAK_SPEC"
    return {
        "function": spec.get("function_name", "unknown"),
        "verdict": verdict,
        "non_vacuous": True,
        "exact_functional_postcondition": exact_functional,
        "mutants_tested": total_distinct,
        "mutants_killed": killed,
        "kill_rate_pct": round(100.0 * killed / max(1, total_distinct), 1),
        "surviving_mutants": surviving,
        "clover_disambiguation": clover,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit pre-codegen specs with Z3 SpecMut & Clover.")
    parser.add_argument("--spec-json", type=str, help="Path to JSON spec definition")
    parser.add_argument("--demo", action="store_true", help="Run built-in capped-fee spec & Clover demo")
    args = parser.parse_args()

    spec = json.loads(Path(args.spec_json).read_text(encoding="utf-8")) if args.spec_json else DEMO_SPEC
    report = audit_spec_dict(spec)
    print(json.dumps(report, indent=2))
    return 0 if report["verdict"] == "UNIQUELY_TIGHT" else 1


if __name__ == "__main__":
    sys.exit(main())
