"""Protobuf-native diagnostics, counterexample encoding, and repair hints (v0.2)."""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from google.protobuf import text_format

from ailang import ail_agent_pb2 as pb

U64_MAX = (1 << 64) - 1
I64_MAX = (1 << 63) - 1
I64_MIN = -(1 << 63)

REPAIR_HINTS: dict[int, str] = {
    pb.E_SYNTAX: "Balance parentheses/brackets or pass a schema-validated `.ail.pb` ModuleProto.",
    pb.E_UNBOUND_SYMBOL: "Bind symbol in function parameters, `let`, `struct`, or declare `(spec ...)` / `(fn ...)` before use.",
    pb.E_TYPE_MISMATCH: "Match types (`u64`, `i64`, `struct`, `slice`, `mut_slice`, `cap.*`). Use `(to_i64 x)` / `(to_u64 x)` for explicit casts.",
    pb.E_LINEAR_USE_AFTER_MOVE: "Thread linear tokens sequentially (`cap.io`, `cap.fs`, `cap.net`): each linear token can be consumed only once.",
    pb.E_LINEAR_UNCONSUMED: "Consume every `cap.io` (`io.done`), `cap.fs` (`fs.close`), and `cap.net` (`net.close`) token before scope exit.",
    pb.E_CAPABILITY_MISSING: "Side-effect intrinsics require a live linear `cap.io`, `cap.fs`, or `cap.net` capability token.",
    pb.E_ALIASING_VIOLATION: "Do not pass the same `mut_slice` or `slice` buffer more than once as a mutable argument in a single call.",
    pb.E_U64_OVERFLOW: "Decompose `(a * b) / c` into `(+ (* (/ a c) b) (/ (* (% a c) b) c))`, use `(+ lo (/ (- hi lo) 2))`, or tighten input refinement bounds.",
    pb.E_U64_UNDERFLOW: "Guard unsigned subtraction `(if (<= a b) 0 (- a b))` or strengthen parameter lower bound `b: u64[0..a]`.",
    pb.E_DIV_BY_ZERO: "Constrain divisor refinement away from 0 (and for `i64`, prevent `MIN_I64 / -1`) or guard with `if`.",
    pb.E_SHIFT_OUT_OF_RANGE: "Constrain shift amount to `[0..63]`.",
    pb.E_SLICE_OUT_OF_BOUNDS: "Ensure slice index `idx` satisfies `0 <= idx < len_var`.",
    pb.E_PRECONDITION_FAILED: "Caller arguments violate callee parameter refinement range (e.g., `net.loopback_send_u64` requires port in `1024..65535`).",
    pb.E_POSTCONDITION_FAILED: "Implementation output violates return refinement range or `ensures` clause on the counterexample.",
    pb.E_LOOP_BASE_FAILED: "Initial `fold` accumulator violates accumulator refinement at `i = 0`.",
    pb.E_LOOP_STEP_FAILED: "Inductive `fold` step violates accumulator refinement at `i + 1`; widen invariant bound as a function of `i`.",
    pb.E_ATOMIC_INVARIANT_FAILED: "Ensure atomic transition preserves the `atomic_protocol` invariant and guards against `obs < req` underflow.",
    pb.E_SPEC_VACUOUS: "Preconditions are contradictory (`UNSAT`); relax parameter refinement bounds.",
    pb.E_SPEC_MUTANT_SURVIVED: "Postcondition only checks partial bounds; add exact relational clause `(== out (spec_fn ...))` to kill buggy mutants.",
    pb.E_SPEC_AMBIGUITY: "Candidate specs disagree on the distinguishing input witness; resolve edge-case policy before codegen.",
    pb.E_I64_OVERFLOW: "Signed 64-bit operation can exceed `[MIN_I64..MAX_I64]` (or trigger `MIN_I64 / -1`); clamp or tighten `i64[lo..hi]` bounds.",
    pb.E_STRUCT_INVARIANT_FAILED: "Field values passed to `(make StructName ...)` violate the struct's dependent field refinement bounds.",
    pb.E_NON_EXHAUSTIVE_MATCH: "Add match arms covering every variant of the enum (or add a trailing wildcard `(_ ...)` arm).",
    pb.E_DUPLICATE_MATCH_ARM: "Remove duplicate variant names in `(enum ...)` or duplicate match pattern arms.",
    pb.E_ENUM_INVARIANT_FAILED: "Field values passed to `(variant EnumName VariantName ...)` violate the variant's dependent field refinement bounds.",
}


@dataclass
class Span:
    line: int = 1
    col: int = 1


class AILCompilerError(Exception):
    def __init__(
        self,
        code: int,
        stage: int,
        item_name: str,
        message: str,
        span: Span | None = None,
        expr: str = "",
        counterexample: dict[str, int] | None = None,
        repair_hint: str | None = None,
    ) -> None:
        super().__init__(message)
        self.diag = make_diagnostic(
            code=code,
            stage=stage,
            item_name=item_name,
            message=message,
            span=span,
            expr=expr,
            counterexample=counterexample,
            repair_hint=repair_hint,
        )


def dict_to_ce_bindings(ce: dict[str, int] | None) -> list[pb.CounterexampleBinding]:
    if not ce:
        return []
    out: list[pb.CounterexampleBinding] = []
    for k in sorted(ce.keys()):
        v = int(ce[k])
        b = pb.CounterexampleBinding(name=k)
        if 0 <= v <= U64_MAX:
            b.u64_val = v
        elif I64_MIN <= v < 0:
            b.i64_val = v
        else:
            b.big_int = str(v)
    return out


def dict_to_ce_bindings_fixed(ce: dict[str, int] | None) -> list[pb.CounterexampleBinding]:
    if not ce:
        return []
    out: list[pb.CounterexampleBinding] = []
    for k in sorted(ce.keys()):
        v = int(ce[k])
        b = pb.CounterexampleBinding(name=k)
        if 0 <= v <= U64_MAX:
            b.u64_val = v
        elif I64_MIN <= v < 0:
            b.i64_val = v
        else:
            b.big_int = str(v)
        out.append(b)
    return out


# Alias primary name cleanly
dict_to_ce_bindings = dict_to_ce_bindings_fixed


def ce_bindings_to_dict(bindings: list[pb.CounterexampleBinding]) -> dict[str, int]:
    res: dict[str, int] = {}
    for b in bindings:
        which = b.WhichOneof("value")
        if which == "u64_val":
            res[b.name] = int(b.u64_val)
        elif which == "i64_val":
            res[b.name] = int(b.i64_val)
        elif which == "big_int":
            res[b.name] = int(b.big_int)
    return res


def make_diagnostic(
    code: int,
    stage: int,
    item_name: str,
    message: str,
    span: Span | None = None,
    expr: str = "",
    counterexample: dict[str, int] | None = None,
    repair_hint: str | None = None,
) -> pb.Diagnostic:
    sp = pb.SourceSpan(line=span.line if span else 1, column=span.col if span else 1)
    return pb.Diagnostic(
        code=code,
        stage=stage,
        item_name=item_name,
        span=sp,
        expr=expr,
        message=message,
        counterexample=dict_to_ce_bindings(counterexample),
        repair_hint=repair_hint if repair_hint is not None else REPAIR_HINTS.get(code, ""),
    )


def to_prototext(msg: Any) -> str:
    return text_format.MessageToString(msg, as_one_line=False)


def to_proto_bytes(msg: Any) -> bytes:
    return msg.SerializeToString()


def format_human_summary(resp: pb.CompilerResponse) -> str:
    lines: list[str] = []
    status_name = pb.Status.Name(resp.status)
    lines.append(f"[{status_name}] total_elapsed={resp.total_elapsed_ms:.2f} ms")
    for st in resp.proof_stats:
        mark = "PROVED" if st.verified else "FAILED"
        lines.append(
            f"  [{mark}] {st.item_name:<22} {st.elapsed_ms:6.2f} ms "
            f"(T0_Interval={st.tier0_interval_discharged}, T1_Bitwuzla={st.tier1_bitwuzla_queries}, "
            f"T2_Z3={st.tier2_z3_queries}, O1_Loops={st.o1_loop_steps})"
        )
    for au in resp.spec_audits:
        tag = "TIGHT" if (au.non_vacuous and au.uniquely_tight) else "WEAK "
        lines.append(
            f"  [SPEC_{tag}] {au.fn_name:<18} {au.elapsed_ms:6.2f} ms "
            f"(non_vacuous={au.non_vacuous}, uniquely_tight={au.uniquely_tight}, killed={au.mutants_killed}/{au.mutants_tested})"
        )
        for sm in au.surviving_mutants[:3]:
            ce = ce_bindings_to_dict(list(sm.witness))
            lines.append(
                f"      * Surviving mutant `{sm.mutant_kind}` ({sm.mutant_expr}) at {ce} -> mutant={sm.mutant_output}, ref={sm.reference_output}"
            )
    for df in resp.spec_diffs:
        if df.equivalent:
            lines.append(f"  [EQUIVALENT] {df.fn_name:<18} {df.elapsed_ms:6.2f} ms (0 discrepancies across 2^64 domain)")
        else:
            ce = ce_bindings_to_dict(list(df.distinguishing_input))
            lines.append(f"  [AMBIGUITY]  {df.fn_name:<18} {df.elapsed_ms:6.2f} ms | witness={ce}")
            lines.append(
                f"      * Spec_A={df.spec_a_output} (violates_conservation={df.spec_a_violates_conservation}) "
                f"vs Spec_B={df.spec_b_output} (violates_conservation={df.spec_b_violates_conservation})"
            )
            lines.append(f"      * Question: {df.clarification_question}")
    for d in resp.diagnostics:
        ce = ce_bindings_to_dict(list(d.counterexample))
        code_name = pb.ErrorCode.Name(d.code)
        stage_name = pb.Stage.Name(d.stage)
        lines.append(
            f"  [{code_name}] ({stage_name}) in `{d.item_name}` at L{d.span.line}:{d.span.column}: {d.message}"
        )
        if d.expr:
            lines.append(f"      Expr: {d.expr}")
        if ce:
            lines.append(f"      Counterexample: {ce}")
        if d.repair_hint:
            lines.append(f"      Repair Hint: {d.repair_hint}")
    if resp.HasField("artifacts") and resp.artifacts.binary_or_lib_path:
        art = resp.artifacts
        lines.append(
            f"  [ARTIFACTS] output={art.binary_or_lib_path} (NEON_SIMD_ops={art.neon_simd_instructions}, Atomic_ops={art.hardware_atomic_instructions})"
        )
    return "\n".join(lines)


def format_repair_session(sess: pb.RepairSession) -> str:
    lines = [
        f"[REPAIR_{pb.Status.Name(sess.final_status)}] iterations={sess.iterations} total_elapsed={sess.total_elapsed_ms:.2f} ms"
    ]
    for step in sess.steps:
        cname = pb.ErrorCode.Name(step.triggered_code)
        lines.append(f"  Turn {step.turn}: [{cname}] on `{step.target_item}` -> {step.patch_summary}")
    if sess.HasField("artifacts") and sess.artifacts.binary_or_lib_path:
        lines.append(f"  [COMPILED] {sess.artifacts.binary_or_lib_path}")
    return "\n".join(lines)
