"""Closed-Loop Protobuf Agent Repair Harness (`ail repair`): Counterexample-Guided AST Synthesis + LLM Hook."""

from __future__ import annotations
from collections.abc import Callable
import json
import os
from pathlib import Path
import time
import urllib.request

from ailang import ail_agent_pb2 as pb
from ailang.codegen_llvm import compile_llvm_to_native
from ailang.diagnostics import AILCompilerError, Span, to_prototext
from ailang.ownership import LINEAR_CAPS, ModuleTypeEnv, check_module_ownership_v2
from ailang.parser import SNode, load_ail_path, module_to_proto, parse_source, pretty
from ailang.spec_firewall import audit_module_specifications
from ailang.verifier import ModuleVerifier, _extract_range_nodes

LLMRepairCallback = Callable[[str, pb.CompilerResponse], str]

CAP_STEP_OPS: dict[str, str] = {
    "io.print_u64": "cap.io",
    "io.print_i64": "cap.io",
    "fs.write_u64": "cap.fs",
    "fs.write_i64": "cap.fs",
    "net.loopback_send_u64": "cap.net",
}
CAP_CLOSE_OPS: dict[str, str] = {
    "io.done": "cap.io",
    "fs.close": "cap.fs",
    "net.close": "cap.net",
}


def format_module_source(forms: list[SNode]) -> str:
    lines: list[str] = []
    for f in forms:
        head = str(f.val[0].val)
        if head in ("fn", "main") and len(f.val) >= 4:
            if head == "fn":
                lines.append(
                    f"(fn {pretty(f.val[1])} {pretty(f.val[2])}\n"
                    f"  {pretty(f.val[3])}\n"
                    f"  {pretty(f.val[4])})"
                )
            else:
                lines.append(
                    f"(main {pretty(f.val[1])} {pretty(f.val[2])}\n"
                    f"  {pretty(f.val[3])})"
                )
        else:
            lines.append(pretty(f))
    return "\n\n".join(lines) + "\n"


def _mk(val: int | str | list[SNode], sp: Span | None = None) -> SNode:
    return SNode(val, sp or Span(1, 1))


def _clone(node: SNode) -> SNode:
    if isinstance(node.val, list):
        return SNode([_clone(ch) for ch in node.val], node.span)
    return SNode(node.val, node.span)


def _rewrite_first_expr(node: SNode, rule: Callable[[SNode], SNode | None]) -> tuple[SNode, bool]:
    """Top-down single-site AST rewrite (tries parent before children so `/ (+ a b) 2` matches before `(+ a b)`)."""
    replaced = rule(node)
    if replaced is not None:
        return replaced, True
    if isinstance(node.val, list):
        new_items: list[SNode] = []
        changed = False
        for ch in node.val:
            if not changed:
                nch, changed = _rewrite_first_expr(ch, rule)
                new_items.append(nch)
            else:
                new_items.append(_clone(ch))
        if changed:
            return SNode(new_items, node.span), True
    return _clone(node), False


def _repair_linear_capabilities(fn_or_main: SNode) -> tuple[SNode, str]:
    """Re-threads reused linear tokens sequentially and closes any unconsumed linear capabilities before exit."""
    is_main = str(fn_or_main.val[0].val) == "main"
    params_node = fn_or_main.val[1] if is_main else fn_or_main.val[2]
    body_idx = 3 if is_main else 4
    body = _clone(fn_or_main.val[body_idx])

    live_tok: dict[str, str] = {}
    tok_kind: dict[str, str] = {}
    seq_id = 0

    for p in params_node.val:
        pname = str(p.val[0].val)
        praw = p.val[1].raw()
        if isinstance(praw, str) and praw in LINEAR_CAPS:
            live_tok[praw] = pname
            tok_kind[pname] = praw

    def fresh_tok(cap_k: str) -> str:
        nonlocal seq_id
        seq_id += 1
        base = cap_k.split(".")[1]
        nm = f"_{base}_t{seq_id}"
        tok_kind[nm] = cap_k
        return nm

    def thread_expr(n: SNode) -> SNode:
        if not isinstance(n.val, list) or not n.val:
            return n
        op = str(n.val[0].val)
        if op == "let":
            new_bindings: list[SNode] = []
            for b in n.val[1].val:
                bname = str(b.val[0].val)
                rhs = thread_expr(b.val[1])
                if isinstance(rhs.val, list) and rhs.val and str(rhs.val[0].val) in CAP_STEP_OPS:
                    ck = CAP_STEP_OPS[str(rhs.val[0].val)]
                    # Always assign a fresh SSA-style linear token name so reused/shadowed bindings never collide
                    actual_bname = bname if bname not in tok_kind else fresh_tok(ck)
                    tok_kind[actual_bname] = ck
                    live_tok[ck] = actual_bname
                    new_bindings.append(_mk([_mk(actual_bname, b.val[0].span), rhs], b.span))
                else:
                    new_bindings.append(_mk([_clone(b.val[0]), rhs], b.span))
            new_body = thread_expr(n.val[2])
            return _mk([_clone(n.val[0]), _mk(new_bindings, n.val[1].span), new_body], n.span)

        if op in CAP_STEP_OPS:
            ck = CAP_STEP_OPS[op]
            cur = live_tok.get(ck)
            tok_arg = _mk(cur, n.val[1].span) if cur else thread_expr(n.val[1])
            rest = [thread_expr(a) for a in n.val[2:]]
            return _mk([_clone(n.val[0]), tok_arg, *rest], n.span)

        if op in CAP_CLOSE_OPS:
            ck = CAP_CLOSE_OPS[op]
            cur = live_tok.pop(ck, None)
            tok_arg = _mk(cur, n.val[1].span) if cur else thread_expr(n.val[1])
            rest = [thread_expr(a) for a in n.val[2:]]
            return _mk([_clone(n.val[0]), tok_arg, *rest], n.span)

        return _mk([thread_expr(ch) for ch in n.val], n.span)

    repaired_body = thread_expr(body)

    # Consume any still-live linear tokens (`cap.fs`, `cap.net`, `cap.io`) inside the innermost `let` scope
    close_bindings: list[SNode] = []
    for ck in ("cap.fs", "cap.net"):
        if ck in live_tok:
            tok = live_tok.pop(ck)
            close_op = "fs.close" if ck == "cap.fs" else "net.close"
            close_bindings.append(_mk([_mk(f"_closed_{tok}"), _mk([_mk(close_op), _mk(tok)])]))

    rem_io = live_tok.pop("cap.io", None)

    def _attach_cleanup_inside_lets(expr: SNode) -> SNode:
        if isinstance(expr.val, list) and len(expr.val) == 3 and expr.val[0].val == "let":
            return _mk([expr.val[0], expr.val[1], _attach_cleanup_inside_lets(expr.val[2])], expr.span)
        out_e = expr
        if rem_io is not None:
            out_e = _mk([_mk("io.done"), _mk(rem_io), out_e], out_e.span)
        if close_bindings:
            out_e = _mk([_mk("let"), _mk(close_bindings), out_e], out_e.span)
        return out_e

    repaired_body = _attach_cleanup_inside_lets(repaired_body)

    new_items = list(fn_or_main.val)
    new_items[body_idx] = repaired_body
    return SNode(new_items, fn_or_main.span), "Re-threaded linear capability tokens sequentially and closed live handles"


def _lift_expr_to_pure_spec(node: SNode, tenv: ModuleTypeEnv | None = None) -> SNode:
    """Converts runtime casts/helpers and signed C-truncating division into pure mathematical `int` spec AST."""
    if not isinstance(node.val, list) or not node.val:
        return _clone(node)
    op = str(node.val[0].val)
    if op in ("to_i64", "to_u64"):
        return _lift_expr_to_pure_spec(node.val[1], tenv)
    if tenv and tenv.expr_types.get(id(node)) == "i64" and op in ("/", "%"):
        mapped = "trunc_div" if op == "/" else "trunc_rem"
        return SNode([_mk(mapped, node.val[0].span), *[_lift_expr_to_pure_spec(ch, tenv) for ch in node.val[1:]]], node.span)
    return SNode([_lift_expr_to_pure_spec(ch, tenv) for ch in node.val], node.span)


def apply_deterministic_repair(forms: list[SNode], diag: pb.Diagnostic) -> tuple[list[SNode], str]:
    """Applies one deterministic AST repair step guided by `pb.Diagnostic`."""
    code = diag.code
    target = diag.item_name
    new_forms: list[SNode] = []

    # 1. Spec Firewall Weak Specification (`E_SPEC_MUTANT_SURVIVED`)
    if code == pb.E_SPEC_MUTANT_SURVIVED:
        tenv = check_module_ownership_v2(forms)
        existing_specs: dict[str, int] = {}
        for f in forms:
            if str(f.val[0].val) == "spec":
                existing_specs[str(f.val[1].val)] = len(f.val[2].val)

        synth_spec_decl: SNode | None = None
        summary = ""
        for f in forms:
            if str(f.val[0].val) == "fn" and str(f.val[1].val) == target:
                params_n, ret_n, body_n = f.val[2], f.val[3], f.val[4]
                pnames = [str(p.val[0].val) for p in params_n.val]

                # Prefer existing `(spec exact_<target> ...)` or `(spec <target>_spec ...)`
                cand_names = [f"exact_{target}", f"{target}_spec", f"spec_{target}"]
                chosen_spec = next((cn for cn in cand_names if existing_specs.get(cn) == len(pnames)), None)
                if chosen_spec is None:
                    chosen_spec = f"spec_{target}"
                    spec_params = _mk([_mk([_mk(pn), _mk("int")]) for pn in pnames])
                    synth_spec_decl = _mk([_mk("spec"), _mk(chosen_spec), spec_params, _lift_expr_to_pure_spec(body_n, tenv)])

                spec_call = _mk([_mk(chosen_spec), *[_mk(pn) for pn in pnames]])
                raw_ret = ret_n.raw()
                if isinstance(raw_ret, str) or (isinstance(raw_ret, list) and raw_ret and raw_ret[0] in ("u64_range", "i64_range")):
                    rname = "out"
                    new_ret = _mk([_mk(rname), _clone(ret_n), _mk([_mk("=="), _mk(rname), spec_call])], ret_n.span)
                else:
                    rname = str(ret_n.val[0].val)
                    new_ret = _mk([*[_clone(x) for x in ret_n.val], _mk([_mk("=="), _mk(rname), spec_call])], ret_n.span)

                new_fn = _mk([_clone(f.val[0]), _clone(f.val[1]), _clone(params_n), new_ret, _clone(body_n)], f.span)
                if synth_spec_decl is not None:
                    new_forms.append(synth_spec_decl)
                new_forms.append(new_fn)
                summary = f"Tightened `{target}` postcondition with exact relational spec `(== {rname} ({chosen_spec} ...))`"
            else:
                new_forms.append(_clone(f))
        if summary:
            return new_forms, summary

    # Collect struct definitions for struct-invariant clamping if needed
    structs_map: dict[str, list[tuple[str, SNode]]] = {}
    for f in forms:
        if str(f.val[0].val) == "struct":
            snm = str(f.val[1].val)
            structs_map[snm] = [(str(fld.val[0].val), fld.val[1]) for fld in f.val[2].val]

    # 2. Function / Main Body AST Repairs
    for f in forms:
        head = str(f.val[0].val)
        item_nm = "main" if head == "main" else (str(f.val[1].val) if len(f.val) > 1 else "")
        if item_nm != target or head not in ("fn", "main"):
            new_forms.append(_clone(f))
            continue

        if code in (pb.E_LINEAR_USE_AFTER_MOVE, pb.E_LINEAR_UNCONSUMED):
            rep_f, summary = _repair_linear_capabilities(f)
            new_forms.append(rep_f)
            for rem in forms[forms.index(f) + 1 :]:
                new_forms.append(_clone(rem))
            return new_forms, summary

        body_idx = 3 if head == "main" else 4
        body_node = f.val[body_idx]
        summary_box = [""]

        def rule(n: SNode) -> SNode | None:
            if not isinstance(n.val, list) or not n.val:
                return None
            op = str(n.val[0].val)

            # Overflow inside `(/ (+ a b) 2)` or `(/ (* a b) C)`
            if code == pb.E_U64_OVERFLOW and op == "/" and len(n.val) == 3:
                num, den = n.val[1], n.val[2]
                if isinstance(num.val, list) and len(num.val) == 3 and pretty(num) == diag.expr:
                    nop = str(num.val[0].val)
                    a, b = num.val[1], num.val[2]
                    if nop == "+" and den.val == 2:
                        summary_box[0] = f"Rewrote `{pretty(n)}` to overflow-free midpoint"
                        return _mk(
                            [
                                _mk("if"),
                                _mk([_mk("<="), _clone(a), _clone(b)]),
                                _mk([_mk("+"), _clone(a), _mk([_mk("/"), _mk([_mk("-"), _clone(b), _clone(a)]), _mk(2)])]),
                                _mk([_mk("+"), _clone(b), _mk([_mk("/"), _mk([_mk("-"), _clone(a), _clone(b)]), _mk(2)])]),
                            ],
                            n.span,
                        )
                    if nop == "*" and isinstance(den.val, int) and den.val > 0:
                        c = _mk(den.val)
                        summary_box[0] = f"Decomposed `{pretty(n)}` via quotient-remainder identity"
                        return _mk(
                            [
                                _mk("+"),
                                _mk([_mk("*"), _mk([_mk("/"), _clone(a), _clone(c)]), _clone(b)]),
                                _mk([_mk("/"), _mk([_mk("*"), _mk([_mk("%"), _clone(a), _clone(c)]), _clone(b)]), _clone(c)]),
                            ],
                            n.span,
                        )

            if pretty(n) != diag.expr:
                return None

            if code == pb.E_U64_UNDERFLOW:
                if op == "-" and len(n.val) == 3:
                    a, b = n.val[1], n.val[2]
                    summary_box[0] = f"Guarded unsigned subtraction `{pretty(n)}` with saturating floor `0`"
                    return _mk([_mk("if"), _mk([_mk("<="), _clone(a), _clone(b)]), _mk(0), _clone(n)], n.span)
                if op == "to_u64" and len(n.val) == 2:
                    x = n.val[1]
                    summary_box[0] = f"Clamped negative input in `{pretty(n)}` to `0` before `to_u64`"
                    return _mk([_mk("to_u64"), _mk([_mk("if"), _mk([_mk("<"), _clone(x), _mk(0)]), _mk(0), _clone(x)])], n.span)

            if code == pb.E_U64_OVERFLOW and op == "+" and len(n.val) == 3:
                a, b = n.val[1], n.val[2]
                summary_box[0] = f"Added saturating `MAX` guard to `{pretty(n)}`"
                return _mk(
                    [_mk("if"), _mk([_mk(">"), _clone(a), _mk([_mk("-"), _mk("MAX"), _clone(b)])]), _mk("MAX"), _clone(n)],
                    n.span,
                )

            if code == pb.E_I64_OVERFLOW:
                if op == "/" and len(n.val) == 3:
                    a, b = n.val[1], n.val[2]
                    summary_box[0] = f"Guarded signed division `{pretty(n)}` against `MIN_I64 / -1` trap"
                    return _mk(
                        [
                            _mk("if"),
                            _mk([_mk("and"), _mk([_mk("=="), _clone(a), _mk("MIN_I64")]), _mk([_mk("=="), _clone(b), _mk(-1)])]),
                            _mk("MAX_I64"),
                            _clone(n),
                        ],
                        n.span,
                    )
                if op == "to_i64" and len(n.val) == 2:
                    x = n.val[1]
                    summary_box[0] = f"Clamped `u64` argument to `MAX_I64` inside `{pretty(n)}`"
                    return _mk([_mk("to_i64"), _mk([_mk("min"), _clone(x), _mk(9223372036854775807)])], n.span)

            if code == pb.E_DIV_BY_ZERO and op in ("/", "%") and len(n.val) == 3:
                b = n.val[2]
                summary_box[0] = f"Guarded `{pretty(n)}` against zero divisor"
                return _mk([_mk("if"), _mk([_mk("=="), _clone(b), _mk(0)]), _mk(0), _clone(n)], n.span)

            if code == pb.E_SHIFT_OUT_OF_RANGE and op in (">>", "<<") and len(n.val) == 3:
                a, k = n.val[1], n.val[2]
                summary_box[0] = f"Masked shift count `{pretty(k)}` to `[0..63]`"
                return _mk([_mk(op), _clone(a), _mk([_mk("&"), _clone(k), _mk(63)])], n.span)

            if code == pb.E_STRUCT_INVARIANT_FAILED and op == "make" and str(n.val[1].val) in structs_map:
                sname = str(n.val[1].val)
                fspecs = structs_map[sname]
                fargs = list(n.val[2:])
                bound_vals: dict[str, SNode] = {}
                rebuilt_args: list[SNode] = []
                for (fnm, ftype), farg in zip(fspecs, fargs):
                    lo_n, hi_n = _extract_range_nodes(ftype)
                    # Substitute earlier field names in dependent bounds (`u64[bid..1000]`)
                    def subst_field_refs(bn: SNode) -> SNode:
                        if isinstance(bn.val, str) and bn.val in bound_vals:
                            return _clone(bound_vals[bn.val])
                        if isinstance(bn.val, list):
                            return SNode([subst_field_refs(ch) for ch in bn.val], bn.span)
                        return _clone(bn)

                    slo = subst_field_refs(lo_n)
                    shi = subst_field_refs(hi_n)
                    clamped = _mk([_mk("max"), slo, _mk([_mk("min"), shi, _clone(farg)])], farg.span)
                    rebuilt_args.append(clamped)
                    bound_vals[fnm] = clamped
                summary_box[0] = f"Clamped `(make {sname} ...)` field arguments to dependent struct bounds"
                return _mk([_mk("make"), _mk(sname), *rebuilt_args], n.span)

            return None

        new_body, changed = _rewrite_first_expr(body_node, rule)
        if changed:
            new_items = [_clone(x) for x in f.val]
            new_items[body_idx] = new_body
            new_forms.append(SNode(new_items, f.span))
            for rem in forms[forms.index(f) + 1 :]:
                new_forms.append(_clone(rem))
            return new_forms, summary_box[0]

        new_forms.append(_clone(f))

    raise AILCompilerError(
        pb.E_SYNTAX,
        pb.STAGE_AGENT_REPAIR,
        target,
        f"Deterministic repair engine has no rewrite rule for `{pb.ErrorCode.Name(code)}` on `{diag.expr}`",
    )


def _call_gemini_repair(current_source: str, resp: pb.CompilerResponse) -> str:
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise AILCompilerError(
            pb.E_CAPABILITY_MISSING,
            pb.STAGE_AGENT_REPAIR,
            "<gemini>",
            "GEMINI_API_KEY is not set; pass `--backend deterministic` or configure GEMINI_API_KEY.",
        )
    prompt = (
        "You are repairing an AIL (AI-Native formally verified S-expression language) module.\n"
        "Return ONLY valid AIL S-expression code with no markdown fences.\n\n"
        f"CompilerResponse (Protobuf TextFormat):\n{to_prototext(resp)}\n\n"
        f"Current AIL Module:\n{current_source}\n"
    )
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}"
    payload = json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=20) as http_resp:
        data = json.loads(http_resp.read().decode("utf-8"))
    text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
    if text.startswith("```"):
        lines = [ln for ln in text.splitlines() if not ln.strip().startswith("```")]
        text = "\n".join(lines).strip()
    return text + "\n"


def _evaluate_forms(forms: list[SNode], require_tight_specs: bool) -> tuple[pb.CompilerResponse, ModuleTypeEnv | None]:
    t0 = time.perf_counter()
    resp = pb.CompilerResponse()
    try:
        tenv = check_module_ownership_v2(forms)
        mv = ModuleVerifier(tenv)
        stats = mv.verify_module(forms)
        resp.proof_stats.extend(stats)
        if require_tight_specs:
            audits, diags = audit_module_specifications(forms, tenv)
            resp.spec_audits.extend(audits)
            if diags:
                resp.diagnostics.extend(diags)
                resp.status = pb.STATUS_REJECTED
                resp.total_elapsed_ms = (time.perf_counter() - t0) * 1000.0
                return resp, None
        resp.status = pb.STATUS_VERIFIED
        resp.total_elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return resp, tenv
    except AILCompilerError as err:
        resp.status = pb.STATUS_REJECTED
        resp.diagnostics.append(err.diag)
        resp.total_elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return resp, None


def run_repair_session(
    input_path_or_source: Path | str,
    out_dir: Path | None = None,
    stem: str = "repaired_module",
    max_iters: int = 8,
    require_tight_specs: bool = True,
    backend: str = "deterministic",
    llm_callback: LLMRepairCallback | None = None,
) -> pb.RepairSession:
    """Runs a closed-loop Protobuf verification & self-repair session (`pb.RepairSession`)."""
    t_start = time.perf_counter()
    sess = pb.RepairSession(final_status=pb.STATUS_REJECTED)

    if isinstance(input_path_or_source, Path):
        forms = load_ail_path(input_path_or_source)
        stem = input_path_or_source.name.removesuffix(".ail.pb").removesuffix(".ail").removesuffix(".pb")
    else:
        forms = parse_source(input_path_or_source)

    cur_src = format_module_source(forms)

    for turn in range(1, max_iters + 1):
        resp, tenv = _evaluate_forms(forms, require_tight_specs=require_tight_specs)
        if resp.status == pb.STATUS_VERIFIED and tenv is not None:
            sess.final_status = pb.STATUS_VERIFIED
            sess.iterations = turn - 1
            sess.repaired_ail_source = cur_src
            sess.repaired_ast.CopyFrom(module_to_proto(forms, module_name=stem))
            if out_dir is not None:
                artifacts = compile_llvm_to_native(forms, tenv, out_dir, stem)
                sess.artifacts.CopyFrom(artifacts)
            sess.total_elapsed_ms = (time.perf_counter() - t_start) * 1000.0
            return sess

        diag = resp.diagnostics[0]
        try:
            if llm_callback is not None:
                cur_src = llm_callback(cur_src, resp)
                forms = parse_source(cur_src)
                patch_summary = "Applied external LLM callback repair patch over Protobuf CompilerResponse"
            elif backend == "gemini":
                cur_src = _call_gemini_repair(cur_src, resp)
                forms = parse_source(cur_src)
                patch_summary = "Applied Gemini LLM repair patch over Protobuf CompilerResponse"
            else:
                forms, patch_summary = apply_deterministic_repair(forms, diag)
                cur_src = format_module_source(forms)
        except AILCompilerError as rep_err:
            sess.steps.append(
                pb.RepairStep(
                    turn=turn,
                    triggered_code=diag.code,
                    target_item=diag.item_name,
                    patch_summary=f"Aborted: {rep_err.diag.message}",
                    check_response=resp,
                )
            )
            break

        sess.steps.append(
            pb.RepairStep(
                turn=turn,
                triggered_code=diag.code,
                target_item=diag.item_name,
                patch_summary=patch_summary,
                check_response=resp,
            )
        )
        sess.iterations = turn

    # Final evaluation check if loop used its last turn to repair
    resp_final, tenv_final = _evaluate_forms(forms, require_tight_specs=require_tight_specs)
    sess.repaired_ail_source = cur_src
    sess.repaired_ast.CopyFrom(module_to_proto(forms, module_name=stem))
    if resp_final.status == pb.STATUS_VERIFIED and tenv_final is not None:
        sess.final_status = pb.STATUS_VERIFIED
        if out_dir is not None:
            artifacts = compile_llvm_to_native(forms, tenv_final, out_dir, stem)
            sess.artifacts.CopyFrom(artifacts)
    sess.total_elapsed_ms = (time.perf_counter() - t_start) * 1000.0
    return sess
