"""AIL v1.0 Model Context Protocol (MCP) Stdio JSON-RPC 2.0 Server."""

from __future__ import annotations

import base64
from dataclasses import asdict
import json
from pathlib import Path
import re
import sys
import tempfile
import time
from typing import Any, Callable, TextIO

from ailang import ail_agent_pb2 as pb
from ailang.agent_loop import format_module_source, run_repair_session
from ailang.diagnostics import (
    AILCompilerError,
    ce_bindings_to_dict,
    format_human_summary,
    format_repair_session,
    to_prototext,
)
from ailang.ownership import ModuleTypeEnv, check_module_ownership_v2
from ailang.parser import SNode, load_ail_path, parse_source, pretty
from ailang.spec_firewall import audit_module_specifications, diff_candidate_modules
from ailang.verifier import ModuleVerifier

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "ailang-mcp", "version": "1.0.0"}
STDLIB_DIR = Path(__file__).resolve().parent / "stdlib"
VALID_TARGETS = ("native", "wasm", "c", "rust", "all")


def _diagnostic_to_dict(d: pb.Diagnostic) -> dict[str, Any]:
    return {
        "code": pb.ErrorCode.Name(d.code),
        "code_id": int(d.code),
        "stage": pb.Stage.Name(d.stage),
        "item_name": d.item_name,
        "span": {"line": int(d.span.line), "column": int(d.span.column)},
        "expr": d.expr,
        "message": d.message,
        "counterexample": ce_bindings_to_dict(list(d.counterexample)),
        "repair_hint": d.repair_hint,
    }


def _proof_stat_to_dict(st: pb.FunctionProofStats) -> dict[str, Any]:
    return {
        "item_name": st.item_name,
        "verified": bool(st.verified),
        "elapsed_ms": round(float(st.elapsed_ms), 3),
        "tier0_interval_discharged": int(st.tier0_interval_discharged),
        "tier1_bitwuzla_queries": int(st.tier1_bitwuzla_queries),
        "tier2_z3_queries": int(st.tier2_z3_queries),
        "o1_loop_steps": int(st.o1_loop_steps),
    }


def _spec_audit_to_dict(au: pb.SpecAuditItem) -> dict[str, Any]:
    return {
        "fn_name": au.fn_name,
        "non_vacuous": bool(au.non_vacuous),
        "uniquely_tight": bool(au.uniquely_tight),
        "mutants_tested": int(au.mutants_tested),
        "mutants_killed": int(au.mutants_killed),
        "elapsed_ms": round(float(au.elapsed_ms), 3),
        "surviving_mutants": [
            {
                "mutant_kind": sm.mutant_kind,
                "mutant_expr": sm.mutant_expr,
                "witness": ce_bindings_to_dict(list(sm.witness)),
                "mutant_output": int(sm.mutant_output),
                "reference_output": int(sm.reference_output),
            }
            for sm in au.surviving_mutants
        ],
    }


def _spec_diff_to_dict(df: pb.SpecDiscrepancy) -> dict[str, Any]:
    return {
        "fn_name": df.fn_name,
        "equivalent": bool(df.equivalent),
        "elapsed_ms": round(float(df.elapsed_ms), 3),
        "distinguishing_input": ce_bindings_to_dict(list(df.distinguishing_input)),
        "spec_a_output": int(df.spec_a_output),
        "spec_b_output": int(df.spec_b_output),
        "spec_a_violates_conservation": bool(df.spec_a_violates_conservation),
        "spec_b_violates_conservation": bool(df.spec_b_violates_conservation),
        "clarification_question": df.clarification_question,
    }


def _compiler_response_to_dict(resp: pb.CompilerResponse, include_prototext: bool = True) -> dict[str, Any]:
    out: dict[str, Any] = {
        "status": pb.Status.Name(resp.status),
        "verified": resp.status == pb.STATUS_VERIFIED,
        "total_elapsed_ms": round(float(resp.total_elapsed_ms), 3),
        "proof_stats": [_proof_stat_to_dict(st) for st in resp.proof_stats],
        "spec_audits": [_spec_audit_to_dict(au) for au in resp.spec_audits],
        "spec_diffs": [_spec_diff_to_dict(df) for df in resp.spec_diffs],
        "diagnostics": [_diagnostic_to_dict(d) for d in resp.diagnostics],
        "human_summary": format_human_summary(resp),
    }
    if include_prototext:
        out["prototext"] = to_prototext(resp)
    return out


def _load_forms(source: str | None = None, path: str | None = None) -> tuple[list[SNode], str]:
    if source and path:
        raise ValueError("Provide either 'source' or 'path', not both.")
    if not source and not path:
        raise ValueError("Either 'source' or 'path' must be provided.")

    if path:
        p = Path(path).expanduser()
        if not p.exists():
            raise FileNotFoundError(f"AIL module file not found: {p}")
        stem = p.name.removesuffix(".ail.pb").removesuffix(".ail").removesuffix(".pb")
        if p.suffix == ".pb" or p.name.endswith(".ail.pb"):
            return load_ail_path(p), stem
        try:
            from ailang.modules import load_ail_module_with_imports

            return load_ail_module_with_imports(p), stem
        except ImportError:
            return load_ail_path(p), stem

    assert source is not None
    if "(" in source or "\n" in source:
        try:
            from ailang.modules import load_ail_module_with_imports

            return load_ail_module_with_imports(source), "ail_kernel"
        except ImportError:
            pass
    return parse_source(source), "ail_kernel"


def _verify_forms(
    source: str | None = None,
    path: str | None = None,
) -> tuple[pb.CompilerResponse, list[SNode], ModuleTypeEnv, str]:
    t0 = time.perf_counter()
    resp = pb.CompilerResponse()
    stem = "ail_kernel"
    try:
        forms, stem = _load_forms(source=source, path=path)
        tenv = check_module_ownership_v2(forms)
        stats = ModuleVerifier(tenv).verify_module(forms)
        resp.proof_stats.extend(stats)
        resp.status = pb.STATUS_VERIFIED
        resp.total_elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return resp, forms, tenv, stem
    except AILCompilerError as err:
        resp.status = pb.STATUS_REJECTED
        resp.diagnostics.append(err.diag)
        resp.total_elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return resp, [], ModuleTypeEnv(), stem


def _tool_check_and_prove(args: dict[str, Any]) -> dict[str, Any]:
    include_prototext = bool(args.get("include_prototext", True))
    resp, _, _, _ = _verify_forms(source=args.get("source"), path=args.get("path"))
    return _compiler_response_to_dict(resp, include_prototext=include_prototext)


def _tool_audit_spec(args: dict[str, Any]) -> dict[str, Any]:
    t0 = time.perf_counter()
    include_prototext = bool(args.get("include_prototext", True))
    resp, forms_a, tenv_a, _ = _verify_forms(source=args.get("source"), path=args.get("path"))
    if resp.status == pb.STATUS_VERIFIED:
        try:
            audits, diags = audit_module_specifications(forms_a, tenv_a)
            resp.spec_audits.extend(audits)
            resp.diagnostics.extend(diags)
            if diags:
                resp.status = pb.STATUS_REJECTED
        except AILCompilerError as err:
            resp.diagnostics.append(err.diag)
            resp.status = pb.STATUS_REJECTED

    spec_b_source = args.get("spec_b_source")
    spec_b_path = args.get("spec_b_path")
    if (spec_b_source or spec_b_path) and forms_a:
        try:
            forms_b, _ = _load_forms(source=spec_b_source, path=spec_b_path)
            diffs, diff_diags = diff_candidate_modules(forms_a, forms_b)
            resp.spec_diffs.extend(diffs)
            resp.diagnostics.extend(diff_diags)
            if diff_diags:
                resp.status = pb.STATUS_REJECTED
        except AILCompilerError as err:
            resp.diagnostics.append(err.diag)
            resp.status = pb.STATUS_REJECTED

    resp.total_elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return _compiler_response_to_dict(resp, include_prototext=include_prototext)


def _tool_repair_code(args: dict[str, Any]) -> dict[str, Any]:
    source = args.get("source")
    path = args.get("path")
    if source and path:
        raise ValueError("Provide either 'source' or 'path', not both.")
    if not source and not path:
        raise ValueError("Either 'source' or 'path' must be provided.")

    max_iters_raw = args.get("max_iters", 8)
    max_iters = max(1, min(32, int(max_iters_raw)))
    require_tight_specs = bool(args.get("require_tight_specs", True))
    backend = str(args.get("backend", "deterministic"))
    if backend not in ("deterministic", "gemini"):
        raise ValueError(f"Unsupported repair backend '{backend}'; expected 'deterministic' or 'gemini'.")

    try:
        forms, stem = _load_forms(source=source, path=path)
    except AILCompilerError as err:
        resp = pb.CompilerResponse(status=pb.STATUS_REJECTED, diagnostics=[err.diag])
        sess = pb.RepairSession(
            final_status=pb.STATUS_REJECTED,
            iterations=0,
            steps=[
                pb.RepairStep(
                    turn=1,
                    triggered_code=err.diag.code,
                    target_item=err.diag.item_name,
                    patch_summary=f"Load failed: {err.diag.message}",
                    check_response=resp,
                )
            ],
        )
        steps_out = [
            {
                "turn": 1,
                "triggered_code": pb.ErrorCode.Name(err.diag.code),
                "target_item": err.diag.item_name,
                "patch_summary": f"Load failed: {err.diag.message}",
                "diagnostics": [_diagnostic_to_dict(err.diag)],
            }
        ]
        out_err: dict[str, Any] = {
            "final_status": "STATUS_REJECTED",
            "verified": False,
            "iterations": 0,
            "total_elapsed_ms": 0.0,
            "repaired_ail_source": source or "",
            "steps": steps_out,
            "human_summary": format_repair_session(sess),
        }
        if bool(args.get("include_prototext", True)):
            out_err["prototext"] = to_prototext(sess)
        return out_err

    sess = run_repair_session(
        format_module_source(forms),
        out_dir=None,
        stem=stem,
        max_iters=max_iters,
        require_tight_specs=require_tight_specs,
        backend=backend,
    )
    steps_out = [
        {
            "turn": int(st.turn),
            "triggered_code": pb.ErrorCode.Name(st.triggered_code),
            "target_item": st.target_item,
            "patch_summary": st.patch_summary,
            "diagnostics": [_diagnostic_to_dict(d) for d in st.check_response.diagnostics],
        }
        for st in sess.steps
    ]
    out: dict[str, Any] = {
        "final_status": pb.Status.Name(sess.final_status),
        "verified": sess.final_status == pb.STATUS_VERIFIED,
        "iterations": int(sess.iterations),
        "total_elapsed_ms": round(float(sess.total_elapsed_ms), 3),
        "repaired_ail_source": sess.repaired_ail_source,
        "steps": steps_out,
        "human_summary": format_repair_session(sess),
    }
    if bool(args.get("include_prototext", True)):
        out["prototext"] = to_prototext(sess)
    return out


def _read_text_snippet(path_str: str, max_chars: int = 24_000) -> str:
    p = Path(path_str)
    if not path_str or not p.exists():
        return ""
    txt = p.read_text(encoding="utf-8", errors="replace")
    if len(txt) <= max_chars:
        return txt
    return txt[:max_chars] + f"\n... [truncated {len(txt) - max_chars} chars]"


def _sanitize_module_name(name: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_]", "_", name).strip("_")
    if not cleaned:
        return "ail_kernel"
    if cleaned[0].isdigit():
        return f"ail_{cleaned}"
    return cleaned


def _compile_single_target(
    target: str,
    forms: list[SNode],
    tenv: ModuleTypeEnv,
    target_dir: Path,
    mod_name: str,
    include_code: bool,
) -> dict[str, Any]:
    if target == "native":
        from ailang.codegen_llvm import compile_llvm_to_native

        art = compile_llvm_to_native(forms, tenv, target_dir, mod_name, build_shared_lib=None)
        res: dict[str, Any] = {
            "ok": True,
            "target": "native",
            "llvm_ir_path": art.llvm_ir_path,
            "asm_path": art.asm_path,
            "binary_or_lib_path": art.binary_or_lib_path,
            "c_header_path": art.c_header_path,
            "python_bindings_path": art.python_bindings_path,
            "neon_simd_instructions": int(art.neon_simd_instructions),
            "hardware_atomic_instructions": int(art.hardware_atomic_instructions),
        }
        if include_code:
            res["llvm_ir"] = _read_text_snippet(art.llvm_ir_path)
            if art.c_header_path:
                res["c_header"] = _read_text_snippet(art.c_header_path)
        return res

    if target == "wasm":
        from ailang.codegen_wasm import compile_to_wasm

        art = compile_to_wasm(forms, tenv, target_dir, mod_name)
        res = {"ok": True, "target": "wasm", **asdict(art)}
        if include_code:
            res["wat"] = _read_text_snippet(art.wat_path)
            res["js_wrapper"] = _read_text_snippet(art.js_wrapper_path)
            res["ts_dts"] = _read_text_snippet(art.ts_dts_path)
            wasm_file = Path(art.wasm_path)
            if wasm_file.exists() and wasm_file.stat().st_size <= 262_144:
                res["wasm_base64"] = base64.b64encode(wasm_file.read_bytes()).decode("ascii")
        return res

    if target == "c":
        from ailang.codegen_c import compile_to_c

        art = compile_to_c(forms, tenv, target_dir, mod_name, compile_shared=True)
        res = {"ok": True, "target": "c", **asdict(art)}
        if include_code:
            res["c_source"] = _read_text_snippet(art.c_source_path)
            res["c_header"] = _read_text_snippet(art.c_header_path)
        return res

    if target == "rust":
        from ailang.codegen_rust import compile_to_rust

        art = compile_to_rust(forms, tenv, target_dir, mod_name, verify_rustc=True)
        res = {"ok": True, "target": "rust", **asdict(art)}
        if include_code:
            res["lib_rs"] = _read_text_snippet(art.lib_rs_path)
            res["cargo_toml"] = _read_text_snippet(art.cargo_toml_path)
        return res

    raise ValueError(f"Unsupported target '{target}'.")


def _tool_compile_target(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target", "native")).lower()
    if target not in VALID_TARGETS:
        raise ValueError(f"Invalid target '{target}'. Expected one of {VALID_TARGETS}.")

    require_tight_specs = bool(args.get("require_tight_specs", False))
    include_code = bool(args.get("include_generated_code", True))
    include_prototext = bool(args.get("include_prototext", True))

    t0 = time.perf_counter()
    resp, forms, tenv, stem = _verify_forms(source=args.get("source"), path=args.get("path"))
    if resp.status == pb.STATUS_VERIFIED and require_tight_specs:
        try:
            audits, diags = audit_module_specifications(forms, tenv)
            resp.spec_audits.extend(audits)
            resp.diagnostics.extend(diags)
            if diags:
                resp.status = pb.STATUS_REJECTED
        except AILCompilerError as err:
            resp.diagnostics.append(err.diag)
            resp.status = pb.STATUS_REJECTED

    if resp.status != pb.STATUS_VERIFIED:
        resp.total_elapsed_ms = (time.perf_counter() - t0) * 1000.0
        out = _compiler_response_to_dict(resp, include_prototext=include_prototext)
        out["compiled"] = False
        out["target"] = target
        out["targets"] = {}
        return out

    mod_name = _sanitize_module_name(str(args.get("module_name") or stem))
    out_dir_arg = args.get("out_dir")
    out_dir = Path(out_dir_arg).expanduser() if out_dir_arg else Path(tempfile.mkdtemp(prefix=f"ail_mcp_{mod_name}_"))
    out_dir.mkdir(parents=True, exist_ok=True)

    requested = ["native", "wasm", "c", "rust"] if target == "all" else [target]
    compiled_targets: dict[str, Any] = {}
    for tgt in requested:
        tgt_dir = out_dir / tgt if target == "all" else out_dir
        try:
            compiled_targets[tgt] = _compile_single_target(tgt, forms, tenv, tgt_dir, mod_name, include_code)
        except ImportError as exc:
            if target != "all":
                raise RuntimeError(f"Target backend '{tgt}' is not available: {exc}") from exc
            compiled_targets[tgt] = {"ok": False, "target": tgt, "error": f"Backend unavailable: {exc}"}

    resp.total_elapsed_ms = (time.perf_counter() - t0) * 1000.0
    out = _compiler_response_to_dict(resp, include_prototext=include_prototext)
    out["compiled"] = any(v.get("ok") for v in compiled_targets.values())
    out["target"] = target
    out["module_name"] = mod_name
    out["out_dir"] = str(out_dir)
    out["targets"] = compiled_targets
    return out


def _summarize_ail_module(path: Path, include_source: bool) -> dict[str, Any]:
    raw_text = path.read_text(encoding="utf-8")
    forms = parse_source(raw_text)
    imports: list[str] = []
    consts: list[dict[str, Any]] = []
    structs: list[dict[str, Any]] = []
    enums: list[dict[str, Any]] = []
    specs: list[dict[str, Any]] = []
    functions: list[dict[str, Any]] = []

    for form in forms:
        if not isinstance(form.val, list) or not form.val:
            continue
        head = str(form.val[0].val)
        if head == "import" and len(form.val) >= 2:
            imports.append(str(form.val[1].val).strip('"'))
        elif head == "const" and len(form.val) >= 4:
            consts.append(
                {
                    "name": str(form.val[1].val),
                    "type": pretty(form.val[2]),
                    "value": pretty(form.val[3]),
                }
            )
        elif head == "struct" and len(form.val) >= 3:
            fields = [
                {"name": str(fld.val[0].val), "type": pretty(fld.val[1])}
                for fld in form.val[2].val
                if isinstance(fld.val, list) and len(fld.val) >= 2
            ]
            structs.append({"name": str(form.val[1].val), "fields": fields})
        elif head == "enum" and len(form.val) >= 3:
            variants = [
                {
                    "name": str(v.val[0].val),
                    "fields": [
                        {"name": str(fld.val[0].val), "type": pretty(fld.val[1])}
                        for fld in v.val[1:]
                        if isinstance(fld.val, list) and len(fld.val) >= 2
                    ],
                }
                for v in form.val[2:]
                if isinstance(v.val, list) and v.val
            ]
            enums.append({"name": str(form.val[1].val), "variants": variants})
        elif head == "spec" and len(form.val) >= 4:
            params = [
                f"({pretty(p.val[0])} {pretty(p.val[1])})"
                for p in form.val[2].val
                if isinstance(p.val, list) and len(p.val) >= 2
            ]
            name = str(form.val[1].val)
            specs.append({"name": name, "params": params, "signature": f"(spec {name} ({' '.join(params)}))"})
        elif head in ("fn", "map_inplace") and len(form.val) >= 4:
            name = str(form.val[1].val)
            params = [
                f"({pretty(p.val[0])} {pretty(p.val[1])})"
                for p in form.val[2].val
                if isinstance(p.val, list) and len(p.val) >= 2
            ]
            ret_spec = pretty(form.val[3])
            functions.append(
                {
                    "name": name,
                    "kind": head,
                    "params": params,
                    "return_spec": ret_spec,
                    "signature": f"({head} {name} ({' '.join(params)}) {ret_spec})",
                }
            )

    entry: dict[str, Any] = {
        "module_id": f"stdlib/{path.stem}",
        "name": path.stem,
        "path": str(path),
        "imports": imports,
        "consts": consts,
        "structs": structs,
        "enums": enums,
        "specs": specs,
        "functions": functions,
    }
    if include_source:
        entry["source"] = raw_text
    return entry


def _tool_stdlib_catalog(args: dict[str, Any]) -> dict[str, Any]:
    module_filter = str(args.get("module") or "").strip().removesuffix(".ail").removeprefix("stdlib/")
    include_source = bool(args.get("include_source", False))

    try:
        from ailang.modules import STDLIB_DIR as mod_stdlib_dir, list_stdlib_modules

        stdlib_dir = mod_stdlib_dir
        files = list_stdlib_modules()
    except ImportError:
        stdlib_dir = STDLIB_DIR
        files = sorted(stdlib_dir.glob("*.ail")) if stdlib_dir.is_dir() else []

    if not files:
        return {
            "available": False,
            "stdlib_dir": str(stdlib_dir),
            "module_count": 0,
            "modules": [],
        }

    if module_filter:
        files = [f for f in files if f.stem == module_filter]

    modules = [_summarize_ail_module(p, include_source=include_source) for p in files]
    return {
        "available": len(modules) > 0,
        "stdlib_dir": str(stdlib_dir),
        "module_count": len(modules),
        "modules": modules,
    }


TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "ail_check_and_prove",
        "description": (
            "Parse, ownership/capability typecheck, and formally verify an AIL module using "
            "Tier-0 Intervals, Tier-1 Bitwuzla QF_BV(64), and Tier-2 Z3. Returns structured JSON "
            "and Protobuf TextFormat diagnostic/proof telemetry."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "source": {"type": "string", "description": "AIL S-expression source code to verify."},
                "path": {"type": "string", "description": "Filesystem path to a `.ail` or `.ail.pb` file."},
                "include_prototext": {
                    "type": "boolean",
                    "description": "Include raw CompilerResponse Protobuf TextFormat (default: true).",
                    "default": True,
                },
            },
        },
    },
    {
        "name": "ail_audit_spec",
        "description": (
            "Run Layer 1 Spec Firewall: non-vacuity and SpecMut specification mutation testing on an AIL "
            "module, plus optional Clover differential ambiguity checking (`spec_a` vs `spec_b`)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "source": {"type": "string", "description": "Primary candidate AIL source code."},
                "path": {"type": "string", "description": "Primary candidate `.ail` or `.ail.pb` file path."},
                "spec_b_source": {
                    "type": "string",
                    "description": "Optional second candidate AIL source for Clover spec diff.",
                },
                "spec_b_path": {
                    "type": "string",
                    "description": "Optional second candidate `.ail` or `.ail.pb` path for Clover spec diff.",
                },
                "include_prototext": {"type": "boolean", "default": True},
            },
        },
    },
    {
        "name": "ail_repair_code",
        "description": (
            "Run the closed-loop autonomous AST repair harness (`run_repair_session`) over a broken or "
            "under-specified AIL module until all diagnostics and SpecMut checks pass, returning repaired "
            "`.ail` source and step-by-step repair trace."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "source": {"type": "string", "description": "Broken/unverified AIL source code."},
                "path": {"type": "string", "description": "Path to broken `.ail` or `.ail.pb` file."},
                "max_iters": {"type": "integer", "minimum": 1, "maximum": 32, "default": 8},
                "require_tight_specs": {"type": "boolean", "default": True},
                "backend": {
                    "type": "string",
                    "enum": ["deterministic", "gemini"],
                    "default": "deterministic",
                },
                "include_prototext": {"type": "boolean", "default": True},
            },
        },
    },
    {
        "name": "ail_compile_target",
        "description": (
            "Verify an AIL module and compile it to one or all supported backend targets: "
            "`native` (LLVM -O3 binary/.dylib + C .h + Python bindings), `wasm` (WebAssembly 1.0 .wasm + .wat + .mjs + .d.ts), "
            "`c` (strict ISO C11 .c/.h/.dylib), `rust` (#![no_std] #![forbid(unsafe_code)] crate/.rlib), or `all`."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "enum": list(VALID_TARGETS),
                    "description": "Compilation target (`native`, `wasm`, `c`, `rust`, or `all`).",
                    "default": "native",
                },
                "source": {"type": "string", "description": "AIL S-expression source code."},
                "path": {"type": "string", "description": "Path to `.ail` or `.ail.pb` file."},
                "module_name": {"type": "string", "description": "Optional output module/crate stem."},
                "out_dir": {"type": "string", "description": "Optional output directory (defaults to a temp dir)."},
                "require_tight_specs": {"type": "boolean", "default": False},
                "include_generated_code": {"type": "boolean", "default": True},
                "include_prototext": {"type": "boolean", "default": True},
            },
            "required": ["target"],
        },
    },
    {
        "name": "ail_stdlib_catalog",
        "description": (
            "List built-in verified `src/ailang/stdlib/*.ail` modules, constants, structs, enums, specs, "
            "and function signatures available via `(import \"stdlib/<name>\")`."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "module": {
                    "type": "string",
                    "description": "Optional module filter (e.g. `math`, `finance`, `bits`, `parse`).",
                },
                "include_source": {
                    "type": "boolean",
                    "description": "Include full `.ail` source text for matched modules (default: false).",
                    "default": False,
                },
            },
        },
    },
]

TOOL_HANDLERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "ail_check_and_prove": _tool_check_and_prove,
    "ail_audit_spec": _tool_audit_spec,
    "ail_repair_code": _tool_repair_code,
    "ail_compile_target": _tool_compile_target,
    "ail_stdlib_catalog": _tool_stdlib_catalog,
}


def _jsonrpc_error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def handle_jsonrpc_message(msg: Any) -> dict[str, Any] | None:
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        req_id = msg.get("id") if isinstance(msg, dict) else None
        return _jsonrpc_error(req_id, -32600, "Invalid Request: expected JSON-RPC 2.0 object")

    method = msg.get("method")
    if not isinstance(method, str):
        return _jsonrpc_error(msg.get("id"), -32600, "Invalid Request: missing string 'method'")

    has_id = "id" in msg
    req_id = msg.get("id")
    params = msg.get("params")
    if params is None:
        params = {}
    if not isinstance(params, dict):
        return _jsonrpc_error(req_id, -32602, "Invalid params: expected JSON object") if has_id else None

    if method == "notifications/initialized" or (method.startswith("notifications/") and not has_id):
        return None

    if method == "initialize":
        result = {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": SERVER_INFO,
        }
        return {"jsonrpc": "2.0", "id": req_id, "result": result} if has_id else None

    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}} if has_id else None

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOL_DEFINITIONS}} if has_id else None

    if method == "tools/call":
        if not has_id:
            return None
        tool_name = params.get("name")
        if not isinstance(tool_name, str) or tool_name not in TOOL_HANDLERS:
            return _jsonrpc_error(req_id, -32602, f"Unknown tool '{tool_name}'")
        tool_args = params.get("arguments")
        if tool_args is None:
            tool_args = {}
        if not isinstance(tool_args, dict):
            return _jsonrpc_error(req_id, -32602, "Invalid tool 'arguments': expected object")

        try:
            payload = TOOL_HANDLERS[tool_name](tool_args)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
                    "isError": False,
                },
            }
        except (ValueError, FileNotFoundError, RuntimeError) as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps({"error": str(exc)}, indent=2)}],
                    "isError": True,
                },
            }
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps({"error": f"Internal error: {exc}"}, indent=2)}],
                    "isError": True,
                },
            }

    if not has_id:
        return None
    return _jsonrpc_error(req_id, -32601, f"Method not found: {method}")


def _write_framed(stdout: TextIO, payload: dict[str, Any], content_length_framing: bool) -> None:
    body = json.dumps(payload, separators=(",", ":"))
    if content_length_framing:
        body_bytes = body.encode("utf-8")
        stdout.write(f"Content-Length: {len(body_bytes)}\r\n\r\n{body}")
    else:
        stdout.write(body + "\n")
    stdout.flush()


def run_stdio_server(stdin: TextIO | None = None, stdout: TextIO | None = None) -> int:
    in_stream = sys.stdin if stdin is None else stdin
    out_stream = sys.stdout if stdout is None else stdout

    while True:
        line = in_stream.readline()
        if line == "":
            break
        stripped = line.strip()
        if not stripped:
            continue

        use_cl = False
        raw_json = stripped
        if stripped.lower().startswith("content-length:"):
            use_cl = True
            try:
                content_len = int(stripped.split(":", 1)[1].strip())
            except ValueError:
                _write_framed(out_stream, _jsonrpc_error(None, -32700, "Invalid Content-Length header"), True)
                continue
            while True:
                hdr = in_stream.readline()
                if hdr == "" or hdr.strip() == "":
                    break
            raw_json = in_stream.read(content_len)
            if not raw_json:
                break

        try:
            msg = json.loads(raw_json)
        except json.JSONDecodeError as exc:
            _write_framed(out_stream, _jsonrpc_error(None, -32700, f"Parse error: {exc}"), use_cl)
            continue

        if isinstance(msg, list):
            responses = [r for item in msg if (r := handle_jsonrpc_message(item)) is not None]
            if responses:
                body = json.dumps(responses, separators=(",", ":"))
                if use_cl:
                    out_stream.write(f"Content-Length: {len(body.encode('utf-8'))}\r\n\r\n{body}")
                else:
                    out_stream.write(body + "\n")
                out_stream.flush()
            continue

        resp = handle_jsonrpc_message(msg)
        if resp is not None:
            _write_framed(out_stream, resp, use_cl)

    return 0


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if any(a in ("-h", "--help") for a in args):
        sys.stderr.write("ailang-mcp: JSON-RPC 2.0 stdio MCP server for AIL\n")
        return 0
    if any(a == "--version" for a in args):
        sys.stderr.write("ailang-mcp 1.0.0\n")
        return 0
    return run_stdio_server(sys.stdin, sys.stdout)


if __name__ == "__main__":
    raise SystemExit(main())
