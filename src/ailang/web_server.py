"""AIL v1.0 Web Studio HTTP Server & Standalone WASM Demo Generator."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib
import importlib.util
import json
import mimetypes
from pathlib import Path
import tempfile
import time
from typing import Any
from urllib.parse import urlparse

from ailang import ail_agent_pb2 as pb
from ailang.agent_loop import format_module_source, run_repair_session
from ailang.codegen_llvm import compile_llvm_to_native, emit_llvm_module
from ailang.diagnostics import (
    AILCompilerError,
    ce_bindings_to_dict,
    to_prototext,
)
from ailang.ownership import LINEAR_CAPS, ModuleTypeEnv, check_module_ownership_v2
from ailang.parser import SNode, parse_source, pretty
from ailang.spec_firewall import audit_module_specifications
from ailang.verifier import ModuleVerifier

STUDIO_VERSION = "1.0.0"
MAX_REQUEST_BYTES = 1024 * 1024  # 1 MiB safety limit for JSON payloads
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_WEB_DIR = REPO_ROOT / "web"
DEFAULT_EXAMPLES_DIR = REPO_ROOT / "examples"
DEFAULT_STDLIB_PARENT = Path(__file__).resolve().parent


_FALLBACK_SIGNED_QUOTE = """; AIL v0.2 Signed i64 Refinements + Dependent Algebraic struct
(struct Quote
  ((bid u64[0..1000000000])
   (ask u64[bid..1000000000])
   (pnl_adj i64[-50000..50000])))

(spec exact_spread ((bid int) (ask int))
  (- ask bid))

(spec exact_net_mid ((bid int) (ask int) (adj int))
  (+ (+ bid (/ (- ask bid) 2)) adj))

(spec exact_scaled_pnl ((pnl int))
  (trunc_div pnl 10))

(fn build_quote ((bid u64[0..999990000]) (spread u64[0..10000]) (pnl_adj i64[-50000..50000]))
  Quote
  (make Quote bid (+ bid spread) pnl_adj))

(fn quote_spread ((q Quote))
  (out u64[0..1000000000] (== out (exact_spread (field q bid) (field q ask))))
  (- (field q ask) (field q bid)))

(fn quote_net_mid ((q Quote))
  (out i64[-50000..1000050000] (== out (exact_net_mid (field q bid) (field q ask) (field q pnl_adj))))
  (+ (to_i64 (+ (field q bid) (/ (- (field q ask) (field q bid)) 2))) (field q pnl_adj)))

(fn scale_signed_pnl ((pnl i64[-1000000..1000000]))
  (out i64[-100000..100000] (== out (exact_scaled_pnl pnl)))
  (/ pnl 10))
"""

_FALLBACK_DEFI_WATERFALL = """; DeFi Fee Waterfall Kernel
(spec exact_fee ((amt int) (bps int) (cap int))
  (min cap (/ (* amt bps) 10000)))

(spec exact_protocol_split ((fee int) (treasury_bps int))
  (/ (* fee treasury_bps) 10000))

(fn waterfall_net_payout
  ((amt u64[0..10000000000000000]) (bps u64[0..10000]) (cap u64[0..10000000000000000]))
  (out u64[0..amt] (== (- amt out) (exact_fee amt bps cap)))
  (- amt (min cap (+ (* (/ amt 10000) bps) (/ (* (% amt 10000) bps) 10000)))))

(fn treasury_fee_share
  ((fee u64[0..10000000000000000]) (treasury_bps u64[0..10000]))
  (out u64[0..fee] (== out (exact_protocol_split fee treasury_bps)))
  (+ (* (/ fee 10000) treasury_bps) (/ (* (% fee 10000) treasury_bps) 10000)))
"""

_FALLBACK_WIRE_FRAME = """; Placeholder until examples/wire_frame_parser.ail is present
(spec exact_frame_header ((version int) (payload_len int))
  (+ (* version 65536) payload_len))

(fn encode_frame_header ((version u64[1..15]) (payload_len u64[0..65535]))
  (out u64[65536..1048575] (== out (exact_frame_header version payload_len)))
  (+ (* version 65536) payload_len))
"""


def _read_example_or_fallback(filename: str, fallback: str) -> str:
    p = DEFAULT_EXAMPLES_DIR / filename
    if p.exists():
        return p.read_text(encoding="utf-8")
    return fallback


def get_available_targets() -> list[str]:
    targets = ["llvm"]
    for name, mod in (
        ("wasm", "ailang.codegen_wasm"),
        ("c", "ailang.codegen_c"),
        ("rust", "ailang.codegen_rust"),
    ):
        if importlib.util.find_spec(mod) is not None:
            targets.append(name)
    return targets


def get_presets() -> list[dict[str, Any]]:
    """Return curated AIL presets for the Web Studio."""
    return [
        {
            "id": "signed_quote",
            "title": "Signed Quote",
            "subtitle": "Dependent struct bounds (ask >= bid) + signed i64 PnL refinements",
            "tags": ["struct", "i64", "SpecMut"],
            "expect_error": False,
            "require_tight_specs": True,
            "sample_call": {"fn": "scale_signed_pnl", "args": [-12345]},
            "source": _read_example_or_fallback("signed_struct_quote.ail", _FALLBACK_SIGNED_QUOTE),
        },
        {
            "id": "sum_type_settlement",
            "title": "Sum Type Settlement",
            "subtitle": "Algebraic enum sum types + exhaustive match lowering",
            "tags": ["enum", "match", "Z3"],
            "expect_error": False,
            "require_tight_specs": True,
            "sample_call": {"fn": "outcome_notional", "args": ["0,250,4000"]},
            "source": _read_example_or_fallback("sum_type_settlement.ail", ""),
        },
        {
            "id": "defi_waterfall",
            "title": "DeFi Fee Waterfall",
            "subtitle": "Verified basis-point waterfall & stdlib composition",
            "tags": ["stdlib", "import", "u64"],
            "expect_error": False,
            "require_tight_specs": True,
            "sample_call": {"fn": "waterfall_junior_payout", "args": [1000000, 500000, 250, 2000]},
            "source": _read_example_or_fallback("defi_waterfall_v1.ail", _FALLBACK_DEFI_WATERFALL),
        },
        {
            "id": "wire_frame_parser",
            "title": "Wire Frame Parser",
            "subtitle": "Zero-copy verified bytes slice + big-endian binary parser",
            "tags": ["bytes", "zero-copy", "enum"],
            "expect_error": False,
            "require_tight_specs": True,
            "sample_call": {"fn": "parse_frame", "args": [12, "65,73,76,49,1,7,0,4,0,0,0,42"]},
            "source": _read_example_or_fallback("wire_frame_parser.ail", _FALLBACK_WIRE_FRAME),
        },
        {
            "id": "simd_halving",
            "title": "SIMD Halving",
            "subtitle": "O(1)-verified billion-element slice fold + linear mut_slice NEON SIMD",
            "tags": ["SIMD", "slice", "fold"],
            "expect_error": False,
            "require_tight_specs": False,
            "sample_call": {"fn": "settle_net", "args": [1000000, 250, 50000]},
            "source": _read_example_or_fallback("financial_kernel.ail", ""),
        },
        {
            "id": "broken_agent_draft",
            "title": "Broken Agent Draft",
            "subtitle": "4 intentional bugs (2^63 overflow, weak spec, underflow, cap leak) for ail repair",
            "tags": ["repair", "counterexample", "SpecMut"],
            "expect_error": True,
            "require_tight_specs": True,
            "sample_call": {"fn": "midpoint_draft", "args": ["9223372036854775808", "9223372036854775810"]},
            "source": _read_example_or_fallback("broken_agent_draft.ail", ""),
        },
    ]


def get_benchmark_data() -> dict[str, Any]:
    """Return observed empirical benchmark numbers from benchmarks/results/."""
    return {
        "compile_wall_ms": {"ail": 414.03, "rust": 433.92, "c": 123.78},
        "llm_spec_to_silicon": {
            "turn1_pass": "6/6 (100.0%)",
            "avg_tokens": 123.0,
            "total_ms": 2455.5,
        },
        "kernels": [
            {
                "kernel": "midpoint_u64",
                "ail_tokens": "71 (698 B)",
                "other_tokens": "48 / 46 / 45",
                "ail_ns": "1.47 ns/op",
                "other_ns": "1.83 / 1.38 / 220.79 ns",
                "bug_caught": "E_U64_OVERFLOW (at 2^63)",
            },
            {
                "kernel": "settle_fee_net",
                "ail_tokens": "127 (1087 B)",
                "other_tokens": "112 / 96 / 59",
                "ail_ns": "1.80 ns/op",
                "other_ns": "4.15 / 5.81 / 273.59 ns",
                "bug_caught": "E_SPEC_MUTANT_SURVIVED",
            },
            {
                "kernel": "halve_bonus_simd",
                "ail_tokens": "87 (621 B)",
                "other_tokens": "85 / 85 / 58",
                "ail_ns": "181.58 ns/op",
                "other_ns": "182.98 / 181.35 / 55866.46 ns",
                "bug_caught": "O(1) Bounds + Aliasing",
            },
            {
                "kernel": "quote_net_mid",
                "ail_tokens": "91 (795 B)",
                "other_tokens": "117 / 100 / 79",
                "ail_ns": "0.92 ns/op",
                "other_ns": "1.82 / 1.83 / 185.61 ns",
                "bug_caught": "E_STRUCT_INVARIANT_FAILED",
            },
            {
                "kernel": "settle_outcome_dispatch",
                "ail_tokens": "90 (811 B)",
                "other_tokens": "136 / 93 / 47",
                "ail_ns": "1.02 ns/op",
                "other_ns": "2.08 / 2.27 / 121.78 ns",
                "bug_caught": "E_NON_EXHAUSTIVE_MATCH",
            },
        ],
    }


def _parse_source_with_imports(source: str) -> list[SNode]:
    try:
        modules_mod = importlib.import_module("ailang.modules")
        loader = getattr(modules_mod, "load_ail_module_with_imports", None)
    except ImportError:
        loader = None

    if loader is None:
        return parse_source(source)

    search_dirs = [DEFAULT_EXAMPLES_DIR, DEFAULT_STDLIB_PARENT, REPO_ROOT]
    try:
        return loader(source, search_dirs=search_dirs)
    except TypeError:
        return loader(source)
    except FileNotFoundError:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_ail = Path(tmpdir) / "studio_input.ail"
            tmp_ail.write_text(source, encoding="utf-8")
            return loader(tmp_ail, search_dirs=search_dirs)


def _serialize_diagnostic(diag: pb.Diagnostic) -> dict[str, Any]:
    return {
        "code": pb.ErrorCode.Name(diag.code),
        "code_num": int(diag.code),
        "stage": pb.Stage.Name(diag.stage),
        "item_name": diag.item_name,
        "line": int(diag.span.line),
        "column": int(diag.span.column),
        "expr": diag.expr,
        "message": diag.message,
        "counterexample": ce_bindings_to_dict(list(diag.counterexample)),
        "repair_hint": diag.repair_hint,
    }


def _serialize_proof_stats(stats: list[pb.FunctionProofStats]) -> list[dict[str, Any]]:
    return [
        {
            "item_name": st.item_name,
            "verified": bool(st.verified),
            "elapsed_ms": round(float(st.elapsed_ms), 3),
            "tier0_interval_discharged": int(st.tier0_interval_discharged),
            "tier1_bitwuzla_queries": int(st.tier1_bitwuzla_queries),
            "tier2_z3_queries": int(st.tier2_z3_queries),
            "o1_loop_steps": int(st.o1_loop_steps),
        }
        for st in stats
    ]


def _serialize_spec_audits(audits: list[pb.SpecAuditItem]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for au in audits:
        out.append(
            {
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
        )
    return out


def _extract_module_interface(forms: list[SNode], tenv: ModuleTypeEnv) -> dict[str, Any]:
    functions: list[dict[str, Any]] = []
    for form in forms:
        head = str(form.val[0].val)
        if head == "fn":
            fname = str(form.val[1].val)
            sig = tenv.sigs.get(fname)
            params: list[dict[str, str]] = []
            for idx, p in enumerate(form.val[2].val):
                pname = str(p.val[0].val)
                pkind = sig.param_kinds[idx] if sig and idx < len(sig.param_kinds) else "u64"
                params.append({"name": pname, "kind": pkind, "type_str": pretty(p.val[1])})
            ret_kind = sig.ret_kind if sig else "u64"
            scalar_ok = all(pm["kind"] in ("u64", "i64", "bytes") for pm in params) and ret_kind in ("u64", "i64")
            functions.append(
                {
                    "name": fname,
                    "kind": "fn",
                    "params": params,
                    "ret_kind": ret_kind,
                    "wasm_callable": scalar_ok,
                }
            )
        elif head == "map_inplace":
            fname = str(form.val[1].val)
            sig = tenv.sigs.get(fname)
            params = []
            for idx, p in enumerate(form.val[2].val):
                pname = str(p.val[0].val)
                pkind = sig.param_kinds[idx] if sig and idx < len(sig.param_kinds) else "u64"
                params.append({"name": pname, "kind": pkind, "type_str": pretty(p.val[1])})
            functions.append(
                {
                    "name": fname,
                    "kind": "map_inplace",
                    "params": params,
                    "ret_kind": "void",
                    "wasm_callable": False,
                }
            )
        elif head == "main":
            functions.append(
                {
                    "name": "main",
                    "kind": "main",
                    "params": [],
                    "ret_kind": "u64",
                    "wasm_callable": True,
                }
            )

    structs = [
        {
            "name": sdef.name,
            "fields": [{"name": fd.name, "kind": fd.kind, "type_str": pretty(fd.type_node)} for fd in sdef.fields],
        }
        for sdef in tenv.structs.values()
    ]
    enums = [
        {
            "name": edef.name,
            "variants": [
                {
                    "name": vdef.name,
                    "tag": vdef.tag,
                    "fields": [{"name": fd.name, "kind": fd.kind, "type_str": pretty(fd.type_node)} for fd in vdef.fields],
                }
                for vdef in edef.variants
            ],
        }
        for edef in tenv.enums.values()
    ]
    return {"functions": functions, "structs": structs, "enums": enums}


def _compile_all_targets(
    forms: list[SNode],
    tenv: ModuleTypeEnv,
    module_name: str,
    resp: pb.CompilerResponse,
) -> tuple[dict[str, Any], dict[str, str], str, int]:
    targets: dict[str, Any] = {
        "llvm": {"available": False},
        "wasm": {"available": False},
        "c": {"available": False},
        "rust": {"available": False},
    }
    target_errors: dict[str, str] = {}
    wasm_b64 = ""
    wasm_size = 0

    with tempfile.TemporaryDirectory() as tmpdir_s:
        tmp_dir = Path(tmpdir_s)

        # 1. LLVM IR + optional ARM64/x86 assembly telemetry
        try:
            ir_text, _exports, _has_main = emit_llvm_module(forms, tenv)
            llvm_info: dict[str, Any] = {
                "available": True,
                "ir": ir_text,
                "asm": "",
                "c_header": "",
                "neon_simd_instructions": 0,
                "hardware_atomic_instructions": 0,
            }
            try:
                llvm_art = compile_llvm_to_native(forms, tenv, tmp_dir / "llvm", module_name)
                resp.artifacts.CopyFrom(llvm_art)
                llvm_info["neon_simd_instructions"] = int(llvm_art.neon_simd_instructions)
                llvm_info["hardware_atomic_instructions"] = int(llvm_art.hardware_atomic_instructions)
                if llvm_art.asm_path and Path(llvm_art.asm_path).exists():
                    llvm_info["asm"] = Path(llvm_art.asm_path).read_text(encoding="utf-8")
                if llvm_art.c_header_path and Path(llvm_art.c_header_path).exists():
                    llvm_info["c_header"] = Path(llvm_art.c_header_path).read_text(encoding="utf-8")
            except Exception as exc:
                target_errors["llvm_native"] = str(exc)
            targets["llvm"] = llvm_info
        except Exception as exc:
            target_errors["llvm"] = str(exc)

        # 2. Pure-Python WebAssembly 1.0 target
        try:
            wasm_mod = importlib.import_module("ailang.codegen_wasm")
            wart = wasm_mod.compile_to_wasm(forms, tenv, tmp_dir / "wasm", module_name=module_name)
            wasm_bytes = Path(wart.wasm_path).read_bytes()
            wasm_b64 = base64.b64encode(wasm_bytes).decode("ascii")
            wasm_size = int(wart.wasm_size_bytes or len(wasm_bytes))
            targets["wasm"] = {
                "available": True,
                "wat": Path(wart.wat_path).read_text(encoding="utf-8"),
                "js_wrapper": Path(wart.js_wrapper_path).read_text(encoding="utf-8"),
                "ts_dts": Path(wart.ts_dts_path).read_text(encoding="utf-8"),
                "wasm_base64": wasm_b64,
                "wasm_size_bytes": wasm_size,
            }
        except ImportError:
            target_errors["wasm"] = "codegen_wasm backend not available"
        except Exception as exc:
            target_errors["wasm"] = str(exc)

        # 3. ISO C11 target
        try:
            c_mod = importlib.import_module("ailang.codegen_c")
            cart = c_mod.compile_to_c(forms, tenv, tmp_dir / "c", module_name=module_name, compile_shared=False)
            targets["c"] = {
                "available": True,
                "source": Path(cart.c_source_path).read_text(encoding="utf-8"),
                "header": Path(cart.c_header_path).read_text(encoding="utf-8"),
            }
        except ImportError:
            target_errors["c"] = "codegen_c backend not available"
        except Exception as exc:
            target_errors["c"] = str(exc)

        # 4. Rust #![no_std] #![forbid(unsafe_code)] target
        try:
            rust_mod = importlib.import_module("ailang.codegen_rust")
            rart = rust_mod.compile_to_rust(forms, tenv, tmp_dir / "rust", module_name=module_name, verify_rustc=False)
            targets["rust"] = {
                "available": True,
                "lib_rs": Path(rart.lib_rs_path).read_text(encoding="utf-8"),
                "cargo_toml": Path(rart.cargo_toml_path).read_text(encoding="utf-8"),
            }
        except ImportError:
            target_errors["rust"] = "codegen_rust backend not available"
        except Exception as exc:
            target_errors["rust"] = str(exc)

    return targets, target_errors, wasm_b64, wasm_size


def compile_source_bundle(
    source: str,
    *,
    require_tight_specs: bool = True,
    module_name: str = "studio_mod",
) -> dict[str, Any]:
    """Verify AIL source and lazily emit LLVM, WASM, C11, and Rust artifacts."""
    t0 = time.perf_counter()
    resp = pb.CompilerResponse()
    try:
        forms = _parse_source_with_imports(source)
        tenv = check_module_ownership_v2(forms)
        mv = ModuleVerifier(tenv)
        stats = mv.verify_module(forms)
        resp.proof_stats.extend(stats)

        audits: list[pb.SpecAuditItem] = []
        spec_diags: list[pb.Diagnostic] = []
        try:
            audits, spec_diags = audit_module_specifications(forms, tenv)
            resp.spec_audits.extend(audits)
        except AILCompilerError as spec_err:
            spec_diags = [spec_err.diag]

        if require_tight_specs and spec_diags:
            resp.diagnostics.extend(spec_diags)
            resp.status = pb.STATUS_REJECTED
            resp.total_elapsed_ms = (time.perf_counter() - t0) * 1000.0
            iface = _extract_module_interface(forms, tenv)
            return {
                "ok": True,
                "verified": False,
                "status": pb.Status.Name(resp.status),
                "elapsed_ms": round(float(resp.total_elapsed_ms), 3),
                "proof_stats": _serialize_proof_stats(list(resp.proof_stats)),
                "spec_audits": _serialize_spec_audits(list(resp.spec_audits)),
                "diagnostics": [_serialize_diagnostic(d) for d in resp.diagnostics],
                "prototext": to_prototext(resp),
                "wasm_base64": "",
                "wasm_size_bytes": 0,
                "targets": {},
                "target_errors": {},
                **iface,
            }

        resp.status = pb.STATUS_VERIFIED
        targets, target_errors, wasm_b64, wasm_size = _compile_all_targets(forms, tenv, module_name, resp)
        resp.total_elapsed_ms = (time.perf_counter() - t0) * 1000.0
        iface = _extract_module_interface(forms, tenv)
        return {
            "ok": True,
            "verified": True,
            "status": pb.Status.Name(resp.status),
            "elapsed_ms": round(float(resp.total_elapsed_ms), 3),
            "proof_stats": _serialize_proof_stats(list(resp.proof_stats)),
            "spec_audits": _serialize_spec_audits(list(resp.spec_audits)),
            "diagnostics": [_serialize_diagnostic(d) for d in resp.diagnostics],
            "prototext": to_prototext(resp),
            "wasm_base64": wasm_b64,
            "wasm_size_bytes": wasm_size,
            "targets": targets,
            "target_errors": target_errors,
            **iface,
        }
    except AILCompilerError as err:
        resp.status = pb.STATUS_REJECTED
        resp.diagnostics.append(err.diag)
        resp.total_elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return {
            "ok": True,
            "verified": False,
            "status": pb.Status.Name(resp.status),
            "elapsed_ms": round(float(resp.total_elapsed_ms), 3),
            "proof_stats": _serialize_proof_stats(list(resp.proof_stats)),
            "spec_audits": _serialize_spec_audits(list(resp.spec_audits)),
            "diagnostics": [_serialize_diagnostic(d) for d in resp.diagnostics],
            "prototext": to_prototext(resp),
            "wasm_base64": "",
            "wasm_size_bytes": 0,
            "targets": {},
            "target_errors": {},
            "functions": [],
            "structs": [],
            "enums": [],
        }
    except Exception as exc:
        err_diag = pb.Diagnostic(
            code=pb.E_SYNTAX,
            stage=pb.STAGE_PARSE,
            item_name="<module>",
            span=pb.SourceSpan(line=1, column=1),
            expr="",
            message=f"Malformed declaration or AST structure: {exc}",
            repair_hint="Check S-expression syntax and declaration parameter lists.",
        )
        resp.status = pb.STATUS_REJECTED
        resp.diagnostics.append(err_diag)
        resp.total_elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return {
            "ok": True,
            "verified": False,
            "status": pb.Status.Name(resp.status),
            "elapsed_ms": round(float(resp.total_elapsed_ms), 3),
            "proof_stats": [],
            "spec_audits": [],
            "diagnostics": [_serialize_diagnostic(err_diag)],
            "prototext": to_prototext(resp),
            "wasm_base64": "",
            "wasm_size_bytes": 0,
            "targets": {},
            "target_errors": {},
            "functions": [],
            "structs": [],
            "enums": [],
        }


def repair_source_bundle(
    source: str,
    *,
    max_iters: int = 8,
    require_tight_specs: bool = True,
) -> dict[str, Any]:
    """Run closed-loop autonomous repair on broken AIL source and return JSON trace."""
    try:
        resolved_source = source
        if "(import " in source:
            forms = _parse_source_with_imports(source)
            resolved_source = format_module_source(forms)
        sess = run_repair_session(
            resolved_source,
            out_dir=None,
            stem="studio_repaired",
            max_iters=max_iters,
            require_tight_specs=require_tight_specs,
            backend="deterministic",
        )
    except AILCompilerError as err:
        resp = pb.CompilerResponse(status=pb.STATUS_REJECTED, diagnostics=[err.diag])
        return {
            "ok": True,
            "verified": False,
            "final_status": "STATUS_REJECTED",
            "iterations": 0,
            "total_elapsed_ms": 0.0,
            "repaired_source": source,
            "repaired_ail_source": source,
            "prototext": to_prototext(resp),
            "steps": [],
            "diagnostics": [_serialize_diagnostic(err.diag)],
            "compile": None,
        }

    steps_json: list[dict[str, Any]] = []
    for st in sess.steps:
        steps_json.append(
            {
                "turn": int(st.turn),
                "triggered_code": pb.ErrorCode.Name(st.triggered_code),
                "target_item": st.target_item,
                "patch_summary": st.patch_summary,
                "diagnostics": [_serialize_diagnostic(d) for d in st.check_response.diagnostics],
                "proof_stats": _serialize_proof_stats(list(st.check_response.proof_stats)),
                "spec_audits": _serialize_spec_audits(list(st.check_response.spec_audits)),
            }
        )

    verified = sess.final_status == pb.STATUS_VERIFIED
    compile_payload = (
        compile_source_bundle(sess.repaired_ail_source, require_tight_specs=require_tight_specs, module_name="repaired_mod")
        if verified and sess.repaired_ail_source
        else None
    )

    return {
        "ok": True,
        "verified": verified,
        "final_status": pb.Status.Name(sess.final_status),
        "iterations": int(sess.iterations),
        "total_elapsed_ms": round(float(sess.total_elapsed_ms), 3),
        "repaired_source": sess.repaired_ail_source,
        "repaired_ail_source": sess.repaired_ail_source,
        "prototext": to_prototext(sess),
        "steps": steps_json,
        "diagnostics": [],
        "compile": compile_payload,
    }


def generate_static_demos(out_path: Path | None = None) -> dict[str, Any]:
    """Precompile all curated presets into standalone `web/demos.json` for zero-server static execution."""
    target_path = out_path or (DEFAULT_WEB_DIR / "demos.json")
    target_path.parent.mkdir(parents=True, exist_ok=True)

    preset_entries: list[dict[str, Any]] = []
    for preset in get_presets():
        pid = preset["id"]
        src = preset["source"]
        tight = bool(preset.get("require_tight_specs", True))
        compile_res = compile_source_bundle(src, require_tight_specs=tight, module_name=pid)
        repair_res = repair_source_bundle(src, max_iters=8, require_tight_specs=tight) if preset.get("expect_error") else None
        preset_entries.append(
            {
                **preset,
                "compile": compile_res,
                "repair": repair_res,
            }
        )

    payload = {
        "version": STUDIO_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "targets": get_available_targets(),
        "benchmarks": get_benchmark_data(),
        "presets": preset_entries,
    }
    target_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def _make_handler(web_dir: Path, quiet: bool = False) -> type[BaseHTTPRequestHandler]:
    resolved_web_dir = web_dir.resolve()

    class StudioHandler(BaseHTTPRequestHandler):
        server_version = f"AILStudio/{STUDIO_VERSION}"

        def log_message(self, fmt: str, *args: Any) -> None:
            if not quiet:
                super().log_message(fmt, *args)

        def _send_bytes(self, status: int, body: bytes, content_type: str, cache_control: str = "no-store") -> None:
            try:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", cache_control)
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)
            except BrokenPipeError:
                pass

        def _send_json(self, status: int, data: Any) -> None:
            raw = json.dumps(data).encode("utf-8")
            self._send_bytes(status, raw, "application/json; charset=utf-8", cache_control="no-store")

        def _read_json_body(self) -> dict[str, Any] | None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Invalid Content-Length header"})
                return None
            if length < 0 or length > MAX_REQUEST_BYTES:
                self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"ok": False, "error": "Payload exceeds 1 MiB limit"})
                return None
            raw = self.rfile.read(length) if length > 0 else b"{}"
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": f"Malformed JSON body: {exc}"})
                return None
            if not isinstance(parsed, dict):
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "JSON body must be an object"})
                return None
            return parsed

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path

            if path == "/api/health":
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "version": STUDIO_VERSION,
                        "targets": get_available_targets(),
                    },
                )
                return

            if path == "/api/presets":
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "presets": get_presets(),
                        "benchmarks": get_benchmark_data(),
                    },
                )
                return

            if path.startswith("/api/"):
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": f"Unknown API endpoint: {path}"})
                return

            rel = "index.html" if path == "/" else path.lstrip("/")
            candidate = (resolved_web_dir / rel).resolve()
            if not candidate.is_relative_to(resolved_web_dir) or not candidate.is_file():
                self._send_bytes(HTTPStatus.NOT_FOUND, b"Not Found", "text/plain; charset=utf-8")
                return

            ctype, _ = mimetypes.guess_type(str(candidate))
            if candidate.suffix == ".css":
                ctype = "text/css; charset=utf-8"
            elif candidate.suffix == ".js":
                ctype = "application/javascript; charset=utf-8"
            elif candidate.suffix == ".json":
                ctype = "application/json; charset=utf-8"
            elif candidate.suffix == ".html":
                ctype = "text/html; charset=utf-8"
            elif candidate.suffix == ".wasm":
                ctype = "application/wasm"
            elif not ctype:
                ctype = "application/octet-stream"

            self._send_bytes(HTTPStatus.OK, candidate.read_bytes(), ctype, cache_control="no-cache")

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            body = self._read_json_body()
            if body is None:
                return

            if path == "/api/compile":
                source = body.get("source")
                if not isinstance(source, str) or not source.strip():
                    self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "`source` must be a non-empty string"})
                    return
                require_tight = bool(body.get("require_tight_specs", True))
                mod_name = str(body.get("module_name") or "studio_mod")
                mod_name = "".join(ch if (ch.isalnum() or ch == "_") else "_" for ch in mod_name) or "studio_mod"
                res = compile_source_bundle(source, require_tight_specs=require_tight, module_name=mod_name)
                self._send_json(HTTPStatus.OK, res)
                return

            if path == "/api/repair":
                source = body.get("source")
                if not isinstance(source, str) or not source.strip():
                    self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "`source` must be a non-empty string"})
                    return
                max_iters = int(body.get("max_iters", 8))
                max_iters = max(1, min(max_iters, 20))
                require_tight = bool(body.get("require_tight_specs", True))
                res = repair_source_bundle(source, max_iters=max_iters, require_tight_specs=require_tight)
                self._send_json(HTTPStatus.OK, res)
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": f"Unknown API endpoint: {path}"})

    return StudioHandler


class StudioHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def create_studio_server(
    host: str = "127.0.0.1",
    port: int = 8765,
    web_dir: Path | None = None,
    quiet: bool = True,
) -> StudioHTTPServer:
    """Create a configured ThreadingHTTPServer bound strictly to `host`."""
    resolved_dir = (web_dir or DEFAULT_WEB_DIR).resolve()
    handler = _make_handler(resolved_dir, quiet=quiet)
    return StudioHTTPServer((host, port), handler)


def serve_studio(
    host: str = "127.0.0.1",
    port: int = 8765,
    web_dir: Path | None = None,
) -> None:
    """Start AIL Web Studio blocking HTTP server bound to localhost."""
    srv = create_studio_server(host=host, port=port, web_dir=web_dir, quiet=False)
    actual_host, actual_port = srv.server_address[:2]
    print(f"[AIL Web Studio v{STUDIO_VERSION}] Serving {DEFAULT_WEB_DIR} at http://{actual_host}:{actual_port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
