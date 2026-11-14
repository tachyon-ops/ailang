"""Unified `ail` v1.0 CLI: Protobuf (`--proto` / `--prototext`), `check`, `audit-spec`, `diff-specs`, `build`, `run`, `repair`, `studio`, `mcp`, `stdlib`."""

from __future__ import annotations
import argparse
from pathlib import Path
import subprocess
import sys
import time

from ailang import ail_agent_pb2 as pb
from ailang.agent_loop import format_module_source, run_repair_session
from ailang.diagnostics import (
    AILCompilerError,
    format_human_summary,
    format_repair_session,
    to_proto_bytes,
    to_prototext,
)
from ailang.lang_bench import format_language_benchmark_markdown, run_language_benchmark
from ailang.llm_bench import run_llm_benchmark
from ailang.modules import list_stdlib_modules, load_ail_module_with_imports
from ailang.multi_target import SUPPORTED_TARGETS, build_multi_target
from ailang.ownership import ModuleTypeEnv, check_module_ownership_v2
from ailang.parser import SNode, module_to_proto, parse_source, pretty
from ailang.spec_firewall import audit_module_specifications, diff_candidate_modules
from ailang.verifier import ModuleVerifier


def _module_stem(path: Path) -> str:
    return path.name.removesuffix(".ail.pb").removesuffix(".ail").removesuffix(".pb")


def _emit_response(resp: pb.CompilerResponse, fmt: str, proto_out: str | None = None) -> int:
    if proto_out:
        Path(proto_out).write_bytes(to_proto_bytes(resp))
    if fmt == "proto":
        sys.stdout.buffer.write(to_proto_bytes(resp))
        sys.stdout.buffer.flush()
    elif fmt == "prototext":
        sys.stdout.write(to_prototext(resp))
    else:
        print(format_human_summary(resp))
    return 0 if resp.status == pb.STATUS_VERIFIED else 1


def _emit_repair_session(sess: pb.RepairSession, fmt: str, proto_out: str | None = None) -> int:
    if proto_out:
        Path(proto_out).write_bytes(to_proto_bytes(sess))
    if fmt == "proto":
        sys.stdout.buffer.write(to_proto_bytes(sess))
        sys.stdout.buffer.flush()
    elif fmt == "prototext":
        sys.stdout.write(to_prototext(sess))
    else:
        print(format_repair_session(sess))
    return 0 if sess.final_status == pb.STATUS_VERIFIED else 1


def _emit_generic_proto(msg: object, text_summary: str, fmt: str, proto_out: str | None = None) -> int:
    if proto_out:
        out_path = Path(proto_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(to_proto_bytes(msg))
    if fmt == "proto":
        sys.stdout.buffer.write(to_proto_bytes(msg))
        sys.stdout.buffer.flush()
    elif fmt == "prototext":
        sys.stdout.write(to_prototext(msg))
    else:
        print(text_summary)
    return 0


def check_and_verify_path(path: Path) -> tuple[pb.CompilerResponse, list[SNode], ModuleTypeEnv]:
    t0 = time.perf_counter()
    resp = pb.CompilerResponse()
    try:
        forms = load_ail_module_with_imports(path)
        tenv = check_module_ownership_v2(forms)
        mv = ModuleVerifier(tenv)
        stats = mv.verify_module(forms)
        resp.proof_stats.extend(stats)
        resp.status = pb.STATUS_VERIFIED
        resp.total_elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return resp, forms, tenv
    except AILCompilerError as err:
        resp.status = pb.STATUS_REJECTED
        resp.diagnostics.append(err.diag)
        resp.total_elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return resp, [], ModuleTypeEnv()


def _format_stdlib_catalog(module_filter: str | None = None) -> str:
    paths = list_stdlib_modules()
    if module_filter:
        filt = module_filter.strip().removesuffix(".ail").removeprefix("stdlib/")
        paths = [p for p in paths if p.stem == filt]
    if not paths:
        return "[STDLIB] No matching built-in stdlib modules found."

    lines = [f"[AIL STDLIB] {len(paths)} verified module(s):"]
    for mod_path in paths:
        forms = parse_source(mod_path.read_text(encoding="utf-8"))
        lines.append(f"\n  Module `stdlib/{mod_path.stem}` ({mod_path}):")
        for form in forms:
            if not isinstance(form.val, list) or not form.val:
                continue
            head = str(form.val[0].val)
            if head == "const" and len(form.val) >= 4:
                lines.append(f"    const  {pretty(form.val[1])}: {pretty(form.val[2])} = {pretty(form.val[3])}")
            elif head == "struct" and len(form.val) >= 3:
                flds = ", ".join(
                    f"{pretty(f.val[0])}: {pretty(f.val[1])}"
                    for f in form.val[2].val
                    if isinstance(f.val, list) and len(f.val) >= 2
                )
                lines.append(f"    struct {pretty(form.val[1])} {{ {flds} }}")
            elif head == "enum" and len(form.val) >= 3:
                vnames = [pretty(v.val[0]) for v in form.val[2:] if isinstance(v.val, list) and v.val]
                lines.append(f"    enum   {pretty(form.val[1])} ({' | '.join(vnames)})")
            elif head == "spec" and len(form.val) >= 4:
                params = " ".join(pretty(p) for p in form.val[2].val)
                lines.append(f"    spec   ({pretty(form.val[1])} ({params}))")
            elif head in ("fn", "map_inplace") and len(form.val) >= 4:
                params = " ".join(pretty(p) for p in form.val[2].val)
                lines.append(f"    {head:<6} ({pretty(form.val[1])} ({params})) -> {pretty(form.val[3])}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ail",
        description="AIL v1.0: Protobuf-Native Formally Verified AI Agent Language & Multi-Target Compiler Toolchain",
    )
    parser.add_argument(
        "--format",
        choices=["human", "prototext", "proto"],
        default="human",
        help="Output protocol: `proto` (binary Protobuf wire format), `prototext` (Protobuf TextFormat), or `human`.",
    )
    parser.add_argument(
        "--proto-out",
        default=None,
        help="Optional path to write binary `CompilerResponse` or `RepairSession` Protobuf payload (`.pb`).",
    )

    sub = parser.add_subparsers(dest="cmd", required=True)

    p_check = sub.add_parser("check", help="Typecheck ownership/capabilities/structs and verify module in Bitwuzla + Z3")
    p_check.add_argument("input", type=Path, help="Input `.ail` or binary `.ail.pb` module")

    p_audit = sub.add_parser("audit-spec", help="Run non-vacuity & specification mutation testing (SpecMut)")
    p_audit.add_argument("input", type=Path, help="Input `.ail` or `.ail.pb` module")

    p_diff = sub.add_parser("diff-specs", help="Extract distinguishing inputs between two candidate formalizations (Clover)")
    p_diff.add_argument("spec_a", type=Path, help="Candidate A `.ail` or `.ail.pb`")
    p_diff.add_argument("spec_b", type=Path, help="Candidate B `.ail` or `.ail.pb`")

    p_build = sub.add_parser(
        "build",
        help="Verify module (and optionally audit specs) then compile to native LLVM, WebAssembly, C11, Rust, or all targets",
    )
    p_build.add_argument("input", type=Path, help="Input `.ail` or `.ail.pb` module")
    p_build.add_argument("-o", "--out-dir", type=Path, default=Path("build"), help="Output directory for compiled artifacts")
    p_build.add_argument(
        "--target",
        choices=list(SUPPORTED_TARGETS),
        default="native",
        help="Compilation target (`native`, `wasm`, `c`, `rust`, or `all`; default: `native`)",
    )
    p_build.add_argument("--lib", action="store_true", help="Force shared library `.dylib`/`.so` + C/Python FFI generation")
    p_build.add_argument("--require-tight-specs", action="store_true", help="Reject build if any scalar `fn` fails spec mutation tightness")

    p_run = sub.add_parser("run", help="Verify, compile, and execute a standalone capability-gated AIL `main` binary")
    p_run.add_argument("input", type=Path, help="Input `.ail` or `.ail.pb` module with `(main ...)`")
    p_run.add_argument("-o", "--out-dir", type=Path, default=Path("build"), help="Output directory")

    p_ast = sub.add_parser("encode-ast", help="Compile `.ail` source into a zero-syntax-error binary `ModuleProto` (`.ail.pb`)")
    p_ast.add_argument("input", type=Path, help="Input `.ail` source file")
    p_ast.add_argument("-o", "--output", type=Path, required=True, help="Output `.ail.pb` binary AST path")

    p_rep = sub.add_parser("repair", help="Run closed-loop Protobuf verification & autonomous AST self-repair (`RepairSession`)")
    p_rep.add_argument("input", type=Path, help="Broken/unverified `.ail` or `.ail.pb` module")
    p_rep.add_argument("-o", "--out-dir", type=Path, default=None, help="Optional output directory to compile verified native binary/dylib")
    p_rep.add_argument("--write-fixed", type=Path, default=None, help="Optional path to write repaired `.ail` source")
    p_rep.add_argument("--write-ast", type=Path, default=None, help="Optional path to write repaired binary `.ail.pb` `ModuleProto`")
    p_rep.add_argument("--max-iters", type=int, default=8, help="Maximum repair loop turns (default: 8)")
    p_rep.add_argument("--backend", choices=["deterministic", "gemini"], default="deterministic", help="Repair backend")
    p_rep.add_argument("--no-tight-specs", action="store_true", help="Skip SpecMut tightness enforcement during repair")

    p_studio = sub.add_parser("studio", help="Launch AIL Web Studio playground or regenerate static `web/demos.json`")
    p_studio.add_argument("--host", default="127.0.0.1", help="Bind host address (default: 127.0.0.1)")
    p_studio.add_argument("--port", type=int, default=8765, help="HTTP port (default: 8765)")
    p_studio.add_argument(
        "--regenerate-demos",
        action="store_true",
        help="Regenerate static `web/demos.json` bundle from v1.0 backends and exit",
    )
    p_studio.add_argument("--out", type=Path, default=None, help="Optional output path for `--regenerate-demos`")

    sub.add_parser("mcp", help="Launch the AIL Model Context Protocol (MCP) JSON-RPC 2.0 stdio server")

    p_stdlib = sub.add_parser("stdlib", help="List built-in verified `stdlib/*.ail` modules and exported functions/specs")
    p_stdlib.add_argument("--module", default=None, help="Optional stdlib module filter (e.g. `math`, `finance`, `bits`, `parse`)")

    p_bl = sub.add_parser("bench-langs", help="Run empirical benchmark comparing AIL vs Rust vs C vs Python")
    p_bl.add_argument("-o", "--out-dir", type=Path, default=Path("build/bench_langs"), help="Working build directory")
    p_bl.add_argument("--scalar-iters", type=int, default=2_000_000, help="Iterations for scalar/array kernels")
    p_bl.add_argument("--simd-iters", type=int, default=100_000, help="Iterations for SIMD/matrix kernels")
    p_bl.add_argument("--markdown-out", type=Path, default=None, help="Optional path to save Markdown benchmark report")

    p_bllm = sub.add_parser("bench-llm", help="Run blind LLM spec-to-silicon benchmark suite")
    p_bllm.add_argument("-o", "--out-dir", type=Path, default=Path("build/bench_llm"), help="Working build directory")
    p_bllm.add_argument("--provider", default="gemini", help="LLM provider backend")
    p_bllm.add_argument("--model", default="gemini-2.5-flash", help="Model name")
    p_bllm.add_argument("--max-turns", type=int, default=4, help="Maximum self-repair turns per task")
    p_bllm.add_argument("--markdown-out", type=Path, default=None, help="Optional path to save Markdown benchmark report")

    args = parser.parse_args(argv)

    if args.cmd == "encode-ast":
        forms = parse_source(args.input.read_text())
        mp = module_to_proto(forms, module_name=args.input.stem)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        raw = mp.SerializeToString()
        args.output.write_bytes(raw)
        if args.format == "human":
            print(f"[ENCODED] {args.input} -> {args.output} ({len(raw)} bytes ModuleProto)")
        return 0

    if args.cmd == "check":
        resp, _, _ = check_and_verify_path(args.input)
        return _emit_response(resp, args.format, args.proto_out)

    if args.cmd == "audit-spec":
        t0 = time.perf_counter()
        resp, forms, tenv = check_and_verify_path(args.input)
        if resp.status == pb.STATUS_VERIFIED:
            audits, diags = audit_module_specifications(forms, tenv)
            resp.spec_audits.extend(audits)
            resp.diagnostics.extend(diags)
            if diags:
                resp.status = pb.STATUS_REJECTED
        resp.total_elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return _emit_response(resp, args.format, args.proto_out)

    if args.cmd == "diff-specs":
        t0 = time.perf_counter()
        resp = pb.CompilerResponse()
        try:
            fa = load_ail_module_with_imports(args.spec_a)
            fb = load_ail_module_with_imports(args.spec_b)
            diffs, diags = diff_candidate_modules(fa, fb)
            resp.spec_diffs.extend(diffs)
            resp.diagnostics.extend(diags)
            resp.status = pb.STATUS_REJECTED if diags else pb.STATUS_VERIFIED
        except AILCompilerError as err:
            resp.status = pb.STATUS_REJECTED
            resp.diagnostics.append(err.diag)
        resp.total_elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return _emit_response(resp, args.format, args.proto_out)

    if args.cmd in ("build", "run"):
        t0 = time.perf_counter()
        resp, forms, tenv = check_and_verify_path(args.input)
        if resp.status != pb.STATUS_VERIFIED:
            return _emit_response(resp, args.format, args.proto_out)

        if getattr(args, "require_tight_specs", False):
            audits, diags = audit_module_specifications(forms, tenv)
            resp.spec_audits.extend(audits)
            if diags:
                resp.diagnostics.extend(diags)
                resp.status = pb.STATUS_REJECTED
                resp.total_elapsed_ms = (time.perf_counter() - t0) * 1000.0
                return _emit_response(resp, args.format, args.proto_out)

        stem = _module_stem(args.input)
        target = getattr(args, "target", "native") if args.cmd == "build" else "native"
        force_lib = True if getattr(args, "lib", False) else (False if args.cmd == "run" else None)

        try:
            report = build_multi_target(
                forms,
                tenv,
                args.out_dir,
                stem,
                target=target,
                build_shared_lib=force_lib,
            )
        except AILCompilerError as err:
            resp.status = pb.STATUS_REJECTED
            resp.diagnostics.append(err.diag)
            resp.total_elapsed_ms = (time.perf_counter() - t0) * 1000.0
            return _emit_response(resp, args.format, args.proto_out)

        if report.native is not None:
            resp.artifacts.CopyFrom(report.native)
        resp.total_elapsed_ms = (time.perf_counter() - t0) * 1000.0

        if args.cmd == "build":
            rc = _emit_response(resp, args.format, args.proto_out)
            if args.format == "human" and target != "native":
                print(report.format_human())
            return rc

        if args.format in ("proto", "prototext") or args.proto_out:
            _emit_response(resp, args.format, args.proto_out)
        assert report.native is not None
        proc = subprocess.run([report.native.binary_or_lib_path], check=False)
        return proc.returncode

    if args.cmd == "repair":
        stem = _module_stem(args.input)
        try:
            forms = load_ail_module_with_imports(args.input)
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
            return _emit_repair_session(sess, args.format, args.proto_out)

        sess = run_repair_session(
            format_module_source(forms),
            out_dir=args.out_dir,
            stem=stem,
            max_iters=args.max_iters,
            require_tight_specs=(not args.no_tight_specs),
            backend=args.backend,
        )
        if args.write_fixed and sess.repaired_ail_source:
            args.write_fixed.parent.mkdir(parents=True, exist_ok=True)
            args.write_fixed.write_text(sess.repaired_ail_source)
        if args.write_ast and sess.HasField("repaired_ast"):
            args.write_ast.parent.mkdir(parents=True, exist_ok=True)
            args.write_ast.write_bytes(sess.repaired_ast.SerializeToString())
        return _emit_repair_session(sess, args.format, args.proto_out)

    if args.cmd == "studio":
        from ailang.web_server import DEFAULT_WEB_DIR, generate_static_demos, serve_studio

        if args.regenerate_demos:
            target_path = args.out or (DEFAULT_WEB_DIR / "demos.json")
            payload = generate_static_demos(out_path=target_path)
            if args.format == "human":
                print(
                    f"[REGENERATED] {target_path} ({len(payload.get('presets', []))} presets, "
                    f"targets={','.join(payload.get('targets', []))})"
                )
            elif args.format in ("proto", "prototext") or args.proto_out:
                _emit_response(pb.CompilerResponse(status=pb.STATUS_VERIFIED), args.format, args.proto_out)
            return 0
        serve_studio(host=args.host, port=args.port)
        return 0

    if args.cmd == "mcp":
        from ailang.mcp_server import main as mcp_main

        return mcp_main()

    if args.cmd == "stdlib":
        summary = _format_stdlib_catalog(args.module)
        if args.format in ("proto", "prototext") or args.proto_out:
            return _emit_response(pb.CompilerResponse(status=pb.STATUS_VERIFIED), args.format, args.proto_out)
        print(summary)
        return 0

    if args.cmd == "bench-langs":
        report, md = run_language_benchmark(
            args.out_dir,
            scalar_iters=args.scalar_iters,
            simd_iters=args.simd_iters,
        )
        if not md:
            md = format_language_benchmark_markdown(report)
        if args.markdown_out:
            args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
            args.markdown_out.write_text(md)
        return _emit_generic_proto(report, md, args.format, args.proto_out)

    if args.cmd == "bench-llm":
        report, md = run_llm_benchmark(
            args.out_dir,
            provider=args.provider,
            model_name=args.model,
            max_turns=args.max_turns,
        )
        if args.markdown_out:
            args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
            args.markdown_out.write_text(md)
        return _emit_generic_proto(report, md, args.format, args.proto_out)

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
