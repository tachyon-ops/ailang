"""Unified `ail` v0.2 CLI: Protobuf (`--proto` / `--prototext`), `check`, `audit-spec`, `diff-specs`, `build`, `run`, `repair`."""

from __future__ import annotations
import argparse
from pathlib import Path
import subprocess
import sys
import time

from ailang import ail_agent_pb2 as pb
from ailang.agent_loop import run_repair_session
from ailang.codegen_llvm import compile_llvm_to_native
from ailang.diagnostics import (
    AILCompilerError,
    format_human_summary,
    format_repair_session,
    to_proto_bytes,
    to_prototext,
)
from ailang.ownership import ModuleTypeEnv, check_module_ownership_v2
from ailang.parser import SNode, load_ail_path, module_to_proto, parse_source
from ailang.spec_firewall import audit_module_specifications, diff_candidate_modules
from ailang.verifier import ModuleVerifier


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


def check_and_verify_path(path: Path) -> tuple[pb.CompilerResponse, list[SNode], ModuleTypeEnv]:
    t0 = time.perf_counter()
    resp = pb.CompilerResponse()
    try:
        forms = load_ail_path(path)
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ail",
        description="AIL v0.2: Protobuf-Native Formally Verified AI Agent Programming Language Toolchain",
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

    p_build = sub.add_parser("build", help="Verify module (and optionally audit specs) then compile via LLVM -O3 to native silicon")
    p_build.add_argument("input", type=Path, help="Input `.ail` or `.ail.pb` module")
    p_build.add_argument("-o", "--out-dir", type=Path, default=Path("build"), help="Output directory for native artifacts")
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
            fa = load_ail_path(args.spec_a)
            fb = load_ail_path(args.spec_b)
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

        stem = args.input.name.removesuffix(".ail.pb").removesuffix(".ail").removesuffix(".pb")
        force_lib = True if getattr(args, "lib", False) else (False if args.cmd == "run" else None)
        artifacts = compile_llvm_to_native(forms, tenv, args.out_dir, stem, build_shared_lib=force_lib)
        resp.artifacts.CopyFrom(artifacts)
        resp.total_elapsed_ms = (time.perf_counter() - t0) * 1000.0

        if args.cmd == "build":
            return _emit_response(resp, args.format, args.proto_out)

        if args.format in ("proto", "prototext") or args.proto_out:
            _emit_response(resp, args.format, args.proto_out)
        proc = subprocess.run([artifacts.binary_or_lib_path], check=False)
        return proc.returncode

    if args.cmd == "repair":
        sess = run_repair_session(
            args.input,
            out_dir=args.out_dir,
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

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
