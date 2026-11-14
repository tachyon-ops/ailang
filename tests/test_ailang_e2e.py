"""Comprehensive End-to-End Test Suite for the 4-Layer Protobuf-Native AIL Toolchain."""

from __future__ import annotations
import ctypes
import importlib.util
import json
from pathlib import Path
import subprocess
import tiktoken

from ailang import ail_agent_pb2 as pb
from ailang.cli import check_and_verify_path, main as cli_main
from ailang.diagnostics import ce_bindings_to_dict, to_prototext
from ailang.parser import parse_source

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"


def _run_cli_proto(args: list[str], tmp_path: Path) -> tuple[int, pb.CompilerResponse]:
    pb_out = tmp_path / "resp.pb"
    rc = cli_main(["--format", "proto", "--proto-out", str(pb_out), *args])
    resp = pb.CompilerResponse()
    resp.ParseFromString(pb_out.read_bytes())
    return rc, resp


def test_protobuf_lossless_u64_counterexample_vs_ieee754_json(tmp_path: Path) -> None:
    """Proves binary Protobuf preserves exact >2^53 u64 counterexamples (2^63) and saves wire bytes & tokens."""
    buggy = tmp_path / "mid_bug.ail"
    buggy.write_text("(fn midpoint ((lo u64[0..MAX]) (hi u64[lo..MAX])) u64[lo..hi] (/ (+ lo hi) 2))\n")

    rc, resp = _run_cli_proto(["check", str(buggy)], tmp_path)
    assert rc == 1
    assert resp.status == pb.STATUS_REJECTED
    assert len(resp.diagnostics) == 1

    diag = resp.diagnostics[0]
    assert diag.code == pb.E_U64_OVERFLOW
    assert diag.stage == pb.STAGE_TIER2_Z3
    ce = ce_bindings_to_dict(list(diag.counterexample))
    assert ce["lo"] + ce["hi"] > (1 << 64) - 1
    assert ce["lo"] > (1 << 53)  # Exceeds IEEE-754 float64 safe integer limit!
    # Verify exact u64 varint field was used (not stringified fallback)
    assert any(b.WhichOneof("value") == "u64_val" and b.u64_val == ce["lo"] for b in diag.counterexample)

    # Compare wire size & LLM token count: Binary Protobuf vs ProtoText vs equivalent JSON
    pb_bytes = resp.SerializeToString()
    prototext_str = to_prototext(resp)
    equiv_json = json.dumps(
        {
            "status": "STATUS_REJECTED",
            "total_elapsed_ms": resp.total_elapsed_ms,
            "diagnostics": [
                {
                    "code": "E_U64_OVERFLOW",
                    "stage": "STAGE_TIER2_Z3",
                    "item_name": diag.item_name,
                    "span": {"line": diag.span.line, "column": diag.span.column},
                    "expr": diag.expr,
                    "message": diag.message,
                    "counterexample": ce,
                    "repair_hint": diag.repair_hint,
                }
            ],
        },
        indent=2,
    )
    enc = tiktoken.get_encoding("o200k_base")
    assert len(pb_bytes) < len(equiv_json.encode("utf-8")) // 2
    assert len(enc.encode(prototext_str)) < len(enc.encode(equiv_json))


def test_ownership_and_linear_capability_errors(tmp_path: Path) -> None:
    # 1. Reuse linear cap.io after move
    p1 = tmp_path / "use_after_move.ail"
    p1.write_text(
        "(main ((io cap.io)) u64[0..0]\n"
        "  (let ((io1 (io.print_u64 io 1))\n"
        "        (io2 (io.print_u64 io 2)))\n"
        "    (io.done io2 0)))\n"
    )
    _, r1 = _run_cli_proto(["check", str(p1)], tmp_path)
    assert r1.diagnostics[0].code == pb.E_LINEAR_USE_AFTER_MOVE

    # 2. Unconsumed linear cap.io leak
    p2 = tmp_path / "leak_cap.ail"
    p2.write_text("(main ((io cap.io)) u64[0..0] 0)\n")
    _, r2 = _run_cli_proto(["check", str(p2)], tmp_path)
    assert r2.diagnostics[0].code == pb.E_LINEAR_UNCONSUMED

    # 3. Missing capability in pure function
    p3 = tmp_path / "missing_cap.ail"
    p3.write_text("(fn pure_fn ((x u64[0..10])) u64[0..10] (io.print_u64 x x))\n")
    _, r3 = _run_cli_proto(["check", str(p3)], tmp_path)
    assert r3.diagnostics[0].code == pb.E_CAPABILITY_MISSING

    # 4. Mutable slice aliasing violation
    p4 = tmp_path / "alias_mut.ail"
    p4.write_text(
        "(fn two_muts ((n u64[0..10]) (a (mut_slice n u64[0..10])) (b (mut_slice n u64[0..10]))) u64[0..0] 0)\n"
        "(fn caller ((n u64[0..10]) (buf (mut_slice n u64[0..10]))) u64[0..0] (call two_muts n buf buf))\n"
    )
    _, r4 = _run_cli_proto(["check", str(p4)], tmp_path)
    assert r4.diagnostics[0].code == pb.E_ALIASING_VIOLATION


def test_stratified_verifier_bitwuzla_and_z3_rejections(tmp_path: Path) -> None:
    # 1. Bitwuzla Tier-1 shift >= 64 UB rejection
    p_shift = tmp_path / "bad_shift.ail"
    p_shift.write_text("(fn bad_sh ((x u64[0..1000]) (k u64[0..64])) u64[0..1000] (>> x k))\n")
    _, r_sh = _run_cli_proto(["check", str(p_shift)], tmp_path)
    assert r_sh.diagnostics[0].stage == pb.STAGE_TIER1_BITWUZLA
    assert r_sh.diagnostics[0].code == pb.E_SHIFT_OUT_OF_RANGE
    assert ce_bindings_to_dict(list(r_sh.diagnostics[0].counterexample))["k"] == 64

    # 2. Slice out-of-bounds inside fold
    p_oob = tmp_path / "oob.ail"
    p_oob.write_text(
        "(fn oob ((n u64[1..100]) (buf (slice n u64[0..10]))) u64[0..1000]\n"
        "  (fold (i n) (acc 0 u64[0..(* i 10)]) (+ acc (get buf (+ i 1)))))\n"
    )
    _, r_oob = _run_cli_proto(["check", str(p_oob)], tmp_path)
    assert r_oob.diagnostics[0].code == pb.E_SLICE_OUT_OF_BOUNDS

    # 3. Modular call precondition violation
    p_pre = tmp_path / "bad_call.ail"
    p_pre.write_text(
        "(fn pct ((bps u64[0..10000])) u64[0..10000] bps)\n"
        "(fn bad_caller ((x u64[0..20000])) u64[0..20000] (call pct x))\n"
    )
    _, r_pre = _run_cli_proto(["check", str(p_pre)], tmp_path)
    assert r_pre.diagnostics[0].code == pb.E_PRECONDITION_FAILED

    # 4. Broken concurrent atomic protocol conservation
    p_atom = tmp_path / "bad_atomic.ail"
    p_atom.write_text(
        "(atomic_protocol BadVault ((vault u64) (disb u64) (tot u64))\n"
        "  (== (+ vault disb) tot)\n"
        "  (step steal ((req u64[0..vault])) ((- vault req) (+ disb (* req 2)) tot)))\n"
    )
    _, r_atom = _run_cli_proto(["check", str(p_atom)], tmp_path)
    assert r_atom.diagnostics[0].code == pb.E_ATOMIC_INVARIANT_FAILED


def test_spec_firewall_audit_and_diff(tmp_path: Path) -> None:
    # 1. Weak spec rejected by SpecMut auditor
    weak = tmp_path / "weak.ail"
    weak.write_text(
        "(fn settle_weak ((amt u64[0..1000000]) (bps u64[0..10000])) u64[0..amt]\n"
        "  (- amt (/ (* amt bps) 10000)))\n"
    )
    rc_w, r_weak = _run_cli_proto(["audit-spec", str(weak)], tmp_path)
    assert rc_w == 1
    assert r_weak.diagnostics[0].code == pb.E_SPEC_MUTANT_SURVIVED
    assert not r_weak.spec_audits[0].uniquely_tight

    # 2. Tight specs in financial_kernel.ail pass audit-spec (for midpoint & settle_net)
    tight = tmp_path / "tight_only.ail"
    tight.write_text(
        "(spec exact_fee ((amt int) (bps int) (cap int)) (min cap (/ (* amt bps) 10000)))\n"
        "(fn settle_net ((amt u64[0..10000000000000000]) (bps u64[0..10000]) (cap u64[0..10000000000000000]))\n"
        "  (out u64[0..amt] (== (- amt out) (exact_fee amt bps cap)))\n"
        "  (- amt (min cap (+ (* (/ amt 10000) bps) (/ (* (% amt 10000) bps) 10000)))))\n"
    )
    rc_t, r_tight = _run_cli_proto(["audit-spec", str(tight)], tmp_path)
    assert rc_t == 0
    assert r_tight.spec_audits[0].uniquely_tight
    assert r_tight.spec_audits[0].mutants_killed == r_tight.spec_audits[0].mutants_tested

    # 3. Differential autoformalization catches Candidate A vs B conservation bug
    rc_d, r_diff = _run_cli_proto(
        [
            "diff-specs",
            str(EXAMPLES / "ambiguous_specs" / "candidate_a.ail"),
            str(EXAMPLES / "ambiguous_specs" / "candidate_b.ail"),
        ],
        tmp_path,
    )
    assert rc_d == 1
    assert r_diff.diagnostics[0].code == pb.E_SPEC_AMBIGUITY
    assert r_diff.spec_diffs[0].spec_a_violates_conservation is True
    assert r_diff.spec_diffs[0].spec_b_violates_conservation is False


def test_binary_ast_encode_and_native_simd_dylib_execution(tmp_path: Path) -> None:
    # 1. Encode `financial_kernel.ail` to binary Protobuf AST (`.ail.pb`), then build `.dylib` from `.ail.pb`!
    ast_pb = tmp_path / "financial_kernel.ail.pb"
    assert cli_main(["encode-ast", str(EXAMPLES / "financial_kernel.ail"), "-o", str(ast_pb)]) == 0
    assert ast_pb.exists() and ast_pb.stat().st_size > 0

    out_dir = tmp_path / "native_lib"
    rc, resp = _run_cli_proto(["build", "--lib", str(ast_pb), "-o", str(out_dir)], tmp_path)
    assert rc == 0
    assert resp.artifacts.neon_simd_instructions >= 10
    assert Path(resp.artifacts.c_header_path).exists()

    # Load auto-generated Python ctypes bindings and execute verified native ARM64 functions!
    spec = importlib.util.spec_from_file_location("fk_bindings", resp.artifacts.python_bindings_path)
    assert spec and spec.loader
    fk = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fk)

    assert fk.midpoint(1 << 63, (1 << 63) + 100) == (1 << 63) + 50
    assert fk.settle_net(2_000_000_000_000_000, 9500, 2_000_000_000_000_000) == 100_000_000_000_000

    arr = (ctypes.c_uint64 * 16)(*[1000 * i for i in range(16)])
    fk.halve_bonus_inplace(16, 250, 5000, arr)
    assert arr[0] == 250
    assert arr[4] == 2250
    assert arr[15] == 5000  # capped at 5000!
    assert fk.batch_cap_sum(16, arr) == sum(arr)


def test_lockfree_vault_cas_and_standalone_verified_cli(tmp_path: Path) -> None:
    # 1. Lock-free atomic vault `.dylib` (`casal` hardware instruction)
    vault_dir = tmp_path / "vault_build"
    rc_v, resp_v = _run_cli_proto(["build", "--lib", str(EXAMPLES / "lockfree_vault.ail"), "-o", str(vault_dir)], tmp_path)
    assert rc_v == 0
    assert resp_v.artifacts.hardware_atomic_instructions >= 1

    spec = importlib.util.spec_from_file_location("vault_bindings", resp_v.artifacts.python_bindings_path)
    assert spec and spec.loader
    vb = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vb)

    vault_cell = ctypes.c_uint64(1000)
    assert vb.cas_withdraw(ctypes.byref(vault_cell), 400) == 1
    assert vault_cell.value == 600
    assert vb.cas_withdraw(ctypes.byref(vault_cell), 700) == 0  # Insufficient reserve -> atomic CAS guard aborts!
    assert vault_cell.value == 600

    # 2. Standalone capability-gated executable (`ail run examples/verified_cli.ail`)
    cli_dir = tmp_path / "cli_build"
    rc_c, resp_c = _run_cli_proto(["build", str(EXAMPLES / "verified_cli.ail"), "-o", str(cli_dir)], tmp_path)
    assert rc_c == 0
    out = subprocess.check_output([resp_c.artifacts.binary_or_lib_path], text=True)
    assert out.strip().splitlines() == ["975000", "4950000"]
