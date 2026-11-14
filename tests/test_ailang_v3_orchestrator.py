"""v0.3 Orchestrator Test Suite: Algebraic `enum`/`match`, `SpecMut`, Language & Live LLM Benchmarks."""

from __future__ import annotations
import importlib.util
from pathlib import Path
import subprocess
import sys

import pytest

from ailang import ail_agent_pb2 as pb
from ailang.agent_loop import run_repair_session
from ailang.cli import main as cli_main
from ailang.codegen_llvm import compile_llvm_to_native
from ailang.diagnostics import AILCompilerError
from ailang.lang_bench import run_language_benchmark
from ailang.llm_bench import BENCHMARK_TASKS, LLMBenchTask, run_llm_benchmark
from ailang.ownership import check_module_ownership_v2
from ailang.parser import parse_source, pretty
from ailang.verifier import ModuleVerifier

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"


def _run_cli_proto(args: list[str], tmp_path: Path) -> tuple[int, pb.CompilerResponse]:
    pb_out = tmp_path / "resp.pb"
    rc = cli_main(["--format", "proto", "--proto-out", str(pb_out), *args])
    resp = pb.CompilerResponse()
    resp.ParseFromString(pb_out.read_bytes())
    return rc, resp


def _load_bindings(bindings_path: str, tag: str):
    spec = importlib.util.spec_from_file_location(f"ail_v3_{tag}", bindings_path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_optional_module_wrapper_parsing() -> None:
    bare = """
    (spec f ((x int)) (+ x 1))
    (fn inc ((x u64[0..100])) (out u64[1..101] (== out (f x))) (+ x 1))
    """
    wrapped = f"(module demo_mod\n{bare}\n)"
    f_bare = parse_source(bare)
    f_wrap = parse_source(wrapped)
    assert [pretty(n) for n in f_bare] == [pretty(n) for n in f_wrap]

    with pytest.raises(AILCompilerError) as ei:
        parse_source("(module)")
    assert ei.value.diag.code == pb.E_SYNTAX


def test_enum_match_static_firewall_and_wildcard(tmp_path: Path) -> None:
    enum_decl = "(enum Mode (Fast (rate u64[1..100])) (Slow (rate u64[1..10])) (Off))"

    # 1. Missing variant arm without wildcard -> E_NON_EXHAUSTIVE_MATCH
    p_miss = tmp_path / "non_exhaustive.ail"
    p_miss.write_text(
        f"{enum_decl}\n"
        "(fn score ((m Mode)) u64[0..100] (match m ((Fast r) r) ((Slow r) r)))\n"
    )
    rc1, r1 = _run_cli_proto(["check", str(p_miss)], tmp_path)
    assert rc1 == 1
    assert r1.diagnostics[0].code == pb.E_NON_EXHAUSTIVE_MATCH

    # 2. Duplicate variant arm -> E_DUPLICATE_MATCH_ARM
    p_dup = tmp_path / "dup_arm.ail"
    p_dup.write_text(
        f"{enum_decl}\n"
        "(fn score ((m Mode)) u64[0..100] (match m ((Fast r) r) ((Fast r) r) ((Slow r) r) ((Off) 0)))\n"
    )
    rc2, r2 = _run_cli_proto(["check", str(p_dup)], tmp_path)
    assert rc2 == 1
    assert r2.diagnostics[0].code == pb.E_DUPLICATE_MATCH_ARM

    # 3. Variant constructor violating field refinement -> E_ENUM_INVARIANT_FAILED
    p_inv = tmp_path / "bad_variant.ail"
    p_inv.write_text(
        f"{enum_decl}\n"
        "(fn mk_slow ((r u64[5..50])) Mode (variant Mode Slow r))\n"
    )
    rc3, r3 = _run_cli_proto(["check", str(p_inv)], tmp_path)
    assert rc3 == 1
    assert r3.diagnostics[0].code == pb.E_ENUM_INVARIANT_FAILED

    # 4. Wildcard fallback + is_variant compiles and executes natively
    p_ok = tmp_path / "wildcard_ok.ail"
    p_ok.write_text(
        f"{enum_decl}\n"
        "(spec exact_s ((m Mode)) (match m ((Fast r) (+ r 10)) (_ 5)))\n"
        "(fn s ((m Mode)) (out u64[5..110] (== out (exact_s m))) (match m ((Fast r) (+ r 10)) (_ 5)))\n"
        "(fn is_off ((m Mode)) u64[0..1] (if (is_variant m Off) 1 0))\n"
    )
    build_dir = tmp_path / "out_ok"
    rc4, r4 = _run_cli_proto(["build", "--lib", "-o", str(build_dir), str(p_ok)], tmp_path)
    assert rc4 == 0
    assert r4.status == pb.STATUS_VERIFIED
    b = _load_bindings(r4.artifacts.python_bindings_path, "wildcard_ok")
    assert b.s(b.Mode.Fast(30)) == 40
    assert b.s(b.Mode.Slow(7)) == 5
    assert b.s(b.Mode.Off()) == 5
    assert b.is_off(b.Mode.Off()) == 1
    assert b.is_off(b.Mode.Slow(2)) == 0


def test_sum_type_settlement_e2e_and_llvm_switch(tmp_path: Path) -> None:
    src = EXAMPLES / "sum_type_settlement.ail"
    rc_aud, r_aud = _run_cli_proto(["audit-spec", str(src)], tmp_path)
    assert rc_aud == 0
    assert r_aud.status == pb.STATUS_VERIFIED
    assert len(r_aud.spec_audits) == 3
    assert all(a.uniquely_tight and a.mutants_killed == a.mutants_tested == 4 for a in r_aud.spec_audits)

    out_dir = tmp_path / "settlement_build"
    rc_bld, r_bld = _run_cli_proto(["build", "--lib", "--require-tight-specs", "-o", str(out_dir), str(src)], tmp_path)
    assert rc_bld == 0
    assert "switch i64" in Path(r_bld.artifacts.llvm_ir_path).read_text()

    b = _load_bindings(r_bld.artifacts.python_bindings_path, "sum_type_settlement")
    assert b.outcome_notional(b.SettleOutcome.Cancelled()) == 0
    assert b.outcome_notional(b.make_fill(25, 400)) == 10_000
    assert b.outcome_notional(b.SettleOutcome.Partial(30, 10, 100)) == 3_000
    rej = b.make_rejected(-7)
    assert b.outcome_audit_score(rej) == -7
    assert b.is_rejected_outcome(rej) == 1
    assert b.is_rejected_outcome(b.make_fill(1, 2)) == 0


def test_repair_non_exhaustive_match(tmp_path: Path) -> None:
    broken = tmp_path / "broken_match.ail"
    broken.write_text(
        "(enum Ticket (Paid (amt u64[1..1000])) (Void))\n"
        "(fn val ((t Ticket)) u64[0..1000]\n"
        "  (match t ((Paid a) a)))\n"
    )
    sess = run_repair_session(broken, out_dir=tmp_path / "rep_out", max_iters=6, require_tight_specs=True)
    assert sess.final_status == pb.STATUS_VERIFIED
    assert any(st.triggered_code == pb.E_NON_EXHAUSTIVE_MATCH for st in sess.steps)
    b = _load_bindings(sess.artifacts.python_bindings_path, "repaired_match")
    assert b.val(b.Ticket.Paid(250)) == 250
    assert b.val(b.Ticket.Void()) == 0


def test_io_done_fflush_and_nested_cap_sequencing(tmp_path: Path) -> None:
    src = """
    (fn emit_and_flush ((io cap.io) (v u64[0..1000])) u64[0..0]
      (io.done (io.print_u64 io v) 0))
    """
    forms = parse_source(src)
    tenv = check_module_ownership_v2(forms)
    ModuleVerifier(tenv).verify_module(forms)
    art = compile_llvm_to_native(forms, tenv, tmp_path / "io_flush", "io_flush", build_shared_lib=True)

    driver = (
        f"import importlib.util; "
        f"sp = importlib.util.spec_from_file_location('iof', {art.python_bindings_path!r}); "
        f"m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m); "
        f"rc = m.emit_and_flush(42); print('RET=' + str(rc))"
    )
    lines = subprocess.check_output([sys.executable, "-c", driver], text=True).strip().splitlines()
    assert lines == ["42", "RET=0"]


def test_lang_bench_smoke(tmp_path: Path) -> None:
    report, md = run_language_benchmark(tmp_path / "lb", scalar_iters=20_000, simd_iters=1_000)
    assert len(report.kernels) == 5
    assert sum(r.ail_tokens for r in report.kernels) < sum(r.rust_tokens for r in report.kernels)
    assert all(r.ail_ns_per_op > 0.0 and r.rust_ns_per_op > 0.0 and r.c_ns_per_op > 0.0 for r in report.kernels)
    assert len(report.bug_firewall) == 5
    assert all(row.ail_caught_statically for row in report.bug_firewall)
    assert "CAUGHT" in md

    rt = pb.LanguageBenchmarkReport()
    rt.ParseFromString(report.SerializeToString())
    assert [r.kernel_name for r in rt.kernels] == [r.kernel_name for r in report.kernels]


def test_llm_bench_multiturn_self_repair(tmp_path: Path) -> None:
    valid_modules = {
        "signed_sensor_step": """
        (spec exact_sensor_step ((curr int) (base int)) (trunc_div (- curr base) 4))
        (fn sensor_step ((curr i64[-100000..100000]) (base i64[-100000..100000]))
          (out i64[-50000..50000] (== out (exact_sensor_step curr base)))
          (/ (- curr base) 4))
        """,
        "dependent_window_span": """
        (struct Window ((lo u64[0..1000000000]) (hi u64[lo..1000000000])))
        (fn make_win ((lo u64[0..999000000]) (width u64[0..1000000])) Window (make Window lo (+ lo width)))
        (spec exact_win_span ((w Window)) (- (field w hi) (field w lo)))
        (fn win_span ((w Window)) (out u64[0..1000000000] (== out (exact_win_span w)))
          (- (field w hi) (field w lo)))
        """,
        "enum_ticket_payout": """
        (enum Ticket
          (Won (stake u64[1..1000000]) (mult u64[1..1000]))
          (Refunded (stake u64[1..1000000]))
          (Void))
        (spec exact_ticket_payout ((t Ticket))
          (match t ((Won stake mult) (* stake mult)) ((Refunded stake) stake) ((Void) 0)))
        (fn ticket_payout ((t Ticket)) (out u64[0..1000000000] (== out (exact_ticket_payout t)))
          (match t ((Won stake mult) (* stake mult)) ((Refunded stake) stake) ((Void) 0)))
        """,
        "folded_energy_sum": """
        (fn sum_energy ((n u64[0..1000]) (readings (slice n u64[0..50000]))) u64[0..50000000]
          (fold (i n) (acc 0 u64[0..(* i 50000)]) (+ acc (get readings i))))
        """,
        "sandboxed_beacon": """
        (fn send_beacon ((io cap.io) (fs cap.fs) (net cap.net) (port u64[1024..65535]) (code u64[0..1000])) u64[0..0]
          (let ((io1 (io.print_u64 io code))
                (fs1 (fs.write_u64 fs code))
                (net1 (net.loopback_send_u64 net port code))
                (fdone (fs.close fs1))
                (ndone (net.close net1)))
            (io.done io1 0)))
        """,
    }

    def callback(task: LLMBenchTask, turn: int, _prev_src: str | None, prev_resp: pb.CompilerResponse | None) -> str:
        if task.task_id != "clamped_bps_rebate":
            return valid_modules[task.task_id]
        if turn == 1:
            return """
            (spec exact_clamped_rebate ((notional int) (bps int) (cap int))
              (min cap (/ (* notional bps) 10000)))
            (fn clamped_rebate ((notional u64[0..1000000000000000]) (bps u64[0..10000]) (cap u64[0..1000000000000000]))
              (out u64[0..1000000000000000] (== out (exact_clamped_rebate notional bps cap)))
              (min cap (/ (+ (* notional bps) 10000000000000000000) 10000)))
            """
        assert prev_resp is not None and prev_resp.diagnostics[0].code == pb.E_U64_OVERFLOW
        return """
        (spec exact_clamped_rebate ((notional int) (bps int) (cap int))
          (min cap (/ (* notional bps) 10000)))
        (fn clamped_rebate ((notional u64[0..1000000000000000]) (bps u64[0..10000]) (cap u64[0..1000000000000000]))
          (out u64[0..1000000000000000] (== out (exact_clamped_rebate notional bps cap)))
          (min cap (+ (* (/ notional 10000) bps) (/ (* (% notional 10000) bps) 10000))))
        """

    report, md = run_llm_benchmark(tmp_path / "llmb", provider="callback", model_name="sim", max_turns=4, llm_generator=callback)
    assert len(BENCHMARK_TASKS) == 6
    assert report.tasks_total == 6
    assert report.tasks_passed_turn1 == 5
    assert report.tasks_passed_final == 6
    by_id = {r.task_id: r for r in report.results}
    assert by_id["clamped_bps_rebate"].turns_used == 2
    assert pb.E_U64_OVERFLOW in by_id["clamped_bps_rebate"].triggered_errors
    assert "6/6" in md
