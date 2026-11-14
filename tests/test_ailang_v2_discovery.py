"""v0.2 Discovery Edition Test Suite: Signed `i64`, Dependent `struct`, `cap.fs`/`cap.net`, and `ail repair`."""

from __future__ import annotations
import importlib.util
import os
from pathlib import Path
import socket
import struct
import subprocess

from ailang import ail_agent_pb2 as pb
from ailang.agent_loop import run_repair_session
from ailang.cli import main as cli_main
from ailang.diagnostics import I64_MIN, ce_bindings_to_dict
from ailang.parser import module_to_proto, parse_source, proto_to_module

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"


def _run_cli_proto(args: list[str], tmp_path: Path) -> tuple[int, pb.CompilerResponse]:
    pb_out = tmp_path / "resp.pb"
    rc = cli_main(["--format", "proto", "--proto-out", str(pb_out), *args])
    resp = pb.CompilerResponse()
    resp.ParseFromString(pb_out.read_bytes())
    return rc, resp


def test_signed_i64_refinements_and_min_i64_trap(tmp_path: Path) -> None:
    # 1. Mixing `u64` and `i64` without explicit cast is rejected
    p_mix = tmp_path / "mix.ail"
    p_mix.write_text("(fn bad_mix ((u u64[0..10]) (s i64[-10..10])) i64[-10..20] (+ u s))\n")
    rc1, r1 = _run_cli_proto(["check", str(p_mix)], tmp_path)
    assert rc1 == 1
    assert r1.diagnostics[0].code == pb.E_TYPE_MISMATCH

    # 2. `(to_u64 s)` where `s` can be negative -> `E_U64_UNDERFLOW` with exact `i64_val` counterexample
    p_cast = tmp_path / "bad_to_u64.ail"
    p_cast.write_text("(fn bad_cast ((s i64[-50..50])) u64[0..50] (to_u64 s))\n")
    rc2, r2 = _run_cli_proto(["check", str(p_cast)], tmp_path)
    assert rc2 == 1
    assert r2.diagnostics[0].code == pb.E_U64_UNDERFLOW
    ce2 = ce_bindings_to_dict(list(r2.diagnostics[0].counterexample))
    assert ce2["s"] < 0
    assert any(b.WhichOneof("value") == "i64_val" and b.i64_val < 0 for b in r2.diagnostics[0].counterexample)

    # 3. `MIN_I64 / -1` hardware trap caught by Z3 (`E_I64_OVERFLOW`)
    p_div = tmp_path / "min_i64_trap.ail"
    p_div.write_text(
        "(fn bad_sdiv ((x i64[MIN_I64..MAX_I64]) (d i64[-5..5])) i64[MIN_I64..MAX_I64]\n"
        "  (if (== d 0) 0 (/ x d)))\n"
    )
    rc3, r3 = _run_cli_proto(["check", str(p_div)], tmp_path)
    assert rc3 == 1
    assert r3.diagnostics[0].code == pb.E_I64_OVERFLOW
    ce3 = ce_bindings_to_dict(list(r3.diagnostics[0].counterexample))
    assert ce3["x"] == I64_MIN
    assert ce3["d"] == -1

    # 4. Binary `ModuleProto` round-trips negative `i64_lit` losslessly
    forms = parse_source("(fn neg_const ((x i64[-500..-10])) i64[-1000..0] (+ x -250))\n")
    mp = module_to_proto(forms, "neg_test")
    restored = proto_to_module(pb.ModuleProto.FromString(mp.SerializeToString()))
    assert restored[0].raw() == forms[0].raw()


def test_dependent_struct_invariants_and_ctypes_ffi(tmp_path: Path) -> None:
    # 1. Constructing a `Quote` with `ask < bid` fails `E_STRUCT_INVARIANT_FAILED`
    p_bad_struct = tmp_path / "bad_quote.ail"
    p_bad_struct.write_text(
        "(struct Quote ((bid u64[0..1000]) (ask u64[bid..1000]) (pnl i64[-100..100])))\n"
        "(fn inverted ((b u64[100..500])) Quote (make Quote b (- b 1) 0))\n"
    )
    rc_b, r_b = _run_cli_proto(["check", str(p_bad_struct)], tmp_path)
    assert rc_b == 1
    assert r_b.diagnostics[0].code == pb.E_STRUCT_INVARIANT_FAILED

    # 2. `examples/signed_struct_quote.ail` passes SpecMut (`audit-spec`) and builds native ARM64 `.dylib`
    rc_a, r_a = _run_cli_proto(["audit-spec", str(EXAMPLES / "signed_struct_quote.ail")], tmp_path)
    assert rc_a == 0
    assert len(r_a.spec_audits) == 3
    assert all(au.uniquely_tight and au.mutants_killed == au.mutants_tested for au in r_a.spec_audits)

    out_dir = tmp_path / "quote_lib"
    rc_lib, resp_lib = _run_cli_proto(
        ["build", "--lib", "--require-tight-specs", str(EXAMPLES / "signed_struct_quote.ail"), "-o", str(out_dir)],
        tmp_path,
    )
    assert rc_lib == 0
    ll_text = Path(resp_lib.artifacts.llvm_ir_path).read_text()
    assert "%struct.Quote = type { i64, i64, i64 }" in ll_text
    assert "add nsw i64" in ll_text
    assert "sdiv i64" in ll_text

    # 3. Execute compiled `.dylib` via auto-generated Python `ctypes.Structure` bindings!
    spec = importlib.util.spec_from_file_location("quote_bindings", resp_lib.artifacts.python_bindings_path)
    assert spec and spec.loader
    qb = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(qb)

    q = qb.build_quote(100_000, 250, -300)
    assert isinstance(q, qb.Quote)
    assert (q.bid, q.ask, q.pnl_adj) == (100_000, 100_250, -300)
    assert qb.quote_spread(q) == 250
    assert qb.quote_net_mid(q) == 100_125 - 300  # 99,825
    assert qb.scale_signed_pnl(-77) == -7  # Exact C/LLVM truncation-toward-zero!


def test_linear_fs_and_loopback_net_capabilities(tmp_path: Path) -> None:
    # 1. Privileged port (< 1024) and invalid port (> 65535) statically rejected by Z3
    p_priv = tmp_path / "bad_port.ail"
    p_priv.write_text(
        "(main ((net cap.net)) u64[0..0]\n"
        "  (let ((n1 (net.loopback_send_u64 net 80 42)))\n"
        "    (net.close n1)))\n"
    )
    rc_p, r_p = _run_cli_proto(["check", str(p_priv)], tmp_path)
    assert rc_p == 1
    assert r_p.diagnostics[0].code == pb.E_PRECONDITION_FAILED

    # 2. Cross-capability misuse (`io` passed to `fs.write_u64`) rejected by ownership checker
    p_wrong_cap = tmp_path / "wrong_cap.ail"
    p_wrong_cap.write_text(
        "(main ((io cap.io)) u64[0..0]\n"
        "  (let ((f1 (fs.write_u64 io 42)))\n"
        "    (io.done io 0)))\n"
    )
    rc_w, r_w = _run_cli_proto(["check", str(p_wrong_cap)], tmp_path)
    assert rc_w == 1
    assert r_w.diagnostics[0].code == pb.E_CAPABILITY_MISSING

    # 3. End-to-end native execution of `cap.io` + `cap.fs` + `127.0.0.1` UDP `cap.net`!
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
        udp_sock.bind(("127.0.0.1", 0))
        udp_sock.settimeout(3.0)
        ephemeral_port = udp_sock.getsockname()[1]

        live_cli = tmp_path / "live_sandbox.ail"
        live_cli.write_text(
            "(main ((io cap.io) (fs cap.fs) (net cap.net)) u64[0..0]\n"
            "  (let ((io1 (io.print_u64 io 200))\n"
            "        (io2 (io.print_i64 io1 -250))\n"
            "        (fs1 (fs.write_u64 fs 200))\n"
            "        (fs2 (fs.write_i64 fs1 -250))\n"
            "        (fc (fs.close fs2))\n"
            f"        (net1 (net.loopback_send_u64 net {ephemeral_port} 987654321012345))\n"
            "        (nc (net.close net1)))\n"
            "    (io.done io2 0)))\n"
        )
        build_dir = tmp_path / "sandbox_bin"
        rc_b, resp_b = _run_cli_proto(["build", str(live_cli), "-o", str(build_dir)], tmp_path)
        assert rc_b == 0

        fs_log = tmp_path / "sandbox_audit.log"
        env = dict(os.environ, AIL_FS_OUT=str(fs_log))
        out = subprocess.check_output([resp_b.artifacts.binary_or_lib_path], env=env, text=True)
        assert out.strip().splitlines() == ["200", "-250"]
        assert fs_log.read_text().strip().splitlines() == ["200", "-250"]

        pkt, sender = udp_sock.recvfrom(64)
        assert sender[0] == "127.0.0.1"
        assert len(pkt) == 8
        assert struct.unpack("<Q", pkt)[0] == 987654321012345


def test_closed_loop_agent_repair_harness_and_protobuf_session(tmp_path: Path) -> None:
    # 1. Autonomous multi-turn repair of `examples/broken_agent_draft.ail` -> verified native `.dylib`
    sess_pb = tmp_path / "repair_session.pb"
    fixed_ail = tmp_path / "fixed_draft.ail"
    fixed_ast = tmp_path / "fixed_draft.ail.pb"
    out_dir = tmp_path / "repaired_lib"

    rc = cli_main(
        [
            "--format",
            "proto",
            "--proto-out",
            str(sess_pb),
            "repair",
            str(EXAMPLES / "broken_agent_draft.ail"),
            "-o",
            str(out_dir),
            "--write-fixed",
            str(fixed_ail),
            "--write-ast",
            str(fixed_ast),
            "--max-iters",
            "12",
        ]
    )
    assert rc == 0
    sess = pb.RepairSession()
    sess.ParseFromString(sess_pb.read_bytes())
    assert sess.final_status == pb.STATUS_VERIFIED
    assert sess.iterations >= 5
    triggered_codes = {step.triggered_code for step in sess.steps}
    assert pb.E_LINEAR_USE_AFTER_MOVE in triggered_codes
    assert pb.E_U64_OVERFLOW in triggered_codes
    assert pb.E_U64_UNDERFLOW in triggered_codes
    assert pb.E_SPEC_MUTANT_SURVIVED in triggered_codes

    # Verify the emitted binary `.ail.pb` AST passes strict `audit-spec` with 0 surviving mutants!
    rc_audit, resp_audit = _run_cli_proto(["audit-spec", str(fixed_ast)], tmp_path)
    assert rc_audit == 0
    assert all(au.uniquely_tight for au in resp_audit.spec_audits)

    # Load repaired `.dylib` and test edge inputs that previously overflowed/underflowed!
    spec = importlib.util.spec_from_file_location("rep_bindings", sess.artifacts.python_bindings_path)
    assert spec and spec.loader
    rb = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rb)

    assert rb.midpoint_draft(1 << 63, (1 << 63) + 20) == (1 << 63) + 10
    assert rb.fee_net_draft(2_000_000_000_000_000, 500) == 1_900_000_000_000_000
    assert rb.rebate_sub_draft(100, 250) == 0

    # 2. Pluggable external LLM callback over `pb.CompilerResponse`
    calls: list[int] = []

    def mock_agent_llm(cur_src: str, resp: pb.CompilerResponse) -> str:
        calls.append(resp.diagnostics[0].code)
        return (
            "(spec spec_dbl ((x int)) (* x 2))\n"
            "(fn dbl ((x u64[0..1000])) (out u64[0..2000] (== out (spec_dbl x))) (* x 2))\n"
        )

    cb_sess = run_repair_session(
        "(fn dbl ((x u64[0..MAX])) u64[0..MAX] (* x 2))\n",
        llm_callback=mock_agent_llm,
    )
    assert cb_sess.final_status == pb.STATUS_VERIFIED
    assert calls == [pb.E_U64_OVERFLOW]
