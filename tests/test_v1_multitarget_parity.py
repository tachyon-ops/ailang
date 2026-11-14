"""End-to-End Multi-Target Bit-Exact Parity Test Suite (Native LLVM, WASM, ISO C11, Safe Rust)."""

from __future__ import annotations

import ctypes
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys

from ailang import __version__
from ailang import ail_agent_pb2 as pb
from ailang.cli import main as cli_main

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
U64_MAX = (1 << 64) - 1
EXT = ".dylib" if platform.system() == "Darwin" else ".so"
RUSTC_BIN = shutil.which("rustc") or str(Path.home() / ".cargo" / "bin" / "rustc")


def _run_cli_proto(args: list[str], proto_path: Path) -> tuple[int, pb.CompilerResponse]:
    rc = cli_main(["--format", "proto", "--proto-out", str(proto_path), *args])
    resp = pb.CompilerResponse()
    resp.ParseFromString(proto_path.read_bytes())
    return rc, resp


def _load_py_module(py_path: Path, mod_name: str):
    spec = importlib.util.spec_from_file_location(mod_name, str(py_path))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def _run_node_json(script: str) -> dict:
    proc = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(f"Node ESM failed ({proc.returncode}):\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
    return json.loads(proc.stdout.strip())


def _run_rust_driver_json(work_dir: Path, crate_name: str, rlib_path: Path, driver_src: str) -> dict:
    rs_path = work_dir / f"{crate_name}_parity_driver.rs"
    exe_path = work_dir / f"{crate_name}_parity_driver"
    rs_path.write_text(driver_src, encoding="utf-8")
    subprocess.run(
        [
            RUSTC_BIN,
            "--edition",
            "2021",
            "-D",
            "warnings",
            str(rs_path),
            "--extern",
            f"{crate_name}={rlib_path}",
            "-o",
            str(exe_path),
        ],
        check=True,
    )
    out = subprocess.check_output([str(exe_path)], text=True).strip()
    return json.loads(out)


def _build_all_targets(example_name: str, out_dir: Path, tmp_path: Path) -> dict[str, Path]:
    src_path = EXAMPLES / example_name
    stem = src_path.stem
    rc, resp = _run_cli_proto(
        ["build", "--target", "all", str(src_path), "-o", str(out_dir)],
        tmp_path / f"{stem}_build.pb",
    )
    assert rc == 0, f"Build failed for {example_name}: {resp.diagnostics}"
    assert resp.status == pb.STATUS_VERIFIED

    native_dir = out_dir / "native"
    wasm_dir = out_dir / "wasm"
    c_dir = out_dir / "c"
    rust_dir = out_dir / "rust"

    paths = {
        "native_lib": native_dir / f"lib{stem}{EXT}",
        "native_py": native_dir / f"{stem}_bindings.py",
        "native_h": native_dir / f"{stem}.h",
        "wasm_bin": wasm_dir / f"{stem}.wasm",
        "wasm_mjs": wasm_dir / f"{stem}.mjs",
        "wasm_wat": wasm_dir / f"{stem}.wat",
        "wasm_dts": wasm_dir / f"{stem}.d.ts",
        "c_src": c_dir / f"{stem}.c",
        "c_h": c_dir / f"{stem}.h",
        "c_lib": c_dir / f"lib{stem}{EXT}",
        "rust_lib_rs": rust_dir / "src" / "lib.rs",
        "rust_cargo": rust_dir / "Cargo.toml",
        "rust_rlib": rust_dir / f"lib{stem}.rlib",
    }
    for key, p in paths.items():
        assert p.exists(), f"Missing {key} at {p}"

    lib_rs = paths["rust_lib_rs"].read_text(encoding="utf-8")
    assert "#![no_std]" in lib_rs
    assert "#![forbid(unsafe_code)]" in lib_rs
    return paths


def test_parity_financial_kernel_all_4_targets(tmp_path: Path) -> None:
    p = _build_all_targets("financial_kernel.ail", tmp_path / "fk_all", tmp_path)

    # (a) Native LLVM .dylib
    nv = _load_py_module(p["native_py"], "parity_fk_native")
    nv_arr = (ctypes.c_uint64 * 16)(*[1000 * i for i in range(16)])
    nv.halve_bonus_inplace(16, 250, 5000, nv_arr)
    native_res = {
        "mid_hi": str(nv.midpoint(1 << 63, (1 << 63) + 100)),
        "mid_max": str(nv.midpoint(U64_MAX - 10, U64_MAX)),
        "settle_big": str(nv.settle_net(2_000_000_000_000_000, 9500, 2_000_000_000_000_000)),
        "settle_cap": str(nv.settle_net(2_000_000_000_000_000, 9500, 1_000_000_000)),
        "pkt": str(nv.aligned_fee_packet(1_000_000, 250, 50_000)),
        "arr": [str(nv_arr[i]) for i in range(16)],
        "cap_sum": str(nv.batch_cap_sum(16, nv_arr)),
        "empty_sum": str(nv.batch_cap_sum(0, nv_arr)),
    }

    # (c) ISO C11 .dylib
    clib = ctypes.CDLL(str(p["c_lib"]))
    clib.midpoint.argtypes = [ctypes.c_uint64, ctypes.c_uint64]
    clib.midpoint.restype = ctypes.c_uint64
    clib.settle_net.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64]
    clib.settle_net.restype = ctypes.c_uint64
    clib.aligned_fee_packet.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64]
    clib.aligned_fee_packet.restype = ctypes.c_uint64
    clib.halve_bonus_inplace.argtypes = [
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.POINTER(ctypes.c_uint64),
    ]
    clib.halve_bonus_inplace.restype = None
    clib.batch_cap_sum.argtypes = [ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64)]
    clib.batch_cap_sum.restype = ctypes.c_uint64

    c_arr = (ctypes.c_uint64 * 16)(*[1000 * i for i in range(16)])
    clib.halve_bonus_inplace(16, 250, 5000, c_arr)
    c_res = {
        "mid_hi": str(clib.midpoint(1 << 63, (1 << 63) + 100)),
        "mid_max": str(clib.midpoint(U64_MAX - 10, U64_MAX)),
        "settle_big": str(clib.settle_net(2_000_000_000_000_000, 9500, 2_000_000_000_000_000)),
        "settle_cap": str(clib.settle_net(2_000_000_000_000_000, 9500, 1_000_000_000)),
        "pkt": str(clib.aligned_fee_packet(1_000_000, 250, 50_000)),
        "arr": [str(c_arr[i]) for i in range(16)],
        "cap_sum": str(clib.batch_cap_sum(16, c_arr)),
        "empty_sum": str(clib.batch_cap_sum(0, c_arr)),
    }

    # (b) WASM via Node.js .mjs
    wasm_res = _run_node_json(
        f"""
import assert from "node:assert/strict";
import fs from "node:fs";
import * as fk from {p['wasm_mjs'].as_uri()!r};

assert.equal(WebAssembly.validate(fs.readFileSync({str(p['wasm_bin'])!r})), true);
const arr = new BigUint64Array(16);
for (let i = 0; i < 16; i++) arr[i] = BigInt(1000 * i);
fk.halve_bonus_inplace(16n, 250n, 5000n, arr);
const u64Max = (1n << 64n) - 1n;
console.log(JSON.stringify({{
  mid_hi: fk.midpoint(1n << 63n, (1n << 63n) + 100n).toString(),
  mid_max: fk.midpoint(u64Max - 10n, u64Max).toString(),
  settle_big: fk.settle_net(2_000_000_000_000_000n, 9500n, 2_000_000_000_000_000n).toString(),
  settle_cap: fk.settle_net(2_000_000_000_000_000n, 9500n, 1_000_000_000n).toString(),
  pkt: fk.aligned_fee_packet(1_000_000n, 250n, 50_000n).toString(),
  arr: Array.from(arr, (x) => x.toString()),
  cap_sum: fk.batch_cap_sum(16n, arr).toString(),
  empty_sum: fk.batch_cap_sum(0n, arr).toString(),
}}));
"""
    )

    # (d) Safe Rust .rlib
    rust_res = _run_rust_driver_json(
        tmp_path,
        "financial_kernel",
        p["rust_rlib"],
        r"""
extern crate financial_kernel;
use financial_kernel::{aligned_fee_packet, batch_cap_sum, halve_bonus_inplace, midpoint, settle_net};

fn main() {
    let mut arr = [0u64; 16];
    for (i, slot) in arr.iter_mut().enumerate() {
        *slot = (i as u64) * 1000;
    }
    halve_bonus_inplace(16, 250, 5000, &mut arr);
    let arr_json: Vec<String> = arr.iter().map(|v| format!("\"{}\"", v)).collect();
    println!(
        "{{\"mid_hi\":\"{}\",\"mid_max\":\"{}\",\"settle_big\":\"{}\",\"settle_cap\":\"{}\",\"pkt\":\"{}\",\"arr\":[{}],\"cap_sum\":\"{}\",\"empty_sum\":\"{}\"}}",
        midpoint(1u64 << 63, (1u64 << 63) + 100),
        midpoint(u64::MAX - 10, u64::MAX),
        settle_net(2_000_000_000_000_000, 9500, 2_000_000_000_000_000),
        settle_net(2_000_000_000_000_000, 9500, 1_000_000_000),
        aligned_fee_packet(1_000_000, 250, 50_000),
        arr_json.join(","),
        batch_cap_sum(16, &arr),
        batch_cap_sum(0, &arr),
    );
}
""",
    )

    assert native_res == wasm_res == c_res == rust_res
    assert native_res["mid_hi"] == str((1 << 63) + 50)
    assert native_res["mid_max"] == str(U64_MAX - 5)


def test_parity_signed_struct_quote_all_4_targets(tmp_path: Path) -> None:
    p = _build_all_targets("signed_struct_quote.ail", tmp_path / "quote_all", tmp_path)

    # (a) Native LLVM
    nv = _load_py_module(p["native_py"], "parity_quote_native")
    nq1 = nv.build_quote(100_000, 250, -300)
    nq2 = nv.build_quote(999_990_000, 10_000, -50_000)
    native_res = {
        "q1": [nq1.bid, nq1.ask, nq1.pnl_adj],
        "spread1": nv.quote_spread(nq1),
        "mid1": nv.quote_net_mid(nq1),
        "spread2": nv.quote_spread(nq2),
        "mid2": nv.quote_net_mid(nq2),
        "pnl_neg": nv.scale_signed_pnl(-77),
        "pnl_small": nv.scale_signed_pnl(-9),
        "pnl_pos": nv.scale_signed_pnl(100_005),
    }

    # (c) ISO C11
    class CQuote(ctypes.Structure):
        _fields_ = [
            ("bid", ctypes.c_uint64),
            ("ask", ctypes.c_uint64),
            ("pnl_adj", ctypes.c_int64),
        ]

    clib = ctypes.CDLL(str(p["c_lib"]))
    clib.build_quote.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int64, ctypes.POINTER(CQuote)]
    clib.build_quote.restype = None
    clib.quote_spread.argtypes = [ctypes.POINTER(CQuote)]
    clib.quote_spread.restype = ctypes.c_uint64
    clib.quote_net_mid.argtypes = [ctypes.POINTER(CQuote)]
    clib.quote_net_mid.restype = ctypes.c_int64
    clib.scale_signed_pnl.argtypes = [ctypes.c_int64]
    clib.scale_signed_pnl.restype = ctypes.c_int64

    cq1, cq2 = CQuote(), CQuote()
    clib.build_quote(100_000, 250, -300, ctypes.byref(cq1))
    clib.build_quote(999_990_000, 10_000, -50_000, ctypes.byref(cq2))
    c_res = {
        "q1": [cq1.bid, cq1.ask, cq1.pnl_adj],
        "spread1": clib.quote_spread(ctypes.byref(cq1)),
        "mid1": clib.quote_net_mid(ctypes.byref(cq1)),
        "spread2": clib.quote_spread(ctypes.byref(cq2)),
        "mid2": clib.quote_net_mid(ctypes.byref(cq2)),
        "pnl_neg": clib.scale_signed_pnl(-77),
        "pnl_small": clib.scale_signed_pnl(-9),
        "pnl_pos": clib.scale_signed_pnl(100_005),
    }

    # (b) WASM
    wasm_res = _run_node_json(
        f"""
import assert from "node:assert/strict";
import fs from "node:fs";
import * as qb from {p['wasm_mjs'].as_uri()!r};

assert.equal(WebAssembly.validate(fs.readFileSync({str(p['wasm_bin'])!r})), true);
const q1 = qb.build_quote(100_000n, 250n, -300n);
const q2 = qb.build_quote(999_990_000n, 10_000n, -50_000n);
console.log(JSON.stringify({{
  q1: [Number(q1.bid), Number(q1.ask), Number(q1.pnl_adj)],
  spread1: Number(qb.quote_spread(q1)),
  mid1: Number(qb.quote_net_mid(q1)),
  spread2: Number(qb.quote_spread(q2)),
  mid2: Number(qb.quote_net_mid(q2)),
  pnl_neg: Number(qb.scale_signed_pnl(-77n)),
  pnl_small: Number(qb.scale_signed_pnl(-9n)),
  pnl_pos: Number(qb.scale_signed_pnl(100_005n)),
}}));
"""
    )

    # (d) Rust
    rust_res = _run_rust_driver_json(
        tmp_path,
        "signed_struct_quote",
        p["rust_rlib"],
        r"""
extern crate signed_struct_quote;
use signed_struct_quote::{build_quote, quote_net_mid, quote_spread, scale_signed_pnl};

fn main() {
    let q1 = build_quote(100_000, 250, -300);
    let q2 = build_quote(999_990_000, 10_000, -50_000);
    println!(
        "{{\"q1\":[{},{},{}],\"spread1\":{},\"mid1\":{},\"spread2\":{},\"mid2\":{},\"pnl_neg\":{},\"pnl_small\":{},\"pnl_pos\":{}}}",
        q1.bid, q1.ask, q1.pnl_adj,
        quote_spread(q1), quote_net_mid(q1),
        quote_spread(q2), quote_net_mid(q2),
        scale_signed_pnl(-77), scale_signed_pnl(-9), scale_signed_pnl(100_005),
    );
}
""",
    )

    assert native_res == wasm_res == c_res == rust_res
    assert native_res["mid1"] == 99_825
    assert native_res["pnl_neg"] == -7


def test_parity_sum_type_settlement_all_4_targets(tmp_path: Path) -> None:
    p = _build_all_targets("sum_type_settlement.ail", tmp_path / "settle_all", tmp_path)

    # (a) Native LLVM
    nv = _load_py_module(p["native_py"], "parity_settle_native")
    n_fill = nv.make_fill(25, 400)
    n_part = nv.SettleOutcome.Partial(30, 10, 100)
    n_rej = nv.make_rejected(-7)
    n_can = nv.SettleOutcome.Cancelled()
    native_res = {
        "fill": [nv.outcome_notional(n_fill), nv.outcome_audit_score(n_fill), nv.is_rejected_outcome(n_fill)],
        "partial": [nv.outcome_notional(n_part), nv.outcome_audit_score(n_part), nv.is_rejected_outcome(n_part)],
        "rejected": [nv.outcome_notional(n_rej), nv.outcome_audit_score(n_rej), nv.is_rejected_outcome(n_rej)],
        "cancelled": [nv.outcome_notional(n_can), nv.outcome_audit_score(n_can), nv.is_rejected_outcome(n_can)],
    }

    # (c) ISO C11
    class CSettle(ctypes.Structure):
        _fields_ = [
            ("tag", ctypes.c_uint64),
            ("_p0", ctypes.c_uint64),
            ("_p1", ctypes.c_uint64),
            ("_p2", ctypes.c_uint64),
        ]

    clib = ctypes.CDLL(str(p["c_lib"]))
    clib.make_fill.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.POINTER(CSettle)]
    clib.make_fill.restype = None
    clib.make_rejected.argtypes = [ctypes.c_int64, ctypes.POINTER(CSettle)]
    clib.make_rejected.restype = None
    clib.outcome_notional.argtypes = [ctypes.POINTER(CSettle)]
    clib.outcome_notional.restype = ctypes.c_uint64
    clib.outcome_audit_score.argtypes = [ctypes.POINTER(CSettle)]
    clib.outcome_audit_score.restype = ctypes.c_int64
    clib.is_rejected_outcome.argtypes = [ctypes.POINTER(CSettle)]
    clib.is_rejected_outcome.restype = ctypes.c_uint64

    c_fill, c_rej = CSettle(), CSettle()
    clib.make_fill(25, 400, ctypes.byref(c_fill))
    clib.make_rejected(-7, ctypes.byref(c_rej))
    c_part = CSettle(tag=1, _p0=30, _p1=10, _p2=100)
    c_can = CSettle(tag=3)
    c_res = {
        "fill": [clib.outcome_notional(ctypes.byref(c_fill)), clib.outcome_audit_score(ctypes.byref(c_fill)), clib.is_rejected_outcome(ctypes.byref(c_fill))],
        "partial": [clib.outcome_notional(ctypes.byref(c_part)), clib.outcome_audit_score(ctypes.byref(c_part)), clib.is_rejected_outcome(ctypes.byref(c_part))],
        "rejected": [clib.outcome_notional(ctypes.byref(c_rej)), clib.outcome_audit_score(ctypes.byref(c_rej)), clib.is_rejected_outcome(ctypes.byref(c_rej))],
        "cancelled": [clib.outcome_notional(ctypes.byref(c_can)), clib.outcome_audit_score(ctypes.byref(c_can)), clib.is_rejected_outcome(ctypes.byref(c_can))],
    }

    # (b) WASM
    wasm_res = _run_node_json(
        f"""
import assert from "node:assert/strict";
import fs from "node:fs";
import * as st from {p['wasm_mjs'].as_uri()!r};

assert.equal(WebAssembly.validate(fs.readFileSync({str(p['wasm_bin'])!r})), true);
const fill = st.make_fill(25n, 400n);
const part = st.SettleOutcome.Partial(30n, 10n, 100n);
const rej = st.make_rejected(-7n);
const can = st.SettleOutcome.Cancelled();
console.log(JSON.stringify({{
  fill: [Number(st.outcome_notional(fill)), Number(st.outcome_audit_score(fill)), Number(st.is_rejected_outcome(fill))],
  partial: [Number(st.outcome_notional(part)), Number(st.outcome_audit_score(part)), Number(st.is_rejected_outcome(part))],
  rejected: [Number(st.outcome_notional(rej)), Number(st.outcome_audit_score(rej)), Number(st.is_rejected_outcome(rej))],
  cancelled: [Number(st.outcome_notional(can)), Number(st.outcome_audit_score(can)), Number(st.is_rejected_outcome(can))],
}}));
"""
    )

    # (d) Rust
    rust_res = _run_rust_driver_json(
        tmp_path,
        "sum_type_settlement",
        p["rust_rlib"],
        r"""
extern crate sum_type_settlement;
use sum_type_settlement::{
    is_rejected_outcome, make_fill, make_rejected, outcome_audit_score, outcome_notional, SettleOutcome,
};

fn eval(o: SettleOutcome) -> String {
    format!("[{},{},{}]", outcome_notional(o), outcome_audit_score(o), is_rejected_outcome(o))
}

fn main() {
    let f = make_fill(25, 400);
    let p = SettleOutcome::Partial(30, 10, 100);
    let r = make_rejected(-7);
    let c = SettleOutcome::Cancelled;
    println!(
        "{{\"fill\":{},\"partial\":{},\"rejected\":{},\"cancelled\":{}}}",
        eval(f), eval(p), eval(r), eval(c),
    );
}
""",
    )

    assert native_res == wasm_res == c_res == rust_res
    assert native_res["fill"] == [10_000, 25, 0]
    assert native_res["rejected"] == [0, -7, 1]


def test_parity_wire_frame_parser_all_4_targets(tmp_path: Path) -> None:
    p = _build_all_targets("wire_frame_parser.ail", tmp_path / "wire_all", tmp_path)

    valid_frame = b"AIL1\x01\x2a\x00\x0c\x12\x34\x56\x78\xaa\xbb\xcc\xdd\xee\xff\x00\x11"
    msb_frame = b"AIL1\x01\xff\x00\x08\xfe\xdc\xba\x98\x76\x54\x32\x10"
    short_frame = b"AIL1"
    bad_magic = b"NOPE\x01\x00\x00\x04\x00\x00\x00\x01"
    bad_ver = b"AIL1\x02\x00\x00\x04\x00\x00\x00\x01"
    trunc_payload = b"AIL1\x01\x00\x00\x20\x00\x00\x00\x01"
    small_plen = b"AIL1\x01\x00\x00\x03\x00\x00\x00\x01"

    # (a) Native LLVM
    nv = _load_py_module(p["native_py"], "parity_wire_native")
    r_valid = nv.parse_frame(len(valid_frame), valid_frame)
    r_short = nv.parse_frame(len(short_frame), short_frame)
    r_magic = nv.parse_frame(len(bad_magic), bad_magic)
    r_ver = nv.parse_frame(len(bad_ver), bad_ver)
    r_trunc = nv.parse_frame(len(trunc_payload), trunc_payload)
    r_small = nv.parse_frame(len(small_plen), small_plen)
    native_res = {
        "has_magic_ok": nv.has_ail_magic(len(valid_frame), valid_frame),
        "has_magic_bad": nv.has_ail_magic(len(bad_magic), bad_magic),
        "ver_byte": nv.frame_version_byte(len(valid_frame), valid_frame),
        "plen": nv.frame_payload_len_u16(len(valid_frame), valid_frame),
        "valid": [r_valid.tag, r_valid.field(0), r_valid.field(1), r_valid.field(2), r_valid.field(3)],
        "valid_seq": nv.frame_result_seq(r_valid),
        "u64_payload": str(nv.read_frame_u64_payload(len(valid_frame), valid_frame)),
        "u64_msb": str(nv.read_frame_u64_payload(len(msb_frame), msb_frame)),
        "short": [r_short.tag, r_short.field(0), r_short.field(1)],
        "bad_magic": [r_magic.tag, nv.frame_result_seq(r_magic)],
        "bad_ver": [r_ver.tag, r_ver.field(0)],
        "trunc_payload": [r_trunc.tag, r_trunc.field(0), r_trunc.field(1)],
        "small_plen": [r_small.tag, r_small.field(0), r_small.field(1)],
    }

    # (c) ISO C11
    class CFrameResult(ctypes.Structure):
        _fields_ = [
            ("tag", ctypes.c_uint64),
            ("_p0", ctypes.c_uint64),
            ("_p1", ctypes.c_uint64),
            ("_p2", ctypes.c_uint64),
            ("_p3", ctypes.c_uint64),
        ]

    clib = ctypes.CDLL(str(p["c_lib"]))
    for fn in ("has_ail_magic", "frame_version_byte", "frame_payload_len_u16", "read_frame_u64_payload"):
        f = getattr(clib, fn)
        f.argtypes = [ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint8)]
        f.restype = ctypes.c_uint64
    clib.parse_frame.argtypes = [ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(CFrameResult)]
    clib.parse_frame.restype = None
    clib.frame_result_seq.argtypes = [ctypes.POINTER(CFrameResult)]
    clib.frame_result_seq.restype = ctypes.c_uint64

    def _cbuf(data: bytes):
        return (ctypes.c_uint8 * len(data))(*data)

    def _c_parse(data: bytes) -> CFrameResult:
        out = CFrameResult()
        clib.parse_frame(len(data), _cbuf(data), ctypes.byref(out))
        return out

    cv = _c_parse(valid_frame)
    cs = _c_parse(short_frame)
    cm = _c_parse(bad_magic)
    cver = _c_parse(bad_ver)
    ct = _c_parse(trunc_payload)
    csm = _c_parse(small_plen)
    c_res = {
        "has_magic_ok": clib.has_ail_magic(len(valid_frame), _cbuf(valid_frame)),
        "has_magic_bad": clib.has_ail_magic(len(bad_magic), _cbuf(bad_magic)),
        "ver_byte": clib.frame_version_byte(len(valid_frame), _cbuf(valid_frame)),
        "plen": clib.frame_payload_len_u16(len(valid_frame), _cbuf(valid_frame)),
        "valid": [cv.tag, cv._p0, cv._p1, cv._p2, cv._p3],
        "valid_seq": clib.frame_result_seq(ctypes.byref(cv)),
        "u64_payload": str(clib.read_frame_u64_payload(len(valid_frame), _cbuf(valid_frame))),
        "u64_msb": str(clib.read_frame_u64_payload(len(msb_frame), _cbuf(msb_frame))),
        "short": [cs.tag, cs._p0, cs._p1],
        "bad_magic": [cm.tag, clib.frame_result_seq(ctypes.byref(cm))],
        "bad_ver": [cver.tag, cver._p0],
        "trunc_payload": [ct.tag, ct._p0, ct._p1],
        "small_plen": [csm.tag, csm._p0, csm._p1],
    }

    # (b) WASM
    wasm_res = _run_node_json(
        f"""
import assert from "node:assert/strict";
import fs from "node:fs";
import * as wf from {p['wasm_mjs'].as_uri()!r};

assert.equal(WebAssembly.validate(fs.readFileSync({str(p['wasm_bin'])!r})), true);
const b = (arr) => new Uint8Array(arr);
const valid = b({list(valid_frame)});
const msb = b({list(msb_frame)});
const shortF = b({list(short_frame)});
const badMagic = b({list(bad_magic)});
const badVer = b({list(bad_ver)});
const truncP = b({list(trunc_payload)});
const smallP = b({list(small_plen)});

const rv = wf.parse_frame(valid.length, valid);
const rs = wf.parse_frame(shortF.length, shortF);
const rm = wf.parse_frame(badMagic.length, badMagic);
const rver = wf.parse_frame(badVer.length, badVer);
const rt = wf.parse_frame(truncP.length, truncP);
const rsm = wf.parse_frame(smallP.length, smallP);

console.log(JSON.stringify({{
  has_magic_ok: Number(wf.has_ail_magic(valid.length, valid)),
  has_magic_bad: Number(wf.has_ail_magic(badMagic.length, badMagic)),
  ver_byte: Number(wf.frame_version_byte(valid.length, valid)),
  plen: Number(wf.frame_payload_len_u16(valid.length, valid)),
  valid: [rv.tag, Number(rv.field(0)), Number(rv.field(1)), Number(rv.field(2)), Number(rv.field(3))],
  valid_seq: Number(wf.frame_result_seq(rv)),
  u64_payload: wf.read_frame_u64_payload(valid.length, valid).toString(),
  u64_msb: wf.read_frame_u64_payload(msb.length, msb).toString(),
  short: [rs.tag, Number(rs.field(0)), Number(rs.field(1))],
  bad_magic: [rm.tag, Number(wf.frame_result_seq(rm))],
  bad_ver: [rver.tag, Number(rver.field(0))],
  trunc_payload: [rt.tag, Number(rt.field(0)), Number(rt.field(1))],
  small_plen: [rsm.tag, Number(rsm.field(0)), Number(rsm.field(1))],
}}));
"""
    )

    # (d) Rust
    rust_res = _run_rust_driver_json(
        tmp_path,
        "wire_frame_parser",
        p["rust_rlib"],
        f"""
extern crate wire_frame_parser;
use wire_frame_parser::{{
    frame_payload_len_u16, frame_result_seq, frame_version_byte, has_ail_magic,
    parse_frame, read_frame_u64_payload, FrameResult,
}};

fn tag_of(r: FrameResult) -> u64 {{
    match r {{
        FrameResult::Valid(..) => 0,
        FrameResult::BadMagic => 1,
        FrameResult::UnsupportedVersion(..) => 2,
        FrameResult::Truncated(..) => 3,
    }}
}}

fn main() {{
    let valid: &[u8] = &{list(valid_frame)!r};
    let msb: &[u8] = &{list(msb_frame)!r};
    let short_f: &[u8] = &{list(short_frame)!r};
    let bad_magic: &[u8] = &{list(bad_magic)!r};
    let bad_ver: &[u8] = &{list(bad_ver)!r};
    let trunc_p: &[u8] = &{list(trunc_payload)!r};
    let small_p: &[u8] = &{list(small_plen)!r};

    let rv = parse_frame(valid.len() as u64, valid);
    let FrameResult::Valid(v0, v1, v2, v3) = rv else {{ panic!("expected Valid") }};
    let rs = parse_frame(short_f.len() as u64, short_f);
    let FrameResult::Truncated(sa, sn) = rs else {{ panic!("expected Truncated") }};
    let rm = parse_frame(bad_magic.len() as u64, bad_magic);
    let rver = parse_frame(bad_ver.len() as u64, bad_ver);
    let FrameResult::UnsupportedVersion(vf) = rver else {{ panic!("expected UnsupportedVersion") }};
    let rt = parse_frame(trunc_p.len() as u64, trunc_p);
    let FrameResult::Truncated(ta, tn) = rt else {{ panic!("expected Truncated") }};
    let rsm = parse_frame(small_p.len() as u64, small_p);
    let FrameResult::Truncated(ma, mn) = rsm else {{ panic!("expected Truncated") }};

    println!(
        "{{{{
            \\"has_magic_ok\\":{{}},\\"has_magic_bad\\":{{}},\\"ver_byte\\":{{}},\\"plen\\":{{}},
            \\"valid\\":[{{}},{{}},{{}},{{}},{{}}],\\"valid_seq\\":{{}},
            \\"u64_payload\\":\\"{{}}\\",\\"u64_msb\\":\\"{{}}\\",
            \\"short\\":[{{}},{{}},{{}}],\\"bad_magic\\":[{{}},{{}}],\\"bad_ver\\":[{{}},{{}}],
            \\"trunc_payload\\":[{{}},{{}},{{}}],\\"small_plen\\":[{{}},{{}},{{}}]
        }}}}",
        has_ail_magic(valid.len() as u64, valid),
        has_ail_magic(bad_magic.len() as u64, bad_magic),
        frame_version_byte(valid.len() as u64, valid),
        frame_payload_len_u16(valid.len() as u64, valid),
        tag_of(rv), v0, v1, v2, v3,
        frame_result_seq(rv),
        read_frame_u64_payload(valid.len() as u64, valid),
        read_frame_u64_payload(msb.len() as u64, msb),
        tag_of(rs), sa, sn,
        tag_of(rm), frame_result_seq(rm),
        tag_of(rver), vf,
        tag_of(rt), ta, tn,
        tag_of(rsm), ma, mn,
    );
}}
""",
    )

    assert native_res == wasm_res == c_res == rust_res
    assert native_res["u64_msb"] == str(0xFEDCBA9876543210)
    assert native_res["valid"] == [0, 1, 0x2A, 12, 0x12345678]


def test_parity_defi_waterfall_v1_all_4_targets(tmp_path: Path) -> None:
    p = _build_all_targets("defi_waterfall_v1.ail", tmp_path / "defi_all", tmp_path)

    # (a) Native LLVM
    nv = _load_py_module(p["native_py"], "parity_defi_native")
    nq = nv.Quote2Way(bid=100_000, ask=100_250)
    native_res = {
        "junior_1": str(nv.waterfall_junior_payout(10_000_000, 3_000_000, 250, 2000)),
        "junior_zero": str(nv.waterfall_junior_payout(1_000_000, 5_000_000, 500, 1000)),
        "junior_0": str(nv.waterfall_junior_payout(0, 0, 0, 0)),
        "ceil_0": str(nv.share_price_ceil_per_unit(0, 100)),
        "ceil_rem": str(nv.share_price_ceil_per_unit(101, 10)),
        "ceil_exact": str(nv.share_price_ceil_per_unit(100, 10)),
        "health": str(nv.pool_quote_health_check(nq, 5_000_000, 50, 20_000)),
        "sat_add": str(nv.sat_add_u64(U64_MAX - 5, 100)),
        "sat_sub": str(nv.sat_sub_u64(10, 50)),
        "midpoint_hi": str(nv.midpoint_u64((1 << 63) + 100, 1 << 63)),
    }

    # (c) ISO C11
    class CQuote2Way(ctypes.Structure):
        _fields_ = [("bid", ctypes.c_uint64), ("ask", ctypes.c_uint64)]

    clib = ctypes.CDLL(str(p["c_lib"]))
    clib.waterfall_junior_payout.argtypes = [ctypes.c_uint64] * 4
    clib.waterfall_junior_payout.restype = ctypes.c_uint64
    clib.share_price_ceil_per_unit.argtypes = [ctypes.c_uint64, ctypes.c_uint64]
    clib.share_price_ceil_per_unit.restype = ctypes.c_uint64
    clib.pool_quote_health_check.argtypes = [ctypes.POINTER(CQuote2Way), ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64]
    clib.pool_quote_health_check.restype = ctypes.c_uint64
    clib.sat_add_u64.argtypes = [ctypes.c_uint64, ctypes.c_uint64]
    clib.sat_add_u64.restype = ctypes.c_uint64
    clib.sat_sub_u64.argtypes = [ctypes.c_uint64, ctypes.c_uint64]
    clib.sat_sub_u64.restype = ctypes.c_uint64
    clib.midpoint_u64.argtypes = [ctypes.c_uint64, ctypes.c_uint64]
    clib.midpoint_u64.restype = ctypes.c_uint64

    cq = CQuote2Way(bid=100_000, ask=100_250)
    c_res = {
        "junior_1": str(clib.waterfall_junior_payout(10_000_000, 3_000_000, 250, 2000)),
        "junior_zero": str(clib.waterfall_junior_payout(1_000_000, 5_000_000, 500, 1000)),
        "junior_0": str(clib.waterfall_junior_payout(0, 0, 0, 0)),
        "ceil_0": str(clib.share_price_ceil_per_unit(0, 100)),
        "ceil_rem": str(clib.share_price_ceil_per_unit(101, 10)),
        "ceil_exact": str(clib.share_price_ceil_per_unit(100, 10)),
        "health": str(clib.pool_quote_health_check(ctypes.byref(cq), 5_000_000, 50, 20_000)),
        "sat_add": str(clib.sat_add_u64(U64_MAX - 5, 100)),
        "sat_sub": str(clib.sat_sub_u64(10, 50)),
        "midpoint_hi": str(clib.midpoint_u64((1 << 63) + 100, 1 << 63)),
    }

    # (b) WASM
    wasm_res = _run_node_json(
        f"""
import assert from "node:assert/strict";
import fs from "node:fs";
import * as df from {p['wasm_mjs'].as_uri()!r};

assert.equal(WebAssembly.validate(fs.readFileSync({str(p['wasm_bin'])!r})), true);
const q = df.Quote2Way(100_000n, 100_250n);
const u64Max = (1n << 64n) - 1n;
console.log(JSON.stringify({{
  junior_1: df.waterfall_junior_payout(10_000_000n, 3_000_000n, 250n, 2000n).toString(),
  junior_zero: df.waterfall_junior_payout(1_000_000n, 5_000_000n, 500n, 1000n).toString(),
  junior_0: df.waterfall_junior_payout(0n, 0n, 0n, 0n).toString(),
  ceil_0: df.share_price_ceil_per_unit(0n, 100n).toString(),
  ceil_rem: df.share_price_ceil_per_unit(101n, 10n).toString(),
  ceil_exact: df.share_price_ceil_per_unit(100n, 10n).toString(),
  health: df.pool_quote_health_check(q, 5_000_000n, 50n, 20_000n).toString(),
  sat_add: df.sat_add_u64(u64Max - 5n, 100n).toString(),
  sat_sub: df.sat_sub_u64(10n, 50n).toString(),
  midpoint_hi: df.midpoint_u64((1n << 63n) + 100n, 1n << 63n).toString(),
}}));
"""
    )

    # (d) Rust
    rust_res = _run_rust_driver_json(
        tmp_path,
        "defi_waterfall_v1",
        p["rust_rlib"],
        r"""
extern crate defi_waterfall_v1;
use defi_waterfall_v1::{
    midpoint_u64, pool_quote_health_check, sat_add_u64, sat_sub_u64,
    share_price_ceil_per_unit, waterfall_junior_payout, Quote2Way,
};

fn main() {
    let q = Quote2Way { bid: 100_000, ask: 100_250 };
    println!(
        "{{\"junior_1\":\"{}\",\"junior_zero\":\"{}\",\"junior_0\":\"{}\",\"ceil_0\":\"{}\",\"ceil_rem\":\"{}\",\"ceil_exact\":\"{}\",\"health\":\"{}\",\"sat_add\":\"{}\",\"sat_sub\":\"{}\",\"midpoint_hi\":\"{}\"}}",
        waterfall_junior_payout(10_000_000, 3_000_000, 250, 2000),
        waterfall_junior_payout(1_000_000, 5_000_000, 500, 1000),
        waterfall_junior_payout(0, 0, 0, 0),
        share_price_ceil_per_unit(0, 100),
        share_price_ceil_per_unit(101, 10),
        share_price_ceil_per_unit(100, 10),
        pool_quote_health_check(q, 5_000_000, 50, 20_000),
        sat_add_u64(u64::MAX - 5, 100),
        sat_sub_u64(10, 50),
        midpoint_u64((1u64 << 63) + 100, 1u64 << 63),
    );
}
""",
    )

    assert native_res == wasm_res == c_res == rust_res
    assert native_res["junior_1"] == "6950000"
    assert native_res["health"] == "20025"
    assert native_res["sat_add"] == str(U64_MAX)


def test_v1_cli_commands_imports_pb_and_studio_regen(tmp_path: Path) -> None:
    assert __version__ == "1.0.0"

    # 1. `ail stdlib`
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        assert cli_main(["stdlib"]) == 0
    stdlib_out = buf.getvalue()
    for mod_name in ("stdlib/bits", "stdlib/finance", "stdlib/math", "stdlib/parse"):
        assert mod_name in stdlib_out

    # 2. Import cycle rejected by `ail check` with E_IMPORT_CYCLE
    mod_a = tmp_path / "cycle_a.ail"
    mod_b = tmp_path / "cycle_b.ail"
    mod_a.write_text('(import "cycle_b")\n(fn fa ((x u64[0..10])) u64[0..10] x)\n', encoding="utf-8")
    mod_b.write_text('(import "cycle_a")\n(fn fb ((x u64[0..10])) u64[0..10] x)\n', encoding="utf-8")
    rc_cyc, resp_cyc = _run_cli_proto(["check", str(mod_a)], tmp_path / "cyc.pb")
    assert rc_cyc == 1
    assert resp_cyc.diagnostics[0].code == pb.E_IMPORT_CYCLE

    # 3. Binary `.ail.pb` round-trip with multi-target `ail build --target all`
    pb_src = tmp_path / "defi.ail.pb"
    with contextlib.redirect_stdout(io.StringIO()):
        assert cli_main(["encode-ast", str(EXAMPLES / "defi_waterfall_v1.ail"), "-o", str(pb_src)]) == 0
    rc_pb, resp_pb = _run_cli_proto(
        ["build", "--target", "all", str(pb_src), "-o", str(tmp_path / "pb_out")],
        tmp_path / "pb_resp.pb",
    )
    assert rc_pb == 0
    assert resp_pb.status == pb.STATUS_VERIFIED
    assert (tmp_path / "pb_out" / "wasm" / "defi.wasm").exists()
    assert (tmp_path / "pb_out" / "c" / "defi.c").exists()
    assert (tmp_path / "pb_out" / "rust" / "libdefi.rlib").exists()

    # 4. Individual `--target wasm|c|rust` + `ail studio --regenerate-demos --out ...`
    with contextlib.redirect_stdout(io.StringIO()):
        assert cli_main(["build", "--target", "wasm", str(EXAMPLES / "signed_struct_quote.ail"), "-o", str(tmp_path / "single_wasm")]) == 0
    assert (tmp_path / "single_wasm" / "signed_struct_quote.wasm").exists()

    demos_out = tmp_path / "demos_check.json"
    with contextlib.redirect_stdout(io.StringIO()):
        assert cli_main(["studio", "--regenerate-demos", "--out", str(demos_out)]) == 0
    demos = json.loads(demos_out.read_text(encoding="utf-8"))
    assert demos["version"] == "1.0.0"
    assert len(demos["presets"]) >= 5

    # 5. `audit-spec` & `build --target all --require-tight-specs` on import-using `defi_waterfall_v1.ail`
    rc_aud, resp_aud = _run_cli_proto(
        ["audit-spec", str(EXAMPLES / "defi_waterfall_v1.ail")],
        tmp_path / "defi_aud.pb",
    )
    assert rc_aud == 0 and resp_aud.status == pb.STATUS_VERIFIED
    assert resp_aud.spec_audits and all(a.uniquely_tight for a in resp_aud.spec_audits)

    # 6. `ail run` on `(main ...)` module importing `stdlib/math` and using `(const ...)`
    run_src = tmp_path / "run_with_import.ail"
    run_src.write_text(
        '(import "stdlib/math")\n'
        "(const OFFSET u64 25)\n"
        "(main ((io cap.io)) u64[0..0]\n"
        "  (let ((v (call sat_add_u64 100 OFFSET))\n"
        "        (io1 (io.print_u64 io v)))\n"
        "    (io.done io1 0)))\n",
        encoding="utf-8",
    )
    proc_run = subprocess.run(
        [sys.executable, "-m", "ailang.cli", "run", str(run_src), "-o", str(tmp_path / "run_bin")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc_run.returncode == 0
    assert proc_run.stdout.strip().splitlines()[-1] == "125"

    # 7. `ail repair` on broken module importing `stdlib/math`
    rep_src = tmp_path / "broken_with_import.ail"
    rep_src.write_text(
        '(import "stdlib/math")\n'
        "(const CAP u64 1000)\n"
        "(fn clamped_mid ((lo u64[0..MAX]) (hi u64[lo..MAX])) u64[0..CAP]\n"
        "  (call clamp_u64 (/ (+ lo hi) 2) 0 CAP))\n",
        encoding="utf-8",
    )
    rep_pb = tmp_path / "rep_sess.pb"
    rc_rep = cli_main(["--format", "proto", "--proto-out", str(rep_pb), "repair", str(rep_src), "--no-tight-specs"])
    assert rc_rep == 0
    sess = pb.RepairSession()
    sess.ParseFromString(rep_pb.read_bytes())
    assert sess.final_status == pb.STATUS_VERIFIED

    # 8. `ail mcp` stdio JSON-RPC initialize + tools/list smoke check
    init_req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    list_req = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    proc_mcp = subprocess.run(
        [sys.executable, "-m", "ailang.cli", "mcp"],
        input=f"{init_req}\n{list_req}\n",
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc_mcp.returncode == 0
    mcp_lines = [json.loads(line) for line in proc_mcp.stdout.strip().splitlines() if line.strip()]
    assert len(mcp_lines) == 2
    assert mcp_lines[0]["result"]["serverInfo"]["name"] == "ailang-mcp"
    tool_names = {t["name"] for t in mcp_lines[1]["result"]["tools"]}
    assert {"ail_check_and_prove", "ail_compile_target", "ail_stdlib_catalog"}.issubset(tool_names)
