"""Rust Target Backend Tests: `#![no_std]`, `#![forbid(unsafe_code)]`, `.rlib` & Binary Driver Execution."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

from ailang.codegen_rust import RustArtifacts, compile_to_rust
from ailang.modules import load_ail_module_with_imports
from ailang.ownership import check_module_ownership_v2
from ailang.parser import parse_source
from ailang.verifier import ModuleVerifier

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"


def _rustc_bin() -> str:
    return shutil.which("rustc") or str(Path.home() / ".cargo" / "bin" / "rustc")


def _compile_and_run_rust_driver(
    work_dir: Path,
    crate_name: str,
    rlib_path: str,
    driver_src: str,
) -> str:
    driver_rs = work_dir / f"{crate_name}_driver.rs"
    driver_exe = work_dir / f"{crate_name}_driver"
    driver_rs.write_text(driver_src)
    subprocess.run(
        [
            _rustc_bin(),
            "--edition",
            "2021",
            "-D",
            "warnings",
            str(driver_rs),
            "--extern",
            f"{crate_name}={rlib_path}",
            "-o",
            str(driver_exe),
        ],
        check=True,
    )
    return subprocess.check_output([str(driver_exe)], text=True).strip()


def _verify_and_compile_rust(src: str, out_dir: Path, module_name: str, verify_rustc: bool = True) -> RustArtifacts:
    forms = parse_source(src)
    tenv = check_module_ownership_v2(forms)
    ModuleVerifier(tenv).verify_module(forms)
    return compile_to_rust(forms, tenv, out_dir, module_name=module_name, verify_rustc=verify_rustc)


def test_rust_financial_kernel_rlib_and_driver(tmp_path: Path) -> None:
    crate_dir = tmp_path / "financial_kernel_crate"
    art = _verify_and_compile_rust(
        (EXAMPLES / "financial_kernel.ail").read_text(),
        crate_dir,
        module_name="financial_kernel",
    )

    assert Path(art.crate_dir) == crate_dir
    assert Path(art.cargo_toml_path).exists()
    assert Path(art.lib_rs_path).exists()
    assert Path(art.rlib_path).exists()

    cargo_toml = Path(art.cargo_toml_path).read_text()
    assert 'edition = "2021"' in cargo_toml
    assert 'crate-type = ["rlib"]' in cargo_toml

    lib_rs = Path(art.lib_rs_path).read_text()
    assert "#![no_std]" in lib_rs
    assert "#![forbid(unsafe_code)]" in lib_rs
    assert "AilHostCaps" not in lib_rs
    assert ".wrapping_add(" in lib_rs

    driver = r"""
extern crate financial_kernel;
use financial_kernel::{
    aligned_fee_packet, batch_cap_sum, halve_bonus_inplace, midpoint, settle_net,
};

fn main() {
    assert_eq!(midpoint(1u64 << 63, (1u64 << 63) + 100), (1u64 << 63) + 50);
    assert_eq!(midpoint(u64::MAX - 2, u64::MAX), u64::MAX - 1);

    let net = settle_net(2_000_000_000_000_000, 9500, 2_000_000_000_000_000);
    assert_eq!(net, 100_000_000_000_000);

    let net2 = settle_net(1_000_000, 250, 50_000);
    assert_eq!(net2, 975_000);

    let pkt = aligned_fee_packet(1_000_000, 250, 50_000);
    let expected_aligned = (975_000u64 + 63) & !63;
    let expected_shard = (975_000u64 >> 6) & 8191;
    assert_eq!(pkt, expected_aligned + expected_shard);

    let mut arr = [0u64; 16];
    for (i, slot) in arr.iter_mut().enumerate() {
        *slot = (i as u64) * 1000;
    }
    halve_bonus_inplace(16, 250, 5000, &mut arr);
    assert_eq!(arr[0], 250);
    assert_eq!(arr[4], 2250);
    assert_eq!(arr[15], 5000);
    assert_eq!(batch_cap_sum(16, &arr), arr.iter().copied().sum::<u64>());
    println!("FINANCIAL_OK");
}
"""
    out = _compile_and_run_rust_driver(tmp_path, "financial_kernel", art.rlib_path, driver)
    assert out == "FINANCIAL_OK"


def test_rust_signed_struct_quote_rlib_and_driver(tmp_path: Path) -> None:
    art = _verify_and_compile_rust(
        (EXAMPLES / "signed_struct_quote.ail").read_text(),
        tmp_path / "signed_struct_quote_crate",
        module_name="signed_struct_quote",
    )
    lib_rs = Path(art.lib_rs_path).read_text()
    assert "#[derive(Debug, Clone, Copy, PartialEq, Eq)]" in lib_rs
    assert "pub struct Quote" in lib_rs

    driver = r"""
extern crate signed_struct_quote;
use signed_struct_quote::{build_quote, quote_net_mid, quote_spread, scale_signed_pnl, Quote};

fn main() {
    let q: Quote = build_quote(100_000, 250, -300);
    assert_eq!(q, Quote { bid: 100_000, ask: 100_250, pnl_adj: -300 });
    let q_copy = q;
    assert_eq!(q_copy.bid, 100_000);
    assert_eq!(quote_spread(q), 250);
    assert_eq!(quote_net_mid(q), 99_825);
    assert_eq!(scale_signed_pnl(-77), -7);
    assert_eq!(scale_signed_pnl(99), 9);
    println!("QUOTE_OK");
}
"""
    out = _compile_and_run_rust_driver(tmp_path, "signed_struct_quote", art.rlib_path, driver)
    assert out == "QUOTE_OK"


def test_rust_sum_type_settlement_rlib_and_driver(tmp_path: Path) -> None:
    art = _verify_and_compile_rust(
        (EXAMPLES / "sum_type_settlement.ail").read_text(),
        tmp_path / "sum_type_settlement_crate",
        module_name="sum_type_settlement",
    )
    lib_rs = Path(art.lib_rs_path).read_text()
    assert "#[derive(Debug, Clone, Copy, PartialEq, Eq)]" in lib_rs
    assert "pub enum SettleOutcome" in lib_rs
    assert "match o" in lib_rs

    driver = r"""
extern crate sum_type_settlement;
use sum_type_settlement::{
    is_rejected_outcome, make_fill, make_rejected, outcome_audit_score, outcome_notional,
    SettleOutcome,
};

fn main() {
    let f = make_fill(25, 400);
    assert_eq!(f, SettleOutcome::Filled(25, 400));
    assert_eq!(outcome_notional(f), 10_000);
    assert_eq!(outcome_audit_score(f), 25);
    assert_eq!(is_rejected_outcome(f), 0);

    let p = SettleOutcome::Partial(30, 10, 100);
    assert_eq!(outcome_notional(p), 3_000);
    assert_eq!(outcome_audit_score(p), 30);
    assert_eq!(is_rejected_outcome(p), 0);

    let r = make_rejected(-7);
    assert_eq!(r, SettleOutcome::Rejected(-7));
    assert_eq!(outcome_notional(r), 0);
    assert_eq!(outcome_audit_score(r), -7);
    assert_eq!(is_rejected_outcome(r), 1);

    let c = SettleOutcome::Cancelled;
    assert_eq!(outcome_notional(c), 0);
    assert_eq!(outcome_audit_score(c), 0);
    assert_eq!(is_rejected_outcome(c), 0);
    println!("SETTLEMENT_OK");
}
"""
    out = _compile_and_run_rust_driver(tmp_path, "sum_type_settlement", art.rlib_path, driver)
    assert out == "SETTLEMENT_OK"


def test_rust_bytes_parser_rlib_and_driver(tmp_path: Path) -> None:
    src = """
(enum FrameResult
  (Ping (seq_num u64[0..4294967295]))
  (Transfer (flags u64[0..255]) (payload_len u64[0..65535]) (amount u64[0..MAX]))
  (BadFrame (code u64[1..10])))

(fn has_magic ((n u64[4..4096]) (buf (bytes n))) u64[0..1]
  (bytes_eq4 buf 0 65 73 76 49))

(fn parse_wire_frame ((n u64[0..4096]) (buf (bytes n))) FrameResult
  (if (< n 16)
    (variant FrameResult BadFrame 1)
    (if (== (call has_magic n buf) 0)
      (variant FrameResult BadFrame 2)
      (let ((tag (byte_at buf 4))
            (flags (byte_at buf 5))
            (plen (read_u16_be buf 6)))
        (if (== tag 1)
          (variant FrameResult Ping (read_u32_be buf 8))
          (if (== tag 2)
            (variant FrameResult Transfer flags plen (read_u64_be buf 8))
            (variant FrameResult BadFrame 3)))))))

(fn frame_checksum ((f FrameResult)) u64[0..MAX]
  (match f
    ((Ping s) s)
    ((Transfer fl ln amt) (+ (+ fl ln) (min amt 1000000000000000000)))
    (_ 0)))
"""
    art = _verify_and_compile_rust(src, tmp_path / "wire_parser_crate", module_name="wire_parser")
    lib_rs = Path(art.lib_rs_path).read_text()
    assert "#![no_std]" in lib_rs
    assert "#![forbid(unsafe_code)]" in lib_rs
    assert "buf: &[u8]" in lib_rs

    driver = r"""
extern crate wire_parser;
use wire_parser::{frame_checksum, has_magic, parse_wire_frame, FrameResult};

fn main() {
    let mut ping = [0u8; 16];
    ping[0..4].copy_from_slice(b"AIL1");
    ping[4] = 1;
    ping[8..12].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    assert_eq!(has_magic(ping.len() as u64, &ping), 1);
    let p_res = parse_wire_frame(ping.len() as u64, &ping);
    assert_eq!(p_res, FrameResult::Ping(0xDEAD_BEEF));
    assert_eq!(frame_checksum(p_res), 0xDEAD_BEEF);

    let mut xfer = [0u8; 16];
    xfer[0..4].copy_from_slice(b"AIL1");
    xfer[4] = 2;
    xfer[5] = 0x5A;
    xfer[6..8].copy_from_slice(&512u16.to_be_bytes());
    xfer[8..16].copy_from_slice(&123_456_789_012_345u64.to_be_bytes());
    let x_res = parse_wire_frame(xfer.len() as u64, &xfer);
    assert_eq!(x_res, FrameResult::Transfer(0x5A, 512, 123_456_789_012_345));
    assert_eq!(frame_checksum(x_res), 0x5A + 512 + 123_456_789_012_345);

    let short = [65u8, 73, 76, 49];
    assert_eq!(parse_wire_frame(4, &short), FrameResult::BadFrame(1));
    assert_eq!(frame_checksum(FrameResult::BadFrame(1)), 0);

    let mut bad_magic = [0u8; 16];
    bad_magic[0..4].copy_from_slice(b"NOPE");
    assert_eq!(parse_wire_frame(16, &bad_magic), FrameResult::BadFrame(2));
    println!("BYTES_OK");
}
"""
    out = _compile_and_run_rust_driver(tmp_path, "wire_parser", art.rlib_path, driver)
    assert out == "BYTES_OK"


def test_rust_capabilities_trait_atomics_and_i64_slices(tmp_path: Path) -> None:
    # 1. Capability-gated module emits `pub trait AilHostCaps` and safe `ail_main`
    art_cap = _verify_and_compile_rust(
        (EXAMPLES / "capability_sandbox_cli.ail").read_text(),
        tmp_path / "cap_sandbox_crate",
        module_name="cap_sandbox",
    )
    cap_lib = Path(art_cap.lib_rs_path).read_text()
    assert "pub trait AilHostCaps" in cap_lib
    assert "#![no_std]" in cap_lib
    assert "#![forbid(unsafe_code)]" in cap_lib

    cap_driver = r"""
extern crate cap_sandbox;
use cap_sandbox::{ail_main, AilHostCaps};

#[derive(Default)]
struct MockHost {
    io_u: Vec<u64>,
    io_i: Vec<i64>,
    fs_u: Vec<u64>,
    fs_i: Vec<i64>,
    net: Vec<(u64, u64)>,
    closed_io: bool,
    closed_fs: bool,
    closed_net: bool,
}

impl AilHostCaps for MockHost {
    fn io_print_u64(&mut self, val: u64) { self.io_u.push(val); }
    fn io_print_i64(&mut self, val: i64) { self.io_i.push(val); }
    fn io_done(&mut self) { self.closed_io = true; }
    fn fs_write_u64(&mut self, val: u64) { self.fs_u.push(val); }
    fn fs_write_i64(&mut self, val: i64) { self.fs_i.push(val); }
    fn fs_close(&mut self) { self.closed_fs = true; }
    fn net_loopback_send_u64(&mut self, port: u64, payload: u64) { self.net.push((port, payload)); }
    fn net_close(&mut self) { self.closed_net = true; }
}

fn main() {
    let mut host = MockHost::default();
    let rc = ail_main(&mut host);
    assert_eq!(rc, 0);
    assert_eq!(host.io_u, vec![200]);
    assert_eq!(host.io_i, vec![99_750]);
    assert_eq!(host.fs_u, vec![200]);
    assert_eq!(host.fs_i, vec![99_750]);
    assert_eq!(host.net, vec![(49152, 200)]);
    assert!(host.closed_io && host.closed_fs && host.closed_net);
    println!("CAPS_OK");
}
"""
    assert _compile_and_run_rust_driver(tmp_path, "cap_sandbox", art_cap.rlib_path, cap_driver) == "CAPS_OK"

    # 2. Lock-free atomic CAS using safe `core::sync::atomic::AtomicU64`
    art_atom = _verify_and_compile_rust(
        (EXAMPLES / "lockfree_vault.ail").read_text(),
        tmp_path / "vault_crate",
        module_name="lockfree_vault",
    )
    atom_driver = r"""
extern crate lockfree_vault;
use core::sync::atomic::{AtomicU64, Ordering};
use lockfree_vault::cas_withdraw;

fn main() {
    let vault = AtomicU64::new(1000);
    assert_eq!(cas_withdraw(&vault, 400), 1);
    assert_eq!(vault.load(Ordering::SeqCst), 600);
    assert_eq!(cas_withdraw(&vault, 700), 0);
    assert_eq!(vault.load(Ordering::SeqCst), 600);
    println!("ATOMIC_OK");
}
"""
    assert _compile_and_run_rust_driver(tmp_path, "lockfree_vault", art_atom.rlib_path, atom_driver) == "ATOMIC_OK"

    # 3. Signed i64 slices, `map_inplace` on `i64`, and `verify_rustc=False`
    signed_src = """
(fn sum_signed ((n u64[0..1000]) (xs (slice n i64[-1000..1000]))) i64[-1000000..1000000]
  (fold (i n) (acc 0 i64[(* -1000 i)..(* 1000 i)])
    (+ acc (to_i64 (get xs i)))))

(map_inplace clamp_signed_inplace
  ((n u64[0..1000]) (lo i64[-100..0]) (hi i64[0..100]) (xs (mut_slice n i64[-1000..1000])))
  i64[-100..100]
  (el)
  (min hi (max lo el)))
"""
    art_no_rc = _verify_and_compile_rust(signed_src, tmp_path / "signed_no_rc", "signed-test", verify_rustc=False)
    assert art_no_rc.rlib_path == ""
    assert Path(art_no_rc.lib_rs_path).exists()

    art_signed = _verify_and_compile_rust(signed_src, tmp_path / "signed_rc", "signed-test", verify_rustc=True)
    signed_driver = r"""
extern crate signed_test;
use signed_test::{clamp_signed_inplace, sum_signed};

fn main() {
    let mut xs = [-500i64, -20, 0, 45, 999];
    assert_eq!(sum_signed(5, &xs), 524);
    clamp_signed_inplace(5, -50, 50, &mut xs);
    assert_eq!(xs, [-50, -20, 0, 45, 50]);
    println!("SIGNED_SLICE_OK");
}
"""
    assert _compile_and_run_rust_driver(tmp_path, "signed_test", art_signed.rlib_path, signed_driver) == "SIGNED_SLICE_OK"


def test_rust_v1_examples_with_stdlib_imports_and_drivers(tmp_path: Path) -> None:
    # 1. `examples/wire_frame_parser.ail` (stdlib/parse import + const + zero-field BadMagic variant)
    wire_forms = load_ail_module_with_imports(EXAMPLES / "wire_frame_parser.ail")
    wire_tenv = check_module_ownership_v2(wire_forms)
    ModuleVerifier(wire_tenv).verify_module(wire_forms)
    art_wire = compile_to_rust(
        wire_forms,
        wire_tenv,
        tmp_path / "wire_v1_crate",
        module_name="wire_frame_parser",
        verify_rustc=True,
    )
    wire_driver = r"""
extern crate wire_frame_parser;
use wire_frame_parser::{frame_result_seq, parse_frame, read_frame_u64_payload, FrameResult};

fn main() {
    let short = [0u8; 4];
    assert_eq!(parse_frame(4, &short), FrameResult::Truncated(4, 8));

    let bad_magic = [b'N', b'O', b'P', b'E', 1, 0, 0, 4, 0, 0, 0, 1];
    assert_eq!(parse_frame(12, &bad_magic), FrameResult::BadMagic);
    assert_eq!(frame_result_seq(FrameResult::BadMagic), 0);

    let bad_ver = [b'A', b'I', b'L', b'1', 2, 0, 0, 4, 0, 0, 0, 1];
    assert_eq!(parse_frame(12, &bad_ver), FrameResult::UnsupportedVersion(2));

    let mut valid = [0u8; 16];
    valid[0..4].copy_from_slice(b"AIL1");
    valid[4] = 1;
    valid[5] = 0x7F;
    valid[6..8].copy_from_slice(&4u16.to_be_bytes());
    valid[8..12].copy_from_slice(&99_887_766u32.to_be_bytes());
    let parsed = parse_frame(16, &valid);
    assert_eq!(parsed, FrameResult::Valid(1, 0x7F, 4, 99_887_766));
    assert_eq!(frame_result_seq(parsed), 99_887_766);

    let mut u64_frame = [0u8; 16];
    u64_frame[8..16].copy_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
    assert_eq!(read_frame_u64_payload(16, &u64_frame), 0x0102_0304_0506_0708);
    println!("WIRE_V1_OK");
}
"""
    assert _compile_and_run_rust_driver(tmp_path, "wire_frame_parser", art_wire.rlib_path, wire_driver) == "WIRE_V1_OK"

    # 2. `examples/defi_waterfall_v1.ail` (stdlib/finance + stdlib/math imports + const + Quote2Way)
    defi_forms = load_ail_module_with_imports(EXAMPLES / "defi_waterfall_v1.ail")
    defi_tenv = check_module_ownership_v2(defi_forms)
    ModuleVerifier(defi_tenv).verify_module(defi_forms)
    art_defi = compile_to_rust(
        defi_forms,
        defi_tenv,
        tmp_path / "defi_v1_crate",
        module_name="defi_waterfall_v1",
        verify_rustc=True,
    )
    defi_driver = r"""
extern crate defi_waterfall_v1;
use defi_waterfall_v1::{
    pool_quote_health_check, share_price_ceil_per_unit, waterfall_junior_payout, Quote2Way,
};

fn main() {
    assert_eq!(waterfall_junior_payout(100_000, 90_000, 200, 1_000), 9_800);
    assert_eq!(share_price_ceil_per_unit(0, 100), 0);
    assert_eq!(share_price_ceil_per_unit(101, 10), 11);
    let q = Quote2Way { bid: 10_000, ask: 10_025 };
    assert_eq!(pool_quote_health_check(q, 50_000, 10, 100), 25 + 50);
    println!("DEFI_V1_OK");
}
"""
    assert _compile_and_run_rust_driver(tmp_path, "defi_waterfall_v1", art_defi.rlib_path, defi_driver) == "DEFI_V1_OK"


def test_rust_fold_bound_shadowing_regression(tmp_path: Path) -> None:
    src = """
(fn fold_shadow_bound ((x u64[0..100])) u64[0..10000]
  (fold (i x) (x 0 u64[0..(* i 100)])
    (+ x i)))
"""
    art = _verify_and_compile_rust(src, tmp_path / "fold_shadow_crate", module_name="fold_shadow")
    driver = r"""
extern crate fold_shadow;
use fold_shadow::fold_shadow_bound;

fn main() {
    assert_eq!(fold_shadow_bound(0), 0);
    assert_eq!(fold_shadow_bound(5), 10);
    println!("FOLD_SHADOW_OK");
}
"""
    assert _compile_and_run_rust_driver(tmp_path, "fold_shadow", art.rlib_path, driver) == "FOLD_SHADOW_OK"
