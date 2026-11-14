"""Comprehensive Pure-Python WebAssembly 1.0 Target Tests (Node.js `WebAssembly.validate` + `.mjs` execution)."""

from __future__ import annotations
import json
from pathlib import Path
import subprocess

from ailang.codegen_wasm import WasmArtifacts, compile_to_wasm
from ailang.modules import load_ail_module_with_imports
from ailang.ownership import check_module_ownership_v2
from ailang.parser import parse_source
from ailang.verifier import ModuleVerifier

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"


def _compile_verified_wasm(
    src_or_path: Path | str, out_dir: Path, module_name: str, *, with_imports: bool = False
) -> WasmArtifacts:
    if with_imports:
        forms = load_ail_module_with_imports(src_or_path)
    else:
        src = src_or_path.read_text() if isinstance(src_or_path, Path) else src_or_path
        forms = parse_source(src)
    tenv = check_module_ownership_v2(forms)
    ModuleVerifier(tenv).verify_module(forms)
    art = compile_to_wasm(forms, tenv, out_dir, module_name=module_name)

    wasm_bytes = Path(art.wasm_path).read_bytes()
    assert wasm_bytes[:8] == b"\x00asm\x01\x00\x00\x00"
    assert art.wasm_size_bytes == len(wasm_bytes)
    assert Path(art.wat_path).exists()
    assert Path(art.js_wrapper_path).exists()
    assert Path(art.ts_dts_path).exists()
    return art


def _run_node_esm(script: str) -> str:
    proc = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise AssertionError(f"Node ESM exited {proc.returncode}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
    return proc.stdout


def test_wasm_financial_kernel_u64_fold_slice_and_map_inplace(tmp_path: Path) -> None:
    art = _compile_verified_wasm(EXAMPLES / "financial_kernel.ail", tmp_path / "fin", "financial_kernel")
    wat_text = Path(art.wat_path).read_text()
    dts_text = Path(art.ts_dts_path).read_text()
    assert '(memory (export "memory") 1)' in wat_text
    assert "i64.div_u" in wat_text
    assert "i64.rem_u" in wat_text
    assert "i64.shr_u" in wat_text
    assert "export const midpoint:" in dts_text

    # Includes >2^53 u64 midpoint, >64KiB slice triggering memory.grow, and mut_slice in-place mutation
    node_script = f"""
import assert from "node:assert/strict";
import fs from "node:fs";
import * as fk from {Path(art.js_wrapper_path).as_uri()!r};

const rawBytes = fs.readFileSync({art.wasm_path!r});
assert.equal(WebAssembly.validate(rawBytes), true);

const hiBase = 1n << 63n;
assert.equal(fk.midpoint(hiBase, hiBase + 100n), hiBase + 50n);
const u64Max = (1n << 64n) - 1n;
assert.equal(fk.midpoint(u64Max - 10n, u64Max), u64Max - 5n);

assert.equal(
  fk.settle_net(2_000_000_000_000_000n, 9500n, 2_000_000_000_000_000n),
  100_000_000_000_000n
);
assert.equal(
  fk.settle_net(2_000_000_000_000_000n, 9500n, 1_000_000_000n),
  2_000_000_000_000_000n - 1_000_000_000n
);

const net = fk.settle_net(1_000_000n, 250n, 50_000n);
const expectedAligned = ((net + 63n) & ~63n) + ((net >> 6n) & 8191n);
assert.equal(fk.aligned_fee_packet(1_000_000n, 250n, 50_000n), expectedAligned);

// mut_slice with BigUint64Array
const arr = new BigUint64Array(16);
for (let i = 0; i < 16; i++) arr[i] = BigInt(1000 * i);
fk.halve_bonus_inplace(16n, 250n, 5000n, arr);
assert.equal(arr[0], 250n);
assert.equal(arr[4], 2250n);
assert.equal(arr[15], 5000n);

// mut_slice with plain JS Array + slice fold sum
const jsArr = [0n, 2000n, 4000n, 20000n];
fk.halve_bonus_inplace(4n, 100n, 5000n, jsArr);
assert.deepEqual(jsArr, [100n, 1100n, 2100n, 5000n]);
assert.equal(fk.batch_cap_sum(16n, arr), arr.reduce((a, b) => a + b, 0n));
assert.equal(fk.batch_cap_sum(0n, new BigUint64Array(0)), 0n);

// >64 KiB slice (20,000 * 8 = 160,000 bytes) triggers memory.grow cleanly and resets heap mark
const bigArr = new BigUint64Array(20000);
bigArr.fill(15000n);
assert.equal(fk.batch_cap_sum(20000n, bigArr), 20000n * 10000n);
assert.equal(fk.rawExports.__ail_heap_mark(), 1024);
console.log("OK_FIN");
"""
    assert _run_node_esm(node_script).strip() == "OK_FIN"


def test_wasm_signed_struct_quote_and_i64_ops(tmp_path: Path) -> None:
    art = _compile_verified_wasm(EXAMPLES / "signed_struct_quote.ail", tmp_path / "quote", "signed_struct_quote")
    wat_text = Path(art.wat_path).read_text()
    assert "i64.div_s" in wat_text

    node_script = f"""
import assert from "node:assert/strict";
import fs from "node:fs";
import * as qb from {Path(art.js_wrapper_path).as_uri()!r};

assert.equal(WebAssembly.validate(fs.readFileSync({art.wasm_path!r})), true);

const q1 = qb.build_quote(100_000n, 250n, -300n);
assert.equal(q1.bid, 100_000n);
assert.equal(q1.ask, 100_250n);
assert.equal(q1.pnl_adj, -300n);
assert.equal(qb.quote_spread(q1), 250n);
assert.equal(qb.quote_net_mid(q1), 99_825n);

// Ergonomics: Quote(...) callable with or without `new`, plus plain object
const q2 = qb.Quote(500_000, 500_400, -125);
const q3 = new qb.Quote(500_000n, 500_400n, -125n);
assert.equal(qb.quote_spread(q2), 400n);
assert.equal(qb.quote_net_mid(q3), 500_200n - 125n);
assert.equal(qb.quote_spread({{ bid: 10, ask: 35, pnl_adj: 0 }}), 25n);

assert.equal(qb.scale_signed_pnl(-77n), -7n);
assert.equal(qb.scale_signed_pnl(77n), 7n);
assert.equal(qb.scale_signed_pnl(-9n), 0n);
assert.equal(qb.rawExports.__ail_heap_mark(), 1024);
console.log("OK_QUOTE");
"""
    assert _run_node_esm(node_script).strip() == "OK_QUOTE"


def test_wasm_sum_type_settlement_and_br_table(tmp_path: Path) -> None:
    art = _compile_verified_wasm(EXAMPLES / "sum_type_settlement.ail", tmp_path / "settle", "sum_type_settlement")
    wat_text = Path(art.wat_path).read_text()
    assert "br_table" in wat_text

    # Also compile a wildcard + out-of-order match module
    wc_src = """
    (enum Ticket
      (Won (stake u64[1..1000000]) (mult u64[1..1000]))
      (Refunded (stake u64[1..1000000]))
      (Loss (penalty i64[-10000..-1]))
      (Void))
    (fn payout ((t Ticket)) u64[0..1000000000]
      (match t
        ((Void) 0)
        ((Won s m) (* s m))
        (_ 42)))
    (fn is_loss ((t Ticket)) u64[0..1]
      (if (is_variant t Loss) 1 0))
    """
    wc_art = _compile_verified_wasm(wc_src, tmp_path / "ticket", "ticket")

    node_script = f"""
import assert from "node:assert/strict";
import fs from "node:fs";
import * as st from {Path(art.js_wrapper_path).as_uri()!r};
import * as tk from {Path(wc_art.js_wrapper_path).as_uri()!r};

assert.equal(WebAssembly.validate(fs.readFileSync({art.wasm_path!r})), true);
assert.equal(WebAssembly.validate(fs.readFileSync({wc_art.wasm_path!r})), true);

assert.equal(st.outcome_notional(st.SettleOutcome.Cancelled()), 0n);
const fill = st.make_fill(25n, 400n);
assert.equal(fill.tag, st.SettleOutcome.TAG_Filled);
assert.equal(fill.field(0), 25n);
assert.equal(fill.field(1), 400n);
assert.equal(st.outcome_notional(fill), 10_000n);
assert.equal(st.outcome_notional(st.SettleOutcome.Partial(30n, 10n, 100n)), 3_000n);

const rej = st.make_rejected(-7n);
assert.equal(rej.tag, st.SettleOutcome.TAG_Rejected);
assert.equal(rej.field(0, true), -7n);
assert.equal(st.outcome_audit_score(rej), -7n);
assert.equal(st.is_rejected_outcome(rej), 1n);
assert.equal(st.is_rejected_outcome(fill), 0n);

// Wildcard + out-of-order match arms
assert.equal(tk.payout(tk.Ticket.Void()), 0n);
assert.equal(tk.payout(tk.Ticket.Won(250n, 4n)), 1000n);
assert.equal(tk.payout(tk.Ticket.Refunded(99n)), 42n);
assert.equal(tk.payout(tk.Ticket.Loss(-50n)), 42n);
assert.equal(tk.is_loss(tk.Ticket.Loss(-1n)), 1n);
assert.equal(tk.is_loss(tk.Ticket.Won(1n, 2n)), 0n);
console.log("OK_ENUM");
"""
    assert _run_node_esm(node_script).strip() == "OK_ENUM"


def test_wasm_bytes_endian_parsing_and_eq4(tmp_path: Path) -> None:
    src = """
    (fn parse_magic ((n u64[4..1024]) (buf (bytes n))) u64[0..1]
      (bytes_eq4 buf 0 65 73 76 49))

    (fn parse_version ((n u64[8..1024]) (buf (bytes n))) u64[0..255]
      (byte_at buf 4))

    (fn parse_u16 ((n u64[8..1024]) (buf (bytes n))) u64[0..65535]
      (read_u16_be buf 5))

    (fn parse_u32 ((n u64[12..1024]) (buf (bytes n))) u64[0..4294967295]
      (read_u32_be buf 7))

    (fn parse_u64 ((n u64[20..1024]) (buf (bytes n))) u64[0..MAX]
      (read_u64_be buf 11))

    (fn sum_header ((n u64[20..1024]) (buf (bytes n))) u64[0..MAX]
      (let ((ok (call parse_magic n buf))
            (ver (call parse_version n buf))
            (plen (call parse_u16 n buf)))
        (if (== ok 1) (+ ver plen) 0)))
    """
    art = _compile_verified_wasm(src, tmp_path / "bytes_mod", "bytes_mod")

    # Payload: "AIL1" | ver=0x03 | u16=0x1234 | u32=0x89ABCDEF | u64=0xFEDCBA9876543210 (MSB set!)
    packet = bytes([65, 73, 76, 49, 0x03, 0x12, 0x34, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x00])
    pkt_list = json.dumps(list(packet))

    node_script = f"""
import assert from "node:assert/strict";
import fs from "node:fs";
import * as bm from {Path(art.js_wrapper_path).as_uri()!r};

assert.equal(WebAssembly.validate(fs.readFileSync({art.wasm_path!r})), true);

const u8 = new Uint8Array({pkt_list});
assert.equal(bm.parse_magic(u8.length, u8), 1n);
assert.equal(bm.parse_version(u8.length, u8), 3n);
assert.equal(bm.parse_u16(u8.length, u8), 0x1234n);
assert.equal(bm.parse_u32(u8.length, u8), 0x89ABCDEFn);
assert.equal(bm.parse_u64(u8.length, u8), 0xFEDCBA9876543210n);
assert.equal(bm.sum_header(u8.length, u8), 3n + 0x1234n);

// Also works with ArrayBuffer and plain JS number array
assert.equal(bm.parse_u32(u8.length, u8.buffer), 0x89ABCDEFn);
assert.equal(bm.parse_magic(4, [0, 1, 2, 3]), 0n);
assert.equal(bm.sum_header(u8.length, [0, ...Array.from(u8.slice(1))]), 0n);

// Reject buffer shorter than declared n
assert.throws(() => bm.parse_magic(10, new Uint8Array(4)), RangeError);
console.log("OK_BYTES");
"""
    assert _run_node_esm(node_script).strip() == "OK_BYTES"


def test_wasm_capabilities_main_and_atomic_cas(tmp_path: Path) -> None:
    cli_art = _compile_verified_wasm(EXAMPLES / "verified_cli.ail", tmp_path / "vcli", "verified_cli")
    cap_art = _compile_verified_wasm(EXAMPLES / "capability_sandbox_cli.ail", tmp_path / "caps", "capability_sandbox_cli")
    vault_art = _compile_verified_wasm(EXAMPLES / "lockfree_vault.ail", tmp_path / "vault", "lockfree_vault")

    node_script = f"""
import assert from "node:assert/strict";
import fs from "node:fs";
import * as vcli from {Path(cli_art.js_wrapper_path).as_uri()!r};
import * as capMod from {Path(cap_art.js_wrapper_path).as_uri()!r};
import * as vault from {Path(vault_art.js_wrapper_path).as_uri()!r};

assert.equal(WebAssembly.validate(fs.readFileSync({cli_art.wasm_path!r})), true);
assert.equal(WebAssembly.validate(fs.readFileSync({cap_art.wasm_path!r})), true);
assert.equal(WebAssembly.validate(fs.readFileSync({vault_art.wasm_path!r})), true);

const ioLogs = [];
const vInst = await vcli.instantiate({{ io_print_u64: (v) => ioLogs.push(v) }});
assert.equal(vInst.ail_main(), 0n);
assert.equal(vInst.main(), 0n);
assert.deepEqual(ioLogs, [975000n, 4950000n, 975000n, 4950000n]);

const capEvents = [];
const cInst = await capMod.instantiate({{
  io_print_u64: (v) => capEvents.push(["io_u64", v]),
  io_print_i64: (v) => capEvents.push(["io_i64", v]),
  fs_write_u64: (v) => capEvents.push(["fs_u64", v]),
  fs_write_i64: (v) => capEvents.push(["fs_i64", v]),
  net_loopback_u64: (p, d) => capEvents.push(["net", p, d]),
}});
assert.equal(cInst.ail_main(), 0n);
assert.deepEqual(capEvents, [
  ["io_u64", 200n],
  ["io_i64", 99750n],
  ["fs_u64", 200n],
  ["fs_i64", 99750n],
  ["net", 49152n, 200n],
]);

// atomic_cas via BigUint64Array
const cell = new BigUint64Array([1000n]);
assert.equal(vault.cas_withdraw(cell, 400n), 1n);
assert.equal(cell[0], 600n);
assert.equal(vault.cas_withdraw(cell, 700n), 0n);
assert.equal(cell[0], 600n);
console.log("OK_CAPS");
"""
    assert _run_node_esm(node_script).strip() == "OK_CAPS"


def test_wasm_all_signed_unsigned_ops_and_shadowing(tmp_path: Path) -> None:
    src = """
    (fn signed_ops ((a i64[-1000..1000]) (b i64[1..100])) i64[-10000..10000]
      (let ((q (/ a b))
            (r (% a b))
            (sr (>> a 2))
            (mn (min a -50))
            (mx (max a 50)))
        (+ (+ q r) (+ sr (- mx mn)))))

    (fn signed_dyn_shift ((a i64[-1000..1000]) (sh u64[0..10])) i64[MIN_I64..MAX_I64]
      (>> a sh))

    (fn unsigned_ops ((a u64[0..MAX]) (b u64[1..1000]) (sh u64[0..63])) u64[0..MAX]
      (let ((q (/ a b))
            (r (% a b))
            (sl (<< r (min sh 10)))
            (sr (>> a sh))
            (bw (^ (& q sr) (| sl 7))))
        (if (and (> a 10) (not (== b 0))) bw 0)))

    (fn shadowing_and_casts ((u u64[0..1000]) (s i64[-500..500])) i64[-2000..2000]
      (let ((x (to_i64 u))
            (x (+ x s)))
        (if (< x 0) (min x -10) (to_i64 (to_u64 x)))))
    """
    art = _compile_verified_wasm(src, tmp_path / "ops", "all_ops")
    wat_text = Path(art.wat_path).read_text()
    assert "i64.div_s" in wat_text
    assert "i64.rem_s" in wat_text
    assert "i64.shr_s" in wat_text
    assert "i64.div_u" in wat_text
    assert "i64.rem_u" in wat_text
    assert "i64.shr_u" in wat_text
    assert "i64.shl" in wat_text
    assert "i64.xor" in wat_text

    node_script = f"""
import assert from "node:assert/strict";
import fs from "node:fs";
import * as ops from {Path(art.js_wrapper_path).as_uri()!r};

assert.equal(WebAssembly.validate(fs.readFileSync({art.wasm_path!r})), true);

// signed_ops(-77, 10): q=-7, r=-7, sr=-20 (arithmetic shift right of -77 >> 2 = -20), mn=-77, mx=50 => (-14) + (-20 + 127) = 93
assert.equal(ops.signed_ops(-77n, 10n), 93n);
assert.equal(ops.signed_dyn_shift(-77n, 2n), -20n);
assert.equal(ops.signed_dyn_shift(-77n, 6n), -2n);

// unsigned_ops with bit 63 set (> 2^63)
const bigU = (1n << 63n) + 123456n;
const q = bigU / 100n;
const r = bigU % 100n;
const sl = BigInt.asUintN(64, r << 5n);
const sr = bigU >> 5n;
const expected = BigInt.asUintN(64, (q & sr) ^ (sl | 7n));
assert.equal(ops.unsigned_ops(bigU, 100n, 5n), expected);

assert.equal(ops.shadowing_and_casts(100n, -150n), -50n);
assert.equal(ops.shadowing_and_casts(100n, -105n), -10n);
assert.equal(ops.shadowing_and_casts(100n, 50n), 150n);
console.log("OK_OPS");
"""
    assert _run_node_esm(node_script).strip() == "OK_OPS"


def test_wasm_wire_frame_parser_with_imports(tmp_path: Path) -> None:
    art = _compile_verified_wasm(
        EXAMPLES / "wire_frame_parser.ail", tmp_path / "wire", "wire_frame_parser", with_imports=True
    )
    wat_text = Path(art.wat_path).read_text()
    assert "br_table" in wat_text

    node_script = f"""
import assert from "node:assert/strict";
import fs from "node:fs";
import * as wf from {Path(art.js_wrapper_path).as_uri()!r};

assert.equal(WebAssembly.validate(fs.readFileSync({art.wasm_path!r})), true);

// 1. Valid frame: magic="AIL1" (65,73,76,49), ver=1, flags=0x2a, plen=4, seq=0x12345678
const validBuf = new Uint8Array([65, 73, 76, 49, 1, 0x2a, 0x00, 0x04, 0x12, 0x34, 0x56, 0x78]);
const validRes = wf.parse_frame(validBuf.length, validBuf);
assert.equal(validRes.tag, wf.FrameResult.TAG_Valid);
assert.equal(validRes.field(0), 1n);
assert.equal(validRes.field(1), 0x2an);
assert.equal(validRes.field(2), 4n);
assert.equal(validRes.field(3), 0x12345678n);
assert.equal(wf.frame_result_seq(validRes), 0x12345678n);

// 2. Truncated short header (<8 bytes)
const shortBuf = new Uint8Array([65, 73, 76]);
const shortRes = wf.parse_frame(shortBuf.length, shortBuf);
assert.equal(shortRes.tag, wf.FrameResult.TAG_Truncated);
assert.equal(shortRes.field(0), 3n);
assert.equal(shortRes.field(1), 8n);
assert.equal(wf.frame_result_seq(shortRes), 0n);

// 3. BadMagic
const badMagic = new Uint8Array([65, 73, 76, 50, 1, 0, 0, 4, 1, 2, 3, 4]);
assert.equal(wf.parse_frame(badMagic.length, badMagic).tag, wf.FrameResult.TAG_BadMagic);

// 4. UnsupportedVersion
const badVer = new Uint8Array([65, 73, 76, 49, 2, 0, 0, 4, 1, 2, 3, 4]);
const verRes = wf.parse_frame(badVer.length, badVer);
assert.equal(verRes.tag, wf.FrameResult.TAG_UnsupportedVersion);
assert.equal(verRes.field(0), 2n);

// 5. Truncated payload (declares plen=10, actual=12 < 18)
const truncPayload = new Uint8Array([65, 73, 76, 49, 1, 0, 0, 10, 1, 2, 3, 4]);
const tpRes = wf.parse_frame(truncPayload.length, truncPayload);
assert.equal(tpRes.tag, wf.FrameResult.TAG_Truncated);
assert.equal(tpRes.field(0), 12n);
assert.equal(tpRes.field(1), 18n);

// 6. read_frame_u64_payload (>=16 bytes)
const u64Buf = new Uint8Array([65, 73, 76, 49, 1, 0, 0, 8, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]);
assert.equal(wf.read_frame_u64_payload(u64Buf.length, u64Buf), 0xfedcba9876543210n);

// 7. Imported stdlib/parse helpers are also exported and work directly
assert.equal(wf.has_ail_magic(validBuf.length, validBuf), 1n);
assert.equal(wf.frame_version_byte(validBuf.length, validBuf), 1n);
assert.equal(wf.frame_payload_len_u16(validBuf.length, validBuf), 4n);

console.log("OK_WIRE");
"""
    assert _run_node_esm(node_script).strip() == "OK_WIRE"


def test_wasm_defi_waterfall_v1_with_imports(tmp_path: Path) -> None:
    art = _compile_verified_wasm(
        EXAMPLES / "defi_waterfall_v1.ail", tmp_path / "defi", "defi_waterfall_v1", with_imports=True
    )

    node_script = f"""
import assert from "node:assert/strict";
import fs from "node:fs";
import * as df from {Path(art.js_wrapper_path).as_uri()!r};

assert.equal(WebAssembly.validate(fs.readFileSync({art.wasm_path!r})), true);

// gross=100000, senior_cap=80000, fee_bps=300 (3%), reserve_bps=2000 (20% of fee=600 -> dist=99400 -> junior=19400)
assert.equal(await df.waterfall_junior_payout(100000n, 80000n, 300n, 2000n), 19400n);
assert.equal(await df.waterfall_junior_payout(50000n, 80000n, 300n, 2000n), 0n);

assert.equal(await df.share_price_ceil_per_unit(0n, 100n), 0n);
assert.equal(await df.share_price_ceil_per_unit(1001n, 100n), 11n);

// Quote2Way(bid=10000, ask=10025) => spread=25 bps; rebate(100000, 50bps=500 capped at 400) => 425
const q = new df.Quote2Way(10000n, 10025n);
assert.equal(await df.pool_quote_health_check(q, 100000n, 50n, 400n), 425n);

console.log("OK_DEFI");
"""
    assert _run_node_esm(node_script).strip() == "OK_DEFI"
