"""Comprehensive Test Suite for the ISO C11 Backend (`src/ailang/codegen_c.py`)."""

from __future__ import annotations

import ctypes
import os
from pathlib import Path
import platform
import shutil
import socket
import struct
import subprocess
import sys

from ailang.codegen_c import CArtifacts, compile_to_c
from ailang.modules import list_stdlib_modules, load_ail_module_with_imports
from ailang.ownership import check_module_ownership_v2
from ailang.parser import parse_source
from ailang.verifier import ModuleVerifier

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
ZIG_BIN = shutil.which("zig") or "/opt/homebrew/bin/zig"


def _verify_and_compile_c(
    src_text: str,
    out_dir: Path,
    module_name: str,
    compile_shared: bool = True,
) -> tuple[CArtifacts, object]:
    forms = parse_source(src_text)
    tenv = check_module_ownership_v2(forms)
    ModuleVerifier(tenv).verify_module(forms)
    art = compile_to_c(forms, tenv, out_dir, module_name=module_name, compile_shared=compile_shared)
    return art, tenv


def _assert_wasm32_freestanding_c11(c_path: str, out_dir: Path) -> None:
    obj_path = out_dir / f"{Path(c_path).stem}_wasm32.o"
    subprocess.run(
        [
            ZIG_BIN,
            "cc",
            "-target",
            "wasm32-freestanding",
            "-std=c11",
            "-O3",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-c",
            c_path,
            "-o",
            str(obj_path),
        ],
        check=True,
    )
    assert obj_path.exists() and obj_path.stat().st_size > 0


def test_c_artifacts_interface_and_compile_shared_flag(tmp_path: Path) -> None:
    src = "(fn add1 ((x u64[0..100])) u64[1..101] (+ x 1))"
    art_no_lib, _ = _verify_and_compile_c(src, tmp_path / "no_lib", "no_lib_mod", compile_shared=False)
    assert isinstance(art_no_lib, CArtifacts)
    assert Path(art_no_lib.c_source_path).exists()
    assert Path(art_no_lib.c_header_path).exists()
    assert art_no_lib.shared_lib_path == ""

    art_lib, _ = _verify_and_compile_c(src, tmp_path / "with_lib", "lib_mod", compile_shared=True)
    ext = ".dylib" if platform.system() == "Darwin" else ".so"
    assert art_lib.shared_lib_path.endswith(f"liblib_mod{ext}")
    assert Path(art_lib.shared_lib_path).exists()
    _assert_wasm32_freestanding_c11(art_lib.c_source_path, tmp_path / "with_lib")


def test_c11_financial_kernel_ctypes_and_wasm32_freestanding(tmp_path: Path) -> None:
    out_dir = tmp_path / "fk_c"
    art, _ = _verify_and_compile_c((EXAMPLES / "financial_kernel.ail").read_text(), out_dir, "financial_kernel")
    _assert_wasm32_freestanding_c11(art.c_source_path, out_dir)

    h_text = Path(art.c_header_path).read_text()
    assert "uint64_t midpoint(uint64_t lo, uint64_t hi);" in h_text
    assert "const uint64_t* buf" in h_text
    assert "void halve_bonus_inplace(uint64_t n, uint64_t bonus, uint64_t cap, uint64_t* buf);" in h_text

    lib = ctypes.CDLL(art.shared_lib_path)
    lib.midpoint.argtypes = [ctypes.c_uint64, ctypes.c_uint64]
    lib.midpoint.restype = ctypes.c_uint64
    assert lib.midpoint(1 << 63, (1 << 63) + 100) == (1 << 63) + 50

    lib.settle_net.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64]
    lib.settle_net.restype = ctypes.c_uint64
    assert lib.settle_net(2_000_000_000_000_000, 9500, 2_000_000_000_000_000) == 100_000_000_000_000

    lib.aligned_fee_packet.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64]
    lib.aligned_fee_packet.restype = ctypes.c_uint64
    net = 100_000_000_000_000
    expected_pkt = ((net + 63) & ~63) + ((net >> 6) & 8191)
    assert lib.aligned_fee_packet(2_000_000_000_000_000, 9500, 2_000_000_000_000_000) == expected_pkt

    lib.halve_bonus_inplace.argtypes = [
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.POINTER(ctypes.c_uint64),
    ]
    lib.halve_bonus_inplace.restype = None
    lib.batch_cap_sum.argtypes = [ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64)]
    lib.batch_cap_sum.restype = ctypes.c_uint64

    arr = (ctypes.c_uint64 * 16)(*[1000 * i for i in range(16)])
    lib.halve_bonus_inplace(16, 250, 5000, arr)
    assert arr[0] == 250
    assert arr[4] == 2250
    assert arr[15] == 5000
    assert lib.batch_cap_sum(16, arr) == sum(arr)
    assert lib.batch_cap_sum(0, arr) == 0


def test_c11_signed_struct_quote_c_abi_parity(tmp_path: Path) -> None:
    out_dir = tmp_path / "quote_c"
    art, _ = _verify_and_compile_c((EXAMPLES / "signed_struct_quote.ail").read_text(), out_dir, "signed_struct_quote")
    _assert_wasm32_freestanding_c11(art.c_source_path, out_dir)

    h_text = Path(art.c_header_path).read_text()
    assert "uint64_t bid;" in h_text
    assert "uint64_t ask;" in h_text
    assert "int64_t pnl_adj;" in h_text
    assert "void build_quote(uint64_t bid, uint64_t spread, int64_t pnl_adj, Quote* _out);" in h_text
    assert "uint64_t quote_spread(const Quote* q);" in h_text
    assert "int64_t quote_net_mid(const Quote* q);" in h_text

    class Quote(ctypes.Structure):
        _fields_ = [
            ("bid", ctypes.c_uint64),
            ("ask", ctypes.c_uint64),
            ("pnl_adj", ctypes.c_int64),
        ]

    lib = ctypes.CDLL(art.shared_lib_path)
    lib.build_quote.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int64, ctypes.POINTER(Quote)]
    lib.build_quote.restype = None
    lib.quote_spread.argtypes = [ctypes.POINTER(Quote)]
    lib.quote_spread.restype = ctypes.c_uint64
    lib.quote_net_mid.argtypes = [ctypes.POINTER(Quote)]
    lib.quote_net_mid.restype = ctypes.c_int64
    lib.scale_signed_pnl.argtypes = [ctypes.c_int64]
    lib.scale_signed_pnl.restype = ctypes.c_int64

    q = Quote()
    lib.build_quote(100_000, 250, -300, ctypes.byref(q))
    assert (q.bid, q.ask, q.pnl_adj) == (100_000, 100_250, -300)
    assert lib.quote_spread(ctypes.byref(q)) == 250
    assert lib.quote_net_mid(ctypes.byref(q)) == 99_825
    assert lib.scale_signed_pnl(-77) == -7


def test_c11_sum_type_settlement_enum_match_and_wildcard(tmp_path: Path) -> None:
    out_dir = tmp_path / "sum_c"
    art, _ = _verify_and_compile_c((EXAMPLES / "sum_type_settlement.ail").read_text(), out_dir, "sum_type_settlement")
    _assert_wasm32_freestanding_c11(art.c_source_path, out_dir)

    h_text = Path(art.c_header_path).read_text()
    assert "SettleOutcome_Filled = 0" in h_text
    assert "SettleOutcome_Cancelled = 3" in h_text
    assert "uint64_t tag;" in h_text
    assert "uint64_t _p2;" in h_text
    assert "void make_fill(uint64_t q, uint64_t p, SettleOutcome* _out);" in h_text

    class SettleOutcome(ctypes.Structure):
        _fields_ = [
            ("tag", ctypes.c_uint64),
            ("_p0", ctypes.c_uint64),
            ("_p1", ctypes.c_uint64),
            ("_p2", ctypes.c_uint64),
        ]

    lib = ctypes.CDLL(art.shared_lib_path)
    lib.make_fill.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.POINTER(SettleOutcome)]
    lib.make_fill.restype = None
    lib.make_rejected.argtypes = [ctypes.c_int64, ctypes.POINTER(SettleOutcome)]
    lib.make_rejected.restype = None
    lib.outcome_notional.argtypes = [ctypes.POINTER(SettleOutcome)]
    lib.outcome_notional.restype = ctypes.c_uint64
    lib.outcome_audit_score.argtypes = [ctypes.POINTER(SettleOutcome)]
    lib.outcome_audit_score.restype = ctypes.c_int64
    lib.is_rejected_outcome.argtypes = [ctypes.POINTER(SettleOutcome)]
    lib.is_rejected_outcome.restype = ctypes.c_uint64

    fill = SettleOutcome()
    lib.make_fill(25, 400, ctypes.byref(fill))
    assert fill.tag == 0
    assert lib.outcome_notional(ctypes.byref(fill)) == 10_000
    assert lib.outcome_audit_score(ctypes.byref(fill)) == 25
    assert lib.is_rejected_outcome(ctypes.byref(fill)) == 0

    partial = SettleOutcome(tag=1, _p0=30, _p1=10, _p2=100)
    assert lib.outcome_notional(ctypes.byref(partial)) == 3_000

    rej = SettleOutcome()
    lib.make_rejected(-7, ctypes.byref(rej))
    assert rej.tag == 2
    assert lib.outcome_notional(ctypes.byref(rej)) == 0
    assert lib.outcome_audit_score(ctypes.byref(rej)) == -7
    assert lib.is_rejected_outcome(ctypes.byref(rej)) == 1

    cancelled = SettleOutcome(tag=3)
    assert lib.outcome_notional(ctypes.byref(cancelled)) == 0
    assert lib.outcome_audit_score(ctypes.byref(cancelled)) == 0

    # Wildcard `_` + enum/struct equality + `let` shadowing
    extra_src = """
    (enum Mode (Fast (rate u64[1..100])) (Slow (rate u64[1..10])) (Off))
    (fn score ((m Mode)) u64[5..110]
      (let ((x 5))
        (let ((x (+ x 5)))
          (match m ((Fast r) (+ r x)) (_ 5)))))
    (fn same_mode ((a Mode) (b Mode)) u64[0..1]
      (if (== a b) 1 0))
    """
    extra_dir = tmp_path / "extra_enum_c"
    art2, _ = _verify_and_compile_c(extra_src, extra_dir, "extra_enum")
    _assert_wasm32_freestanding_c11(art2.c_source_path, extra_dir)

    class Mode(ctypes.Structure):
        _fields_ = [("tag", ctypes.c_uint64), ("_p0", ctypes.c_uint64)]

    lib2 = ctypes.CDLL(art2.shared_lib_path)
    lib2.score.argtypes = [ctypes.POINTER(Mode)]
    lib2.score.restype = ctypes.c_uint64
    lib2.same_mode.argtypes = [ctypes.POINTER(Mode), ctypes.POINTER(Mode)]
    lib2.same_mode.restype = ctypes.c_uint64

    m_fast = Mode(tag=0, _p0=30)
    m_off = Mode(tag=2, _p0=999)  # Ignored payload on Off must not break equality
    m_off2 = Mode(tag=2, _p0=0)
    assert lib2.score(ctypes.byref(m_fast)) == 40
    assert lib2.score(ctypes.byref(Mode(tag=1, _p0=7))) == 5
    assert lib2.same_mode(ctypes.byref(m_off), ctypes.byref(m_off2)) == 1
    assert lib2.same_mode(ctypes.byref(m_fast), ctypes.byref(m_off)) == 0


def test_c11_bytes_zero_copy_readers_and_magic_check(tmp_path: Path) -> None:
    bytes_src = """
    (fn check_ail1_magic ((n u64[4..65536]) (buf (bytes n))) u64[0..1]
      (bytes_eq4 buf 0 65 73 76 49))

    (fn parse_header_fields ((n u64[16..65536]) (buf (bytes n))) u64[0..MAX]
      (let ((magic_ok (call check_ail1_magic n buf))
            (ver (byte_at buf 4))
            (plen (read_u16_be buf 5))
            (seq32 (read_u32_be buf 7))
            (ts64 (read_u64_be buf 8)))
        (if (== magic_ok 1)
            (if (== ver 2) plen seq32)
            ts64)))

    (fn read_tail_u64 ((n u64[16..65536]) (buf (bytes n))) u64[0..MAX]
      (read_u64_be buf 8))
    """
    out_dir = tmp_path / "bytes_c"
    art, _ = _verify_and_compile_c(bytes_src, out_dir, "bytes_parser")
    _assert_wasm32_freestanding_c11(art.c_source_path, out_dir)

    h_text = Path(art.c_header_path).read_text()
    assert "const uint8_t* buf" in h_text

    lib = ctypes.CDLL(art.shared_lib_path)
    for fn_name in ("check_ail1_magic", "parse_header_fields", "read_tail_u64"):
        fn = getattr(lib, fn_name)
        fn.argtypes = [ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint8)]
        fn.restype = ctypes.c_uint64

    frame = b"AIL1" + bytes([2]) + struct.pack(">HI", 0x1234, 0xCAFEBABE) + struct.pack(">Q", 0x0102030405060708)[3:]
    frame_full = b"AIL1" + bytes([2]) + struct.pack(">H", 0x1234) + b"\xCA" + struct.pack(">Q", 0x1122334455667788)
    assert len(frame_full) == 16
    buf_ok = (ctypes.c_uint8 * len(frame_full))(*frame_full)
    assert lib.check_ail1_magic(len(frame_full), buf_ok) == 1
    assert lib.parse_header_fields(len(frame_full), buf_ok) == 0x1234
    assert lib.read_tail_u64(len(frame_full), buf_ok) == 0x1122334455667788

    # Non-v2 version selects read_u32_be at offset 7
    frame_v1 = b"AIL1" + bytes([1]) + struct.pack(">H", 0x0001) + struct.pack(">I", 0xDEADBEEF) + bytes(5)
    buf_v1 = (ctypes.c_uint8 * len(frame_v1))(*frame_v1)
    assert lib.parse_header_fields(len(frame_v1), buf_v1) == 0xDEADBEEF

    # Bad magic falls back to read_u64_be at offset 8
    frame_bad = b"NOPE" + bytes([2]) + struct.pack(">H", 0) + b"\x00" + struct.pack(">Q", 0xFEDCBA9876543210)
    buf_bad = (ctypes.c_uint8 * len(frame_bad))(*frame_bad)
    assert lib.check_ail1_magic(len(frame_bad), buf_bad) == 0
    assert lib.parse_header_fields(len(frame_bad), buf_bad) == 0xFEDCBA9876543210
    _ = frame


def test_c11_lockfree_atomic_cas_stdatomic_and_wasm32(tmp_path: Path) -> None:
    out_dir = tmp_path / "vault_c"
    art, _ = _verify_and_compile_c((EXAMPLES / "lockfree_vault.ail").read_text(), out_dir, "lockfree_vault")
    _assert_wasm32_freestanding_c11(art.c_source_path, out_dir)

    h_text = Path(art.c_header_path).read_text()
    assert "#include <stdatomic.h>" in h_text
    assert "_Atomic uint64_t*" in h_text

    lib = ctypes.CDLL(art.shared_lib_path)
    lib.cas_withdraw.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.c_uint64]
    lib.cas_withdraw.restype = ctypes.c_uint64

    vault = ctypes.c_uint64(1000)
    assert lib.cas_withdraw(ctypes.byref(vault), 400) == 1
    assert vault.value == 600
    assert lib.cas_withdraw(ctypes.byref(vault), 700) == 0
    assert vault.value == 600


def test_c11_signed_shifts_ub_free_and_i64_map_inplace(tmp_path: Path) -> None:
    src = """
    (fn signed_shl ((x i64[-1000000..1000000])) i64[MIN_I64..MAX_I64]
      (<< x 2))

    (fn signed_bitnot ((y i64[-1000..1000])) i64[MIN_I64..MAX_I64]
      (~ y))

    (fn signed_ops ((x i64[-1000000..1000000]) (y i64[-1000..1000])) i64[MIN_I64..MAX_I64]
      (let ((shl_v (<< x 2))
            (ashr_v (>> x 1))
            (inv_v (~ y))
            (m_v (min shl_v ashr_v)))
        (+ (/ m_v 4) (/ (max inv_v y) 4))))

    (map_inplace clamp_i64_slice
      ((n u64[0..1024]) (lo i64[-1000..0]) (hi i64[0..1000]) (buf (mut_slice n i64[-100000..100000])))
      i64[lo..hi]
      (el)
      (max lo (min hi el)))
    """
    out_dir = tmp_path / "signed_ops_c"
    art, _ = _verify_and_compile_c(src, out_dir, "signed_ops")
    _assert_wasm32_freestanding_c11(art.c_source_path, out_dir)

    # Also verify UBSan clean compilation + execution!
    ubsan_lib = out_dir / "lib_ubsan.dylib"
    subprocess.run(
        [
            "clang",
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fsanitize=undefined",
            "-fno-sanitize-recover=all",
            "-shared",
            "-fPIC",
            art.c_source_path,
            "-o",
            str(ubsan_lib),
        ],
        check=True,
    )

    lib = ctypes.CDLL(str(ubsan_lib))
    lib.signed_shl.argtypes = [ctypes.c_int64]
    lib.signed_shl.restype = ctypes.c_int64
    lib.signed_bitnot.argtypes = [ctypes.c_int64]
    lib.signed_bitnot.restype = ctypes.c_int64
    lib.signed_ops.argtypes = [ctypes.c_int64, ctypes.c_int64]
    lib.signed_ops.restype = ctypes.c_int64
    lib.clamp_i64_slice.argtypes = [
        ctypes.c_uint64,
        ctypes.c_int64,
        ctypes.c_int64,
        ctypes.POINTER(ctypes.c_int64),
    ]
    lib.clamp_i64_slice.restype = None

    assert lib.signed_shl(-9) == -36
    assert lib.signed_shl(10) == 40
    assert lib.signed_bitnot(-5) == 4
    assert lib.signed_bitnot(3) == -4

    # x = -12, y = -9: shl_v = -48, ashr_v = -6, inv_v = 8, min = -48 => -12; max(8, -9) = 8 => 2 => -10
    assert lib.signed_ops(-12, -9) == -10
    # x = 10, y = 3: shl_v = 40, ashr_v = 5, inv_v = -4, min = 5 => 1; max(-4, 3) = 3 => 0 => 1
    assert lib.signed_ops(10, 3) == 1

    arr = (ctypes.c_int64 * 4)(-500, -10, 10, 500)
    lib.clamp_i64_slice(4, -100, 100, arr)
    assert list(arr) == [-100, -10, 10, 100]


def test_c11_capabilities_io_fs_net_and_fflush(tmp_path: Path) -> None:
    # 1. Library function using io.done + fflush(NULL)
    io_src = """
    (fn emit_and_flush ((io cap.io) (v u64[0..1000])) u64[0..0]
      (io.done (io.print_u64 io v) 0))
    """
    io_dir = tmp_path / "io_c"
    art_io, _ = _verify_and_compile_c(io_src, io_dir, "io_flush")
    driver = (
        f"import ctypes; "
        f"lib = ctypes.CDLL({art_io.shared_lib_path!r}); "
        f"lib.emit_and_flush.argtypes = [ctypes.c_uint64]; "
        f"lib.emit_and_flush.restype = ctypes.c_uint64; "
        f"rc = lib.emit_and_flush(42); print('RET=' + str(rc))"
    )
    out = subprocess.check_output([sys.executable, "-c", driver], text=True).strip().splitlines()
    assert out == ["42", "RET=0"]

    # 2. Standalone capability sandbox executable (cap.io + cap.fs + cap.net loopback 127.0.0.1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
        udp_sock.bind(("127.0.0.1", 0))
        udp_sock.settimeout(3.0)
        ephemeral_port = udp_sock.getsockname()[1]

        cap_src = (
            "(main ((io cap.io) (fs cap.fs) (net cap.net)) u64[0..0]\n"
            "  (let ((io1 (io.print_u64 io 200))\n"
            "        (io2 (io.print_i64 io1 -350))\n"
            "        (fs1 (fs.write_u64 fs 200))\n"
            "        (fs2 (fs.write_i64 fs1 -350))\n"
            "        (fc (fs.close fs2))\n"
            f"        (net1 (net.loopback_send_u64 net {ephemeral_port} 987654321012345))\n"
            "        (nc (net.close net1)))\n"
            "    (io.done io2 0)))\n"
        )
        cap_dir = tmp_path / "cap_c"
        art_cap, _ = _verify_and_compile_c(cap_src, cap_dir, "cap_sandbox", compile_shared=False)
        exe_path = cap_dir / "cap_sandbox"
        subprocess.run(
            ["clang", "-std=c11", "-O3", "-Wall", "-Wextra", "-Werror", art_cap.c_source_path, "-o", str(exe_path)],
            check=True,
        )

        fs_log = tmp_path / "c_sandbox.log"
        env = dict(os.environ, AIL_FS_OUT=str(fs_log))
        stdout_lines = subprocess.check_output([str(exe_path)], env=env, text=True).strip().splitlines()
        assert stdout_lines == ["200", "-350"]
        assert fs_log.read_text().strip().splitlines() == ["200", "-350"]

        pkt, sender = udp_sock.recvfrom(64)
        assert sender[0] == "127.0.0.1"
        assert len(pkt) == 8
        assert struct.unpack("<Q", pkt)[0] == 987654321012345


def test_c11_v1_wire_frame_defi_and_stdlib_modules(tmp_path: Path) -> None:
    # 1. All built-in stdlib modules compile cleanly to both native C11 and wasm32-freestanding
    stdlib_libs: dict[str, CArtifacts] = {}
    for std_path in list_stdlib_modules():
        forms = load_ail_module_with_imports(std_path)
        tenv = check_module_ownership_v2(forms)
        ModuleVerifier(tenv).verify_module(forms)
        art = compile_to_c(forms, tenv, tmp_path / f"std_{std_path.stem}", module_name=std_path.stem)
        _assert_wasm32_freestanding_c11(art.c_source_path, tmp_path / f"std_{std_path.stem}")
        stdlib_libs[std_path.stem] = art

    bits_lib = ctypes.CDLL(stdlib_libs["bits"].shared_lib_path)
    bits_lib.low_byte.argtypes = [ctypes.c_uint64]
    bits_lib.low_byte.restype = ctypes.c_uint64
    bits_lib.pack_u32_pair.argtypes = [ctypes.c_uint64, ctypes.c_uint64]
    bits_lib.pack_u32_pair.restype = ctypes.c_uint64
    bits_lib.unpack_hi32.argtypes = [ctypes.c_uint64]
    bits_lib.unpack_hi32.restype = ctypes.c_uint64
    bits_lib.unpack_lo32.argtypes = [ctypes.c_uint64]
    bits_lib.unpack_lo32.restype = ctypes.c_uint64
    bits_lib.mask_bits_u64.argtypes = [ctypes.c_uint64, ctypes.c_uint64]
    bits_lib.mask_bits_u64.restype = ctypes.c_uint64

    packed = bits_lib.pack_u32_pair(0xCAFEBABE, 0xDEADBEEF)
    assert packed == 0xCAFEBABEDEADBEEF
    assert bits_lib.unpack_hi32(packed) == 0xCAFEBABE
    assert bits_lib.unpack_lo32(packed) == 0xDEADBEEF
    assert bits_lib.low_byte(packed) == 0xEF
    assert bits_lib.mask_bits_u64(0xFFFF, 5) == 0x1F

    # 2. wire_frame_parser.ail (imports stdlib/parse + const + zero-field BadMagic enum + bytes)
    wf_forms = load_ail_module_with_imports(EXAMPLES / "wire_frame_parser.ail")
    wf_tenv = check_module_ownership_v2(wf_forms)
    ModuleVerifier(wf_tenv).verify_module(wf_forms)
    wf_art = compile_to_c(wf_forms, wf_tenv, tmp_path / "wf_c", module_name="wire_frame_parser")
    _assert_wasm32_freestanding_c11(wf_art.c_source_path, tmp_path / "wf_c")

    class CFrameResult(ctypes.Structure):
        _fields_ = [
            ("tag", ctypes.c_uint64),
            ("_p0", ctypes.c_uint64),
            ("_p1", ctypes.c_uint64),
            ("_p2", ctypes.c_uint64),
            ("_p3", ctypes.c_uint64),
        ]

    wf_lib = ctypes.CDLL(wf_art.shared_lib_path)
    wf_lib.parse_frame.argtypes = [ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(CFrameResult)]
    wf_lib.parse_frame.restype = None
    wf_lib.frame_result_seq.argtypes = [ctypes.POINTER(CFrameResult)]
    wf_lib.frame_result_seq.restype = ctypes.c_uint64
    wf_lib.read_frame_u64_payload.argtypes = [ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint8)]
    wf_lib.read_frame_u64_payload.restype = ctypes.c_uint64

    valid_pkt = b"AIL1" + bytes([1, 0x2A]) + struct.pack(">HI", 8, 0x01020304) + b"\x11\x22\x33\x44"
    res = CFrameResult()
    wf_lib.parse_frame(len(valid_pkt), (ctypes.c_uint8 * len(valid_pkt)).from_buffer_copy(valid_pkt), ctypes.byref(res))
    assert (res.tag, res._p0, res._p1, res._p2, res._p3) == (0, 1, 0x2A, 8, 0x01020304)
    assert wf_lib.frame_result_seq(ctypes.byref(res)) == 0x01020304
    assert wf_lib.read_frame_u64_payload(
        len(valid_pkt),
        (ctypes.c_uint8 * len(valid_pkt)).from_buffer_copy(valid_pkt),
    ) == 0x0102030411223344

    bad_magic = b"NOPE\x01\x00\x00\x08\x00\x00\x00\x01"
    wf_lib.parse_frame(len(bad_magic), (ctypes.c_uint8 * len(bad_magic)).from_buffer_copy(bad_magic), ctypes.byref(res))
    assert res.tag == 1  # BadMagic (zero-field enum variant)
    assert wf_lib.frame_result_seq(ctypes.byref(res)) == 0

    bad_ver = b"AIL1\x09\x00\x00\x08\x00\x00\x00\x01"
    wf_lib.parse_frame(len(bad_ver), (ctypes.c_uint8 * len(bad_ver)).from_buffer_copy(bad_ver), ctypes.byref(res))
    assert (res.tag, res._p0) == (2, 9)  # UnsupportedVersion

    short_hdr = b"AIL1"
    wf_lib.parse_frame(len(short_hdr), (ctypes.c_uint8 * len(short_hdr)).from_buffer_copy(short_hdr), ctypes.byref(res))
    assert (res.tag, res._p0, res._p1) == (3, 4, 8)  # Truncated

    # 3. defi_waterfall_v1.ail (imports stdlib/finance + stdlib/math + Quote2Way C-ABI struct)
    df_forms = load_ail_module_with_imports(EXAMPLES / "defi_waterfall_v1.ail")
    df_tenv = check_module_ownership_v2(df_forms)
    ModuleVerifier(df_tenv).verify_module(df_forms)
    df_art = compile_to_c(df_forms, df_tenv, tmp_path / "df_c", module_name="defi_waterfall_v1")
    _assert_wasm32_freestanding_c11(df_art.c_source_path, tmp_path / "df_c")

    class CQuote2Way(ctypes.Structure):
        _fields_ = [("bid", ctypes.c_uint64), ("ask", ctypes.c_uint64)]

    df_lib = ctypes.CDLL(df_art.shared_lib_path)
    df_lib.waterfall_junior_payout.argtypes = [ctypes.c_uint64] * 4
    df_lib.waterfall_junior_payout.restype = ctypes.c_uint64
    df_lib.share_price_ceil_per_unit.argtypes = [ctypes.c_uint64, ctypes.c_uint64]
    df_lib.share_price_ceil_per_unit.restype = ctypes.c_uint64
    df_lib.pool_quote_health_check.argtypes = [
        ctypes.POINTER(CQuote2Way),
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_uint64,
    ]
    df_lib.pool_quote_health_check.restype = ctypes.c_uint64

    # gross=100_000, senior_cap=80_000, fee_bps=300 (fee=3000, net=97_000), reserve_bps=1000 (res=300)
    # distributable = 97_000 + 2_700 = 99_700; junior = 99_700 - 80_000 = 19_700
    assert df_lib.waterfall_junior_payout(100_000, 80_000, 300, 1000) == 19_700
    assert df_lib.share_price_ceil_per_unit(101, 10) == 11
    assert df_lib.share_price_ceil_per_unit(0, 10) == 0

    q2w = CQuote2Way(bid=10_000, ask=10_025)
    # spread_bps = (25 * 10000) / 10000 = 25; rebate = min(1_000_000 * 50 / 10000 = 5000, 3000) = 3000
    assert df_lib.pool_quote_health_check(ctypes.byref(q2w), 1_000_000, 50, 3000) == 3025
