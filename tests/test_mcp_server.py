"""Tests for AIL v1.0 MCP stdio JSON-RPC 2.0 server and Antigravity plugin."""

from __future__ import annotations

import io
import json
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

import pytest

from ailang import mcp_server

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
REPO_PLUGIN = ROOT / "integrations" / "antigravity-plugin"
INSTALLED_PLUGIN = Path.home() / ".gemini" / "config" / "plugins" / "ailang"

ALLOWED_PLUGIN_JSON_KEYS = {
    "name",
    "displayName",
    "version",
    "description",
    "logo",
    "suggestedPrompts",
    "repository",
    "author",
    "homepage",
    "disabled",
}


def _call_tool_payload(tool_name: str, arguments: dict) -> tuple[dict, dict]:
    resp = mcp_server.handle_jsonrpc_message(
        {
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }
    )
    assert resp is not None
    result = resp["result"]
    payload = json.loads(result["content"][0]["text"])
    return result, payload


def test_mcp_stdio_roundtrip_subprocess(tmp_path: Path) -> None:
    venv_python = ROOT / ".venv" / "bin" / "python"
    py_exe = str(venv_python if venv_python.exists() else Path(sys.executable))

    sample_src = """
    (spec exact_inc ((x int)) (+ x 1))
    (fn inc_safe ((x u64[0..1000])) (out u64[1..1001] (== out (exact_inc x))) (+ x 1))
    """

    requests = [
        "",
        "   ",
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "pytest-mcp-client", "version": "1.0.0"},
                },
            }
        ),
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping"}),
        json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}),
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "ail_check_and_prove", "arguments": {"source": sample_src}},
            }
        ),
        json.dumps({"jsonrpc": "2.0", "id": 5, "method": "nonexistent/method"}),
        "{not-valid-json",
    ]
    stdin_payload = "\n".join(requests) + "\n"

    proc = subprocess.run(
        [py_exe, "-m", "ailang.mcp_server"],
        input=stdin_payload,
        text=True,
        capture_output=True,
        cwd=str(ROOT),
        timeout=30,
        check=True,
    )
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    # notifications/initialized emits no response; 6 requests/parse-error emit 6 responses
    assert len(lines) == 6

    init_resp = json.loads(lines[0])
    assert init_resp["id"] == 1
    assert init_resp["result"]["protocolVersion"] == "2024-11-05"
    assert init_resp["result"]["capabilities"] == {"tools": {}}
    assert init_resp["result"]["serverInfo"] == {"name": "ailang-mcp", "version": "1.0.0"}

    ping_resp = json.loads(lines[1])
    assert ping_resp == {"jsonrpc": "2.0", "id": 2, "result": {}}

    list_resp = json.loads(lines[2])
    assert list_resp["id"] == 3
    tool_names = {t["name"] for t in list_resp["result"]["tools"]}
    assert tool_names == {
        "ail_check_and_prove",
        "ail_audit_spec",
        "ail_repair_code",
        "ail_compile_target",
        "ail_stdlib_catalog",
    }

    call_resp = json.loads(lines[3])
    assert call_resp["id"] == 4
    assert call_resp["result"]["isError"] is False
    call_payload = json.loads(call_resp["result"]["content"][0]["text"])
    assert call_payload["status"] == "STATUS_VERIFIED"
    assert call_payload["verified"] is True
    assert "STATUS_VERIFIED" in call_payload["prototext"]

    method_err = json.loads(lines[4])
    assert method_err["id"] == 5
    assert method_err["error"]["code"] == -32601

    parse_err = json.loads(lines[5])
    assert parse_err["error"]["code"] == -32700


def test_mcp_main_ignores_ail_mcp_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_in = io.StringIO(json.dumps({"jsonrpc": "2.0", "id": 10, "method": "ping"}) + "\n")
    fake_out = io.StringIO()
    monkeypatch.setattr(sys, "argv", ["ail", "mcp"])
    monkeypatch.setattr(sys, "stdin", fake_in)
    monkeypatch.setattr(sys, "stdout", fake_out)
    rc = mcp_server.main()
    assert rc == 0
    resp = json.loads(fake_out.getvalue().strip())
    assert resp == {"jsonrpc": "2.0", "id": 10, "result": {}}


def test_mcp_check_and_prove_verified_and_rejected() -> None:
    res_ok, ok_payload = _call_tool_payload(
        "ail_check_and_prove",
        {"path": str(EXAMPLES / "financial_kernel.ail")},
    )
    assert res_ok["isError"] is False
    assert ok_payload["verified"] is True
    assert ok_payload["status"] == "STATUS_VERIFIED"
    assert len(ok_payload["proof_stats"]) >= 4
    assert "STATUS_VERIFIED" in ok_payload["prototext"]

    buggy_src = """
    (fn bad_mid ((lo u64[0..MAX]) (hi u64[lo..MAX]))
      u64[lo..hi]
      (/ (+ lo hi) 2))
    """
    res_bad, bad_payload = _call_tool_payload("ail_check_and_prove", {"source": buggy_src})
    assert res_bad["isError"] is False
    assert bad_payload["verified"] is False
    assert bad_payload["status"] == "STATUS_REJECTED"
    assert bad_payload["diagnostics"][0]["code"] == "E_U64_OVERFLOW"
    assert bad_payload["diagnostics"][0]["repair_hint"]
    assert "E_U64_OVERFLOW" in bad_payload["prototext"]


def test_mcp_audit_spec_and_clover_diff() -> None:
    res_tight, tight_payload = _call_tool_payload(
        "ail_audit_spec",
        {"path": str(EXAMPLES / "sum_type_settlement.ail")},
    )
    assert res_tight["isError"] is False
    assert tight_payload["verified"] is True
    assert len(tight_payload["spec_audits"]) == 3
    assert all(a["non_vacuous"] and a["uniquely_tight"] for a in tight_payload["spec_audits"])

    weak_src = """
    (fn weak_add ((a u64[0..1000]) (b u64[0..1000]))
      u64[0..2000]
      (+ a b))
    """
    res_weak, weak_payload = _call_tool_payload("ail_audit_spec", {"source": weak_src})
    assert res_weak["isError"] is False
    assert weak_payload["verified"] is False
    assert weak_payload["diagnostics"][0]["code"] == "E_SPEC_MUTANT_SURVIVED"
    assert weak_payload["spec_audits"][0]["surviving_mutants"]

    res_diff, diff_payload = _call_tool_payload(
        "ail_audit_spec",
        {
            "path": str(EXAMPLES / "ambiguous_specs" / "candidate_a.ail"),
            "spec_b_path": str(EXAMPLES / "ambiguous_specs" / "candidate_b.ail"),
        },
    )
    assert res_diff["isError"] is False
    assert diff_payload["verified"] is False
    assert diff_payload["spec_diffs"][0]["equivalent"] is False
    assert diff_payload["spec_diffs"][0]["distinguishing_input"]
    assert diff_payload["diagnostics"][0]["code"] == "E_SPEC_AMBIGUITY"


def test_mcp_repair_code_broken_draft() -> None:
    broken_src = (EXAMPLES / "broken_agent_draft.ail").read_text(encoding="utf-8")
    res_rep, rep_payload = _call_tool_payload(
        "ail_repair_code",
        {"source": broken_src, "max_iters": 12, "require_tight_specs": True},
    )
    assert res_rep["isError"] is False
    assert rep_payload["verified"] is True
    assert rep_payload["final_status"] == "STATUS_VERIFIED"
    assert rep_payload["iterations"] >= 4
    assert len(rep_payload["steps"]) >= 4
    assert rep_payload["repaired_ail_source"]

    _, check_payload = _call_tool_payload(
        "ail_audit_spec",
        {"source": rep_payload["repaired_ail_source"]},
    )
    assert check_payload["verified"] is True


def test_mcp_compile_target_all_backends_and_imports(tmp_path: Path) -> None:
    for tgt in ("native", "wasm", "c", "rust"):
        res_one, one_payload = _call_tool_payload(
            "ail_compile_target",
            {
                "target": tgt,
                "path": str(EXAMPLES / "signed_struct_quote.ail"),
                "out_dir": str(tmp_path / f"single_{tgt}"),
                "require_tight_specs": True,
            },
        )
        assert res_one["isError"] is False
        assert one_payload["verified"] is True
        assert one_payload["compiled"] is True
        assert one_payload["targets"][tgt]["ok"] is True

    res_all, all_payload = _call_tool_payload(
        "ail_compile_target",
        {
            "target": "all",
            "path": str(EXAMPLES / "wire_frame_parser.ail"),
            "out_dir": str(tmp_path / "all_wire"),
            "require_tight_specs": False,
        },
    )
    assert res_all["isError"] is False
    assert all_payload["verified"] is True
    assert all_payload["compiled"] is True

    nat = all_payload["targets"]["native"]
    assert nat["ok"] is True
    assert Path(nat["binary_or_lib_path"]).is_file()
    assert Path(nat["c_header_path"]).is_file()
    assert Path(nat["python_bindings_path"]).is_file()
    assert nat["llvm_ir"]

    wasm = all_payload["targets"]["wasm"]
    assert wasm["ok"] is True
    assert Path(wasm["wasm_path"]).read_bytes()[:4] == b"\x00asm"
    assert Path(wasm["wat_path"]).is_file()
    assert Path(wasm["js_wrapper_path"]).is_file()
    assert Path(wasm["ts_dts_path"]).is_file()
    assert wasm["wasm_size_bytes"] > 0
    assert wasm["wasm_base64"]

    c_art = all_payload["targets"]["c"]
    assert c_art["ok"] is True
    assert Path(c_art["c_source_path"]).is_file()
    assert Path(c_art["c_header_path"]).is_file()
    assert Path(c_art["shared_lib_path"]).is_file()

    rust_art = all_payload["targets"]["rust"]
    assert rust_art["ok"] is True
    assert Path(rust_art["cargo_toml_path"]).is_file()
    assert Path(rust_art["rlib_path"]).is_file()
    assert "#![no_std]" in Path(rust_art["lib_rs_path"]).read_text(encoding="utf-8")
    assert "#![forbid(unsafe_code)]" in Path(rust_art["lib_rs_path"]).read_text(encoding="utf-8")

    res_bad_tgt, bad_tgt_payload = _call_tool_payload(
        "ail_compile_target",
        {"target": "invalid_target", "path": str(EXAMPLES / "signed_struct_quote.ail")},
    )
    assert res_bad_tgt["isError"] is True
    assert "Invalid target" in bad_tgt_payload["error"]


def test_mcp_imports_and_consts_across_tools(tmp_path: Path) -> None:
    src_with_import = """
    (import "stdlib/math")
    (const FEE_MAX u64 2500)
    (spec exact_adj ((a int) (b int) (fee int))
      (+ (min (+ a b) MAX) fee))
    (fn sat_with_fee ((a u64[0..MAX]) (b u64[0..MAX]) (fee u64[0..FEE_MAX]))
      (out u64[0..MAX]
        (<= out MAX))
      (call sat_add_u64 (call sat_add_u64 a b) fee))
    """
    res_chk, chk_payload = _call_tool_payload("ail_check_and_prove", {"source": src_with_import})
    assert res_chk["isError"] is False
    assert chk_payload["verified"] is True
    assert any(st["item_name"] == "sat_with_fee" for st in chk_payload["proof_stats"])

    res_cmp, cmp_payload = _call_tool_payload(
        "ail_compile_target",
        {"target": "wasm", "source": src_with_import, "out_dir": str(tmp_path / "imp_wasm")},
    )
    assert res_cmp["isError"] is False
    assert cmp_payload["compiled"] is True
    assert Path(cmp_payload["targets"]["wasm"]["wasm_path"]).read_bytes()[:4] == b"\x00asm"

    broken_with_import = """
    (import "stdlib/math")
    (const LIM u64 500)
    (fn weak_diff ((x u64[0..LIM]) (y u64[0..LIM]))
      u64[0..LIM]
      (- x y))
    """
    res_rep, rep_payload = _call_tool_payload(
        "ail_repair_code",
        {"source": broken_with_import, "max_iters": 8, "require_tight_specs": True},
    )
    assert res_rep["isError"] is False
    assert rep_payload["verified"] is True
    assert rep_payload["iterations"] >= 1

    mod_a = tmp_path / "cyc_a.ail"
    mod_b = tmp_path / "cyc_b.ail"
    mod_a.write_text('(import "cyc_b")\n(fn fa ((x u64[0..10])) u64[0..10] x)\n', encoding="utf-8")
    mod_b.write_text('(import "cyc_a")\n(fn fb ((x u64[0..10])) u64[0..10] x)\n', encoding="utf-8")
    res_cyc, cyc_payload = _call_tool_payload("ail_check_and_prove", {"path": str(mod_a)})
    assert res_cyc["isError"] is False
    assert cyc_payload["verified"] is False
    assert cyc_payload["diagnostics"][0]["code"] == "E_IMPORT_CYCLE"


def test_mcp_ail_cli_entrypoint_stdio() -> None:
    ail_bin = ROOT / ".venv" / "bin" / "ail"
    assert ail_bin.is_file()
    reqs = "\n".join(
        [
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "ail_stdlib_catalog", "arguments": {}}}),
        ]
    ) + "\n"
    proc = subprocess.run(
        [str(ail_bin), "mcp"],
        input=reqs,
        text=True,
        capture_output=True,
        cwd=str(ROOT),
        timeout=30,
        check=True,
    )
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    assert len(lines) == 2
    assert json.loads(lines[0])["result"]["serverInfo"]["name"] == "ailang-mcp"
    cat = json.loads(json.loads(lines[1])["result"]["content"][0]["text"])
    assert cat["available"] is True
    assert {m["name"] for m in cat["modules"]} == {"bits", "finance", "math", "parse"}


def test_mcp_stdlib_catalog() -> None:
    res, payload = _call_tool_payload("ail_stdlib_catalog", {"include_source": False})
    assert res["isError"] is False
    assert payload["available"] is True
    assert payload["module_count"] == 4
    by_name = {m["name"]: m for m in payload["modules"]}
    assert set(by_name.keys()) == {"bits", "finance", "math", "parse"}
    assert "midpoint_u64" in {f["name"] for f in by_name["math"]["functions"]}
    assert "Quote2Way" in {s["name"] for s in by_name["finance"]["structs"]}
    assert "has_ail_magic" in {f["name"] for f in by_name["parse"]["functions"]}
    assert "pack_u32_pair" in {f["name"] for f in by_name["bits"]["functions"]}

    res_f, fin_payload = _call_tool_payload(
        "ail_stdlib_catalog",
        {"module": "stdlib/finance", "include_source": True},
    )
    assert res_f["isError"] is False
    assert fin_payload["module_count"] == 1
    assert "mul_bps_floor" in fin_payload["modules"][0]["source"]


def _validate_plugin_bundle(plugin_dir: Path) -> dict:
    assert plugin_dir.is_dir(), f"Missing plugin dir: {plugin_dir}"

    plugin_json_path = plugin_dir / "plugin.json"
    assert plugin_json_path.is_file()
    manifest = json.loads(plugin_json_path.read_text(encoding="utf-8"))

    unknown_keys = set(manifest.keys()) - ALLOWED_PLUGIN_JSON_KEYS
    assert not unknown_keys, f"Unsupported plugin.json fields: {unknown_keys}"
    assert manifest["name"] == "ailang"
    assert manifest["displayName"] == "AIL Verified Kernel Compiler"
    assert manifest["version"] == "1.0.0"
    assert manifest["repository"] == "https://github.com/tachyon-ops/ailang"
    assert manifest["logo"] == "assets/logo.svg"
    assert isinstance(manifest["description"], str) and len(manifest["description"]) > 20
    prompts = manifest["suggestedPrompts"]
    assert isinstance(prompts, list) and len(prompts) == 3
    assert all(isinstance(p, str) and p.strip() for p in prompts)

    logo_path = plugin_dir / manifest["logo"]
    assert logo_path.is_file()
    svg_root = ET.fromstring(logo_path.read_text(encoding="utf-8"))
    assert svg_root.attrib.get("viewBox") == "0 0 128 128"

    mcp_cfg_path = plugin_dir / "mcp_config.json"
    assert mcp_cfg_path.is_file()
    mcp_cfg = json.loads(mcp_cfg_path.read_text(encoding="utf-8"))
    srv = mcp_cfg["mcpServers"]["ailang-mcp"]
    assert srv["command"].endswith("uv")
    assert "ail" in srv["args"] and "mcp" in srv["args"]

    skill_path = plugin_dir / "skills" / "ailang" / "SKILL.md"
    assert skill_path.is_file()
    skill_text = skill_path.read_text(encoding="utf-8")
    assert skill_text.startswith("---\n")
    assert "name: ailang" in skill_text

    agent_path = plugin_dir / "agents" / "ail-kernel-synthesizer.md"
    assert agent_path.is_file()
    agent_text = agent_path.read_text(encoding="utf-8")
    assert agent_text.startswith("---\n")
    assert "name: ail-kernel-synthesizer" in agent_text

    rules_path = plugin_dir / "rules" / "AGENTS.md"
    assert rules_path.is_file()
    rules_text = rules_path.read_text(encoding="utf-8")
    assert not rules_text.startswith("---"), "rules/AGENTS.md must be plain markdown without YAML frontmatter"
    assert "ail_check_and_prove" in rules_text
    return srv


def test_antigravity_plugin_schema_and_files() -> None:
    srv = _validate_plugin_bundle(REPO_PLUGIN)
    assert srv["command"] == "uv"
    assert srv["args"] == ["run", "ail", "mcp"]


def test_repo_and_installed_plugins_match_exactly() -> None:
    if not INSTALLED_PLUGIN.is_dir():
        return

    srv = _validate_plugin_bundle(INSTALLED_PLUGIN)
    args = srv["args"]
    assert "--directory" in args
    dir_idx = args.index("--directory")
    assert dir_idx + 1 < len(args) and Path(args[dir_idx + 1]).resolve() == ROOT.resolve()

    repo_files = sorted(p.relative_to(REPO_PLUGIN) for p in REPO_PLUGIN.rglob("*") if p.is_file())
    inst_files = sorted(p.relative_to(INSTALLED_PLUGIN) for p in INSTALLED_PLUGIN.rglob("*") if p.is_file())
    assert repo_files == inst_files
    for rel in repo_files:
        if rel == Path("mcp_config.json"):
            continue
        assert (REPO_PLUGIN / rel).read_bytes() == (INSTALLED_PLUGIN / rel).read_bytes(), f"Mismatch in {rel}"
