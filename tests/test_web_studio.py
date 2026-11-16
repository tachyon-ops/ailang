"""Tests for AIL v1.0 Web Studio server, API endpoints, static demos.json, and Modern Web Guidance compliance."""

from __future__ import annotations

import base64
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import shutil
import subprocess
import threading
import urllib.error
import urllib.request

import pytest

from ailang.web_server import (
    DEFAULT_WEB_DIR,
    create_studio_server,
    generate_static_demos,
)


class _StudioHTMLInspector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_head = False
        self.meta_color_scheme: list[str] = []
        self.tablist_attrs: list[dict[str, str | None]] = []
        self.tab_buttons: list[dict[str, str | None]] = []
        self.tabpanels: list[dict[str, str | None]] = []
        self.panel_inners = 0
        self.table_wrappers: list[dict[str, str | None]] = []

    def handle_starttag(self, tag: str, attrs_list: list[tuple[str, str | None]]) -> None:
        attrs = dict(attrs_list)
        if tag == "head":
            self.in_head = True
        elif tag == "meta" and self.in_head and attrs.get("name") == "color-scheme":
            if attrs.get("content"):
                self.meta_color_scheme.append(attrs["content"] or "")
        elif tag == "div" and attrs.get("role") == "tablist":
            self.tablist_attrs.append(attrs)
        elif tag == "button" and attrs.get("role") == "tab":
            self.tab_buttons.append(attrs)
        elif tag == "div" and attrs.get("role") == "tabpanel":
            self.tabpanels.append(attrs)
        elif tag == "div" and "panel-inner" in (attrs.get("class") or "").split():
            self.panel_inners += 1
        elif tag == "div" and "table-wrapper" in (attrs.get("class") or "").split():
            self.table_wrappers.append(attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag == "head":
            self.in_head = False


def _http_get(base_url: str, path: str) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(f"{base_url}{path}", method="GET")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as err:
        return err.code, dict(err.headers), err.read()


def _http_post_json(base_url: str, path: str, payload: dict) -> tuple[int, dict]:
    raw = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url}{path}",
        data=raw,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read().decode("utf-8"))


@pytest.fixture()
def studio_server():
    srv = create_studio_server(host="127.0.0.1", port=0, quiet=True)
    host, port = srv.server_address[:2]
    assert host == "127.0.0.1"
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{host}:{port}"
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=3)


def test_mwg_compliance_dark_mode_tabs_responsive_table() -> None:
    html_text = (DEFAULT_WEB_DIR / "index.html").read_text(encoding="utf-8")
    css_text = (DEFAULT_WEB_DIR / "styles.css").read_text(encoding="utf-8")
    js_text = (DEFAULT_WEB_DIR / "app.js").read_text(encoding="utf-8")

    inspector = _StudioHTMLInspector()
    inspector.feed(html_text)

    # 1. dark-mode compliance
    assert "light dark" in inspector.meta_color_scheme
    assert "color-scheme: light dark;" in css_text
    assert "@media (prefers-color-scheme: dark)" in css_text
    assert "@supports (color: light-dark(white, black))" in css_text
    assert not re.search(r"transition[^;]*scrollbar-color", css_text)

    # 2. tabs compliance
    assert len(inspector.tablist_attrs) == 1
    assert inspector.tablist_attrs[0].get("focusgroup") == "tablist nomemory"
    assert len(inspector.tab_buttons) == 6
    for i, btn in enumerate(inspector.tab_buttons):
        assert btn.get("type") == "button"
        assert "aria-controls" not in btn
        if i == 0:
            assert btn.get("aria-selected") == "true"
            assert "focusgroupstart" in btn
        else:
            assert btn.get("aria-selected") == "false"
            assert "focusgroupstart" not in btn

    assert len(inspector.tabpanels) == 6
    assert inspector.panel_inners == 6
    for i, panel in enumerate(inspector.tabpanels):
        if i == 0:
            assert "hidden" not in panel
            assert panel.get("tabindex") == "0"
        else:
            assert panel.get("hidden") == "until-found"
            assert "tabindex" not in panel

    tabpanel_rule = re.search(r'\[role="tabpanel"\]\s*\{([^}]*)\}', css_text)
    assert tabpanel_rule is not None
    tabpanel_body = tabpanel_rule.group(1)
    for forbidden in ("padding", "border", "margin", "background"):
        assert forbidden not in tabpanel_body
    assert ".panel-inner" in css_text
    assert '[aria-selected="true"]::after' in css_text
    assert "border-block-end: 3px solid" in css_text
    assert "beforematch" in js_text
    assert "ArrowLeft" in js_text and "ArrowRight" in js_text
    assert "innerHTML" not in js_text
    assert 'startsWith("cap.")' in js_text

    # 3. responsive-table compliance
    assert len(inspector.table_wrappers) == 1
    tw = inspector.table_wrappers[0]
    assert tw.get("tabindex") == "0"
    assert tw.get("role") == "region"
    assert tw.get("aria-labelledby") == "benchmark-table-caption"
    assert "container-type: inline-size;" in css_text
    assert "thead {" in css_text and "position: sticky;" in css_text
    assert "tbody th" in css_text
    assert "@container (width < 600px)" in css_text
    assert "display: none;" in css_text
    assert "td:nth-child(2)::before" in css_text
    assert "var(--label-2)" in css_text


def test_studio_static_routes_and_security(studio_server: str) -> None:
    status, headers, body = _http_get(studio_server, "/")
    assert status == 200
    assert "text/html" in headers.get("Content-Type", "")
    assert b"AIL v1.1 Web Studio" in body

    for path, expected_ct in (
        ("/styles.css", "text/css"),
        ("/app.js", "application/javascript"),
    ):
        st, hdrs, _ = _http_get(studio_server, path)
        assert st == 200
        assert expected_ct in hdrs.get("Content-Type", "")

    st_trav, _, _ = _http_get(studio_server, "/../pyproject.toml")
    assert st_trav == 404


def test_studio_health_and_presets(studio_server: str) -> None:
    st, _, body = _http_get(studio_server, "/api/health")
    assert st == 200
    health = json.loads(body.decode("utf-8"))
    assert health["ok"] is True
    assert health["version"] == "1.1.0"
    assert "llvm" in health["targets"]

    st_p, _, body_p = _http_get(studio_server, "/api/presets")
    assert st_p == 200
    data = json.loads(body_p.decode("utf-8"))
    assert data["ok"] is True
    ids = [p["id"] for p in data["presets"]]
    assert ids == [
        "signed_quote",
        "sum_type_settlement",
        "defi_waterfall",
        "wire_frame_parser",
        "simd_halving",
        "broken_agent_draft",
        "wire_codec_v1_1",
    ]
    sum_preset = next(p for p in data["presets"] if p["id"] == "sum_type_settlement")
    assert sum_preset["sample_call"] == {"fn": "outcome_notional", "args": ["0,250,4000"]}
    assert len(data["benchmarks"]["kernels"]) == 5


def test_studio_compile_verified_and_rejected(studio_server: str) -> None:
    _, _, body_p = _http_get(studio_server, "/api/presets")
    presets = {p["id"]: p for p in json.loads(body_p.decode("utf-8"))["presets"]}

    # Verify & compile Sum Type Settlement
    st, res = _http_post_json(
        studio_server,
        "/api/compile",
        {"source": presets["sum_type_settlement"]["source"], "require_tight_specs": True},
    )
    assert st == 200
    assert res["verified"] is True
    assert res["status"] == "STATUS_VERIFIED"
    assert len(res["proof_stats"]) >= 4
    assert all(ps["verified"] for ps in res["proof_stats"])
    assert len(res["spec_audits"]) >= 1
    assert "define " in res["targets"]["llvm"]["ir"]
    assert "STATUS_VERIFIED" in res["prototext"]

    if res["targets"].get("wasm", {}).get("available"):
        wasm_raw = base64.b64decode(res["wasm_base64"])
        assert wasm_raw[:4] == b"\x00asm"
        assert res["wasm_size_bytes"] == len(wasm_raw)
    if res["targets"].get("c", {}).get("available"):
        assert "uint64_t" in res["targets"]["c"]["source"]
    if res["targets"].get("rust", {}).get("available"):
        assert "#![no_std]" in res["targets"]["rust"]["lib_rs"]

    # Verify & compile DeFi Waterfall (`(import "stdlib/finance")` + `(import "stdlib/math")`)
    st_df, res_df = _http_post_json(
        studio_server,
        "/api/compile",
        {"source": presets["defi_waterfall"]["source"], "require_tight_specs": True},
    )
    assert st_df == 200
    assert res_df["verified"] is True
    assert res_df["target_errors"] == {}
    assert len(res_df["wasm_base64"]) > 0

    # Verify & compile Wire Frame Parser (`bytes` + `(import "stdlib/parse")`)
    st_wf, res_wf = _http_post_json(
        studio_server,
        "/api/compile",
        {"source": presets["wire_frame_parser"]["source"], "require_tight_specs": True},
    )
    assert st_wf == 200
    assert res_wf["verified"] is True
    assert res_wf["target_errors"] == {}
    assert len(res_wf["wasm_base64"]) > 0

    # Reject Broken Agent Draft at ownership stage first (`E_LINEAR_USE_AFTER_MOVE`)
    st_bad, res_bad = _http_post_json(
        studio_server,
        "/api/compile",
        {"source": presets["broken_agent_draft"]["source"], "require_tight_specs": True},
    )
    assert st_bad == 200
    assert res_bad["verified"] is False
    assert res_bad["status"] == "STATUS_REJECTED"
    assert len(res_bad["diagnostics"]) >= 1
    assert res_bad["diagnostics"][0]["code"] == "E_LINEAR_USE_AFTER_MOVE"
    assert res_bad["wasm_base64"] == ""

    # Reject invalid JSON / empty source cleanly with 400
    st_400, err_400 = _http_post_json(studio_server, "/api/compile", {"source": "   "})
    assert st_400 == 400
    assert err_400["ok"] is False


def test_studio_repair_loop_endpoint(studio_server: str) -> None:
    _, _, body_p = _http_get(studio_server, "/api/presets")
    presets = {p["id"]: p for p in json.loads(body_p.decode("utf-8"))["presets"]}

    st, rep = _http_post_json(
        studio_server,
        "/api/repair",
        {"source": presets["broken_agent_draft"]["source"], "max_iters": 8},
    )
    assert st == 200
    assert rep["verified"] is True
    assert rep["final_status"] == "STATUS_VERIFIED"
    assert rep["iterations"] >= 4
    assert len(rep["steps"]) >= 4
    assert rep["compile"]["verified"] is True


def test_generate_static_demos_and_validate_wasm(tmp_path: Path) -> None:
    out_file = tmp_path / "demos.json"
    demos = generate_static_demos(out_file)
    assert out_file.exists()
    loaded = json.loads(out_file.read_text(encoding="utf-8"))
    assert loaded["version"] == "1.1.0"
    assert len(loaded["presets"]) == 7

    broken = next(p for p in loaded["presets"] if p["id"] == "broken_agent_draft")
    assert broken["compile"]["verified"] is False
    assert broken["repair"]["verified"] is True
    assert broken["repair"]["compile"]["verified"] is True

    wasm_samples = [
        p["compile"]["wasm_base64"]
        for p in loaded["presets"]
        if p["compile"].get("verified") and p["compile"].get("wasm_base64")
    ]
    if "wasm" in demos["targets"]:
        assert len(wasm_samples) >= 4
        node_bin = shutil.which("node")
        if node_bin:
            script = (
                "const fs = require('fs');"
                "const data = JSON.parse(fs.readFileSync(process.argv[1], 'utf8'));"
                "(async () => {"
                "  for (const p of data.presets) {"
                "    const c = p.id === 'broken_agent_draft' ? p.repair.compile : p.compile;"
                "    if (c && c.wasm_base64) {"
                "      const buf = Buffer.from(c.wasm_base64, 'base64');"
                "      if (!WebAssembly.validate(buf)) throw new Error('Invalid WASM for ' + p.id);"
                "      const mod = await WebAssembly.compile(buf);"
                "      const imp = { env: {} };"
                "      for (const i of WebAssembly.Module.imports(mod)) {"
                "        if (i.module === 'env') imp.env[i.name] = () => 0n;"
                "      }"
                "      await WebAssembly.instantiate(mod, imp);"
                "    }"
                "  }"
                "  const sq = data.presets.find(p => p.id === 'signed_quote').compile;"
                "  const sqInst = (await WebAssembly.instantiate(Buffer.from(sq.wasm_base64, 'base64'), {})).instance;"
                "  const pnl = BigInt.asIntN(64, sqInst.exports.scale_signed_pnl(-12345n));"
                "  if (pnl !== -1234n) throw new Error('Unexpected scale_signed_pnl: ' + pnl);"
                "  const wf = data.presets.find(p => p.id === 'wire_frame_parser').compile;"
                "  const wfInst = (await WebAssembly.instantiate(Buffer.from(wf.wasm_base64, 'base64'), {})).instance;"
                "  const wex = wfInst.exports;"
                "  const ptr = wex.__ail_alloc(12);"
                "  new Uint8Array(wex.memory.buffer, ptr, 12).set([65,73,76,49,1,7,0,4,0,0,0,42]);"
                "  const resPtr = wex.parse_frame(12n, ptr);"
                "  const seq = wex.frame_result_seq(resPtr);"
                "  if (seq !== 42n) throw new Error('Unexpected frame seq: ' + seq);"
                "  const df = data.presets.find(p => p.id === 'defi_waterfall').compile;"
                "  const dfInst = (await WebAssembly.instantiate(Buffer.from(df.wasm_base64, 'base64'), {})).instance;"
                "  const jp = dfInst.exports.waterfall_junior_payout(1000000n, 500000n, 250n, 2000n);"
                "  if (jp !== 495000n) throw new Error('Unexpected waterfall payout: ' + jp);"
                "})().catch(e => { console.error(e); process.exit(1); });"
            )
            subprocess.run([node_bin, "-e", script, str(out_file)], check=True)
