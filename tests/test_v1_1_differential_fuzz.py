"""Tests for AIL v1.1.0 4-target differential fuzzing engine, CLI, and MCP tool."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

from ailang.diff_fuzz import run_differential_fuzz
from ailang.mcp_server import handle_jsonrpc_message


def test_differential_fuzz_wire_codec_and_settlement(tmp_path: Path) -> None:
    rep_wire = run_differential_fuzz(
        Path("examples/wire_codec_v1_1.ail"),
        tmp_path / "fuzz_wire",
        cases=16,
        seed=42,
    )
    assert rep_wire.mismatches == 0
    assert rep_wire.first_mismatch is None
    assert rep_wire.total_executions == 14 * 16 * 4

    rep_sum = run_differential_fuzz(
        Path("examples/sum_type_settlement.ail"),
        tmp_path / "fuzz_sum",
        cases=16,
        seed=13,
    )
    assert rep_sum.mismatches == 0
    assert rep_sum.total_executions == 5 * 16 * 4


def test_cli_fuzz_json_subcommand(tmp_path: Path) -> None:
    res = subprocess.run(
        [
            sys.executable,
            "-m",
            "ailang.cli",
            "fuzz",
            "examples/sum_type_settlement.ail",
            "-o",
            str(tmp_path / "cli_fuzz"),
            "--cases",
            "8",
            "--seed",
            "99",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(res.stdout)
    assert payload["stem"] == "sum_type_settlement"
    assert payload["seed"] == 99
    assert payload["mismatches"] == 0
    assert payload["total_executions"] == 5 * 8 * 4


def test_mcp_ail_fuzz_targets_tool(tmp_path: Path) -> None:
    inline_src = """
(type Bps u64[0..10000])
(struct Pair ((x u64[1..1000000000000000]) (b Bps)))
(fn wide_fee ((p Pair))
  (out u64[0..MAX] (== out (mul_div_ceil_u64 (field p x) (field p b) 10000)))
  (mul_div_ceil_u64 (field p x) (field p b) 10000))
"""
    msg = {
        "jsonrpc": "2.0",
        "id": 77,
        "method": "tools/call",
        "params": {
            "name": "ail_fuzz_targets",
            "arguments": {
                "source": inline_src,
                "cases": 10,
                "seed": 5,
                "out_dir": str(tmp_path / "mcp_fuzz"),
            },
        },
    }
    resp = handle_jsonrpc_message(msg)
    assert "error" not in resp
    data = json.loads(resp["result"]["content"][0]["text"])
    assert data["status"] == "STATUS_VERIFIED"
    assert data["mismatches"] == 0
    assert data["total_executions"] == 10 * 4
