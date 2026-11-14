"""Live LLM Spec-to-Silicon Benchmark Harness (`ail bench-llm`) & Native Execution Scorer."""

from __future__ import annotations
from collections.abc import Callable
from dataclasses import dataclass
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time
import urllib.request
import tiktoken

from ailang import ail_agent_pb2 as pb
from ailang.codegen_llvm import compile_llvm_to_native
from ailang.diagnostics import AILCompilerError, to_prototext
from ailang.ownership import check_module_ownership_v2
from ailang.parser import parse_source
from ailang.spec_firewall import audit_module_specifications
from ailang.verifier import ModuleVerifier

AIL_V3_GRAMMAR_PROMPT = """\
AIL (v0.3) Reference Card — Output ONLY valid AIL S-expressions (no markdown fences, no prose):

1. Top-level forms (optionally wrapped in `(module <name> ...)`):
   (spec <name> ((<p> int|<Struct>|<Enum>) ...) <expr>)
   (struct <Name> ((<f1> u64[lo..hi]) (<f2> u64[f1..hi]) ...))
   (enum <Name> (<Var1> (<f1> T1) ...) (<Var2>))
   (fn <name> ((<p> <Type>) ...) <RetSpec> <body>)

2. Types & Refinements:
   u64 | u64[lo..hi] | MAX        (unsigned 64-bit; literals >= 0)
   i64 | i64[lo..hi] | MIN_I64 | MAX_I64  (signed 64-bit; negative literals allowed, e.g. -50)
   (slice len_var u64[lo..hi])
   cap.io | cap.fs | cap.net      (single-use linear capabilities)
   Strict separation: NEVER mix u64 and i64 without (to_i64 x) or (to_u64 x)!

3. Expressions:
   + - * / % min max & | ^ >> << ~ == != < <= > >= and or not
   (let ((x e1) (y e2)) body) | (if cond t f) | (call fn_name arg...)
   (make StructName f1 f2 ...) | (field s fname)
   (variant EnumName VarName a0 ...) | (is_variant e VarName)
   (match scrut ((Var1 b0 ...) e1) ... (_ fallback))   ; exhaustive over all variants!
   (fold (i n) (acc init u64[lo..hi]) step_expr) | (get buf idx)

4. Division & Anti-Overflow Rules:
   - Avoid `(notional * bps)` overflow by quotient-remainder decomposition:
     (+ (* (/ notional 10000) bps) (/ (* (% notional 10000) bps) 10000))
   - Signed `i64` `/` truncates toward 0 (C/LLVM `sdiv`): inside `(spec ...)`, write `(trunc_div a b)` instead of `(/ a b)`!

5. Tight SpecMut Requirement (for pure scalar/struct/enum `fn`):
   Pair `(spec exact_<fn> ...)` with named return `(out u64[lo..hi] (== out (exact_<fn> ...)))` (or `i64[lo..hi]`).

6. Linear Capability Intrinsics (thread tokens strictly once, close before returning):
   (io.print_u64 io val) -> cap.io | (io.print_i64 io val) -> cap.io | (io.done io ret) -> u64
   (fs.write_u64 fs val) -> cap.fs | (fs.write_i64 fs val) -> cap.fs | (fs.close fs) -> u64
   (net.loopback_send_u64 net port val) -> cap.net (port verified in [1024..65535]) | (net.close net) -> u64
"""


@dataclass(frozen=True)
class LLMBenchTask:
    task_id: str
    prompt_spec: str
    require_tight_specs: bool
    verifier: Callable[[Path, pb.BuildArtifacts], tuple[bool, str]]


def _load_bindings(bindings_path: str):
    spec = importlib.util.spec_from_file_location(f"ail_llm_{Path(bindings_path).stem}_{time.time_ns()}", bindings_path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _verify_clamped_rebate(_wd: Path, art: pb.BuildArtifacts) -> tuple[bool, str]:
    b = _load_bindings(art.python_bindings_path)
    cases = [
        ((0, 500, 100), 0),
        ((10**15, 9999, 10**15), 999_900_000_000_000),
        ((10**15, 9999, 500_000), 500_000),
        ((123_456, 250, 999_999), 3_086),
    ]
    for args, want in cases:
        got = b.clamped_rebate(*args)
        if got != want:
            return False, f"clamped_rebate{args} returned {got}, expected {want}"
    return True, "ok"


def _verify_signed_sensor_step(_wd: Path, art: pb.BuildArtifacts) -> tuple[bool, str]:
    b = _load_bindings(art.python_bindings_path)
    cases = [((-15, 0), -3), ((15, 0), 3), ((-100_000, 100_000), -50_000), ((100, 100), 0)]
    for args, want in cases:
        got = b.sensor_step(*args)
        if got != want:
            return False, f"sensor_step{args} returned {got}, expected {want}"
    return True, "ok"


def _verify_dependent_window(_wd: Path, art: pb.BuildArtifacts) -> tuple[bool, str]:
    b = _load_bindings(art.python_bindings_path)
    w = b.make_win(500_000, 123_456)
    if (w.lo, w.hi) != (500_000, 623_456):
        return False, f"make_win returned ({w.lo}, {w.hi}), expected (500000, 623456)"
    span = b.win_span(w)
    if span != 123_456:
        return False, f"win_span returned {span}, expected 123456"
    return True, "ok"


def _verify_enum_ticket(_wd: Path, art: pb.BuildArtifacts) -> tuple[bool, str]:
    b = _load_bindings(art.python_bindings_path)
    t_won = b.Ticket.Won(250, 40)
    t_ref = b.Ticket.Refunded(777)
    t_void = b.Ticket.Void()
    checks = [(b.ticket_payout(t_won), 10_000), (b.ticket_payout(t_ref), 777), (b.ticket_payout(t_void), 0)]
    for got, want in checks:
        if got != want:
            return False, f"ticket_payout mismatch: got {got}, expected {want}"
    return True, "ok"


def _verify_folded_energy(_wd: Path, art: pb.BuildArtifacts) -> tuple[bool, str]:
    import ctypes

    b = _load_bindings(art.python_bindings_path)
    empty = (ctypes.c_uint64 * 1)(0)
    if b.sum_energy(0, empty) != 0:
        return False, "sum_energy(0) != 0"
    arr5 = (ctypes.c_uint64 * 5)(100, 200, 300, 400, 500)
    if b.sum_energy(5, arr5) != 1500:
        return False, "sum_energy(5) != 1500"
    arr100 = (ctypes.c_uint64 * 100)(*([50_000] * 100))
    if b.sum_energy(100, arr100) != 5_000_000:
        return False, "sum_energy(100) != 5000000"
    return True, "ok"


def _verify_sandboxed_beacon(wd: Path, art: pb.BuildArtifacts) -> tuple[bool, str]:
    fs_log = wd / "beacon_fs.log"
    if fs_log.exists():
        fs_log.unlink()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
        udp_sock.bind(("127.0.0.1", 0))
        udp_sock.settimeout(3.0)
        port = udp_sock.getsockname()[1]

        runner = (
            f"import importlib.util; "
            f"sp = importlib.util.spec_from_file_location('sb', {art.python_bindings_path!r}); "
            f"m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m); "
            f"rc = m.send_beacon({port}, 42); print('RET=' + str(rc))"
        )
        env = dict(os.environ, AIL_FS_OUT=str(fs_log))
        out = subprocess.check_output([sys.executable, "-c", runner], env=env, text=True).strip().splitlines()
        if out != ["42", "RET=0"]:
            return False, f"Unexpected stdout from send_beacon: {out}"
        if not fs_log.exists() or fs_log.read_text().strip().splitlines() != ["42"]:
            return False, f"Unexpected AIL_FS_OUT contents: {fs_log.read_text() if fs_log.exists() else '<missing>'}"
        pkt, sender = udp_sock.recvfrom(64)
        if sender[0] != "127.0.0.1" or len(pkt) != 8 or struct.unpack("<Q", pkt)[0] != 42:
            return False, f"Unexpected UDP packet from {sender}: {pkt!r}"
    return True, "ok"


BENCHMARK_TASKS: list[LLMBenchTask] = [
    LLMBenchTask(
        task_id="clamped_bps_rebate",
        prompt_spec=(
            "Define function `(fn clamped_rebate ((notional u64[0..1000000000000000]) (bps u64[0..10000]) (cap u64[0..1000000000000000])) ...)` "
            "computing `min(cap, (notional * bps) / 10000)` without 64-bit multiplication overflow, paired with an exact `(spec exact_clamped_rebate ((notional int) (bps int) (cap int)) ...)` postcondition passing SpecMut."
        ),
        require_tight_specs=True,
        verifier=_verify_clamped_rebate,
    ),
    LLMBenchTask(
        task_id="signed_sensor_step",
        prompt_spec=(
            "Define function `(fn sensor_step ((curr i64[-100000..100000]) (base i64[-100000..100000])) ...)` "
            "computing C-truncating signed division `(/ (- curr base) 4)`, paired with an exact `(spec exact_sensor_step ((curr int) (base int)) (trunc_div (- curr base) 4))` postcondition passing SpecMut."
        ),
        require_tight_specs=True,
        verifier=_verify_signed_sensor_step,
    ),
    LLMBenchTask(
        task_id="dependent_window_span",
        prompt_spec=(
            "Define dependent struct `(struct Window ((lo u64[0..1000000000]) (hi u64[lo..1000000000])))`, constructor "
            "`(fn make_win ((lo u64[0..999000000]) (width u64[0..1000000])) Window ...)`, and `(fn win_span ((w Window)) ...)` "
            "returning `(- (field w hi) (field w lo))` with an exact `(spec exact_win_span ((w Window)) ...)` postcondition passing SpecMut."
        ),
        require_tight_specs=True,
        verifier=_verify_dependent_window,
    ),
    LLMBenchTask(
        task_id="enum_ticket_payout",
        prompt_spec=(
            "Define `(enum Ticket (Won (stake u64[1..1000000]) (mult u64[1..1000])) (Refunded (stake u64[1..1000000])) (Void))` "
            "and `(fn ticket_payout ((t Ticket)) ...)` using exhaustive `(match t ...)` returning `(* stake mult)` for `Won`, `stake` for `Refunded`, and `0` for `Void`, paired with an exact `(spec exact_ticket_payout ((t Ticket)) ...)` postcondition passing SpecMut."
        ),
        require_tight_specs=True,
        verifier=_verify_enum_ticket,
    ),
    LLMBenchTask(
        task_id="folded_energy_sum",
        prompt_spec=(
            "Define `(fn sum_energy ((n u64[0..1000]) (readings (slice n u64[0..50000]))) u64[0..50000000] ...)` "
            "that sums elements `0..n-1` of `readings` via bounded O(1) `(fold (i n) (acc 0 u64[0..(* i 50000)]) (+ acc (get readings i)))`."
        ),
        require_tight_specs=False,
        verifier=_verify_folded_energy,
    ),
    LLMBenchTask(
        task_id="sandboxed_beacon",
        prompt_spec=(
            "Define `(fn send_beacon ((io cap.io) (fs cap.fs) (net cap.net) (port u64[1024..65535]) (code u64[0..1000])) u64[0..0] ...)` "
            "that prints `code` via `io.print_u64`, appends `code` via `fs.write_u64`, sends `code` over UDP to `port` via `net.loopback_send_u64`, "
            "closes both `fs` and `net` with `fs.close` and `net.close`, and finishes with `(io.done ... 0)`."
        ),
        require_tight_specs=False,
        verifier=_verify_sandboxed_beacon,
    ),
]


def _strip_fences(raw: str) -> str:
    s = raw.strip()
    if s.startswith("```"):
        lines = s.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        s = "\n".join(lines).strip()
    return s + "\n"


def evaluate_candidate_source(
    task: LLMBenchTask,
    ail_source: str,
    work_dir: Path,
) -> tuple[bool, pb.CompilerResponse, str]:
    t0 = time.perf_counter()
    resp = pb.CompilerResponse()
    task_dir = work_dir / task.task_id
    task_dir.mkdir(parents=True, exist_ok=True)
    clean_src = _strip_fences(ail_source)

    try:
        forms = parse_source(clean_src)
        tenv = check_module_ownership_v2(forms)
        mv = ModuleVerifier(tenv)
        stats = mv.verify_module(forms)
        resp.proof_stats.extend(stats)
        if task.require_tight_specs:
            audits, diags = audit_module_specifications(forms, tenv)
            resp.spec_audits.extend(audits)
            if diags:
                resp.diagnostics.extend(diags)
                resp.status = pb.STATUS_REJECTED
                resp.total_elapsed_ms = (time.perf_counter() - t0) * 1000.0
                return False, resp, clean_src

        art = compile_llvm_to_native(forms, tenv, task_dir, task.task_id, build_shared_lib=True)
        resp.artifacts.CopyFrom(art)
        resp.status = pb.STATUS_VERIFIED
        resp.total_elapsed_ms = (time.perf_counter() - t0) * 1000.0
    except AILCompilerError as err:
        resp.status = pb.STATUS_REJECTED
        resp.diagnostics.append(err.diag)
        resp.total_elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return False, resp, clean_src
    except Exception as exc:
        resp.status = pb.STATUS_REJECTED
        resp.diagnostics.append(
            pb.Diagnostic(
                code=pb.E_SYNTAX,
                stage=pb.STAGE_LLVM_CODEGEN,
                item_name=task.task_id,
                message=f"Compilation/FFI error: {exc}",
            )
        )
        resp.total_elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return False, resp, clean_src

    try:
        ok, msg = task.verifier(task_dir, art)
    except Exception as exc:
        ok, msg = False, f"Native test harness exception: {exc}"

    if not ok:
        resp.status = pb.STATUS_REJECTED
        resp.diagnostics.append(
            pb.Diagnostic(
                code=pb.E_POSTCONDITION_FAILED,
                stage=pb.STAGE_LLVM_CODEGEN,
                item_name=task.task_id,
                message=f"Compiled binary failed functional vector check: {msg}",
            )
        )
    return ok, resp, clean_src


def _gemini_generate(model: str, prompt: str) -> str:
    key = (os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or "").strip()
    if not key:
        raise AILCompilerError(
            pb.E_CAPABILITY_MISSING,
            pb.STAGE_AGENT_REPAIR,
            "<gemini>",
            "GEMINI_API_KEY or GOOGLE_API_KEY must be set for `--provider gemini`.",
        )
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
    payload = json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data["candidates"][0]["content"]["parts"][0]["text"]


def _openai_generate(model: str, prompt: str) -> str:
    key = os.environ.get("OPENAI_API_KEY", "").strip()
    base = os.environ.get("AIL_LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    if not key and "127.0.0.1" not in base and "localhost" not in base:
        raise AILCompilerError(
            pb.E_CAPABILITY_MISSING,
            pb.STAGE_AGENT_REPAIR,
            "<openai>",
            "OPENAI_API_KEY (or local AIL_LLM_BASE_URL) must be set for `--provider openai`.",
        )
    url = f"{base}/chat/completions"
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    payload = json.dumps(
        {
            "model": model,
            "temperature": 0.0,
            "messages": [{"role": "user", "content": prompt}],
        }
    ).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=45) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data["choices"][0]["message"]["content"]


LLMTaskCallback = Callable[[LLMBenchTask, int, str | None, pb.CompilerResponse | None], str]


def format_llm_benchmark_markdown(report: pb.LLMBenchReport) -> str:
    t1_pct = (100.0 * report.tasks_passed_turn1 / report.tasks_total) if report.tasks_total else 0.0
    fin_pct = (100.0 * report.tasks_passed_final / report.tasks_total) if report.tasks_total else 0.0
    lines = [
        f"# Live LLM Spec-to-Silicon Benchmark (`{report.provider}` / `{report.model_name}`)",
        "",
        f"- **Turn-1 Verified Pass Rate:** **{report.tasks_passed_turn1}/{report.tasks_total}** ({t1_pct:.1f}%)",
        f"- **Final Pass Rate (with Protobuf Feedback Loop):** **{report.tasks_passed_final}/{report.tasks_total}** ({fin_pct:.1f}%)",
        f"- **Average Generated AIL Tokens (`o200k_base`):** **{report.avg_tokens:.1f}**",
        f"- **Total Benchmark Wall Time:** **{report.total_elapsed_ms:.1f} ms**",
        "",
        "| Task | Passed | Turns Used | AIL Tokens | Elapsed (`ms`) | Protobuf Errors Caught & Repaired |",
        "| :--- | :---: | :---: | :---: | :---: | :--- |",
    ]
    for r in report.results:
        errs = ", ".join(pb.ErrorCode.Name(e) for e in r.triggered_errors) or "None (Turn-1 Verified)"
        lines.append(
            f"| `{r.task_id}` | **{'PASS' if r.passed else 'FAIL'}** | {r.turns_used} | {r.generated_tokens} | {r.total_ms:.1f} | `{errs}` |"
        )
    lines.append("")
    return "\n".join(lines)


def run_llm_benchmark(
    work_dir: Path,
    provider: str = "gemini",
    model_name: str = "gemini-2.5-flash",
    max_turns: int = 4,
    llm_generator: LLMTaskCallback | None = None,
) -> tuple[pb.LLMBenchReport, str]:
    work_dir.mkdir(parents=True, exist_ok=True)
    enc = tiktoken.get_encoding("o200k_base")
    t_all0 = time.perf_counter()

    results: list[pb.LLMBenchTaskResult] = []
    passed_t1 = 0
    passed_final = 0
    total_tokens = 0

    for task in BENCHMARK_TASKS:
        t0 = time.perf_counter()
        prev_src: str | None = None
        prev_resp: pb.CompilerResponse | None = None
        errs: list[int] = []
        passed = False
        turns_used = 0
        last_toks = 0

        for turn in range(1, max_turns + 1):
            turns_used = turn
            if llm_generator is not None:
                raw_src = llm_generator(task, turn, prev_src, prev_resp)
            else:
                if turn == 1 or prev_resp is None:
                    prompt = f"{AIL_V3_GRAMMAR_PROMPT}\n\nTASK `{task.task_id}`:\n{task.prompt_spec}\n"
                else:
                    prompt = (
                        f"{AIL_V3_GRAMMAR_PROMPT}\n\nTASK `{task.task_id}`:\n{task.prompt_spec}\n\n"
                        f"Your previous draft failed formal verification / testing:\n{prev_src}\n\n"
                        f"CompilerResponse (Protobuf TextFormat):\n{to_prototext(prev_resp)}\n\n"
                        "Fix every diagnostic above and output ONLY corrected AIL code."
                    )
                raw_src = _gemini_generate(model_name, prompt) if provider == "gemini" else _openai_generate(model_name, prompt)

            ok, resp, clean_src = evaluate_candidate_source(task, raw_src, work_dir)
            last_toks = len(enc.encode(clean_src))
            prev_src = clean_src
            prev_resp = resp
            if ok:
                passed = True
                if turn == 1:
                    passed_t1 += 1
                passed_final += 1
                break
            for d in resp.diagnostics:
                errs.append(d.code)

        total_tokens += last_toks
        results.append(
            pb.LLMBenchTaskResult(
                task_id=task.task_id,
                passed=passed,
                turns_used=turns_used,
                generated_tokens=last_toks,
                total_ms=(time.perf_counter() - t0) * 1000.0,
                triggered_errors=errs,
            )
        )

    n = len(BENCHMARK_TASKS)
    report = pb.LLMBenchReport(
        provider=provider,
        model_name=model_name,
        tasks_total=n,
        tasks_passed_turn1=passed_t1,
        tasks_passed_final=passed_final,
        avg_tokens=(total_tokens / n) if n else 0.0,
        total_elapsed_ms=(time.perf_counter() - t_all0) * 1000.0,
        results=results,
    )
    return report, format_llm_benchmark_markdown(report)
