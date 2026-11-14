# Contributing to AIL (`ailang`)

Thank you for your interest in contributing to **AIL**, an AI-native formally verified programming language, SpecMut firewall, Protobuf agent protocol, and multi-target compiler (`LLVM` native silicon, pure-Python `WebAssembly 1.0`, ISO `C11`, and `#![no_std]` `#![forbid(unsafe_code)]` `Rust`).

---

## Development Environment

### Required Toolchain

| Component | Purpose | Notes |
| :--- | :--- | :--- |
| **Python >= 3.11** + **`uv`** | Core compiler, Z3/Bitwuzla verification, CLI, Web Studio, MCP server | Managed via `pyproject.toml` and `uv.lock` |
| **Clang** (`clang`) | Native LLVM `.ll` -> `.dylib`/`.so`/binary compilation & C11 target compilation | Compiled with `-std=c11 -O3 -Wall -Wextra -Werror` |
| **Rust** (`rustc` 2021 edition) | Rust target `.rlib` verification & parity execution | Compiled with `--edition 2021 --crate-type rlib -D warnings` |
| **Node.js** (`node`) | WebAssembly `.wasm` validation (`WebAssembly.validate`) & `.mjs` parity tests | Uses native `BigInt` 64-bit ABI |
| **Protocol Buffers** (`protoc`) | Regenerating `src/ailang/ail_agent_pb2.py` from `proto/ail_agent.proto` | Required only when modifying `proto/ail_agent.proto` |

### Local Setup

```bash
git clone https://github.com/tachyon-ops/ailang.git
cd ailang
uv sync --extra dev
uv run pytest -v
```

Verify that all CLI entrypoints work locally:

```bash
uv run ail --help
uv run ail stdlib
uv run ail check examples/sum_type_settlement.ail
```

---

## Repository Layout

- `proto/ail_agent.proto` — Canonical Protobuf schema for diagnostics, counterexamples, `ModuleProto` binary ASTs, `RepairSession`, and benchmark reports.
- `src/ailang/` — Compiler frontend, stratified verifiers, SpecMut firewall, multi-target backends, repair harness, Web Studio server, and MCP stdio server.
- `src/ailang/stdlib/` — Built-in formally verified AIL modules (`math.ail`, `finance.ail`, `bits.ail`, `parse.ail`).
- `examples/` — Reference AIL programs (financial kernels, algebraic enums, lock-free atomics, wire-frame parsers, capability-sandboxed binaries).
- `web/` — Standalone AIL Web Studio UI (`index.html`, `styles.css`, `app.js`, `demos.json`).
- `integrations/antigravity-plugin/` — Packaged Antigravity plugin (`plugin.json`, `mcp_config.json`, skills, subagent, rules).
- `tests/` — End-to-end verification, multi-target parity, Web Studio, and MCP test suites.
- `benchmarks/` — Language comparison (`human_vs_ail.md`) and blind LLM Spec-to-Silicon (`live_llm_spec_to_silicon.md`) benchmarks.

---

## Coding & Verification Standards

1. **Protobuf Schema Discipline**:
   - Whenever `proto/ail_agent.proto` changes, preserve backward-compatible field numbers, add matching repair hints in `src/ailang/diagnostics.py`, and regenerate bindings with `protoc`.
2. **Stratified Soundness First**:
   - Any new expression form, type, or stdlib primitive must preserve soundness across **all three verification tiers**: Tier 0 (`intervals.py`), Tier 1 (`bitwuzla_tier.py`), and Tier 2 (`verifier.py`), plus `spec_firewall.py`.
3. **Bit-Exact Multi-Target Parity**:
   - Changes affecting semantics or code generation must keep all four targets (`native` LLVM, `wasm`, `c`, `rust`) bit-exact under `tests/test_v1_multitarget_parity.py`.
   - Generated C11 must compile cleanly under `-std=c11 -O3 -Wall -Wextra -Werror` with zero undefined behavior.
   - Generated Rust crates must remain `#![no_std]` and `#![forbid(unsafe_code)]`, compiling cleanly with `-D warnings`.
   - Generated WebAssembly modules must pass `WebAssembly.validate` and execute cleanly via ESM `.mjs` bindings.
4. **Web Studio Accessibility & Modern Web Standards**:
   - Keep `web/` compliant with `light dark` color-scheme theming, accessible `focusgroup` / `hidden="until-found"` tab semantics, and `@container` responsive benchmark tables.
5. **Security & CI Policy**:
   - `.github/workflows/verify.yml` runs on a `self-hosted` runner and is strictly gated to `on: workflow_dispatch` so untrusted pull requests or forks never execute arbitrary code on maintainer workstations.
   - Never commit generated build outputs (`build/`, `*.dylib`, `*.so`, `*.o`, `*.ll`, `*.pb`, `.venv/`, `__pycache__/`).

---

## Submitting Pull Requests

1. Create a focused feature branch off `main`.
2. Add or update unit/integration tests under `tests/`.
3. Ensure the full suite passes locally:
   ```bash
   uv run pytest -v
   ```
4. If updating `web/demos.json`, regenerate it via `uv run ail studio --regenerate-demos` rather than hand-editing base64 blobs.
5. Keep PR descriptions concise with exact test results and, when relevant, `ail check` / `ail audit-spec` outputs.
