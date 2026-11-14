"""Multi-target build orchestrator for verified AIL modules (`native`, `wasm`, `c`, `rust`, `all`)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import time
from typing import Any

from ailang import ail_agent_pb2 as pb
from ailang.codegen_llvm import compile_llvm_to_native
from ailang.ownership import ModuleTypeEnv
from ailang.parser import SNode

SUPPORTED_TARGETS: tuple[str, ...] = ("native", "wasm", "c", "rust", "all")


@dataclass(frozen=True)
class MultiTargetReport:
    """Structured summary of verified artifacts emitted across one or more AIL backends."""

    module_name: str
    target: str
    targets_built: tuple[str, ...]
    out_dir: str
    native: pb.BuildArtifacts | None = None
    wasm: Any | None = None
    c: Any | None = None
    rust: Any | None = None
    elapsed_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable summary dict of all built target artifacts."""
        targets: dict[str, Any] = {}
        if self.native is not None:
            targets["native"] = {
                "llvm_ir_path": self.native.llvm_ir_path,
                "asm_path": self.native.asm_path,
                "binary_or_lib_path": self.native.binary_or_lib_path,
                "c_header_path": self.native.c_header_path,
                "python_bindings_path": self.native.python_bindings_path,
                "neon_simd_instructions": self.native.neon_simd_instructions,
                "hardware_atomic_instructions": self.native.hardware_atomic_instructions,
            }
        if self.wasm is not None:
            targets["wasm"] = asdict(self.wasm)
        if self.c is not None:
            targets["c"] = asdict(self.c)
        if self.rust is not None:
            targets["rust"] = asdict(self.rust)
        return {
            "module_name": self.module_name,
            "target": self.target,
            "targets_built": list(self.targets_built),
            "out_dir": self.out_dir,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "artifacts": targets,
        }

    def format_human(self) -> str:
        """Format a concise multi-line human summary for emitted backend artifacts."""
        lines: list[str] = [
            f"[MULTI-TARGET] module={self.module_name} targets={','.join(self.targets_built)} elapsed={self.elapsed_ms:.2f} ms"
        ]
        if self.native is not None:
            lines.append(
                f"  [NATIVE] bin={self.native.binary_or_lib_path} ll={self.native.llvm_ir_path} "
                f"(NEON_SIMD_ops={self.native.neon_simd_instructions}, Atomic_ops={self.native.hardware_atomic_instructions})"
            )
        if self.wasm is not None:
            lines.append(
                f"  [WASM]   wasm={self.wasm.wasm_path} ({self.wasm.wasm_size_bytes} B) "
                f"mjs={self.wasm.js_wrapper_path} dts={self.wasm.ts_dts_path}"
            )
        if self.c is not None:
            lines.append(
                f"  [C11]    c={self.c.c_source_path} h={self.c.c_header_path} "
                f"lib={self.c.shared_lib_path}"
            )
        if self.rust is not None:
            lines.append(
                f"  [RUST]   crate={self.rust.crate_dir} lib_rs={self.rust.lib_rs_path} "
                f"rlib={self.rust.rlib_path}"
            )
        return "\n".join(lines)


def _target_out_dirs(out_dir: Path, target: str) -> dict[str, Path]:
    if target == "all":
        # Separate subdirs prevent C11 and LLVM native backends from overwriting shared `.h`/`.dylib` names.
        return {t: out_dir / t for t in ("native", "wasm", "c", "rust")}
    return {target: out_dir}


def build_multi_target(
    forms: list[SNode],
    tenv: ModuleTypeEnv,
    out_dir: Path,
    stem: str,
    target: str = "all",
    *,
    build_shared_lib: bool | None = None,
    compile_c_shared: bool = True,
    verify_rustc: bool = True,
) -> MultiTargetReport:
    """Compile a verified AIL module to one or all supported targets (`native`, `wasm`, `c`, `rust`, `all`)."""
    if target not in SUPPORTED_TARGETS:
        raise ValueError(f"Unsupported target `{target}`; expected one of {SUPPORTED_TARGETS}")

    t0 = time.perf_counter()
    out_dir.mkdir(parents=True, exist_ok=True)
    dirs = _target_out_dirs(out_dir, target)
    built: list[str] = []

    native_art: pb.BuildArtifacts | None = None
    wasm_art: Any | None = None
    c_art: Any | None = None
    rust_art: Any | None = None

    if "native" in dirs:
        native_art = compile_llvm_to_native(
            forms,
            tenv,
            dirs["native"],
            stem,
            build_shared_lib=build_shared_lib,
        )
        built.append("native")

    if "wasm" in dirs:
        from ailang.codegen_wasm import compile_to_wasm

        wasm_art = compile_to_wasm(forms, tenv, dirs["wasm"], module_name=stem)
        built.append("wasm")

    if "c" in dirs:
        from ailang.codegen_c import compile_to_c

        c_art = compile_to_c(
            forms,
            tenv,
            dirs["c"],
            module_name=stem,
            compile_shared=compile_c_shared,
        )
        built.append("c")

    if "rust" in dirs:
        from ailang.codegen_rust import compile_to_rust

        rust_art = compile_to_rust(
            forms,
            tenv,
            dirs["rust"],
            module_name=stem,
            verify_rustc=verify_rustc,
        )
        built.append("rust")

    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return MultiTargetReport(
        module_name=stem,
        target=target,
        targets_built=tuple(built),
        out_dir=str(out_dir),
        native=native_art,
        wasm=wasm_art,
        c=c_art,
        rust=rust_art,
        elapsed_ms=elapsed_ms,
    )
