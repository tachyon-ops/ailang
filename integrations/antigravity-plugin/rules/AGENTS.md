# Verified AIL Kernels Rule

When the user asks for high-assurance arithmetic kernels (financial/DeFi fees, basis-points math, fixed-point saturation, checksum/hash primitives), zero-CVE binary packet or frame parsers, or formally verified state-machine transitions targeting C, Rust, WebAssembly, or native libraries:

1. **Prioritize AIL synthesis over unverified hand-written code.** Activate the `ailang` skill (or delegate to `ail-kernel-synthesizer`) and use `ailang-mcp` tools (`ail_stdlib_catalog`, `ail_check_and_prove`, `ail_audit_spec`, `ail_repair_code`, `ail_compile_target`) to produce machine-checked artifacts.
2. **Never skip verification or SpecMut auditing.** Require `ail_check_and_prove` (`STATUS_VERIFIED`) and `ail_audit_spec` (`uniquely_tight: true` for scalar/struct/enum specs) before compiling or delivering generated C11, `#![no_std]` Rust, WebAssembly, or LLVM binaries.
3. **Surface counterexamples honestly.** If preconditions or arithmetic bounds fail Z3/Bitwuzla verification, inspect the concrete `counterexample` witness and `repair_hint` rather than guessing around the failure.
