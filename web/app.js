/* AIL v1.0 Web Studio — Client Controller, Accessible Tabs, & Browser WASM Sandbox */

(() => {
  "use strict";

  const state = {
    liveMode: false,
    presets: [],
    currentPresetId: "signed_quote",
    currentCompile: null,
    currentRepair: null,
    wasmBytes: null,
  };

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  // -------------------------------------------------------------------------
  // 1. Theme Management (respects :root color-scheme: light dark by default)
  // -------------------------------------------------------------------------
  const themeSelect = $("#theme-select");
  const darkQuery = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

  function applyTheme(choice) {
    const root = document.documentElement;
    if (choice === "light" || choice === "dark") {
      root.setAttribute("data-theme", choice);
    } else {
      root.removeAttribute("data-theme");
    }
  }

  if (themeSelect) {
    themeSelect.addEventListener("change", () => applyTheme(themeSelect.value));
  }
  if (darkQuery && typeof darkQuery.addEventListener === "function") {
    darkQuery.addEventListener("change", () => {
      if (!themeSelect || themeSelect.value === "system") {
        applyTheme("system");
      }
    });
  }

  // -------------------------------------------------------------------------
  // 2. MWG Tabs Controller (focusgroup + beforematch + Arrow fallback)
  // -------------------------------------------------------------------------
  const tablist = $('[role="tablist"]');
  const tabs = $$('[role="tab"]', tablist);
  const panels = $$('[role="tabpanel"]');
  const hasNativeFocusgroup = Object.hasOwn(HTMLElement.prototype, "focusGroup");

  function panelForTab(tab) {
    return panels.find((p) => p.getAttribute("aria-labelledby") === tab.id) || null;
  }

  function tabForPanel(panel) {
    const id = panel.getAttribute("aria-labelledby");
    return tabs.find((t) => t.id === id) || null;
  }

  function selectTab(selectedTab, { scroll = true } = {}) {
    if (!selectedTab) return;
    for (const tab of tabs) {
      const active = tab === selectedTab;
      tab.setAttribute("aria-selected", active ? "true" : "false");
      tab.toggleAttribute("focusgroupstart", active);
      const panel = panelForTab(tab);
      if (panel) {
        if (active) {
          panel.removeAttribute("hidden");
          panel.setAttribute("tabindex", "0");
        } else {
          panel.setAttribute("hidden", "until-found");
          panel.removeAttribute("tabindex");
        }
      }
    }

    if (scroll) {
      try {
        selectedTab.scrollIntoView({ block: "nearest", inline: "nearest", container: "nearest" });
      } catch {
        selectedTab.scrollIntoView({ block: "nearest", inline: "nearest" });
      }
    }
  }

  for (const tab of tabs) {
    tab.addEventListener("click", () => selectTab(tab));
    tab.addEventListener("focus", () => selectTab(tab));
  }

  // Wire find-in-page beforematch so hidden="until-found" panels auto-activate their tab
  for (const panel of panels) {
    panel.addEventListener("beforematch", () => {
      const matchingTab = tabForPanel(panel);
      if (matchingTab) {
        selectTab(matchingTab, { scroll: true });
      }
    });
  }

  // Keyboard navigation fallback when native focusgroup is unsupported (Firefox / Safari)
  if (tablist) {
    tablist.addEventListener("keydown", (event) => {
      if (hasNativeFocusgroup) return;
      const current = document.activeElement;
      const idx = tabs.indexOf(current);
      if (idx === -1) return;

      const isRtl = getComputedStyle(tablist).direction === "rtl";
      const nextKey = isRtl ? "ArrowLeft" : "ArrowRight";
      const prevKey = isRtl ? "ArrowRight" : "ArrowLeft";

      let targetIdx = -1;
      if (event.key === nextKey) {
        targetIdx = (idx + 1) % tabs.length;
      } else if (event.key === prevKey) {
        targetIdx = (idx - 1 + tabs.length) % tabs.length;
      } else if (event.key === "Home") {
        targetIdx = 0;
      } else if (event.key === "End") {
        targetIdx = tabs.length - 1;
      }

      if (targetIdx !== -1) {
        event.preventDefault();
        const target = tabs[targetIdx];
        target.focus();
        selectTab(target);
      }
    });
  }

  // -------------------------------------------------------------------------
  // 3. Utilities: Base64, Clipboard, Status Pills
  // -------------------------------------------------------------------------
  function decodeBase64Bytes(b64) {
    const bin = atob(b64);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) {
      arr[i] = bin.charCodeAt(i);
    }
    return arr;
  }

  function setStatusPill(el, text, tone) {
    if (!el) return;
    el.textContent = text;
    el.className = `status-pill status-${tone}`;
  }

  for (const btn of $$(".btn-copy")) {
    btn.addEventListener("click", async () => {
      const targetId = btn.getAttribute("data-copy-target");
      const targetEl = targetId ? document.getElementById(targetId) : null;
      if (!targetEl) return;
      try {
        await navigator.clipboard.writeText(targetEl.textContent || "");
        const prev = btn.textContent;
        btn.textContent = "Copied";
        setTimeout(() => {
          btn.textContent = prev;
        }, 1200);
      } catch {
        // Ignore clipboard denial in restricted contexts
      }
    });
  }

  // -------------------------------------------------------------------------
  // 4. Render Compilation, Proofs, SpecMut, Targets, Diagnostics, Repair
  // -------------------------------------------------------------------------
  function renderBenchmarkTable(benchmarks) {
    if (!benchmarks || !Array.isArray(benchmarks.kernels)) return;
    const tbody = $("#benchmark-tbody");
    const table = $(".benchmark-table");
    if (!tbody || !table) return;

    const headers = $$("thead th", table).map((th) => th.textContent.trim());
    headers.forEach((label, idx) => {
      table.style.setProperty(`--label-${idx + 1}`, JSON.stringify(label));
    });

    tbody.replaceChildren();
    for (const row of benchmarks.kernels) {
      const tr = document.createElement("tr");
      const th = document.createElement("th");
      th.scope = "row";
      th.textContent = row.kernel;
      tr.appendChild(th);

      const cols = [row.ail_tokens, row.other_tokens, row.ail_ns, row.other_ns, row.bug_caught];
      for (const val of cols) {
        const td = document.createElement("td");
        td.textContent = val;
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }
  }

  function renderDiagnostic(diags) {
    const banner = $("#diagnostic-banner");
    const codeEl = $("#diag-code");
    const locEl = $("#diag-location");
    const msgEl = $("#diag-message");
    const ceEl = $("#diag-counterexample");
    const hintEl = $("#diag-hint");

    if (!diags || diags.length === 0) {
      banner.hidden = true;
      return;
    }
    const d = diags[0];
    banner.hidden = false;
    codeEl.textContent = d.code || "STATUS_REJECTED";
    locEl.textContent = `${d.item_name || "<module>"} · L${d.line || 1}:${d.column || 1}`;
    msgEl.textContent = d.message || "";
    const ceKeys = Object.keys(d.counterexample || {});
    if (ceKeys.length > 0) {
      ceEl.hidden = false;
      ceEl.textContent = `Counterexample: ${JSON.stringify(d.counterexample)}`;
    } else {
      ceEl.hidden = true;
    }
    hintEl.textContent = d.repair_hint ? `Repair Hint: ${d.repair_hint}` : "";
  }

  function renderProofsAndAudits(res) {
    const proofStats = res.proof_stats || [];
    const audits = res.spec_audits || [];

    $("#kpi-elapsed").textContent = `${Number(res.elapsed_ms || 0).toFixed(2)} ms`;
    const provedCount = proofStats.filter((s) => s.verified).length;
    $("#kpi-proved").textContent = `${provedCount} / ${proofStats.length}`;

    let tested = 0;
    let killed = 0;
    for (const a of audits) {
      tested += Number(a.mutants_tested || 0);
      killed += Number(a.mutants_killed || 0);
    }
    $("#kpi-mutants").textContent = tested > 0 ? `${killed} / ${tested}` : "—";
    $("#kpi-wasm-size").textContent = res.wasm_size_bytes ? `${res.wasm_size_bytes} B` : "—";

    const proofList = $("#proof-list");
    proofList.replaceChildren();
    if (proofStats.length === 0) {
      const empty = document.createElement("p");
      empty.className = "muted";
      empty.textContent = "No proved functions yet (check diagnostics).";
      proofList.appendChild(empty);
    } else {
      for (const st of proofStats) {
        const row = document.createElement("div");
        row.className = "proof-row";
        const left = document.createElement("div");
        const nameEl = document.createElement("strong");
        nameEl.className = "mono";
        nameEl.textContent = st.item_name;
        const statusEl = document.createElement("span");
        if (st.verified) statusEl.className = "muted";
        statusEl.textContent = st.verified ? "PROVED" : "FAILED";
        left.append(nameEl, " · ", statusEl);

        const right = document.createElement("div");
        right.className = "mono muted";
        right.textContent = `${Number(st.elapsed_ms).toFixed(2)} ms | T0=${st.tier0_interval_discharged} T1=${st.tier1_bitwuzla_queries} T2=${st.tier2_z3_queries} O1=${st.o1_loop_steps}`;
        row.append(left, right);
        proofList.appendChild(row);
      }
    }

    const auditList = $("#audit-list");
    auditList.replaceChildren();
    if (audits.length === 0) {
      const empty = document.createElement("p");
      empty.className = "muted";
      empty.textContent = "No scalar SpecMut audits applicable or compilation halted before SpecMut.";
      auditList.appendChild(empty);
    } else {
      for (const au of audits) {
        const row = document.createElement("div");
        row.className = "audit-row";
        const tight = au.non_vacuous && au.uniquely_tight;
        const left = document.createElement("div");
        const nameEl = document.createElement("strong");
        nameEl.className = "mono";
        nameEl.textContent = au.fn_name;
        left.append(nameEl, ` · ${tight ? "SPEC_TIGHT" : "SPEC_WEAK"}`);

        const right = document.createElement("div");
        right.className = "mono muted";
        right.textContent = `killed=${au.mutants_killed}/${au.mutants_tested} | ${Number(au.elapsed_ms).toFixed(2)} ms`;
        row.append(left, right);
        auditList.appendChild(row);
      }
    }
  }

  function renderTargets(res) {
    const targets = res.targets || {};
    const llvm = targets.llvm || {};
    const wasm = targets.wasm || {};
    const cTarget = targets.c || {};
    const rustTarget = targets.rust || {};

    $("#code-wat").textContent = wasm.wat || "; Unavailable (verification rejected or WASM backend error).";
    $("#wasm-meta").textContent = `${res.wasm_size_bytes || 0} bytes`;
    $("#code-c").textContent = cTarget.source || "/* Unavailable until module verifies cleanly. */";
    $("#code-c-header").textContent = cTarget.header || "/* C ABI header unavailable. */";
    $("#code-rust").textContent = rustTarget.lib_rs || "// Unavailable until module verifies cleanly.";
    $("#code-llvm").textContent = llvm.ir || "; LLVM IR unavailable until module verifies cleanly.";
    $("#code-asm").textContent = llvm.asm || "; Native assembly preview unavailable.";
    $("#llvm-meta").textContent = `NEON: ${llvm.neon_simd_instructions || 0} · Atomics: ${llvm.hardware_atomic_instructions || 0}`;
    $("#code-proto").textContent = res.prototext || "# Protobuf output unavailable.";

    const b64 = res.wasm_base64 || wasm.wasm_base64 || "";
    state.wasmBytes = b64 ? decodeBase64Bytes(b64) : null;
    $("#btn-download-wasm").disabled = !state.wasmBytes;

    populateWasmRunner(res);
  }

  function renderCompileResult(res) {
    state.currentCompile = res;
    if (res.verified) {
      setStatusPill($("#verify-badge"), "STATUS_VERIFIED", "ok");
    } else {
      setStatusPill($("#verify-badge"), "STATUS_REJECTED", "err");
    }
    renderDiagnostic(res.diagnostics || []);
    renderProofsAndAudits(res);
    renderTargets(res);
  }

  function renderRepairResult(rep) {
    state.currentRepair = rep;
    const tl = $("#repair-timeline");
    const stepsEl = $("#repair-steps");
    const summaryEl = $("#repair-summary");

    if (!rep) {
      tl.hidden = true;
      return;
    }

    tl.hidden = false;
    summaryEl.textContent = `${rep.final_status} · ${rep.iterations} turn(s) · ${Number(rep.total_elapsed_ms || 0).toFixed(2)} ms`;
    stepsEl.replaceChildren();
    for (const st of rep.steps || []) {
      const li = document.createElement("li");
      const codeEl = document.createElement("strong");
      codeEl.className = "mono";
      codeEl.textContent = `[${st.triggered_code}]`;
      const targetEl = document.createElement("code");
      targetEl.className = "mono";
      targetEl.textContent = st.target_item;
      li.append(codeEl, " on ", targetEl, ` — ${st.patch_summary}`);
      stepsEl.appendChild(li);
    }
    if ((rep.steps || []).length === 0) {
      const li = document.createElement("li");
      li.textContent = rep.verified ? "Already verified on turn 0." : "No repair steps applied.";
      stepsEl.appendChild(li);
    }

    if (rep.verified && rep.repaired_source) {
      $("#source-editor").value = rep.repaired_source;
      if (rep.compile) {
        renderCompileResult(rep.compile);
      }
    }
  }

  // -------------------------------------------------------------------------
  // 5. Browser WebAssembly Sandbox Execution (BigInt + performance.now)
  // -------------------------------------------------------------------------
  function getWasmRuntimeParams(fnMeta) {
    return (fnMeta?.params || []).filter((p) => !(p.kind && p.kind.startsWith("cap.")));
  }

  function populateWasmRunner(res) {
    const fnSelect = $("#wasm-fn-select");
    const argsBox = $("#wasm-args-container");
    fnSelect.replaceChildren();
    argsBox.replaceChildren();
    $("#wasm-output").textContent = "—";
    $("#wasm-timing").textContent = "—";
    $("#wasm-host-log").hidden = true;

    const funcs = (res.functions || []).filter((f) => f.kind === "fn" || f.kind === "main");
    if (!state.wasmBytes || funcs.length === 0) {
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = "(compile a verified module first)";
      fnSelect.appendChild(opt);
      $("#btn-run-wasm").disabled = true;
      return;
    }

    $("#btn-run-wasm").disabled = false;
    const preset = state.presets.find((p) => p.id === state.currentPresetId);
    const preferredFn = preset?.sample_call?.fn;

    for (const fn of funcs) {
      const opt = document.createElement("option");
      opt.value = fn.name;
      const runtimeParams = getWasmRuntimeParams(fn);
      const sigStr = runtimeParams.map((p) => `${p.name}: ${p.kind}`).join(", ");
      opt.textContent = `${fn.name}(${sigStr}) -> ${fn.ret_kind}`;
      if (fn.name === preferredFn) opt.selected = true;
      fnSelect.appendChild(opt);
    }

    renderWasmArgInputs();
  }

  function renderWasmArgInputs() {
    const fnSelect = $("#wasm-fn-select");
    const argsBox = $("#wasm-args-container");
    argsBox.replaceChildren();
    const fname = fnSelect.value;
    const fnMeta = (state.currentCompile?.functions || []).find((f) => f.name === fname);
    if (!fnMeta) return;

    const preset = state.presets.find((p) => p.id === state.currentPresetId);
    const sampleArgs = preset?.sample_call?.fn === fname ? preset.sample_call.args : null;
    const runtimeParams = getWasmRuntimeParams(fnMeta);

    runtimeParams.forEach((param, idx) => {
      const wrap = document.createElement("div");
      wrap.className = "field-group";
      const label = document.createElement("label");
      const inputId = `wasm-arg-${idx}`;
      label.setAttribute("for", inputId);
      label.textContent = `${param.name} (${param.type_str})`;

      const input = document.createElement("input");
      input.id = inputId;
      input.type = "text";
      input.dataset.paramKind = param.kind;
      input.dataset.paramName = param.name;
      if (sampleArgs && idx < sampleArgs.length) {
        input.value = String(sampleArgs[idx]);
      } else if (param.kind === "bytes") {
        input.value = "65,73,76,49,0,1,0,16";
      } else if (param.kind === "slice" || param.kind === "mut_slice") {
        input.value = "100,200,300,400";
      } else if (param.kind.startsWith("struct:")) {
        input.value = "100,125,0";
      } else if (param.kind.startsWith("enum:")) {
        input.value = "0,250,4000";
      } else if (param.kind === "i64") {
        input.value = "-10";
      } else {
        input.value = "100";
      }
      wrap.appendChild(label);
      wrap.appendChild(input);
      argsBox.appendChild(wrap);
    });
  }

  $("#wasm-fn-select").addEventListener("change", renderWasmArgInputs);

  function parseByteList(raw) {
    const trimmed = raw.trim();
    if (!trimmed) return new Uint8Array(0);
    if (trimmed.includes(",")) {
      return new Uint8Array(trimmed.split(",").map((s) => Number(s.trim()) & 0xff));
    }
    if (/^[0-9a-fA-F\s]+$/.test(trimmed) && trimmed.includes(" ")) {
      return new Uint8Array(trimmed.split(/\s+/).map((h) => parseInt(h, 16) & 0xff));
    }
    return new TextEncoder().encode(trimmed);
  }

  async function runWasmSandbox() {
    if (!state.wasmBytes) return;
    const fnName = $("#wasm-fn-select").value;
    const fnMeta = (state.currentCompile?.functions || []).find((f) => f.name === fnName);
    if (!fnMeta) return;

    const hostLogs = [];
    const compiledMod = await WebAssembly.compile(state.wasmBytes);
    const importsObj = { env: {} };
    for (const imp of WebAssembly.Module.imports(compiledMod)) {
      if (imp.module === "env" && imp.kind === "function") {
        importsObj.env[imp.name] = (...vals) => {
          hostLogs.push(`${imp.name}(${vals.map((v) => String(v)).join(", ")})`);
          return 0n;
        };
      }
    }

    const instance = await WebAssembly.instantiate(compiledMod, importsObj);
    const rawExports = instance.exports;
    const exportName = fnName === "main" && !rawExports.main && rawExports.ail_main ? "ail_main" : fnName;
    const fnExport = rawExports[exportName];
    if (typeof fnExport !== "function") {
      $("#wasm-output").textContent = `Export '${fnName}' not found in WASM exports (${Object.keys(rawExports).join(", ")})`;
      return;
    }

    const argInputs = $$("input", $("#wasm-args-container"));
    const callArgs = [];
    const memory = rawExports.memory;
    let fallbackOffset = 4096;
    const mark = typeof rawExports.__ail_heap_mark === "function" ? rawExports.__ail_heap_mark() : null;

    function allocMem(size) {
      if (typeof rawExports.__ail_alloc === "function") {
        return rawExports.__ail_alloc(Math.max(8, size));
      }
      const p = fallbackOffset;
      fallbackOffset += Math.max(64, size);
      return p;
    }

    const structDefs = Object.fromEntries((state.currentCompile?.structs || []).map((s) => [s.name, s]));
    const enumDefs = Object.fromEntries((state.currentCompile?.enums || []).map((e) => [e.name, e]));

    const runtimeParams = getWasmRuntimeParams(fnMeta);

    try {
      for (let i = 0; i < runtimeParams.length; i += 1) {
        const p = runtimeParams[i];
        const rawVal = argInputs[i]?.value ?? "0";
        if (p.kind === "bytes" && memory) {
          const bytes = parseByteList(rawVal);
          const ptr = bytes.length === 0 ? 0 : allocMem(bytes.length);
          if (bytes.length > 0) {
            new Uint8Array(memory.buffer, ptr, bytes.length).set(bytes);
          }
          callArgs.push(ptr);
        } else if ((p.kind === "slice" || p.kind === "mut_slice") && memory) {
          const vals = rawVal
            .split(",")
            .map((x) => x.trim())
            .filter(Boolean)
            .map((x) => BigInt(x));
          const ptr = vals.length === 0 ? 0 : allocMem(vals.length * 8);
          if (vals.length > 0) {
            const dv = new DataView(memory.buffer);
            vals.forEach((v, idx) => dv.setBigUint64(ptr + idx * 8, BigInt.asUintN(64, v), true));
          }
          callArgs.push(ptr);
        } else if (p.kind.startsWith("struct:") && memory) {
          const sname = p.kind.split(":", 2)[1];
          const sdef = structDefs[sname];
          const parts = rawVal.split(",").map((x) => BigInt(x.trim() || "0"));
          const fcount = sdef ? sdef.fields.length : parts.length;
          const ptr = allocMem(fcount * 8);
          const dv = new DataView(memory.buffer);
          for (let fi = 0; fi < fcount; fi += 1) {
            const fd = sdef?.fields?.[fi];
            if (fd?.kind === "i64") {
              dv.setBigInt64(ptr + fi * 8, BigInt.asIntN(64, parts[fi] ?? 0n), true);
            } else {
              dv.setBigUint64(ptr + fi * 8, BigInt.asUintN(64, parts[fi] ?? 0n), true);
            }
          }
          callArgs.push(ptr);
        } else if (p.kind.startsWith("enum:") && memory) {
          const parts = rawVal.split(",").map((x) => BigInt(x.trim() || "0"));
          const ename = p.kind.split(":", 2)[1];
          const edef = enumDefs[ename];
          const maxF = edef ? Math.max(...edef.variants.map((v) => v.fields.length), 0) : Math.max(0, parts.length - 1);
          const ptr = allocMem((1 + maxF) * 8);
          const dv = new DataView(memory.buffer);
          dv.setBigUint64(ptr, BigInt.asUintN(64, parts[0] ?? 0n), true);
          for (let fi = 0; fi < maxF; fi += 1) {
            dv.setBigUint64(ptr + (fi + 1) * 8, BigInt.asUintN(64, parts[fi + 1] ?? 0n), true);
          }
          callArgs.push(ptr);
        } else if (p.kind === "i64") {
          callArgs.push(BigInt.asIntN(64, BigInt(rawVal.trim() || "0")));
        } else {
          callArgs.push(BigInt.asUintN(64, BigInt(rawVal.trim() || "0")));
        }
      }

      const iters = Math.max(1, Number($("#wasm-iters-select").value || "1"));
      const t0 = performance.now();
      let rawOut;
      for (let k = 0; k < iters; k += 1) {
        rawOut = fnExport(...callArgs);
      }
      const elapsedMs = performance.now() - t0;
      const nsPerOp = (elapsedMs * 1e6) / iters;

      let formattedOut = String(rawOut);
      if (fnMeta.ret_kind.startsWith("struct:") && typeof rawOut === "number" && memory) {
        const sname = fnMeta.ret_kind.split(":", 2)[1];
        const sdef = structDefs[sname];
        const dv = new DataView(memory.buffer);
        if (sdef) {
          const fieldsStr = sdef.fields
            .map((fd, fi) => {
              const v = fd.kind === "i64" ? dv.getBigInt64(rawOut + fi * 8, true) : dv.getBigUint64(rawOut + fi * 8, true);
              return `${fd.name}=${v}`;
            })
            .join(", ");
          formattedOut = `${sname}(${fieldsStr})`;
        }
      } else if (fnMeta.ret_kind.startsWith("enum:") && typeof rawOut === "number" && memory) {
        const ename = fnMeta.ret_kind.split(":", 2)[1];
        const edef = enumDefs[ename];
        const dv = new DataView(memory.buffer);
        const tag = Number(dv.getBigUint64(rawOut, true));
        const vdef = edef?.variants?.find((v) => v.tag === tag);
        if (vdef) {
          const fieldsStr = vdef.fields
            .map((fd, fi) => {
              const v = fd.kind === "i64" ? dv.getBigInt64(rawOut + (1 + fi) * 8, true) : dv.getBigUint64(rawOut + (1 + fi) * 8, true);
              return `${fd.name}=${v}`;
            })
            .join(", ");
          formattedOut = `${ename}.${vdef.name}(${fieldsStr})`;
        } else {
          formattedOut = `${ename}#tag=${tag}`;
        }
      } else if (typeof rawOut === "bigint") {
        formattedOut = fnMeta.ret_kind === "i64" ? BigInt.asIntN(64, rawOut).toString() : BigInt.asUintN(64, rawOut).toString();
      }

      $("#wasm-output").textContent = formattedOut;
      $("#wasm-timing").textContent = `${elapsedMs.toFixed(3)} ms (${iters.toLocaleString()} calls · ${nsPerOp.toFixed(1)} ns/op)`;
    } finally {
      if (mark !== null && typeof rawExports.__ail_heap_reset === "function") {
        rawExports.__ail_heap_reset(mark);
      }
    }

    const logEl = $("#wasm-host-log");
    if (hostLogs.length > 0) {
      logEl.hidden = false;
      logEl.textContent = hostLogs.slice(0, 20).join("\n");
    } else {
      logEl.hidden = true;
    }
  }

  $("#btn-run-wasm").addEventListener("click", () => {
    runWasmSandbox().catch((err) => {
      $("#wasm-output").textContent = `WASM Error: ${err.message}`;
    });
  });

  $("#btn-download-wasm").addEventListener("click", () => {
    if (!state.wasmBytes) return;
    const blob = new Blob([state.wasmBytes], { type: "application/wasm" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${state.currentPresetId || "ail_module"}.wasm`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  });

  // -------------------------------------------------------------------------
  // 6. Preset Loading & Live/Static Compilation Triggers
  // -------------------------------------------------------------------------
  function selectPreset(presetId) {
    const preset = state.presets.find((p) => p.id === presetId);
    if (!preset) return;
    state.currentPresetId = preset.id;

    for (const btn of $$(".preset-btn")) {
      btn.classList.toggle("is-active", btn.dataset.preset === preset.id);
    }

    $("#preset-title").textContent = preset.title;
    $("#preset-subtitle").textContent = preset.subtitle || "";
    const tagRow = $("#preset-tags");
    tagRow.replaceChildren();
    for (const t of preset.tags || []) {
      const span = document.createElement("span");
      span.className = "tag-badge";
      span.textContent = t;
      tagRow.appendChild(span);
    }

    $("#source-editor").value = preset.source || "";
    $("#tight-specs-toggle").checked = preset.require_tight_specs !== false;
    $("#repair-timeline").hidden = true;

    if (preset.compile) {
      renderCompileResult(preset.compile);
    } else if (state.liveMode) {
      compileCurrentSource();
    }
  }

  for (const btn of $$(".preset-btn")) {
    btn.addEventListener("click", () => selectPreset(btn.dataset.preset));
  }

  async function compileCurrentSource() {
    const source = $("#source-editor").value;
    const requireTight = $("#tight-specs-toggle").checked;

    if (!state.liveMode) {
      const matched = state.presets.find(
        (p) => p.source.trim() === source.trim() || p.repair?.repaired_source?.trim() === source.trim()
      );
      if (matched) {
        const res =
          matched.repair?.repaired_source?.trim() === source.trim() && matched.repair?.compile
            ? matched.repair.compile
            : matched.compile;
        if (res) {
          renderCompileResult(res);
          return;
        }
      }
      setStatusPill($("#verify-badge"), "Static Demo (Read-Only Edits)", "warn");
      return;
    }

    setStatusPill($("#verify-badge"), "Verifying…", "neutral");
    const resp = await fetch("/api/compile", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        source,
        require_tight_specs: requireTight,
        module_name: state.currentPresetId || "studio_mod",
      }),
    });
    const data = await resp.json();
    if (!resp.ok || !data.ok) {
      setStatusPill($("#verify-badge"), data.error || "Compile Request Error", "err");
      return;
    }
    renderCompileResult(data);
  }

  async function repairCurrentSource() {
    const source = $("#source-editor").value;
    const requireTight = $("#tight-specs-toggle").checked;

    if (!state.liveMode) {
      const matched = state.presets.find((p) => p.source.trim() === source.trim() && p.repair);
      if (matched && matched.repair) {
        renderRepairResult(matched.repair);
      } else {
        setStatusPill($("#verify-badge"), "Run `ail studio` for live repair", "warn");
      }
      return;
    }

    setStatusPill($("#verify-badge"), "Repairing…", "neutral");
    const resp = await fetch("/api/repair", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        source,
        require_tight_specs: requireTight,
        max_iters: 8,
      }),
    });
    const data = await resp.json();
    if (!resp.ok || !data.ok) {
      setStatusPill($("#verify-badge"), data.error || "Repair Request Error", "err");
      return;
    }
    renderRepairResult(data);
  }

  $("#btn-compile").addEventListener("click", () => compileCurrentSource());
  $("#btn-repair").addEventListener("click", () => repairCurrentSource());
  $("#btn-inline-repair").addEventListener("click", () => repairCurrentSource());
  $("#source-editor").addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
      event.preventDefault();
      compileCurrentSource();
    }
  });

  // -------------------------------------------------------------------------
  // 7. Bootstrap: Probe Live Server, Fallback to Standalone demos.json
  // -------------------------------------------------------------------------
  async function init() {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 1200);
      const healthRes = await fetch("/api/health", { signal: controller.signal });
      clearTimeout(timer);
      if (healthRes.ok) {
        const health = await healthRes.json();
        if (health && health.ok) {
          state.liveMode = true;
          setStatusPill(
            $("#mode-badge"),
            `Live Compiler v${health.version} (${(health.targets || []).join(", ")})`,
            "ok"
          );
          const presetsRes = await fetch("/api/presets");
          const presetsData = await presetsRes.json();
          state.presets = presetsData.presets || [];
          renderBenchmarkTable(presetsData.benchmarks);
          selectPreset(state.presets[0]?.id || "signed_quote");
          return;
        }
      }
    } catch {
      // Fall through cleanly to standalone static demos.json
    }

    try {
      const demosRes = await fetch("demos.json");
      if (demosRes.ok) {
        const demos = await demosRes.json();
        state.liveMode = false;
        state.presets = demos.presets || [];
        setStatusPill($("#mode-badge"), "Static Demo + Browser WASM Sandbox", "warn");
        renderBenchmarkTable(demos.benchmarks);
        selectPreset(state.presets[0]?.id || "signed_quote");
        return;
      }
    } catch {
      // Handled below
    }

    setStatusPill($("#mode-badge"), "Offline (Run `ail studio`)", "err");
  }

  init();
})();
