# Agensi.io & Multi-Marketplace Monetization Playbook

All 6 skill bundles are verified, security-scanned, and packaged in `integrations/agensi-skills/releases/*.zip`.

Re-verify and rebuild all `.zip` archives anytime with:
```bash
uv run python integrations/agensi-skills/build_and_verify.py
```

---

## 1. Ready-to-Paste Agensi Storefront Listings

| # | Zip File (`integrations/agensi-skills/releases/`) | Price | Target Audience | Suggested Storefront Title |
|---|---|---:|---|---|
| 1 | `ailang-verified-kernels.zip` | **Free (\$0)** | All Rust / C / WASM / AI devs | **AIL Verified Kernels: Z3 + Bitwuzla Multi-Target Compiler (`no_std` Rust / C11 / WASM)** |
| 2 | `defi-verified-math-pack.zip` | **\$19** | Solana, EVM, DEX, Fintech | **DeFi & Fintech Overflow-Proof Math Synthesizer (ERC-4626, AMM, `mul_div` Z3 Prover)** |
| 3 | `zero-cve-wire-parsers.zip` | **\$19** | Embedded, C/Rust, Networking, SecEng | **Zero-CVE Binary Wire & TLV Parser Generator (Z3 Bounds-Proven C11 / `no_std` Rust)** |
| 4 | `z3-spec-mutation-auditor.zip` | **\$14** | All Python / TS / Rust / Go devs | **Z3 Pre-Codegen Spec Firewall: Mutation Testing (`SpecMut`) & Prompt Disambiguator** |
| 5 | `lockfree-atomic-protocol-verifier.zip` | **\$19** | Systems, Rust, HFT, Ledger infra | **Lock-Free Atomic CAS & Thread-Interleaving Verifier (Z3 Inductive Protocol Prover)** |
| 6 | `safe-db-migration-auditor.zip` | **\$12** | Next.js, Postgres, Prisma, Drizzle | **5-Gate Zero-Downtime SQL Migration Firewall & 3-Tier Rollback Synthesizer** |
| ★ | **All-in-One Pro Bundle** (Packs 2–6) | **\$49** | Senior Engineers & Teams | **High-Assurance Systems & Backend Suite (5 Z3-Verified Agent Skills)** |

### Suggested Tags per Listing
- **Pack 1–3, 5:** `formal-verification`, `z3`, `rust`, `c`, `webassembly`, `security`, `defi`, `solana`, `compilers`
- **Pack 4:** `testing`, `z3`, `code-review`, `tdd`, `python`, `typescript`, `rust`, `specification`
- **Pack 6:** `postgresql`, `database`, `migrations`, `prisma`, `drizzle`, `devops`, `safety`

---

## 2. How to Squeeze Maximum `$` Out of This ("Doing More")

### Lever 1: Lock In the **90% + 20% 6-Month Tail** via Your GitHub README
Joeri's pitch includes Agensi's creator affiliate program:
- Marketplace organic sale = **70%** to you.
- Sale via **your affiliate link** = **90%** to you **+ 20% of everything else that buyer purchases on Agensi for 6 months**.

Once your Agensi listings are live, add a compact **"Official Pro Skill Packs"** table to `tachyon-ops/ailang`'s `README.md` using **your Agensi affiliate links** (not bare Agensi URLs). Every GitHub visitor who clicks through locks in a 90% payout + 6-month passive rev-share across the entire Agensi catalog.

### Lever 2: Free-Directory Distribution → Paid Funnel
Because `01-ailang-verified-kernels.zip` is **Free (\$0)** and mentions the 4 companion Pro Packs at the bottom of `SKILL.md`, publish `01-ailang-verified-kernels` everywhere free skills are indexed:
- **Vercel `skills.sh`**
- **SkillsMP / AgenticSkills / SkillsDirectory**
- **Agensi.io (Free tier)**

Every free install becomes an in-IDE billboard for your paid packs.

### Lever 3: Non-Exclusive Cross-Listing (Zero Extra Work)
Agensi is **non-exclusive**, and the `SKILL.md` zip format is an open standard:
- List the exact same paid `.zip` packs on **`skill.broker`** (paid `SKILL.md` marketplace).
- List the **\$49 All-in-One Bundle** on **Polar.sh** or **Gumroad** (90–95% payout + GitHub Sponsors integration) for teams buying via corporate card without an Agensi account.

### Lever 4: High-Ticket B2B Inbound Footer
Buyers spending \$19 on an ERC-4626/AMM Z3 prover or Zero-CVE Wire Parser often work at funded protocols or hardware/fintech teams. Adding a single line on your Agensi creator bio (*"Available for custom AIL kernel synthesis & formal protocol verification"*) turns passive marketplace traffic into high-margin consulting/audit leads without cold outreach.
