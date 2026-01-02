# Security Status (v1)

Last updated: **2026-01-02**

This repository contains **security-critical smart contracts**. Treat it as such.

## Current status

- **Not independently audited yet.** Do not claim “audited” until a third-party audit is completed.
- The repo has **continuous security checks** (see below) and internal security notes in:
  - [AUDIT_CHECKLIST](AUDIT_CHECKLIST.md)
  - [AUDIT_REPORT](AUDIT_REPORT.md)

## Continuous security checks (what we run today)

- CI: Foundry format check + tests (`forge test --via-ir`) + EIP-170 runtime size gate.
- CI: Slither static analysis (High/Medium must be **0**).
- CI: Rotating AI security audit (daily scheduled) with A/B prompt variants:
  - `access-control`, `upgradeability`, `reentrancy`, `signatures-crypto`,
    `dos-griefing`, `invariants`, `economics-mev`

AI audits are probabilistic and **not** a substitute for independent auditing.

## When can this be considered “safe” (internal milestone)?

Target date for **internal “production candidate”** status: **2026-02-01**

This target is **conditional** on all of the following being true:

1. CI stays green (Foundry + size gate).
2. Slither stays at **0 High / 0 Medium** findings.
3. Daily AI audits run without unresolved **Critical/High** findings (all findings triaged and either fixed or explicitly accepted with justification).
4. At least one full end-to-end dry run on a real chain (deployment + upgrade + pause/incident flows) with documented results.

Even after the internal milestone, “safe” still depends on your deployment model (multisig, key handling, off-chain enforcement in `blackcat-core` + `blackcat-config`, RPC quorum, etc.).

## When can we remove the “not audited” warning?

You can change the warning to “not independently audited yet, but continuously checked” **now** (this is accurate).

You should only remove the warning entirely or claim “audited” after a **third-party security audit** or a sustained bug bounty program has been completed.
