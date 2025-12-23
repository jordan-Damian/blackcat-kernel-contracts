# BlackCat Kernel Contracts — Roadmap

This roadmap tracks the contract layer of the BlackCat “trust kernel” (Web3 / EVM).

## Stage 0 — Specification (current)
- Threat model and invariants (what must never be possible).
- Canonical hashing rules for “release root” and “installed state root” (shared with `blackcat-integrity`).
- Contract interfaces and event schema:
  - `ReleaseRegistry` (official releases),
  - `InstanceController` (per-install trust authority),
  - `InstanceFactory` (setup ceremony + cloning).
- Trust modes and storage budgets:
  - `root+uri` baseline (cheap),
  - `full detail` mode (paranoid; chunked on-chain bytes or per-file hashes).
- Governance model:
  - authorities as external multisig wallets (Safe) rather than custom on-chain multisig logic,
  - separation of `root_authority` vs `upgrade_authority` vs `emergency_authority`.

## Stage 1 — Foundry scaffold + skeleton contracts (in progress)
- ✅ Foundry project scaffold (`foundry.toml`, fmt/test workflows).
- ✅ Implement skeletons with explicit events and minimal storage:
  - `ReleaseRegistry` mapping `componentId+version → root, uri, meta`,
  - `InstanceController` storing `active_root`, `active_uri`, `paused`, and upgrade slots,
  - `InstanceFactory` cloning controllers and emitting setup receipts.
- ✅ Add revocation/trust model to `ReleaseRegistry` (`revoke`, `isTrustedRoot`).
- ✅ Add optional `ReleaseRegistry` enforcement to `InstanceController` (genesis + upgrades).
- ✅ Add optional upgrade timelock (`minUpgradeDelaySec`) and reporter check-ins to `InstanceController`.
- ✅ Add 2-step authority rotation and incident reporting to `InstanceController`.
- ✅ Add deterministic instance creation via CREATE2 (`predictInstanceAddress`, `createInstanceDeterministic`).
- ✅ Unit tests for storage + access control + upgrade TTL/timelock behavior.
- ▢ Expand event assertions + fuzz tests (invariants).

## Stage 2 — Setup ceremony (multi-device bootstrap)
- Setup nonce + replay protection.
- EIP-712 typed “setup request” signatures (offline review + multi-device confirmation).
- Finalization flow:
  - binds the controller to chosen authorities,
  - pins the initial trust mode and policy hash,
  - emits an immutable “genesis” event for the installation.
 - Optional authority mode `KernelAuthority` (EIP-712 threshold signer) for multi-device flows without Safe.

## Stage 3 — Upgrade state machine + emergency controls
- ✅ Upgrade flow: `propose → activate` with TTL and optional timelock.
- ✅ Emergency controls: `pause/unpause` (plus runtime-enforced “unsafe” decisions off-chain).
- Backward-compatible upgrades: allow overlap windows and multiple roots for migrations.

## Stage 4 — Deployment + integration artifacts
- ✅ Deterministic addresses for instances (CREATE2).
- Deploy scripts for factories/registries.
- Publish ABI + versioned artifacts to be consumed by:
  - `blackcat-core` runtime enforcement,
  - `blackcat-cli` / `blackcat-installer` operator flows.

## Stage 5 — Audit & hardening
- External security audit + formal invariant review.
- Gas/cost benchmarks for trust modes.
- Upgrade safety: explicit “break glass” controls and post-incident recovery runbooks.
