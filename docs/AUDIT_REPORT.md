# Security Audit Report (Internal)

Date: 2025-12-26

Scope:
- `blackcat-kernel-contracts/src/InstanceController.sol`
- `blackcat-kernel-contracts/src/InstanceFactory.sol`
- `blackcat-kernel-contracts/src/KernelAuthority.sol`
- `blackcat-kernel-contracts/src/ReleaseRegistry.sol`
- `blackcat-kernel-contracts/src/ManifestStore.sol`
- `blackcat-kernel-contracts/src/AuditCommitmentHub.sol` (optional)

Tooling / checks used:
- Foundry tests: `forge test --via-ir`
- Bytecode size check: `forge build --via-ir --sizes` (EIP-170)
- Slither: `slither . --exclude-dependencies --filter-paths "test|script|out|broadcast|cache|deployments"`
- Foundry lint (notes/warnings)

## Summary

- All Foundry tests pass (including stateful fuzz/regression suites).
- CI enforces:
  - `forge fmt --check`
  - `forge test --via-ir`
  - `forge build --via-ir --skip test --skip script --sizes` (EIP-170)
  - Slither (static analysis) with **High=0** and **Medium=0**
- Slither severity counts (local run): **High=0 Medium=0 Low=39 Info=30**
- `BlackCatInstanceControllerV1` (per-install controller implementation) remains under the EIP-170 runtime limit:
  - Runtime size: **24,572 bytes**
  - Margin: **4 bytes**

## Findings

### HIGH — EOA-first signature recovery could block EIP-1271 authorities in multi-authority resolvers

Contract: `blackcat-kernel-contracts/src/InstanceController.sol`

Affected paths:
- `setPausedAuthorized(...)` → `_resolvePauseSigner(...)`
- `reportIncidentAuthorized(...)` → `_resolveIncidentSigner(...)`

Issue:
- `_resolvePauseSigner` / `_resolveIncidentSigner` try authorities in order (root → emergency → reporter).
- When the **first checked authority is an EOA**, `_isValidSignatureNow` falls back to `_recover(...)`.
- Historically, this could abort multi-authority resolution if the signature blob was malformed ECDSA for the first EOA (e.g., ABI-encoded EIP-1271 signature bytes, invalid `v/s`, etc.).
- This breaks legitimate use-cases where the **intended signer is an EIP-1271 contract** (e.g., `KernelAuthority`) but an earlier role is an EOA:
  - Example: root is EOA, emergency is `KernelAuthority`, caller provides a valid EIP-1271 signature for emergency.
  - Result before fix: root check could revert and prevent reaching the emergency check.

Impact:
- Prevents “multi-device by design” setups where some roles are EOAs and others are EIP-1271 contracts.
- In practice, this blocks using `KernelAuthority` (or other EIP-1271 signers) for emergency/reporting unless the earlier role(s) are also contract authorities.

Fix (implemented):
- Introduced a lenient validation path used only by multi-authority resolvers:
  - `InstanceController._recoverOrZero(...)` (never reverts, returns `address(0)` on invalid ECDSA),
  - `InstanceController._isValidSignatureNowLenient(...)` (EOA: uses `_recoverOrZero`, contract: uses EIP-1271).
- This lets the resolver continue to the next authority role and properly validate EIP-1271 signatures.

Regression tests (added):
- `test/InstanceController.t.sol`:
  - `test_setPausedAuthorized_accepts_kernelAuthority_emergency_signature`
  - `test_reportIncidentAuthorized_accepts_kernelAuthority_reporter_signature`
- `test/InstanceController.SignatureResolution.t.sol`:
  - `test_setPausedAuthorized_accepts_eip1271_signature_even_if_malformed_ecdsa_for_root`

### INFO — `bytes4(ret)` cast in EIP-1271 checks

Contracts:
- `blackcat-kernel-contracts/src/InstanceController.sol`
- `blackcat-kernel-contracts/src/InstanceFactory.sol`
- `blackcat-kernel-contracts/src/ReleaseRegistry.sol`
- `blackcat-kernel-contracts/src/ManifestStore.sol`

Note:
- Casting `bytes` → `bytes4` can truncate, but is safe here because the code checks `ret.length >= 4` first.

Action (implemented):
- Added an explicit comment + lint suppression:
  - `forge-lint: disable-next-line(unsafe-typecast)`

### LOW — InstanceFactory reentrancy warning (benign) hardened by moving `isInstance[...] = true` before `initialize(...)`

Contract: `blackcat-kernel-contracts/src/InstanceFactory.sol`

Issue:
- Slither flags a reentrancy pattern because state (`isInstance[instance]`) was written after calling `InstanceController.initialize(...)`.

Impact:
- Low. The instance is a freshly deployed clone and the initializer is expected to be trusted; however, this is easy to harden and removes static-analysis ambiguity.

Fix (implemented):
- Set `isInstance[instance] = true` before calling `initialize(...)`.
  - If `initialize(...)` reverts, the entire transaction reverts and the mapping update is rolled back.

### NOTE — KernelAuthority “arbitrary-send-eth” is intentional, but now blocks `target=address(0)`

Contract: `blackcat-kernel-contracts/src/KernelAuthority.sol`

Issue:
- Slither flags `execute(...)` / `executeBatch(...)` as “sends eth to arbitrary user” because they forward calls with `value`.

Design rationale:
- `KernelAuthority` is a generic transaction executor (multisig-like).
- Safety comes from:
  - threshold signature validation,
  - nonce consumption before the external call,
  - deadline-based expiry.

Hardening (implemented):
- Reject `target == address(0)` to avoid accidental burns/misconfig.

### INFO — AuditCommitmentHub replay resistance is enforced via per-instance sequence cursor

Contract: `blackcat-kernel-contracts/src/AuditCommitmentHub.sol`

Notes:
- `commitAuthorized(...)` is EIP-712 / EIP-1271 compatible and includes `(chainId, verifyingContract)` in the domain separator.
- Replays/reordering are prevented by requiring `seqFrom == lastSeq[instance] + 1`.
- The hub intentionally does not gate “server writes”; it only provides an append-only event stream and ordering guarantees.

## Slither Low/Info findings (accepted by design)

CI enforces **High=0** and **Medium=0**. Low/Info findings are reviewed and accepted when they are an intentional design choice.

Common categories observed:

- `timestamp`
  - We use `block.timestamp` only for **deadlines / TTL windows** (auth signatures, upgrade windows).
  - We do not use timestamps for randomness.
  - Risk is limited to small miner/validator timestamp drift; signatures remain time-bounded and replay-protected via nonces.

- `calls-loop` (KernelAuthority batch execution)
  - `KernelAuthority.executeBatch(...)` performs calls inside a loop **by design** (it is a multisig-like executor).
  - Only threshold-approved operations can reach this path, so the primary risk is self-inflicted (oversized batches → out-of-gas).

- `reentrancy-events`
  - Slither flags “event emitted after external call” patterns in `InstanceFactory` and `KernelAuthority`.
  - State that matters for safety (nonces / instance registration) is updated before external calls, and no privileged mutable state is written after.

- `low-level-calls`
  - We intentionally use `staticcall/call` in a few places:
    - EIP-1271 signature checks (`isValidSignature(...)`) for contract authorities,
    - reading `reporterAuthority()` from an instance controller (AuditCommitmentHub),
    - executing arbitrary targets in `KernelAuthority` (multisig executor).
  - These calls are guarded by signature thresholds and/or strict return-value checks.

- `too-many-digits`
  - EIP-1167 minimal proxy initcode constants are expected to be long literals (assembly clone code).

- `missing-inheritance`
  - Slither suggests inheriting interface stubs for `ReleaseRegistry`.
  - This is a type-safety/documentation improvement (no runtime impact). Optional.

- `cyclomatic-complexity`
  - `finalizeProduction(...)` is intentionally “one-shot hardening” and therefore branchy.
  - Covered by unit tests and fuzz suites; any further complexity additions should go into separate helper contracts.

## Explicit non-goals / remaining risks

These contracts enforce on-chain trust transitions and provide authorized paths, but they do not (and cannot) eliminate:
- **Server compromise**: if an attacker controls the host and steals authority keys, they can still sign “valid” operations.
- **Integrity measurement trust**: the chain cannot independently verify filesystem state; it relies on external measurement + keys.
- **Operational availability**: aggressive “fail-closed” policy can cause self-inflicted downtime if misconfigured (e.g., check-in cadence vs `maxCheckInAgeSec`).

## Recommended next steps (before mainnet-like deployments)

- Run a dedicated fuzz/invariant pass (Foundry invariants) focused on:
  - nonces monotonicity and replay resistance,
  - upgrade timelock/TTL boundaries,
  - registry enforcement invariants when `releaseRegistryLocked/expectedComponentIdLocked` are set,
  - signature validation across mixed EOA + EIP-1271 authority configurations.
- Decide and document “production baseline” authority mode (EOA vs `KernelAuthority` vs Safe) and required thresholds per operation.
- Keep `InstanceController` EIP-170 margin in mind for any future additions (**4 bytes remaining** as of this report).
