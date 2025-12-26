# Security Audit Report (Internal)

Date: 2025-12-26

Scope:
- `blackcat-kernel-contracts/src/InstanceController.sol`
- `blackcat-kernel-contracts/src/InstanceFactory.sol`
- `blackcat-kernel-contracts/src/KernelAuthority.sol`
- `blackcat-kernel-contracts/src/ReleaseRegistry.sol`
- `blackcat-kernel-contracts/src/ManifestStore.sol`

Tooling / checks used:
- Foundry tests: `forge test --via-ir`
- Bytecode size check: `forge build --via-ir --sizes` (EIP-170)
- Foundry lint (notes/warnings)

## Summary

- All Foundry tests pass (including stateful fuzz/regression suites).
- CI enforces:
  - `forge fmt --check`
  - `forge test --via-ir`
  - `forge build --via-ir --skip test --skip script --sizes` (EIP-170)
  - Slither (static analysis) in warning-only mode
- `InstanceController` remains under the EIP-170 runtime limit:
  - Runtime size: **24,337 bytes**
  - Margin: **239 bytes**

## Findings

### HIGH — EOA-first signature recovery could block EIP-1271 authorities in multi-authority resolvers

Contract: `blackcat-kernel-contracts/src/InstanceController.sol`

Affected paths:
- `setPausedAuthorized(...)` → `_resolvePauseSigner(...)`
- `reportIncidentAuthorized(...)` → `_resolveIncidentSigner(...)`

Issue:
- `_resolvePauseSigner` / `_resolveIncidentSigner` try authorities in order (root → emergency → reporter).
- When the **first checked authority is an EOA**, `_isValidSignatureNow` falls back to `_recover(...)`.
- Previously, `_recover(...)` reverted on signature lengths other than 64/65.
- This breaks legitimate use-cases where the **intended signer is an EIP-1271 contract** (e.g., `KernelAuthority`) and the signature blob is ABI-encoded (longer than 65 bytes):
  - Example: root is EOA, emergency is `KernelAuthority`, caller provides a valid EIP-1271 signature for emergency.
  - Result before fix: root check reverts (`BadSignatureLength`) and prevents reaching the emergency check.

Impact:
- Prevents “multi-device by design” setups where some roles are EOAs and others are EIP-1271 contracts.
- In practice, this blocks using `KernelAuthority` (or other EIP-1271 signers) for emergency/reporting unless the earlier role(s) are also contract authorities.

Fix (implemented):
- In `InstanceController._recover(...)`, return `address(0)` on unsupported signature length instead of reverting.
- This lets the resolver continue to the next authority role and properly validate EIP-1271 signatures.

Regression tests (added):
- `test/InstanceController.t.sol`:
  - `test_setPausedAuthorized_accepts_kernelAuthority_emergency_signature`
  - `test_reportIncidentAuthorized_accepts_kernelAuthority_reporter_signature`

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
- Keep `InstanceController` EIP-170 margin in mind for any future additions (239B remaining as of this report).
