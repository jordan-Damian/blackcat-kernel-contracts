# Contract Test Report (Foundry)

This document records what the Foundry test suite covers in `blackcat-kernel-contracts/`, with a focus on **security-relevant behavior** and **expected failure paths**.

Scope:
- `src/InstanceController.sol`
- `src/InstanceFactory.sol`
- `src/ReleaseRegistry.sol`
- `src/ManifestStore.sol`
- `src/KernelAuthority.sol`
- `src/AuditCommitmentHub.sol`

Note:
- Security status: **not independently audited yet** (see: [SECURITY_STATUS](SECURITY_STATUS.md)). This is an internal engineering test record, not a formal audit.
- `InstanceController` is close to **EIP-170** size limits; builds use `--via-ir` and `optimizer_runs = 1`. See `docs/BUILD_AND_VERIFICATION.md`.

## How to run locally

From `blackcat-kernel-contracts/`:

```bash
# Use the same toolchain as CI by default.
export FOUNDRY_IMAGE="${FOUNDRY_IMAGE:-ghcr.io/foundry-rs/foundry:stable}"

# format check
docker run --rm -v "$PWD":/app -w /app --entrypoint forge "$FOUNDRY_IMAGE" fmt --check

# tests (required; InstanceController is built via IR)
docker run --rm -v "$PWD":/app -w /app --entrypoint forge "$FOUNDRY_IMAGE" test --via-ir

# size gate (EIP-170)
docker run --rm -v "$PWD":/app -w /app --entrypoint forge "$FOUNDRY_IMAGE" build --via-ir --skip test --skip script --sizes
```

CI runs:
- `forge fmt --check`
- `forge test --via-ir`
- `forge build --via-ir --skip test --skip script --sizes`

## Test suite structure

Main suites:
- `test/InstanceController.t.sol`
- `test/InstanceFactory.t.sol`
- `test/ReleaseRegistry.t.sol`
- `test/ManifestStore.t.sol`
- `test/KernelAuthority.t.sol`
- `test/AuditCommitmentHub.t.sol`

Additional suites (focused on missing edges / failure paths):
- `test/InstanceController.Additional.t.sol`
- `test/InstanceFactory.Additional.t.sol`
- `test/ReleaseRegistry.Additional.t.sol`
- `test/ManifestStore.Additional.t.sol`
- `test/KernelAuthority.Additional.t.sol`

Integration suites (end-to-end flows across contracts):
- `test/KernelAuthority.Integration.t.sol`

Stateful fuzz (“invariant-ish”) suites:
- `test/InstanceController.StatefulFuzz.t.sol`
- `test/ReleaseRegistry.StatefulFuzz.t.sol`
- `test/ManifestStore.StatefulFuzz.t.sol`
- `test/KernelAuthority.StatefulFuzz.t.sol`

The tests intentionally include:
- success paths (expected state transitions),
- negative paths (reverts on invalid input/state),
- signature validation failures (wrong signer, expired deadline, replay attempts),
- strict access control enforcement.

## What is validated (high level)

### Common security invariants

Across contracts with EIP-712 “authorized” flows, tests validate:
- **Domain separation** includes `chainId` and `verifyingContract` (prevents cross-chain and cross-contract replay).
- **Anti-replay** uses on-chain nonces (signatures are single-use).
- **Deadlines** expire signatures (time-bounded authorization).
- **Signature malleability defense** rejects high-`s` signatures and invalid `v`.
- **EIP-2098** compact signatures are accepted where supported.
- **EOA vs contract signers**:
  - EOA flows use ECDSA recovery,
  - `KernelAuthority` provides a minimal “multi-device by design” threshold signer option,
  - signature validation uses EIP-1271 where a contract signer is expected.

### InstanceController (per-install state machine)

Covered areas:
- **Initialization**
  - state is set exactly once,
  - zero-address authorities are rejected,
  - genesis root trust gating is enforced when a registry is configured.
- **Emergency controls**
  - pause/unpause permissions and constraints,
  - `setPausedAuthorized(...)` behavior (EOA + KernelAuthority signatures, deadlines, state mismatch/no-op guards),
  - emergency “kill switch” patterns (fail-closed runtime is an off-chain concern; the controller provides the authoritative state).
- **Authority rotation**
  - root/upgrade/emergency/reporter authorities use two-step transfers (start → accept),
  - transfer cancels revert when nothing is pending and clear pending when used.
- **ReleaseRegistry integration**
  - `setReleaseRegistry` rejects non-contract addresses,
  - when `expectedComponentId` is set, registry changes are constrained to avoid “trust bypass” via registry swaps,
  - trusted-root checks are enforced for active/pending/compat roots when a registry is used.
- **Production hardening knobs**
  - `finalizeProduction(...)` validates registry consistency (presence of `getByRoot` and non-zero component ID),
  - knobs can be locked to prevent weakening after go-live.
- **Check-in + integrity acceptance**
  - `isAcceptedState(...)` and both check-in modes are exercised,
  - missing reporter authority is rejected,
  - paused behavior does not accidentally raise incidents,
  - auto-pause mechanics are verified by state-driven tests (where enabled).
- **Incidents**
  - incident reporting enforces non-zero incident hashes,
  - authorized reporting validates signatures and deadlines,
  - incident nonce usage prevents replay and supports “strong history”.
- **Compatibility rollback**
  - compatibility state can be cleared and rejects clearing when empty,
  - rollback authorized paths validate signatures and deadlines.
- **Snapshots**
  - `snapshot()` and `snapshotV2()` provide read-only state summaries used by off-chain tooling.

### InstanceFactory (per-install controller creation)

Covered areas:
- instance creation rejects zero authorities and zero genesis root,
- deterministic create rejects malformed signatures and invalid signer configurations,
- EOA-root signatures and KernelAuthority-root signatures are both exercised,
- salt reuse safety is exercised (CREATE2 address uniqueness).

### ReleaseRegistry (global release trust list)

Covered areas:
- publish enforces immutability per `(componentId, version)`,
- root uniqueness across releases is enforced,
- owner-only operations are enforced,
- authorized publish/revoke flows validate:
  - EOA signatures,
  - EIP-2098 compact signatures,
  - EIP-1271 contract signers (e.g. `KernelAuthority` as owner),
  - deadline expiry,
  - non-replay (nonce consumption).
- batch APIs validate length matching and reject empty batches,
- revoke behavior updates the trusted root set, including root-not-found and already-revoked failure paths.

### ManifestStore (optional on-chain blob availability)

Covered areas:
- owner-only append/finalize,
- append rejects empty chunks and rejects operations after finalization,
- finalize rejects mismatched hash or zero hash,
- retrieval rejects out-of-range chunk index,
- authorized ownership transfer (deadline, invalid signature, pending owner mismatch).

### KernelAuthority (optional minimal threshold signer)

Covered areas:
- constructor rejects invalid configs (no signers, bad threshold, signer=0, unsorted signers),
- EIP-712 digests are computed and validated in execution,
- replay protection via nonce,
- `execute` and `executeBatch` enforce threshold signatures and order,
- `execute` and `executeBatch` reject `target=0`,
- ETH value transfer via `execute` is tested,
- EIP-1271 `isValidSignature` supports tooling expectations and rejects insufficient/unsorted signer blobs.

Note:
- Signer arrays must be strictly increasing. Duplicate signers are therefore rejected by the ordering invariant.

### AuditCommitmentHub (optional batched audit root commits)

Covered areas:
- reads reporter authority from `InstanceController.reporterAuthority()`,
- enforces monotonic sequence ranges (`seqFrom == lastSeq + 1`),
- accepts EIP-1271 reporter signatures (KernelAuthority signer blob),
- rejects insufficient signature blobs for contract reporters.

## What this does not guarantee

Even with thorough tests, the following remain outside the scope of this test suite:
- a formal security audit (manual + tooling),
- full formal verification of invariants,
- economic and chain-level adversaries (reorgs, censorship, MEV) beyond basic deadline/nonce defenses,
- off-chain enforcement correctness (PEP/back-controller), filesystem permission hardening, and multi-RPC quorum behavior.

For those areas, see:
- `docs/THREAT_MODEL.md`
- `docs/POLICY_ENFORCEMENT.md`
- `docs/SECURITY_FLOWS.md`
