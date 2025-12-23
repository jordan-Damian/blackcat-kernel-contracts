# Trust Kernel (Web3 / EVM) — v1 Spec (Draft)

This is the working specification for the BlackCat **Trust Kernel**.

## Goal

BlackCat treats the local host filesystem as untrusted (FTP mistakes, compromised credentials, partial upgrades).
The system must be:
- **tamper-evident by default** (baseline),
- **tamper-resistant when hardened tiers are enabled** (HSM/KMS signing, out-of-band verification).

The Trust Kernel provides an **external trust authority** for installs/upgrades:
- on-chain state is the source of truth,
- the runtime fails closed in production when trust cannot be verified.

## Chain (v1 default)

Default chain is configurable, but v1 reference network is:
- Chain: Edgen Chain (EVM)
- `chain_id`: `4207`
- RPC: `https://rpc.layeredge.io`
- Explorer: `https://edgenscan.io`

Production must use multi-RPC quorum (recommended: `2/3`, minimum: `2/2`).

## Actors / authorities

Authorities are normally **external multisig wallets** (e.g. Safe) to avoid custom multisig logic in kernel contracts.

Optionally (advanced), BlackCat can use an on-chain EIP-712 threshold signer authority (`KernelAuthority`) to enforce multi-device signing without depending on Safe tooling.
See `blackcat-kernel-contracts/docs/AUTHORITY_MODES.md`.

Recommended split:
- `root_authority` (highest): policy changes, authority rotation, thresholds.
- `upgrade_authority`: propose/stage/activate upgrades.
- `emergency_authority`: pause/unpause and break-glass controls.

Each authority can be a distinct Safe with different thresholds.

## Trust modes

Install-time selectable (with cost estimation):

1) `root_uri` (baseline / recommended)
   - Anchor a `bytes32 root` + `uriHash` (hash of a URI pointing to the full manifest).
   - Full file list stays off-chain (IPFS/HTTPS), still tamper-evident via the root.

2) `full` (paranoid)
   - Anchor more detail on-chain (chunked manifest bytes or per-file hashes).
   - Much more expensive; intended only for high-value deployments.

The contracts store hashes and emit events; full payloads are handled off-chain.

## Hashing (v1 canonical)

The contracts **do not** compute these values on-chain in v1. They are computed off-chain and stored as `bytes32`.

Canonical algorithms (single source of truth lives in `blackcat-integrity`):

- `root`: Merkle/tree root computed by `blackcat-integrity/src/TrustKernel/Sha256Merkle.php`
  - leaf: `sha256(0x00 || path || 0x00 || fileHashBytes32)`
  - node: `sha256(0x01 || left || right)` (duplicate last on odd count)
  - entries are sorted lexicographically by normalized path.
- `uriHash`: `sha256(uri_string_bytes)` (exact bytes; no implicit normalization).
- `policyHash`: `sha256(canonical_json(policy))` where canonical JSON is defined by `blackcat-integrity/src/TrustKernel/CanonicalJson.php` and policy schema by `blackcat-integrity/src/TrustKernel/TrustPolicyV1.php`.
- Baseline `root+uri` receipt helper: `blackcat-integrity/src/TrustKernel/RootUriReceiptV1.php`

## On-chain components

### `ReleaseRegistry` (global)

Purpose: publish “official” release roots for components.

Core mapping:
- `componentId (bytes32)` + `version (uint64)` → `{root, uriHash, metaHash}`

Notes:
- Version encoding must be stable. v1 uses `uint64` (implementation detail; may evolve).
- Publishing is gated (owner now; later: governance authority / Safe).
- Releases are immutable per `(componentId, version)` (republishing is rejected; publish a new version instead).
- Roots are unique across the registry (a `root` can be published only once) to avoid ambiguity.
- Ownership uses a 2-step transfer (`transferOwnership` → `acceptOwnership`) to reduce operator mistakes.
- The registry supports **revocation** per `(componentId, version)`:
  - revocation permanently marks the release as revoked and its `root` as untrusted,
  - `isTrustedRoot(root)` becomes false after revocation,
  - publishing a release with a revoked root is rejected.
- Operators can publish/revoke in batches (`publishBatch`, `revokeBatch`) and revoke by root (`revokeByRoot`) for operational convenience.
- A reverse lookup is available (`getByRoot(root)`) for tooling/inspection.

### `InstanceController` (per install)

Purpose: per-install trust authority holding active attested state and upgrade history.

State:
- `activeRoot`, `activeUriHash`, `activePolicyHash`
- `paused`
- `pendingUpgrade` (proposal with TTL)
- `rootAuthority`, `upgradeAuthority`, `emergencyAuthority`
- Optional `releaseRegistry` (if set, upgrades must reference trusted roots)
- Optional `minUpgradeDelaySec` (timelock)
- Optional `reporterAuthority` + `lastCheckInAt/lastCheckInOk` (monitoring agent check-in)
- Optional `autoPauseOnBadCheckIn` (auto-pause latch on a bad check-in)
- Incident tracking: `incidentCount`, `lastIncidentAt`, `lastIncidentHash`, `lastIncidentBy`

Upgrade flow (v1):
1. `proposeUpgrade(root, uriHash, policyHash, ttlSec)` (upgrade authority)
2. Optional: `cancelUpgrade()` (root authority or upgrade authority)
3. `activateUpgrade()` (root authority, within TTL and after timelock, if configured)

If `releaseRegistry` is set:
- `initialize(...)` requires the genesis `root` to be trusted in the registry.
- `proposeUpgrade(...)` and `activateUpgrade()` require the proposed root to be trusted at the time of the call.

Emergency flow:
- `pause()` / `unpause()` (emergency authority)
- Root authority can also pause/unpause as a fallback (recommended).
- `reportIncident(incidentHash)` can be called by root/emergency/reporter and will pause the controller and record incident metadata.

Monitoring / check-ins (v1):
- `checkIn(observedRoot, observedUriHash, observedPolicyHash)` (reporter authority)
- The controller records `(lastCheckInAt, lastCheckInOk)` for off-chain health evaluation.
- If `autoPauseOnBadCheckIn` is enabled, a bad check-in pauses the controller and records an incident.

Runtime optimization (v1):
- `snapshot()` aggregates the commonly-read state (paused + active hashes + pending proposal) into one `eth_call`.

### `InstanceFactory`

Purpose: create per-install `InstanceController` instances efficiently (EIP-1167 clones).

v1 factory is intentionally permissionless; the important part is that the server pins the correct controller address in runtime config.

Factory behavior (v1):
- `releaseRegistry` is configured at deployment time (immutable, can be `0x0`).
- `createInstance(...)` creates a clone (CREATE) and initializes it.
- `createInstanceDeterministic(..., salt)` creates a clone via CREATE2, enabling pre-computed addresses.
- `predictInstanceAddress(salt)` returns the deterministic CREATE2 address for the factory’s current implementation.

## Runtime policy (off-chain)

The contracts store the attested state; **runtime enforcement** lives in `blackcat-core` + `blackcat-config`.

Key runtime config (see `blackcat-config`):
- `trust.web3.chain_id`
- `trust.web3.rpc_endpoints[]`
- `trust.web3.rpc_quorum`
- `trust.web3.max_stale_sec` (recommended prod default: `180`)
- `trust.web3.mode` (`root_uri` | `full`)
- `trust.web3.contracts.instance_controller`
- `trust.web3.contracts.release_registry` (optional)
- `trust.web3.tx_outbox_dir` (optional, for buffering tx during outages)

Outage rules (recommended for prod):
- if RPC quorum is lost: **pause writes immediately**, buffer critical actions to an outbox if available
- allow reads only until stale (`max_stale_sec`), then fail closed

## Minimal install (core-only on server)

Target server installs only:
- `blackcat-core` (plus dependencies)
- a file-based runtime config (no env dependence)

Setup is done on a separate device:
1. create/clone the per-install controller contract
2. verify the transaction and resulting contract address on-chain
3. confirm via multisig threshold (multiple devices)
4. copy the controller address + chain config into the server runtime config

## Open questions (tracked for Stage 0 → Stage 1)

- Stable version encoding for `ReleaseRegistry` (semver packing vs bytes32 versionId).
- EIP-712 “setup request” format for offline review (optional if Safe is used end-to-end).
- Whether `InstanceController` should reference `ReleaseRegistry` (version-based activation) instead of raw roots.
- Detailed `full` mode encoding strategy (chunking, gas ceilings, pruning).
