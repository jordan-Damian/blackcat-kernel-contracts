# Operations Guide (Draft)

This file documents **operator flows** for deploying and operating the Trust Kernel contracts.

Important:
- These contracts are **not audited**.
- For production, use multisig authorities (Safe) and treat private keys as extremely sensitive.
- Do not share private keys/seed phrases in issues or logs.

## Deploy

Recommended baseline deployment:
- `ReleaseRegistry` (global, owned by Safe)
- `InstanceFactory` (points to ReleaseRegistry)
- `ManifestStore` (optional, for “full detail” mode availability)

Foundry scripts (see `blackcat-kernel-contracts/script/`):
- Deploy registry+factory: `DeployAll.s.sol`
- Deploy registry: `DeployReleaseRegistry.s.sol`
- Deploy factory: `DeployInstanceFactory.s.sol`
- Deploy ManifestStore: `DeployManifestStore.s.sol`

## Publish releases

Use `PublishRelease.s.sol` to publish official releases into `ReleaseRegistry`.

Inputs you must compute off-chain:
- `componentId` (`bytes32`) — stable component identifier
- `version` (`uint64`) — stable version encoding
- `root` (`bytes32`) — attested integrity root
- `uriHash` (`bytes32`) — `sha256(uri_string_bytes)`
- `metaHash` (`bytes32`) — optional metadata hash

Revocation:
- Use `RevokeRelease.s.sol` to revoke a `(componentId, version)`.

## Create instance (per install)

Use `CreateInstanceDeterministic.s.sol` with a stable `salt` so the instance address is predictable via `predictInstanceAddress`.

Set the created controller address into your runtime config (`blackcat-config`) and treat it as a critical trust anchor.

## Upgrade flow

Propose:
- Raw root/uri: `ProposeUpgrade.s.sol`
- By ReleaseRegistry version: `ProposeUpgradeByRelease.s.sol`

Activate/cancel (safe helpers):
- `ActivateUpgradeExpected.s.sol`
- `CancelUpgradeExpected.s.sol`

Rolling upgrades:
- Set overlap window: `SetCompatibilityWindow.s.sol`
- During the overlap, runtimes can accept either active state or compatibility state (`isAcceptedState`).
- Clear compatibility state: `ClearCompatibilityState.s.sol`

## Monitoring and incidents

Reporter check-in (direct):
- `CheckIn.s.sol`

Incident reporting (direct; pauses the controller):
- `ReportIncident.s.sol`

Pause/unpause:
- Direct: `Pause.s.sol`, `Unpause.s.sol`
- Relayer signature: `setPausedAuthorized(...)` (see SPEC)

Relayer variants:
- `checkInAuthorized(...)`, `reportIncidentAuthorized(...)`, `setPausedAuthorized(...)`
  are intended for CLI/tooling that collects signatures on isolated devices and submits via a relayer.

## Attestations (pinning)

The controller provides `attestations[key]=value` slots (root authority) to pin additional integrity facts on-chain.

Example (recommended):
- `key = keccak256("config.runtime.v1")`
- `value = sha256(canonical_runtime_config_bytes)`

Use `SetAttestation.s.sol` for a basic EOA flow (production should use Safe).
Clear an attestation:
- `ClearAttestation.s.sol`

Other recommended settings:
- Set upgrade timelock: `SetMinUpgradeDelay.s.sol`
- Toggle auto-pause on bad check-in: `SetAutoPauseOnBadCheckIn.s.sol`
- Clear reporter authority: `ClearReporterAuthority.s.sol`

## ManifestStore (optional “full detail” availability)

Upload a blob (expensive):
- `UploadManifestBlob.s.sol` reads a file, uses `sha256(fileBytes)` as `blobHash`, stores chunks, and finalizes.

Consumers must:
- reassemble the blob and validate its `sha256` off-chain
- treat on-chain availability as an availability layer, not as “automatic trust”
