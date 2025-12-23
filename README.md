![BlackCat Kernel Contracts banner](.github/blackcat-kernel-contracts-banner.png)

# BlackCat Kernel Contracts

EVM smart contracts that act as the **trust authority** for BlackCat installations.

The core idea:
- every BlackCat install gets its own on-chain **Instance Controller** contract (clone/proxy),
- the contract stores the attested integrity state (install + upgrades) and emergency controls,
- the runtime (via `blackcat-core` + `blackcat-config`) treats the on-chain state as the source of truth and fails closed in production when trust cannot be verified.

This repository is intentionally **Solidity-only**. Runtime policy, config permission checks, and CLI/installer flows live in other repos.

## Contracts (planned)

- `ReleaseRegistry`: global registry of “official” component releases (version → root hash + URI).
- `InstanceFactory`: creates/clones `InstanceController` per install and runs the setup ceremony (CREATE + CREATE2).
- `InstanceController`: per-install state machine (propose → stage → activate upgrades), pause/unpause, and history events.
- `KernelAuthority` (optional): minimal EIP-712 threshold signer authority (multi-device by design without Safe dependency).
- `ManifestStore` (optional): append-only on-chain blob store for manifests (“full detail” mode availability).

## Spec

- `blackcat-kernel-contracts/docs/SPEC.md`
- `blackcat-kernel-contracts/docs/AUTHORITY_MODES.md`
- `blackcat-kernel-contracts/docs/ROADMAP.md`

## Governance model (planned)

Do not embed complex multisig logic inside these contracts. Prefer external multisig wallets (e.g. Safe) and treat them as authorities:
- `root_authority` (policy changes, signer rotation, thresholds)
- `upgrade_authority` (propose/activate upgrades)
- `emergency_authority` (pause/unpause / emergency gates)

In practice each authority can be a separate Safe with its own threshold.

## Trust modes (planned)

- `root+uri` (recommended baseline): store a Merkle/tree root plus a content URI (IPFS/HTTPS) for full manifests.
- `full detail` (paranoid): store more on-chain detail (chunked manifest bytes or per-file hashes). Expensive; only for high-value systems.

## Tooling

Dev stack: Foundry (`forge`).

Run via Docker (recommended for consistent solc/forge versions):

- Format: `docker run --rm -v "$PWD":/app -w /app --entrypoint forge ghcr.io/foundry-rs/foundry:latest fmt`
- Test: `docker run --rm -v "$PWD":/app -w /app --entrypoint forge ghcr.io/foundry-rs/foundry:latest test`

## Deployment (Foundry)

Scripts live in `blackcat-kernel-contracts/script/` and intentionally avoid external dependencies.

- Deploy registry + factory: `blackcat-kernel-contracts/script/DeployAll.s.sol`
- Deploy only registry: `blackcat-kernel-contracts/script/DeployReleaseRegistry.s.sol`
- Deploy only factory: `blackcat-kernel-contracts/script/DeployInstanceFactory.s.sol`
- Deploy ManifestStore (optional): `blackcat-kernel-contracts/script/DeployManifestStore.s.sol`
- Publish/revoke releases: `blackcat-kernel-contracts/script/PublishRelease.s.sol`, `blackcat-kernel-contracts/script/RevokeRelease.s.sol`
- Per-install instance + upgrades:
  - `blackcat-kernel-contracts/script/CreateInstanceDeterministic.s.sol`
  - `blackcat-kernel-contracts/script/ProposeUpgrade.s.sol`
  - `blackcat-kernel-contracts/script/ProposeUpgradeByRelease.s.sol`
  - `blackcat-kernel-contracts/script/ActivateUpgradeExpected.s.sol`
  - `blackcat-kernel-contracts/script/CancelUpgradeExpected.s.sol`
- Pause/unpause: `blackcat-kernel-contracts/script/Pause.s.sol`, `blackcat-kernel-contracts/script/Unpause.s.sol`
- Upload ManifestStore blobs: `blackcat-kernel-contracts/script/UploadManifestBlob.s.sol`

**Note:** contracts are not audited. Do not use in production until reviewed.
