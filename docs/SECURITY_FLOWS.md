# Security Flows & Diagrams (Draft)

This document provides **diagram-first** explanations of the Trust Kernel security flows:
what is expected to happen, what must *not* happen, and what the contracts enforce on-chain.

Diagrams use **Mermaid** (rendered by GitHub).

Important:
- These contracts are **not audited**.
- Off-chain enforcement (fail-closed runtime behavior, multi-RPC quorum, filesystem hardening) lives in `blackcat-core` + `blackcat-config`.

## Component Map

```mermaid
flowchart TB
  %% ===== Off-chain =====
  subgraph Offchain["Off-chain (blackcat-cli / blackcat-installer / blackcat-core)"]
    Builder["Integrity builder<br/>• compute root<br/>• compute uriHash<br/>• compute policyHash<br/>• prepare ReleaseRegistry items"]
    Signer["Authority signer<br/>(Safe / Ledger / KernelAuthority / EOA)"]
    Relayer["Relayer / Operator<br/>(broadcast tx, pays gas)"]
    Runtime["Runtime agent<br/>(verify on-chain state,<br/>block unsafe writes in prod)"]
  end

  %% ===== On-chain =====
  subgraph Onchain["On-chain (EVM)"]
    RR["ReleaseRegistry<br/>(global)<br/>• publish official roots<br/>• revoke roots"]
    MS["ManifestStore (optional)<br/>• chunked blobs<br/>• finalize"]
    IF["InstanceFactory<br/>(global)<br/>• CREATE2 bootstrap<br/>• emits setup receipt"]
    IC["InstanceController<br/>(per install)<br/>• active state<br/>• upgrades<br/>• incidents<br/>• attestations"]
    KA["KernelAuthority (optional)<br/>• threshold signer<br/>• EIP-1271"]
  end

  Builder -->|root uriHash metaHash| RR
  Builder -->|chunks optional| MS

  Signer -->|EIP712 signatures| Relayer
  Relayer -->|tx| IF
  IF -->|initialize| IC
  IC -->|optional enforcement| RR

  Runtime -->|eth_call quorum| IC
  Runtime -->|eth_call quorum| RR
  Runtime -->|optional fetch| Builder
```

## Common Pattern: EIP-712 Digest + Anti-Replay

Most “relayer” flows follow the same pattern:

```mermaid
flowchart LR
  Domain["domainSeparator()\n(name, version,\nchainId, verifyingContract)"]
  Struct["structHash\n(typehash, params,\nnonce, deadline)"]
  Digest["digest\nkeccak256(0x1901 || domain || structHash)"]

  Domain --> Digest
  Struct --> Digest

  Digest --> Sig["signature\n(ECDSA or EIP-1271 blob)"]
```

Properties:
- **Cross-chain replay resistance**: `chainId` is part of the domain separator.
- **Cross-contract replay resistance**: `verifyingContract` is part of the domain separator.
- **Intra-contract replay resistance**: nonces are included in the struct.
- **Time-bounded signatures**: `deadline` bounds signature validity.

## Flow: Runtime Policy Enforcement (“Back Controller” / PEP)

The Trust Kernel cannot “sandbox” a server by itself. Instead:
- `InstanceController` stores the *commitments* (what must be true),
- the runtime enforces the policy (what is allowed to happen) and fails closed in production.

See also: [POLICY_ENFORCEMENT](POLICY_ENFORCEMENT.md).

### Boot sequence (production posture)

```mermaid
sequenceDiagram
  autonumber
  participant App as App / worker
  participant Config as blackcat-config
  participant Runtime as blackcat-core PEP
  participant IC as InstanceController
  participant RR as ReleaseRegistry
  participant MS as ManifestStore

  App->>Config: Load runtime config (secure location)
  Config-->>Runtime: controller address, chainId, RPC quorum, mode

  Runtime->>IC: snapshotV2() (quorum eth_call)
  IC-->>Runtime: activeRoot/uriHash/policyHash + flags + paused

  opt ReleaseRegistry enabled
    Runtime->>RR: isTrustedRoot(activeRoot) (quorum)
    RR-->>Runtime: true/false
  end

  opt Policy bytes availability-on-chain enabled
    Runtime->>MS: get(policyHash) / getChunk(...) (quorum)
    MS-->>Runtime: policy bytes
  end

  Runtime->>Runtime: Compute observedRoot/uriHash/policyHash
  alt mismatch OR paused OR no quorum
    Runtime->>Runtime: Deny security-critical writes (fail closed)
  else OK
    Runtime->>Runtime: Enter normal operation
  end
```

### Per-request enforcement (high level)

```mermaid
flowchart TB
  Req["Incoming request / job"] --> PEP["Back Controller (PEP)\nverify state + policy"]
  PEP -->|"OK"| Do["Perform sensitive op\n(DB write / decrypt / rotate key)"]
  PEP -->|"Mismatch or uncertain"| Deny["Deny / degrade\n(read-only, buffer, or hard fail)"]
  Deny --> Incident["Optional: reportIncident / checkIn"]
```

Expected:
- Sensitive operations are only reachable through the enforcement layer.
- Production does not “continue anyway” when trust cannot be verified.

Forbidden:
- Bypassing the enforcement layer by calling lower-level primitives directly (design must avoid exposing secrets outside PEP).

## Trust Modes: `root+uri` vs “full detail”

```mermaid
flowchart TB
  subgraph Baseline["Baseline (recommended): root+uri"]
    Files["Files on disk\n(paths + bytes)"] --> Root["root (bytes32)\n(off-chain tree/Merkle root)"]
    URI["URI string\n(ipfs/https/evm-manifest://...)"] --> UriHash["uriHash (bytes32)\nsha256(uri bytes)"]
    Root --> Receipt["On-chain receipt\n(root, uriHash,\npolicyHash)"]
    UriHash --> Receipt
  end

  subgraph Paranoid["Paranoid availability (optional): ManifestStore"]
    Blob["Manifest blob bytes\n(off-chain)"] --> BlobHash["blobHash = sha256(blobBytes)"]
    Blob --> Chunks["appendChunk(s)\n(on-chain chunks)"]
    Chunks --> Finalize["finalize(expectedCount, expectedBytes)"]
    BlobHash --> Finalize
  end
```

Expected:
- The on-chain system stores **hashes**, not full manifests (unless you enable `ManifestStore` for availability).
- Consumers **verify** off-chain content against the on-chain root/uriHash.

Forbidden:
- Treating any off-chain URI as “trusted” without verifying it matches the on-chain `uriHash` and `root`.

## Flow: Publish Official Releases (ReleaseRegistry)

### Happy path (owner or relayer)

```mermaid
sequenceDiagram
  autonumber
  participant Builder as Off-chain builder
  participant Owner as ReleaseRegistry owner<br/>(Safe/KernelAuthority/EOA)
  participant Relayer as Relayer
  participant RR as ReleaseRegistry

  Builder->>Owner: Present release items<br/>(componentId, version, root, uriHash, metaHash)
  Owner-->>Relayer: EIP-712 signature<br/>Publish(...)
  Relayer->>RR: publishAuthorized(..., signature)
  RR->>RR: Verify signature (ECDSA/EIP-1271)
  RR->>RR: Enforce uniqueness + not revoked
  RR-->>Relayer: Emit SignatureConsumed + ReleasePublished
```

Key on-chain checks:
- `root` cannot be republished under a different `(componentId, version)` (uniqueness via `rootIndex`).
- `(componentId, version)` is immutable once published.
- Revoked roots cannot be republished.

### Batch publishing

For batch operations, signatures cover `itemsHash = keccak256(abi.encode(items))` where
`items` is an array of structs (`PublishBatchItem[]`).

```mermaid
sequenceDiagram
  autonumber
  participant Owner as ReleaseRegistry owner
  participant Relayer as Relayer
  participant RR as ReleaseRegistry

  Owner-->>Relayer: EIP-712 signature<br/>PublishBatch(itemsHash, nonce, deadline)
  Relayer->>RR: publishBatchAuthorized(items[], deadline, signature)
  RR->>RR: Verify signature + nonce
  loop For each item
    RR->>RR: _publish(componentId, version, root, uriHash, metaHash)
  end
  RR-->>Relayer: ReleasePublished(events...)
```

### Revocation

Expected:
- Revocation is permanent: a revoked root becomes **untrusted**.

Forbidden:
- Activating an upgrade/root that is revoked (controllers enforce this if `releaseRegistry != 0`).

## Flow: Per-Install Bootstrap (InstanceFactory + CREATE2)

Goal: deterministic deployment (predictable address) **without** letting third parties pre-claim salts.

```mermaid
sequenceDiagram
  autonumber
  participant Operator as Operator
  participant Builder as Off-chain builder
  participant Root as rootAuthority<br/>(Safe/KA/EOA)
  participant Relayer as Relayer
  participant IF as InstanceFactory
  participant IC as InstanceController (clone)
  participant RR as ReleaseRegistry

  Operator->>Builder: Compute genesisRoot/uriHash/policyHash
  Operator->>IF: predictInstanceAddress(salt) (eth_call)
  Builder->>Root: Review & sign SetupRequest<br/>(EIP-712, includes salt+deadline)
  Root-->>Relayer: setup signature
  Relayer->>IF: createInstanceDeterministicAuthorized(..., salt, deadline, signature)
  IF->>IF: Verify rootAuthority signature (ECDSA/EIP-1271)
  IF->>IF: CREATE2 clone (salt)
  IF->>IC: initialize(..., releaseRegistry, genesis*)
  alt releaseRegistry configured
    IC->>RR: isTrustedRoot(genesisRoot)
    RR-->>IC: true
  end
  IF-->>Relayer: SetupSignatureConsumed + InstanceCreatedDeterministic
```

Expected:
- `salt` is bound into the signed digest, preventing signature replay into other instance addresses.
- If `releaseRegistry` is configured, genesis must already be published and trusted.

Forbidden:
- Anyone deploying a deterministic instance without a rootAuthority signature.
- Reusing the same `(salt, factory)` to create a second instance (CREATE2 will fail).

## Flow: Upgrades (InstanceController)

### Upgrade state machine (conceptual)

```mermaid
stateDiagram-v2
  [*] --> Active

  Active --> Pending: proposeUpgrade(...) / proposeUpgradeByRelease(...)
  Pending --> Active: activateUpgrade(...) / activateUpgradeAuthorized(...)
  Pending --> Active: cancelUpgrade(...) / cancelUpgradeAuthorized(...)

  Active --> Active: activateUpgrade(...) with compatibility overlap
  Active --> Active: rollbackToCompatibilityState(...) (within overlap)
```

### Propose → Activate (with registry enforcement)

```mermaid
sequenceDiagram
  autonumber
  participant Upgrader as upgradeAuthority
  participant Root as rootAuthority
  participant IC as InstanceController
  participant RR as ReleaseRegistry

  Upgrader->>IC: proposeUpgrade(root, uriHash, policyHash, ttl)
  alt releaseRegistry configured
    IC->>RR: isTrustedRoot(root)
    RR-->>IC: true
  end
  IC-->>Upgrader: UpgradeProposed(root, uriHash, policyHash, ttl, proposalNonce)

  Root->>IC: activateUpgradeExpected(root, uriHash, policyHash)
  IC->>IC: Enforce timelock (minUpgradeDelaySec) + TTL
  alt rolling upgrade enabled
    IC->>IC: set compatibilityState (previous active, until=now+window)
  end
  IC-->>Root: UpgradeActivated(previousRoot, root, uriHash, policyHash)
```

Expected:
- Propose is separated from activate (review window).
- Activation is root-controlled; relayer variants use EIP-712 + nonces.

Forbidden:
- Activating a root that is not trusted by `ReleaseRegistry` (when configured).
- Replaying old “activate” signatures after a new proposal (`pendingUpgradeNonce` prevents this).

### Paused upgrades (incident recovery)

`InstanceController` allows upgrades to be activated while `paused=true` to support incident recovery workflows.
Runtime policy (off-chain) decides what actions are permitted while paused.

## Flow: Incidents, Check-ins, Auto-Pause

```mermaid
sequenceDiagram
  autonumber
  participant Reporter as reporterAuthority
  participant Relayer as Relayer
  participant IC as InstanceController

  Note over IC: Runtime computes observedRoot/uriHash/policyHash from disk

  alt Direct check-in (reporter sends tx)
    Reporter->>IC: checkIn(observedRoot, observedUriHash, observedPolicyHash)
  else Relayed check-in (reporter signs)
    Reporter-->>Relayer: signature CheckIn(...)
    Relayer->>IC: checkInAuthorized(observedRoot, observedUriHash, observedPolicyHash, deadline, signature)
  end

  IC->>IC: Compare observed state vs accepted state(s)
  alt mismatch AND autoPauseOnBadCheckIn=true
    IC->>IC: record IncidentReported("bad_checkin", ...)
    IC->>IC: pause()
    IC-->>Relayer: IncidentReported + Paused
  else ok
    IC-->>Relayer: CheckIn(ok=true, ...)
  end
```

Expected:
- Check-ins are reporter-controlled (direct) or reporter-signed (relayed).
- A “bad check-in” can pause the controller if configured, creating an on-chain incident record.

Forbidden:
- Allowing an untrusted process to act as `reporterAuthority`.

### Permissionless auto-pause helpers (bots)

These helpers are intended for monitoring/guard bots. They are permissionless by design and are safe because they can only reduce availability (pause), not grant new authority.

#### `pauseIfStale()` (check-in freshness)

```mermaid
sequenceDiagram
  autonumber
  participant Bot as Monitoring bot
  participant IC as InstanceController

  Note over IC: Requires maxCheckInAgeSec != 0 (ideally locked in prod)

  Bot->>IC: pauseIfStale()
  alt within max age OR already paused
    IC-->>Bot: returns false (no-op)
  else stale beyond maxCheckInAgeSec
    IC->>IC: IncidentReported("stale_checkin", ...)
    IC->>IC: Paused
    IC-->>Bot: returns true
  end
```

#### `pauseIfActiveRootUntrusted()` (registry revocation)

```mermaid
sequenceDiagram
  autonumber
  participant Bot as Monitoring bot
  participant IC as InstanceController
  participant RR as ReleaseRegistry

  Bot->>IC: pauseIfActiveRootUntrusted()
  alt releaseRegistry not configured OR already paused
    IC-->>Bot: returns false (no-op)
  else activeRoot still trusted
    IC->>RR: isTrustedRoot(activeRoot)
    RR-->>IC: true
    IC-->>Bot: returns false (no-op)
  else activeRoot untrusted/revoked
    IC->>RR: isTrustedRoot(activeRoot)
    RR-->>IC: false
    IC->>IC: IncidentReported("active_root_untrusted", ...)
    IC->>IC: Paused
    IC-->>Bot: returns true
  end
```

## Flow: Authority Rotation (2-step, optional relayer)

```mermaid
sequenceDiagram
  autonumber
  participant Root as rootAuthority
  participant New as pending authority<br/>(Safe/KA/EOA)
  participant Relayer as Relayer
  participant IC as InstanceController

  Root->>IC: startRootAuthorityTransfer(newAuthority)
  IC-->>Root: RootAuthorityTransferStarted(old, pending)

  alt Direct accept (pending sends tx)
    New->>IC: acceptRootAuthority()
  else Relayed accept (pending signs)
    New-->>Relayer: signature AcceptAuthority(...)
    Relayer->>IC: acceptRootAuthorityAuthorized(expectedNew, deadline, signature)
  end

  IC-->>Relayer: RootAuthorityChanged(old, new)
```

Expected:
- Two-step transfers reduce operator mistakes.
- Relayed accepts allow “air-gapped” authorities to approve without sending the tx.

Forbidden:
- Single-step reassignment without a pending accept (not supported by design).

## Flow: Attestations (pinning extra trust anchors)

Attestations are generic `key -> value` slots (root-controlled) used to pin extra integrity facts on-chain (e.g. runtime config hash).

```mermaid
flowchart LR
  Root["rootAuthority"] -->|setAttestation key value| IC["InstanceController"]
  IC -->|AttestationSet event| Chain["On-chain log"]

  Root -->|lockAttestationKey key| IC
  IC -->|AttestationLocked event| Chain

  Bad["Attempted mutation after lock"] --> IC
  IC --> Revert["REVERT (locked)"]
```

Expected:
- Long-lived trust anchors should be write-once (lock after setting).

Forbidden:
- Treating mutable attestations as immutable evidence.

## Flow: Runtime config hardening (blackcat-config + attestations)

Goal: prevent an attacker with filesystem write access from “redirecting” the runtime
(different chain/RPC/controller address, disabling strict checks, changing quorum, etc.).

Recommended pattern:
1. `blackcat-config` generates a **file-based** runtime config in the safest available location for the current host.
2. `rootAuthority` pins the config hash on-chain using an attestation key and locks it.
3. `blackcat-core` fails closed if the local runtime config does not match the pinned hash.

### Diagram: choosing the safest runtime config location

```mermaid
flowchart TB
  Start["Start"] --> Probe["Probe host capabilities\n(POSIX perms, ownership APIs,\nread-only mounts, container FS)"]

  Probe -->|"Secure system path available\nfor example /etc/blackcat\nand permission checks pass"| SystemPath["System path\n/etc/blackcat/runtime.json"]
  Probe -->|"No secure system path\nfallback"| AppPath["App-private path\nvar/lib or user config dir"]

  SystemPath --> Checks
  AppPath --> Checks

  Checks["Permission checks<br/>• not world-writable<br/>• owned by expected user<br/>• writable only when needed<br/>• atomic writes<br/>• fsync where supported"] --> Write["Write runtime config"]
  Write --> Hash["sha256(canonical bytes)"]
  Hash --> OptionalAttest["(optional, recommended)\nPin + lock on-chain via attestation"]
```

Expected:
- The runtime config must be **file-based**, not env-based, for security-critical settings.
- Permission checks must be strict (fail closed if not verifiable).

Forbidden:
- Reading `chain_id`, `rpc_endpoints`, or contract addresses from env in production.
- Writing runtime config to a world-writable path (or accepting it if already there).

### Diagram: pinning runtime config hash on-chain

```mermaid
sequenceDiagram
  autonumber
  participant Root as rootAuthority
  participant Config as blackcat-config
  participant FS as Server filesystem
  participant IC as InstanceController
  participant Runtime as blackcat-core runtime

  Config->>FS: Write runtime config\n(safe location + permission checks)
  Config->>Config: Compute configHash\nsha256(canonical bytes)

  Root->>IC: setAttestation(keccak256("config.runtime.v1"), configHash)
  Root->>IC: lockAttestationKey(keccak256("config.runtime.v1"))

  Runtime->>FS: Read runtime config bytes
  Runtime->>Runtime: Compute configHash (same canonicalization)
  Runtime->>IC: eth_call attestations["config.runtime.v1"]
  IC-->>Runtime: pinned configHash

  alt configHash matches
    Runtime->>Runtime: Allow security-critical writes
  else mismatch
    Runtime->>Runtime: Fail closed (deny writes)\nOptionally report incident/check-in bad state
  end
```

## “Must Never Happen” (high-level invariants)

| Area | Invariant | Enforced by |
|---|---|---|
| Setup | Unauthorized CREATE2 instance creation | `InstanceFactory.createInstanceDeterministicAuthorized` |
| Releases | Root reuse across different releases | `ReleaseRegistry.rootIndex` |
| Releases | Publishing revoked root | `ReleaseRegistry.revokedRoots` |
| Controller | Activate without root authority | access control + signature checks |
| Controller | Replay activate/cancel/pause signatures | nonces + domain separator |
| Controller | Upgrade to untrusted root (if registry set) | `isTrustedRoot(...)` checks |
| Controller | Mutate locked settings/attestations | lock flags |

## Suggested “audit evidence” to monitor (events)

| Contract | Events worth monitoring |
|---|---|
| `ReleaseRegistry` | `ReleasePublished`, `ReleaseRevoked`, `SignatureConsumed`, ownership events |
| `InstanceFactory` | `SetupSignatureConsumed`, `InstanceCreatedDeterministic` |
| `InstanceController` | `UpgradeProposed`, `UpgradeActivated`, `Paused/Unpaused`, `IncidentReported`, `AuthoritySignatureConsumed`, lock events |
| `ManifestStore` | `ChunkAppended`, `BlobFinalized` |
| `KernelAuthority` | `Executed`, `BatchExecuted`, `ConfigChanged` |
