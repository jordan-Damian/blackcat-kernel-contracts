# Test Matrix (External/Public API)

This is a mapping from the **on-chain API surface** to Foundry tests.

Legend:
- ✅ = success path covered
- ❌ = expected failure/revert path covered

## InstanceFactory (`src/InstanceFactory.sol`)

- `domainSeparator()` ✅ (implicit in all EIP-712 flows; used by `hashSetupRequest`)
- `hashSetupRequest(...)` ✅ `test/InstanceFactory.t.sol:test_createInstanceDeterministicAuthorized_accepts_eoa_root_signature`
- `createInstance(...)` ✅ `test/InstanceFactory.t.sol:test_createInstance_initializes_clone` ❌ `test/InstanceFactory.t.sol:test_createInstance_reverts_on_invalid_args`
- `createInstanceDeterministicAuthorized(...)`
  - ✅ EOA root `test/InstanceFactory.t.sol:test_createInstanceDeterministicAuthorized_accepts_eoa_root_signature`
  - ✅ EIP-2098 root `test/InstanceFactory.t.sol:test_createInstanceDeterministicAuthorized_accepts_compact_eip2098_root_signature`
  - ✅ KernelAuthority root `test/InstanceFactory.t.sol:test_createInstanceDeterministicAuthorized_accepts_kernelAuthority_root_signature`
  - ❌ expired `test/InstanceFactory.t.sol:test_createInstanceDeterministicAuthorized_rejects_expired`
  - ❌ wrong sig `test/InstanceFactory.t.sol:test_createInstanceDeterministicAuthorized_rejects_wrong_signature`
  - ❌ high-s `test/InstanceFactory.t.sol:test_createInstanceDeterministicAuthorized_rejects_high_s_malleable_signature`
  - ❌ bad signature length `test/InstanceFactory.Additional.t.sol:test_createInstanceDeterministicAuthorized_rejects_bad_signature_length_for_eoa_root`
  - ❌ bad `v` `test/InstanceFactory.Additional.t.sol:test_createInstanceDeterministicAuthorized_rejects_bad_v_for_eoa_root`
  - ❌ invalid KernelAuthority signature `test/InstanceFactory.Additional.t.sol:test_createInstanceDeterministicAuthorized_rejects_invalid_kernelAuthority_signature`
  - ❌ salt reuse `test/InstanceFactory.t.sol:test_createInstanceDeterministicAuthorized_reverts_on_salt_reuse`
- `predictInstanceAddress(bytes32)` ✅ `test/InstanceFactory.t.sol:test_createInstanceDeterministicAuthorized_accepts_eoa_root_signature`

## InstanceController (`src/InstanceController.sol`)

### Initialization & metadata

- `initialize(...)`
  - ✅ `test/InstanceController.t.sol:test_initialize_sets_state`
  - ❌ double-init `test/InstanceController.t.sol:test_initialize_reverts_on_second_call`
  - ❌ invalid args via factory `test/InstanceController.t.sol:test_initialize_rejects_zero_authorities_via_factory`, `test/InstanceController.Additional.t.sol:test_initialize_rejects_zero_*`
- `domainSeparator()` ✅ (implicit in all `*Authorized(...)` tests)

### Pause / emergency controls

- `pause()` ✅ `test/InstanceController.t.sol:test_pause_unpause_access_control` ❌ unauthorized pause `test/InstanceController.t.sol:test_pause_unpause_access_control`
- `unpause()` ✅ root unpause `test/InstanceController.t.sol:test_pause_unpause_access_control` ❌ emergency unpause disabled `test/InstanceController.t.sol:test_pause_unpause_access_control`
- `setPausedAuthorized(...)`
  - ✅ EOA emergency `test/InstanceController.t.sol:test_setPausedAuthorized_accepts_emergency_signature_and_is_not_replayable`
  - ✅ KernelAuthority emergency `test/InstanceController.t.sol:test_setPausedAuthorized_accepts_kernelAuthority_emergency_signature`
  - ❌ state mismatch `test/InstanceController.t.sol:test_setPausedAuthorized_rejects_when_state_mismatch`
  - ❌ emergency unpause disabled `test/InstanceController.t.sol:test_setPausedAuthorized_rejects_emergency_unpause_when_disabled`
  - ❌ expired/no-op/invalid sig `test/InstanceController.Additional.t.sol:test_setPausedAuthorized_rejects_*`
- `lockEmergencyCanUnpause()` ✅ `test/InstanceController.t.sol:test_emergency_unpause_policy_lock_freezes_value`
- `setEmergencyCanUnpause(bool)` ✅ `test/InstanceController.t.sol:test_emergency_unpause_can_be_enabled_by_root` ❌ post-lock mutation `test/InstanceController.t.sol:test_emergency_unpause_policy_lock_freezes_value`

### Authority rotation (two-step + authorized accept)

- `startRootAuthorityTransfer(...)` ✅ `test/InstanceController.t.sol:test_authority_rotation_only_root`
- `cancelRootAuthorityTransfer()` ❌ no pending `test/InstanceController.Additional.t.sol:test_cancelRootAuthorityTransfer_reverts_without_pending` ✅ clears pending `test/InstanceController.Additional.t.sol:test_cancelRootAuthorityTransfer_clears_pending`
- `acceptRootAuthority()` ✅ `test/InstanceController.t.sol:test_authority_rotation_only_root`
- `acceptRootAuthorityAuthorized(...)` ✅ `test/InstanceController.t.sol:test_acceptRootAuthorityAuthorized_accepts_pending_signature_and_prevents_reuse` ❌ stale signature `test/InstanceController.t.sol:test_acceptRootAuthorityAuthorized_rejects_stale_signature_after_restart`

- `startUpgradeAuthorityTransfer(...)` ✅ `test/InstanceController.t.sol:test_authority_rotation_only_root`
- `cancelUpgradeAuthorityTransfer()` ❌ no pending `test/InstanceController.Additional.t.sol:test_cancelUpgradeAuthorityTransfer_reverts_without_pending` ✅ clears pending `test/InstanceController.Additional.t.sol:test_cancelUpgradeAuthorityTransfer_clears_pending`
- `acceptUpgradeAuthority()` ✅ `test/InstanceController.t.sol:test_authority_rotation_only_root`
- `acceptUpgradeAuthorityAuthorized(...)` ✅ `test/InstanceController.t.sol:test_acceptUpgradeAuthorityAuthorized_accepts_pending_signature`

- `startEmergencyAuthorityTransfer(...)` ✅ (pending signature path) `test/InstanceController.t.sol:test_acceptEmergencyAuthorityAuthorized_accepts_pending_signature`
- `cancelEmergencyAuthorityTransfer()` ❌ no pending `test/InstanceController.Additional.t.sol:test_cancelEmergencyAuthorityTransfer_reverts_without_pending` ✅ clears pending `test/InstanceController.Additional.t.sol:test_cancelEmergencyAuthorityTransfer_clears_pending`
- `acceptEmergencyAuthority()` ✅ `test/InstanceController.Additional.t.sol:test_acceptEmergencyAuthority_direct_flow_and_rejects_wrong_sender` ❌ wrong sender `test/InstanceController.Additional.t.sol:test_acceptEmergencyAuthority_direct_flow_and_rejects_wrong_sender`
- `acceptEmergencyAuthorityAuthorized(...)` ✅ `test/InstanceController.t.sol:test_acceptEmergencyAuthorityAuthorized_accepts_pending_signature`

- `startReporterAuthorityTransfer(...)` ✅ used throughout reporter tests; e.g. `test/InstanceController.t.sol:test_checkIn_only_reporter`
- `cancelReporterAuthorityTransfer()` ❌ no pending `test/InstanceController.Additional.t.sol:test_cancelReporterAuthorityTransfer_reverts_without_pending` ✅ clears pending `test/InstanceController.Additional.t.sol:test_cancelReporterAuthorityTransfer_clears_pending`
- `acceptReporterAuthority()` ✅ used throughout reporter tests; e.g. `test/InstanceController.t.sol:test_checkIn_only_reporter`
- `acceptReporterAuthorityAuthorized(...)` ✅ `test/InstanceController.t.sol:test_acceptReporterAuthorityAuthorized_accepts_pending_signature`
- `clearReporterAuthority()` ✅ `test/InstanceController.Additional.t.sol:test_clearReporterAuthority_clears_reporter_and_pending`

### Registry + expected component trust gating

- `setReleaseRegistry(address)`
  - ✅ + lock/mutate behavior `test/InstanceController.t.sol:test_lockReleaseRegistry_prevents_changes`
  - ❌ non-contract / trust failures `test/InstanceController.Additional.t.sol:test_setReleaseRegistry_rejects_*`
- `lockReleaseRegistry()` ✅/❌ `test/InstanceController.t.sol:test_lockReleaseRegistry_prevents_changes`, `test/InstanceController.t.sol:test_lockReleaseRegistry_rejects_without_registry`
- `setExpectedComponentId(bytes32)` ✅/❌ `test/InstanceController.t.sol:test_setExpectedComponentId_rejects_without_registry`
- `lockExpectedComponentId()` ✅/❌ `test/InstanceController.t.sol:test_lockExpectedComponentId_rejects_zero_value`

### Production knobs + locks

- `setMinUpgradeDelaySec(uint64)` ✅/❌ `test/InstanceController.t.sol:test_setMinUpgradeDelaySec_rejects_too_large`
- `lockMinUpgradeDelay()` ✅/❌ `test/InstanceController.t.sol:test_lockMinUpgradeDelay_freezes_value`, `test/InstanceController.t.sol:test_lockMinUpgradeDelay_rejects_zero_delay`
- `setAutoPauseOnBadCheckIn(bool)` ✅/❌ `test/InstanceController.t.sol:test_autoPauseOnBadCheckIn_pauses_and_records_incident`, `test/InstanceController.t.sol:test_autoPauseOnBadCheckIn_lock_freezes_value`
- `lockAutoPauseOnBadCheckIn()` ✅ `test/InstanceController.t.sol:test_autoPauseOnBadCheckIn_lock_freezes_value`
- `setMaxCheckInAgeSec(uint64)` ✅ `test/InstanceController.t.sol:test_pauseIfStale_pauses_after_max_age` ❌ too large `test/InstanceController.Additional.t.sol:test_setMaxCheckInAgeSec_rejects_too_large`
- `lockMaxCheckInAgeSec()` ✅/❌ `test/InstanceController.Additional.t.sol:test_lockMaxCheckInAgeSec_locks_and_blocks_changes`, `test/InstanceController.Additional.t.sol:test_lockMaxCheckInAgeSec_rejects_when_zero`
- `finalizeProduction(...)`
  - ✅ `test/InstanceController.t.sol:test_finalizeProduction_sets_and_locks_knobs`
  - ❌ inconsistent registry `test/InstanceController.Additional.t.sol:test_finalizeProduction_rejects_*`

### Compatibility rollback

- `setCompatibilityWindowSec(uint64)` ✅ (compat flows) `test/InstanceController.t.sol:test_rollbackToCompatibilityState_restores_previous_state_and_clears_compat`
- `lockCompatibilityWindow()` ✅ `test/InstanceController.t.sol:test_compatibilityWindow_lock_freezes_value`
- `clearCompatibilityState()` ✅/❌ `test/InstanceController.Additional.t.sol:test_clearCompatibilityState_*`
- `rollbackToCompatibilityState()` ✅/❌ `test/InstanceController.t.sol:test_rollbackToCompatibilityState_restores_previous_state_and_clears_compat`, `test/InstanceController.t.sol:test_rollbackToCompatibilityState_rejects_when_expired`
- `rollbackToCompatibilityStateAuthorized(...)` ✅ `test/InstanceController.t.sol:test_rollbackToCompatibilityStateAuthorized_accepts_root_signature_and_is_not_replayable`

### Attestations

- `setAttestation(bytes32,bytes32)` ✅/❌ `test/InstanceController.t.sol:test_attestations_are_root_controlled`
- `setAttestationExpected(...)` ✅/❌ `test/InstanceController.t.sol:test_setAttestationExpected_rejects_mismatch`
- `clearAttestation(bytes32)` ✅/❌ `test/InstanceController.t.sol:test_clearAttestation_rejects_when_already_cleared`
- `setAttestationAndLock(...)` ✅ `test/InstanceController.t.sol:test_setAttestationAndLock_sets_and_locks`
- `lockAttestationKey(bytes32)` ✅/❌ `test/InstanceController.t.sol:test_attestation_lock_prevents_changes_and_clearing`, `test/InstanceController.t.sol:test_lockAttestationKey_rejects_when_empty`

### Check-ins (integrity observation)

- `isAcceptedState(...)` ✅ used in rollback + revocation tests; e.g. `test/InstanceController.t.sol:test_revoking_active_root_makes_state_unaccepted`
- `checkIn(...)` ✅ `test/InstanceController.t.sol:test_checkIn_tracks_runtime_state` ❌ no reporter set `test/InstanceController.Additional.t.sol:test_checkIn_rejects_when_reporter_not_set`
- `checkInAuthorized(...)`
  - ✅ EOA reporter `test/InstanceController.t.sol:test_checkInAuthorized_accepts_eoa_reporter_signature_and_increments_nonce`
  - ✅ KernelAuthority reporter `test/InstanceController.t.sol:test_checkInAuthorized_accepts_kernelAuthority_reporter_signature`
  - ❌ reporter missing / expired / bad sig `test/InstanceController.Additional.t.sol:test_checkInAuthorized_rejects_*`

### Monitoring helpers

- `pauseIfStale()` ✅/❌ `test/InstanceController.t.sol:test_pauseIfStale_pauses_after_max_age`, `test/InstanceController.Additional.t.sol:test_pauseIfStale_is_noop_when_disabled`
- `pauseIfActiveRootUntrusted()` ✅/❌ `test/InstanceController.t.sol:test_pauseIfActiveRootUntrusted_pauses_after_revocation`, `test/InstanceController.Additional.t.sol:test_pauseIfActiveRootUntrusted_is_noop_without_registry`

### Incidents

- `reportIncident(bytes32)` ✅/❌ `test/InstanceController.t.sol:test_reportIncident_pauses`, `test/InstanceController.Additional.t.sol:test_reportIncident_rejects_*`
- `reportIncidentAuthorized(...)`
  - ✅ EOA root signature `test/InstanceController.t.sol:test_reportIncidentAuthorized_accepts_root_signature_and_is_not_replayable`
  - ✅ KernelAuthority reporter signature `test/InstanceController.t.sol:test_reportIncidentAuthorized_accepts_kernelAuthority_reporter_signature`
  - ❌ expired / bad sig / zero hash `test/InstanceController.Additional.t.sol:test_reportIncidentAuthorized_rejects_*`

### Upgrades

- `proposeUpgrade(...)` ✅ `test/InstanceController.t.sol:test_propose_and_activate_upgrade` ❌ TTL too large `test/InstanceController.t.sol:test_proposeUpgrade_rejects_ttl_too_large`
- `proposeUpgradeByRelease(...)` ✅ `test/InstanceController.t.sol:test_proposeUpgradeByRelease_uses_registry_values`
- `cancelUpgrade()` ✅ `test/InstanceController.t.sol:test_activateUpgradeAuthorized_is_not_replayable_across_repropose_same_timestamp`
- `cancelUpgradeExpected(...)` ✅/❌ `test/InstanceController.t.sol:test_cancelUpgradeExpected_rejects_mismatch`
- `cancelUpgradeAuthorized(...)` ✅ `test/InstanceController.t.sol:test_cancelUpgradeAuthorized_accepts_eoa_root_signature`
- `activateUpgrade()` ✅ `test/InstanceController.t.sol:test_propose_and_activate_upgrade`
- `activateUpgradeExpected(...)` ✅/❌ `test/InstanceController.t.sol:test_activateUpgradeExpected_rejects_mismatch`
- `activateUpgradeAuthorized(...)` ✅/❌ `test/InstanceController.t.sol:test_activateUpgradeAuthorized_accepts_eoa_root_signature`, `test/InstanceController.t.sol:test_activateUpgradeAuthorized_rejects_high_s_malleable_signature`

### Snapshots

- `snapshot()` ✅ `test/InstanceController.Additional.t.sol:test_snapshot_includes_paused_and_roots`
- `snapshotV2()` ✅ `test/InstanceController.t.sol:test_snapshotV2_includes_incident_and_flags`

## ReleaseRegistry (`src/ReleaseRegistry.sol`)

- Ownership:
  - `transferOwnership` ✅/❌ `test/ReleaseRegistry.t.sol:test_transferOwnership_only_owner`
  - `transferOwnershipAuthorized` ✅/❌ `test/ReleaseRegistry.t.sol:test_transferOwnershipAuthorized_then_acceptOwnershipAuthorized`, `test/ReleaseRegistry.Additional.t.sol:test_transferOwnershipAuthorized_rejects_*`
  - `acceptOwnership` ✅ `test/ReleaseRegistry.t.sol:test_transferOwnershipAuthorized_then_acceptOwnershipAuthorized`
  - `acceptOwnershipAuthorized` ✅/❌ `test/ReleaseRegistry.t.sol:test_transferOwnershipAuthorized_then_acceptOwnershipAuthorized`, `test/ReleaseRegistry.Additional.t.sol:test_acceptOwnershipAuthorized_rejects_invalid_signature`
- Publishing:
  - `publish` ✅/❌ `test/ReleaseRegistry.t.sol:test_publish_only_owner`, `test/ReleaseRegistry.t.sol:test_publish_rejects_invalid_values`
  - `publishBatch` ✅/❌ `test/ReleaseRegistry.t.sol:test_publishBatch_publishes_multiple_releases`, `test/ReleaseRegistry.Additional.t.sol:test_publishBatch_rejects_length_mismatch`
  - `publishAuthorized` ✅/❌ `test/ReleaseRegistry.t.sol:test_publishAuthorized_accepts_eoa_owner_signature`, `test/ReleaseRegistry.t.sol:test_publishAuthorized_rejects_high_s_malleable_signature`
  - `publishBatchAuthorized` ✅/❌ `test/ReleaseRegistry.t.sol:test_publishBatchAuthorized_accepts_eoa_owner_signature_and_is_not_replayable`, `test/ReleaseRegistry.t.sol:test_publishBatchAuthorized_rejects_empty_batch`
- Revocation:
  - `revoke` ✅/❌ `test/ReleaseRegistry.t.sol:test_revokeByRoot_revokes_release`, `test/ReleaseRegistry.Additional.t.sol:test_revoke_rejects_release_not_found`
  - `revokeBatch` ✅/❌ `test/ReleaseRegistry.t.sol:test_revokeBatchAuthorized_accepts_eoa_owner_signature_and_is_not_replayable`, `test/ReleaseRegistry.Additional.t.sol:test_revokeBatch_rejects_length_mismatch`
  - `revokeByRoot` ✅/❌ `test/ReleaseRegistry.t.sol:test_revokeByRoot_revokes_release`, `test/ReleaseRegistry.Additional.t.sol:test_revokeByRoot_rejects_zero_root`
  - `revokeAuthorized` ✅/❌ `test/ReleaseRegistry.t.sol:test_revokeAuthorized_accepts_eoa_owner_signature`, `test/ReleaseRegistry.Additional.t.sol:test_revokeAuthorized_rejects_invalid_signature`
  - `revokeBatchAuthorized` ✅/❌ `test/ReleaseRegistry.t.sol:test_revokeBatchAuthorized_accepts_eoa_owner_signature_and_is_not_replayable`, `test/ReleaseRegistry.Additional.t.sol:test_revokeBatchAuthorized_rejects_root_mismatch`
  - `revokeByRootAuthorized` ✅/❌ `test/ReleaseRegistry.t.sol:test_revokeByRootAuthorized_accepts_eoa_owner_signature`, `test/ReleaseRegistry.Additional.t.sol:test_revokeByRootAuthorized_rejects_root_not_found`
- Views:
  - `get`, `getByRoot`, `isTrustedRoot`, `isRevokedRoot`, `isRevokedRelease` ✅ `test/ReleaseRegistry.t.sol:testFuzz_publish_then_getByRoot_roundtrip`

## ManifestStore (`src/ManifestStore.sol`)

- Ownership:
  - `transferOwnership` ✅ `test/ManifestStore.t.sol:test_ownership_transfer_two_step`
  - `transferOwnershipAuthorized` ✅/❌ `test/ManifestStore.t.sol:test_transferOwnershipAuthorized_then_acceptOwnershipAuthorized`, `test/ManifestStore.Additional.t.sol:test_transferOwnershipAuthorized_rejects_*`
  - `acceptOwnership` ✅ `test/ManifestStore.t.sol:test_ownership_transfer_two_step`
  - `acceptOwnershipAuthorized` ✅/❌ `test/ManifestStore.t.sol:test_transferOwnershipAuthorized_then_acceptOwnershipAuthorized`, `test/ManifestStore.Additional.t.sol:test_acceptOwnershipAuthorized_rejects_*`
- Blob storage:
  - `appendChunk` ✅/❌ `test/ManifestStore.t.sol:test_append_and_finalize_and_getChunk`, `test/ManifestStore.Additional.t.sol:test_appendChunk_rejects_*`
  - `appendChunks` ✅/❌ `test/ManifestStore.t.sol:test_appendChunks_appends_multiple`, `test/ManifestStore.Additional.t.sol:test_appendChunks_rejects_*`
  - `finalize` ✅/❌ `test/ManifestStore.t.sol:test_finalize_rejects_mismatch`, `test/ManifestStore.Additional.t.sol:test_finalize_rejects_*`
  - `getChunk` ✅/❌ `test/ManifestStore.t.sol:test_append_and_finalize_and_getChunk`, `test/ManifestStore.Additional.t.sol:test_getChunk_reverts_out_of_range`
  - `getMeta` ✅ `test/ManifestStore.t.sol:test_append_and_finalize_and_getChunk`

## KernelAuthority (`src/KernelAuthority.sol`)

- `getSigners()` ✅ `test/KernelAuthority.Additional.t.sol:test_getSigners_returns_sorted_signers`
- `domainSeparator()`, `hashExecute`, `hashExecuteBatch` ✅ (implicit; used by test digests)
- `execute(...)`
  - ✅ `test/KernelAuthority.t.sol:test_execute_increments_nonce_and_calls_target`, `test/KernelAuthority.Additional.t.sol:test_execute_transfers_value_to_target`
  - ❌ insufficient sigs `test/KernelAuthority.t.sol:test_execute_requires_threshold_signatures`
  - ❌ unordered sigs `test/KernelAuthority.t.sol:test_execute_rejects_unsorted_signatures`
  - ❌ invalid signer `test/KernelAuthority.Additional.t.sol:test_execute_rejects_invalid_signer_even_if_ordered`
  - ❌ duplicate sigs `test/KernelAuthority.Additional.t.sol:test_execute_rejects_duplicate_signatures`
- `executeBatch(...)` ✅/❌ `test/KernelAuthority.t.sol:test_executeBatch_runs_multiple_calls`, `test/KernelAuthority.Additional.t.sol:test_executeBatch_rejects_*`
- `isValidSignature(bytes32,bytes)` ✅/❌ `test/KernelAuthority.t.sol:test_isValidSignature_accepts_packed_bytes_array`, `test/KernelAuthority.t.sol:test_isValidSignature_rejects_insufficient_or_unsorted`
- `setConfig(...)` ✅ `test/KernelAuthority.t.sol:test_setConfig_only_self_via_execute` ❌ invalid config `test/KernelAuthority.Additional.t.sol:test_execute_reverts_when_setConfig_is_invalid`
