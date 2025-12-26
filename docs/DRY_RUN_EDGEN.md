# Edgen Chain Dry Run (EOA-only)

Goal: deploy contracts and exercise the most important safety flows against a real EVM chain.

Chain:
- RPC: `https://rpc.layeredge.io`
- chain_id: `4207`
- explorer: `https://edgenscan.io`

This guide assumes:
- Docker is available (we run Foundry via `ghcr.io/foundry-rs/foundry:stable` by default)
- You use a temporary funded EOA for the dry run (do **not** reuse production keys)

## 0) One-time helpers

From `blackcat-kernel-contracts/`:

```bash
export RPC_URL="https://rpc.layeredge.io"
export FOUNDRY_IMAGE="${FOUNDRY_IMAGE:-ghcr.io/foundry-rs/foundry:stable}"

# Create (or reuse) a local dry-run EOA keypair (stored outside the repo).
# Do NOT reuse production keys.
export BLACKCAT_EDGEN_KEYFILE="$HOME/.blackcat/secrets/edgen-dryrun-eoa.json"
mkdir -p "$(dirname "$BLACKCAT_EDGEN_KEYFILE")"
chmod 700 "$(dirname "$BLACKCAT_EDGEN_KEYFILE")"
if [ ! -f "$BLACKCAT_EDGEN_KEYFILE" ]; then
  docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc \
    "cast wallet new --json" >"$BLACKCAT_EDGEN_KEYFILE" 2>/dev/null
  chmod 600 "$BLACKCAT_EDGEN_KEYFILE"
fi

# Your funded EOA (dry-run only). Private key is loaded from the keyfile.
# Do NOT paste private keys into issues/chat logs.
export PRIVATE_KEY="$(
  python3 - <<'PY'
import json, os
path = os.environ["BLACKCAT_EDGEN_KEYFILE"]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)
item = data[0] if isinstance(data, list) else data
print(item["private_key"])
PY
)"
export DEPLOYER_ADDR="$(
  docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc \
    "cast wallet address --private-key \"$PRIVATE_KEY\""
)"
echo "EOA: $DEPLOYER_ADDR"
```

Sanity:

```bash
docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc \
  "cast chain-id --rpc-url \"$RPC_URL\""
docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc \
  "cast balance --rpc-url \"$RPC_URL\" \"$DEPLOYER_ADDR\""
```

Bytecode size sanity (required on-chain):

```bash
docker run --rm -v "$PWD":/app -w /app --entrypoint bash "$FOUNDRY_IMAGE" -lc \
  "forge build --via-ir --skip test --skip script --sizes"
```

## 1) Deploy ReleaseRegistry + InstanceFactory

For the dry run we keep the registry owner the same EOA:

```bash
export BLACKCAT_RELEASE_REGISTRY_OWNER="$DEPLOYER_ADDR"

docker run --rm -v "$PWD":/app -w /app --entrypoint bash "$FOUNDRY_IMAGE" -lc \
  "forge script --via-ir script/DeployAll.s.sol:DeployAll --rpc-url \"$RPC_URL\" --broadcast"
```

Copy the deployed addresses from the output and export them:

```bash
export BLACKCAT_RELEASE_REGISTRY="0x..."
export BLACKCAT_INSTANCE_FACTORY="0x..."
```

## 2) Publish a “genesis” release (required before instance creation)

The controller initializer enforces that `genesisRoot` is trusted by `ReleaseRegistry` (when registry is configured).

For dry run, any random bytes32 is fine:

```bash
export BLACKCAT_COMPONENT_ID="$(
  docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc \
    "cast keccak \"blackcat-core\""
)"
export BLACKCAT_RELEASE_VERSION="1"
export BLACKCAT_GENESIS_ROOT="$(
  docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc \
    "cast keccak \"genesis-root-v1\""
)"
export BLACKCAT_GENESIS_URI_HASH="$(
  docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc \
    "cast keccak \"genesis-uri-v1\""
)"
export BLACKCAT_GENESIS_POLICY_HASH="$(
  docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc \
    "cast keccak \"genesis-policy-v1\""
)"
export BLACKCAT_RELEASE_ROOT="$BLACKCAT_GENESIS_ROOT"
export BLACKCAT_RELEASE_URI_HASH="$BLACKCAT_GENESIS_URI_HASH"
export BLACKCAT_RELEASE_META_HASH="0x0000000000000000000000000000000000000000000000000000000000000000"

docker run --rm -v "$PWD":/app -w /app --entrypoint bash "$FOUNDRY_IMAGE" -lc \
  "forge script --via-ir script/PublishRelease.s.sol:PublishRelease --rpc-url \"$RPC_URL\" --broadcast"
```

## 3) Create an instance (Option A: simple create)

Use the factory’s non-deterministic create (no setup signature):

```bash
export BLACKCAT_ROOT_AUTHORITY="$DEPLOYER_ADDR"
export BLACKCAT_UPGRADE_AUTHORITY="$DEPLOYER_ADDR"
export BLACKCAT_EMERGENCY_AUTHORITY="$DEPLOYER_ADDR"

docker run --rm -v "$PWD":/app -w /app --entrypoint bash "$FOUNDRY_IMAGE" -lc \
  "forge script --via-ir script/CreateInstance.s.sol:CreateInstance --rpc-url \"$RPC_URL\" --broadcast"
```

Copy the returned instance address and export:

```bash
export BLACKCAT_INSTANCE_CONTROLLER="0x..."
```

## 3b) Create an instance (Option B: deterministic + authorized)

If you want the multi-device ceremony path:

```bash
export BLACKCAT_ROOT_AUTHORITY="$DEPLOYER_ADDR"
export BLACKCAT_UPGRADE_AUTHORITY="$DEPLOYER_ADDR"
export BLACKCAT_EMERGENCY_AUTHORITY="$DEPLOYER_ADDR"
export BLACKCAT_INSTANCE_SALT="$(
  docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc \
    "cast keccak \"dry-run-salt-1\""
)"
export BLACKCAT_SETUP_DEADLINE="$(( $(date +%s) + 3600 ))"
```

Compute the EIP-712 digest on-chain and sign it (no extra hashing):

```bash
export SETUP_DIGEST="$(
  docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc "
    cast call --rpc-url \"$RPC_URL\" \"$BLACKCAT_INSTANCE_FACTORY\" \
      \"hashSetupRequest(address,address,address,bytes32,bytes32,bytes32,bytes32,uint256)(bytes32)\" \
      \"$BLACKCAT_ROOT_AUTHORITY\" \"$BLACKCAT_UPGRADE_AUTHORITY\" \"$BLACKCAT_EMERGENCY_AUTHORITY\" \
      \"$BLACKCAT_GENESIS_ROOT\" \"$BLACKCAT_GENESIS_URI_HASH\" \"$BLACKCAT_GENESIS_POLICY_HASH\" \
      \"$BLACKCAT_INSTANCE_SALT\" \"$BLACKCAT_SETUP_DEADLINE\"
  "
)"

export BLACKCAT_SETUP_SIGNATURE="$(
  docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc \
    "cast wallet sign --no-hash --private-key \"$PRIVATE_KEY\" \"$SETUP_DIGEST\""
)"
```

Create the instance:

```bash
docker run --rm -v "$PWD":/app -w /app --entrypoint bash "$FOUNDRY_IMAGE" -lc \
  "forge script --via-ir script/CreateInstanceDeterministic.s.sol:CreateInstanceDeterministic --rpc-url \"$RPC_URL\" --broadcast"
```

## 4) Finalize production knobs (one-shot)

Set strict defaults for dry run (small values so you can observe behavior quickly):

```bash
export BLACKCAT_RELEASE_REGISTRY="$BLACKCAT_RELEASE_REGISTRY"
export BLACKCAT_EXPECTED_COMPONENT_ID="$BLACKCAT_COMPONENT_ID"
export BLACKCAT_MIN_UPGRADE_DELAY_SEC="5"
export BLACKCAT_MAX_CHECKIN_AGE_SEC="10"
export BLACKCAT_AUTO_PAUSE_ON_BAD_CHECKIN="1"
export BLACKCAT_COMPATIBILITY_WINDOW_SEC="0"
export BLACKCAT_EMERGENCY_CAN_UNPAUSE="0"

docker run --rm -v "$PWD":/app -w /app --entrypoint bash "$FOUNDRY_IMAGE" -lc \
  "forge script --via-ir script/FinalizeProduction.s.sol:FinalizeProduction --rpc-url \"$RPC_URL\" --broadcast"
```

## 5) Enable reporter + do check-ins

Use the same EOA as reporter for the dry run:

```bash
export BLACKCAT_NEW_REPORTER_AUTHORITY="$DEPLOYER_ADDR"

docker run --rm -v "$PWD":/app -w /app --entrypoint bash "$FOUNDRY_IMAGE" -lc \
  "forge script --via-ir script/StartReporterAuthorityTransfer.s.sol:StartReporterAuthorityTransfer --rpc-url \"$RPC_URL\" --broadcast"

docker run --rm -v "$PWD":/app -w /app --entrypoint bash "$FOUNDRY_IMAGE" -lc \
  "forge script --via-ir script/AcceptReporterAuthority.s.sol:AcceptReporterAuthority --rpc-url \"$RPC_URL\" --broadcast"
```

Good check-in (should stay unpaused):

```bash
export BLACKCAT_OBSERVED_ROOT="$BLACKCAT_GENESIS_ROOT"
export BLACKCAT_OBSERVED_URI_HASH="$BLACKCAT_GENESIS_URI_HASH"
export BLACKCAT_OBSERVED_POLICY_HASH="$BLACKCAT_GENESIS_POLICY_HASH"

docker run --rm -v "$PWD":/app -w /app --entrypoint bash "$FOUNDRY_IMAGE" -lc \
  "forge script --via-ir script/CheckIn.s.sol:CheckIn --rpc-url \"$RPC_URL\" --broadcast"
```

Bad check-in (should auto-pause because `BLACKCAT_AUTO_PAUSE_ON_BAD_CHECKIN=1`):

```bash
export BLACKCAT_OBSERVED_ROOT="$(
  docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc \
    "cast keccak \"wrong-root\""
)"

docker run --rm -v "$PWD":/app -w /app --entrypoint bash "$FOUNDRY_IMAGE" -lc \
  "forge script --via-ir script/CheckIn.s.sol:CheckIn --rpc-url \"$RPC_URL\" --broadcast"
```

## 6) Test permissionless guards

`pauseIfStale()`:
- Do a good check-in again, then wait ~`BLACKCAT_MAX_CHECKIN_AGE_SEC + 1` seconds, then:

```bash
docker run --rm -v "$PWD":/app -w /app --entrypoint bash "$FOUNDRY_IMAGE" -lc \
  "forge script --via-ir script/PauseIfStale.s.sol:PauseIfStale --rpc-url \"$RPC_URL\" --broadcast"
```

`pauseIfActiveRootUntrusted()`:
- Revoke the genesis release in the registry, then call the guard.

```bash
export BLACKCAT_COMPONENT_ID="$BLACKCAT_COMPONENT_ID"
export BLACKCAT_RELEASE_VERSION="1"

docker run --rm -v "$PWD":/app -w /app --entrypoint bash "$FOUNDRY_IMAGE" -lc \
  "forge script --via-ir script/RevokeRelease.s.sol:RevokeRelease --rpc-url \"$RPC_URL\" --broadcast"

docker run --rm -v "$PWD":/app -w /app --entrypoint bash "$FOUNDRY_IMAGE" -lc \
  "forge script --via-ir script/PauseIfActiveRootUntrusted.s.sol:PauseIfActiveRootUntrusted --rpc-url \"$RPC_URL\" --broadcast"
```

## Notes

- Production should use Safe / `KernelAuthority` split for authorities. This dry run is only to validate the state machine + events + lock behavior.
- Always keep the EIP-170 size check in your deploy pipeline:
  - `forge build --via-ir --force --skip test --skip script --sizes`
