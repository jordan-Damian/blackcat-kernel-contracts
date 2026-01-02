# Edgen Chain Dry Run (KernelAuthority multi-device)

Goal: exercise the core Trust Kernel flows against a real EVM chain while using **KernelAuthority** as a multi-device authority.

This guide complements: [DRY_RUN_EDGEN](DRY_RUN_EDGEN.md).

Chain:
- RPC: `https://rpc.layeredge.io`
- `chain_id`: `4207`
- Explorer: `https://edgenscan.io`

Important:
- This is a **dry run**. Do not reuse production keys.
- `KernelAuthority` is custom security code and is **not independently audited yet** (see: [SECURITY_STATUS](SECURITY_STATUS.md)).
- `InstanceController` is near EIP-170 size limit — always run the size check before deploying.

## 0) Prereqs

From `blackcat-kernel-contracts/`:

```bash
export RPC_URL="https://rpc.layeredge.io"
export FOUNDRY_IMAGE="${FOUNDRY_IMAGE:-ghcr.io/foundry-rs/foundry:stable}"
```

## 1) Create a relayer EOA (pays gas)

The relayer is the tx sender. Authorities are the signers.

```bash
export BLACKCAT_EDGEN_RELAYER_KEYFILE="$HOME/.blackcat/secrets/edgen-dryrun-relayer.json"
mkdir -p "$(dirname "$BLACKCAT_EDGEN_RELAYER_KEYFILE")"
chmod 700 "$(dirname "$BLACKCAT_EDGEN_RELAYER_KEYFILE")"
if [ ! -f "$BLACKCAT_EDGEN_RELAYER_KEYFILE" ]; then
  docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc \
    "cast wallet new --json" >"$BLACKCAT_EDGEN_RELAYER_KEYFILE" 2>/dev/null
  chmod 600 "$BLACKCAT_EDGEN_RELAYER_KEYFILE"
fi

export PRIVATE_KEY="$(
  python3 - <<'PY'
import json, os
path = os.environ["BLACKCAT_EDGEN_RELAYER_KEYFILE"]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)
item = data[0] if isinstance(data, list) else data
print(item["private_key"])
PY
)"
export RELAYER_ADDR="$(
  docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc \
    "cast wallet address --private-key \"$PRIVATE_KEY\""
)"
echo "RELAYER_ADDR=$RELAYER_ADDR"
```

Fund `RELAYER_ADDR` with a small amount of EDGEN.

## 2) Create 3 signer EOAs (simulate multi-device)

In real multi-device mode, each signer key lives on a different device and only shares signatures with the relayer.
For this dry run, we simulate that locally with 3 keyfiles.

```bash
export S1="$HOME/.blackcat/secrets/edgen-signer-1.json"
export S2="$HOME/.blackcat/secrets/edgen-signer-2.json"
export S3="$HOME/.blackcat/secrets/edgen-signer-3.json"
for f in "$S1" "$S2" "$S3"; do
  mkdir -p "$(dirname "$f")"
  chmod 700 "$(dirname "$f")"
  if [ ! -f "$f" ]; then
    docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc \
      "cast wallet new --json" >"$f" 2>/dev/null
    chmod 600 "$f"
  fi
done
```

Extract addresses and sort them (KernelAuthority requires **strictly increasing** signer addresses):

```bash
python3 - <<'PY'
import json, os
paths=[os.environ["S1"], os.environ["S2"], os.environ["S3"]]
addrs=[]
for p in paths:
    with open(p, "r", encoding="utf-8") as f:
        data=json.load(f)
    item = data[0] if isinstance(data, list) else data
    addrs.append(item["address"])
addrs_sorted = sorted(addrs, key=lambda a: int(a, 16))
for i,a in enumerate(addrs_sorted, 1):
    print(f'export BLACKCAT_KERNEL_SIGNER_{i}="{a}"')
PY
```

Choose threshold (recommended `2` for dry-run convenience):

```bash
export BLACKCAT_KERNEL_THRESHOLD="2"
```

## 3) Deploy KernelAuthority

```bash
docker run --rm -v "$PWD":/app -w /app --entrypoint bash "$FOUNDRY_IMAGE" -lc \
  "forge script --via-ir script/DeployKernelAuthority.s.sol:DeployKernelAuthority --rpc-url \"$RPC_URL\" --broadcast"
```

Copy the deployed address into:

```bash
export BLACKCAT_KERNEL_AUTHORITY="0x..."
```

## 4) Deploy ReleaseRegistry + InstanceFactory (registry owner = KernelAuthority)

```bash
export BLACKCAT_RELEASE_REGISTRY_OWNER="$BLACKCAT_KERNEL_AUTHORITY"

docker run --rm -v "$PWD":/app -w /app --entrypoint bash "$FOUNDRY_IMAGE" -lc \
  "forge script --via-ir script/DeployAll.s.sol:DeployAll --rpc-url \"$RPC_URL\" --broadcast"
```

Export the printed addresses:

```bash
export BLACKCAT_RELEASE_REGISTRY="0x..."
export BLACKCAT_INSTANCE_FACTORY="0x..."
```

## 5) Publish a genesis release (signed by KernelAuthority signers)

Pick any dry-run values:

```bash
export BLACKCAT_COMPONENT_ID="$(docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc 'cast keccak "blackcat-core"')"
export BLACKCAT_RELEASE_VERSION="1"
export BLACKCAT_RELEASE_ROOT="$(docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc 'cast keccak "genesis-root-v1"')"
export BLACKCAT_RELEASE_URI_HASH="$(docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc 'cast keccak "genesis-uri-v1"')"
export BLACKCAT_RELEASE_META_HASH="0x0000000000000000000000000000000000000000000000000000000000000000"
export BLACKCAT_RELEASE_PUBLISH_DEADLINE="$(( $(date +%s) + 3600 ))"
```

Compute digest to sign:

```bash
export PUBLISH_DIGEST="$(
  docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc "
    cast call --rpc-url \"$RPC_URL\" \"$BLACKCAT_RELEASE_REGISTRY\" \
      \"hashPublish(bytes32,uint64,bytes32,bytes32,bytes32,uint256)(bytes32)\" \
      \"$BLACKCAT_COMPONENT_ID\" \"$BLACKCAT_RELEASE_VERSION\" \
      \"$BLACKCAT_RELEASE_ROOT\" \"$BLACKCAT_RELEASE_URI_HASH\" \"$BLACKCAT_RELEASE_META_HASH\" \
      \"$BLACKCAT_RELEASE_PUBLISH_DEADLINE\"
  "
)"
echo "PUBLISH_DIGEST=$PUBLISH_DIGEST"
```

Sign on *each signer device*.
For local simulation, read signer PKs from the keyfiles:

```bash
sign_pk () {
  python3 - <<'PY'
import json, os, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    data=json.load(f)
item = data[0] if isinstance(data, list) else data
print(item["private_key"])
PY
}

SIG1="$(docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc "cast wallet sign --no-hash --private-key \"$(sign_pk \"$S1\")\" \"$PUBLISH_DIGEST\"")"
SIG2="$(docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc "cast wallet sign --no-hash --private-key \"$(sign_pk \"$S2\")\" \"$PUBLISH_DIGEST\"")"

# ABI-encode bytes[] so ReleaseRegistry can call KernelAuthority.isValidSignature(hash, signatureBlob)
export BLACKCAT_RELEASE_PUBLISH_SIGNATURE="$(
  docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc \
    "cast abi-encode \"f(bytes[])\" \"[$SIG1,$SIG2]\""
)"
```

Publish (relayer tx):

```bash
docker run --rm -v "$PWD":/app -w /app --entrypoint bash "$FOUNDRY_IMAGE" -lc \
  "forge script --via-ir script/PublishReleaseAuthorized.s.sol:PublishReleaseAuthorized --rpc-url \"$RPC_URL\" --broadcast"
```

## 6) Create an instance (deterministic + authorized by KernelAuthority)

For dry run we keep upgrade/emergency as the relayer EOA, but root authority is KernelAuthority:

```bash
export BLACKCAT_ROOT_AUTHORITY="$BLACKCAT_KERNEL_AUTHORITY"
export BLACKCAT_UPGRADE_AUTHORITY="$RELAYER_ADDR"
export BLACKCAT_EMERGENCY_AUTHORITY="$RELAYER_ADDR"

export BLACKCAT_GENESIS_ROOT="$BLACKCAT_RELEASE_ROOT"
export BLACKCAT_GENESIS_URI_HASH="$BLACKCAT_RELEASE_URI_HASH"
export BLACKCAT_GENESIS_POLICY_HASH="$(docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc 'cast keccak "genesis-policy-v1"')"

export BLACKCAT_INSTANCE_SALT="$(docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc 'cast keccak "ka-dryrun-salt-1"')"
export BLACKCAT_SETUP_DEADLINE="$(( $(date +%s) + 3600 ))"
```

Compute setup digest to sign:

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
echo "SETUP_DIGEST=$SETUP_DIGEST"
```

Sign it (2-of-3):

```bash
SIG1="$(docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc "cast wallet sign --no-hash --private-key \"$(sign_pk \"$S1\")\" \"$SETUP_DIGEST\"")"
SIG2="$(docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc "cast wallet sign --no-hash --private-key \"$(sign_pk \"$S2\")\" \"$SETUP_DIGEST\"")"
export BLACKCAT_SETUP_SIGNATURE="$(docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc "cast abi-encode \"f(bytes[])\" \"[$SIG1,$SIG2]\"")"
```

Create the instance:

```bash
docker run --rm -v "$PWD":/app -w /app --entrypoint bash "$FOUNDRY_IMAGE" -lc \
  "forge script --via-ir script/CreateInstanceDeterministic.s.sol:CreateInstanceDeterministic --rpc-url \"$RPC_URL\" --broadcast"
```

Export the created controller address from output:

```bash
export BLACKCAT_INSTANCE_CONTROLLER="0x..."
```

## 7) Call `finalizeProduction(...)` as root (via KernelAuthority.execute)

`finalizeProduction(...)` has no `...Authorized` variant, so we must call it with `msg.sender = KernelAuthority` via `execute(...)`.

Choose strict settings:

```bash
export BLACKCAT_EXPECTED_COMPONENT_ID="$BLACKCAT_COMPONENT_ID"
export BLACKCAT_MIN_UPGRADE_DELAY_SEC="5"
export BLACKCAT_MAX_CHECKIN_AGE_SEC="10"
export BLACKCAT_AUTO_PAUSE_ON_BAD_CHECKIN="1"
export BLACKCAT_COMPATIBILITY_WINDOW_SEC="0"
export BLACKCAT_EMERGENCY_CAN_UNPAUSE="0"
```

Build the target calldata (InstanceController.finalizeProduction):

```bash
export BLACKCAT_TARGET="$BLACKCAT_INSTANCE_CONTROLLER"
export BLACKCAT_VALUE="0"
export BLACKCAT_CALLDATA="$(
  docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc "
    cast calldata \"finalizeProduction(address,bytes32,uint64,uint64,bool,uint64,bool)\" \
      \"$BLACKCAT_RELEASE_REGISTRY\" \"$BLACKCAT_EXPECTED_COMPONENT_ID\" \
      \"$BLACKCAT_MIN_UPGRADE_DELAY_SEC\" \"$BLACKCAT_MAX_CHECKIN_AGE_SEC\" \
      \"$BLACKCAT_AUTO_PAUSE_ON_BAD_CHECKIN\" \"$BLACKCAT_COMPATIBILITY_WINDOW_SEC\" \
      \"$BLACKCAT_EMERGENCY_CAN_UNPAUSE\"
  "
)"
export BLACKCAT_KERNEL_DEADLINE="$(( $(date +%s) + 3600 ))"
```

Compute KernelAuthority digest to sign (nonce must match current on-chain nonce):

```bash
export KA_NONCE="$(
  docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc "
    cast call --rpc-url \"$RPC_URL\" \"$BLACKCAT_KERNEL_AUTHORITY\" \"nonce()(uint256)\"
  "
)"
export KA_DIGEST="$(
  docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc "
    cast call --rpc-url \"$RPC_URL\" \"$BLACKCAT_KERNEL_AUTHORITY\" \
      \"hashExecute(address,uint256,bytes,uint256,uint256)(bytes32)\" \
      \"$BLACKCAT_TARGET\" \"$BLACKCAT_VALUE\" \"$BLACKCAT_CALLDATA\" \"$KA_NONCE\" \"$BLACKCAT_KERNEL_DEADLINE\"
  "
)"
echo "KA_DIGEST=$KA_DIGEST"
```

Sign and ABI-encode signatures for the script helper:

```bash
SIG1="$(docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc "cast wallet sign --no-hash --private-key \"$(sign_pk \"$S1\")\" \"$KA_DIGEST\"")"
SIG2="$(docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc "cast wallet sign --no-hash --private-key \"$(sign_pk \"$S2\")\" \"$KA_DIGEST\"")"
export BLACKCAT_KERNEL_SIGNATURES="$(docker run --rm --entrypoint bash "$FOUNDRY_IMAGE" -lc "cast abi-encode \"f(bytes[])\" \"[$SIG1,$SIG2]\"")"
```

Execute via KernelAuthority:

```bash
docker run --rm -v "$PWD":/app -w /app --entrypoint bash "$FOUNDRY_IMAGE" -lc \
  "forge script --via-ir script/KernelExecute.s.sol:KernelExecute --rpc-url \"$RPC_URL\" --broadcast"
```

At this point the controller should be locked-down and ready for additional flows (pause/check-in/upgrade).
