# Build & Verification Notes (Foundry)

This repo intentionally prioritizes **deployability + auditability** over micro gas optimizations.

## Why `optimizer_runs = 1`

`InstanceController` is extremely close to the EVM contract runtime size limit (**EIP-170: 24,576 bytes**).

Higher `optimizer_runs` values tend to trade **more bytecode** for slightly cheaper execution paths.
For `InstanceController` that quickly pushes the runtime size over EIP-170 and makes it undeployable.

In practice:
- most state-changing functions are dominated by `SSTORE` cost anyway (optimizer runs has limited impact),
- deployment viability is a hard constraint, so the build is configured “size-first”.

## Why `bytecode_hash = "ipfs"`

This keeps Solidity metadata in a commonly supported format for block explorers / verification tooling.

If you change metadata settings, always re-check EIP-170 size.

## Always check sizes before deployment

Run:
- `forge build --via-ir --force --skip test --skip script --sizes`

Expected:
- `InstanceController` runtime size must be `< 24576`.

## Warning: `InstanceController` is nearly full

Because we’re near EIP-170, any extra feature added to `InstanceController` can break deployability.
Future expansions should prefer:
- a v2 controller, or
- a separate helper contract (guard/bot/ops module) referenced by address.

