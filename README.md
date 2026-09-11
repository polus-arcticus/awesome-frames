# awesome-frames

A playground for crafting [EIP-8141](https://eips.ethereum.org/EIPS/eip-8141) **Frame transactions** on Ethereum — Hardhat v3 + [rocketh](https://github.com/wighawag/rocketh) for contracts, plus a standalone [`viem`](https://viem.sh)-based encoder package, wired up against the only public Frame-tx-capable testnet that exists today.

**Status: Draft EIP, moving target.** As of 2026-08-27, EIP-8141 was upgraded to Scheduled-for-Inclusion for the "Hegotá" fork (target activation late 2026/2027) but is still Draft — field layouts, gas constants, and opcode numbers can and will change before (if) it activates. No mainnet-track execution client has shipped support yet ([go-ethereum#33954](https://github.com/ethereum/go-ethereum/pull/33954), the one known attempt, was closed in favor of a from-scratch implementation). [`lambdaclass/ethrex`](https://github.com/lambdaclass/ethrex)'s own fork runs a public testnet — see below — but even that diverges from both the published EIP text and ethrex's own `main` branch. Treat everything here as research/prototype tooling, not production-ready.

## What's a Frame transaction?

EIP-8141 introduces a new transaction type (`0x06`) built from a list of **frames** — contract calls tagged with a `mode`:

- `VERIFY` — runs as a `STATICCALL`; must call the new `APPROVE` opcode (`0xAA`) to authorize execution and/or payment. This is the account-abstraction hook: arbitrary EVM code decides whether the transaction is valid.
- `SENDER` — the actual user operation(s), executed only if a prior `VERIFY` frame approved them.
- `DEFAULT` — ordinary EOA-style validation.

The `signatures` list supports three schemes: `SECP256K1` (protocol-verified ECDSA, native `ecrecover`), `P256` (secp256r1 via the `P256VERIFY` opcode), and `ARBITRARY` (raw bytes — no protocol-level check at all; verification is entirely up to your `VERIFY` frame's code). `ARBITRARY` is what makes this a genuine account-abstraction primitive: any signature scheme you can implement in EVM opcodes, you can authorize a Frame tx with.

The public mempool's **validation trace rules** are the sharp edge to know about early: a `VERIFY` frame may not `CALL*`/`EXTCODE*` anything except `tx.sender`, a default-code account, or a precompile. A `VERIFY` frame that needs custom crypto has to inline it using only precompiles (`ecrecover`, `SHA256`, `MODEXP`, ...) — it can't delegate to a separately deployed library contract and still be publicly propagatable. See `contracts/src/NostrFrameAccount/NostrFrameAccount.yul`'s header comment for a worked example of exactly this constraint.

## Structure

```
.
├── contracts/                       # Hardhat v3 + rocketh contracts package
│   ├── src/
│   │   ├── BIP340/                  # BIP-340 (Nostr) Schnorr verification library
│   │   ├── NostrFrameAccount/       # recipe #1: a VERIFY-frame account authorized by
│   │   │                             #   a Nostr/BIP-340 Schnorr sig instead of ECDSA
│   │   ├── LightningRSA/            # recipe #2: verify library + account together (unlike
│   │   │                             #   BIP340/NostrFrameAccount's split — LightningRSA.sol
│   │   │                             #   has no reuse outside its own account)
│   │   └── grimoire/                # NOT Frame-tx recipes — a pedagogical-crypto corner,
│   │                                 #   minimal asymmetric primitives, mostly in raw Yul
│   │       ├── ToyCurveECDH/        #   toy-curve ECDH, small enough to verify by hand
│   │       ├── StarkPedersen/       #   Starknet's real Pedersen hash, on-chain in Yul
│   │       ├── YoloRSA/             #   verify library + deployable crackme wallets, a
│   │       │                         #   difficulty ladder including wide (2-word) tiers
│   │       └── post-quantum/        #   JS-only PQC survey: MlKem, Lamport, Falcon,
│   │                                 #   MlDsa, ClassicMcEliece (no on-chain accounts yet)
│   ├── scripts/                     # vector generation + the live end-to-end demos
│   ├── test/                        # solidity (forge-std) + TS (node:test/earl) tests
│   ├── rocketh/                     # rocketh config (accounts, extensions)
│   └── hardhat.config.ts            # includes the `ethrexTestnet` network (chainId 8141)
├── packages/
│   ├── viem-frame-tx/               # unofficial viem-based EIP-8141 encoder — own package,
│   │                                 #   own README, no dependency on the contracts package
│   └── docs/                        # Docusaurus documentation site — see below
├── package.json                     # root monorepo configuration
└── pnpm-workspace.yaml              # pnpm workspace definition
```

## Documentation site

`packages/docs` is a [Docusaurus](https://docusaurus.io/) site covering everything in this README in more depth, plus material this README doesn't have room for — the GNFS-based cost-estimation methodology behind `YoloRSA`'s wide tiers, and the EIP-8141 gas-budget math behind `LightningRSA`'s `e=3` choice, in particular. Run it locally with `pnpm docs:start`, or build the static site with `pnpm docs:build`.

## The testnet

[`lambdaclass/ethrex`](https://github.com/lambdaclass/ethrex)'s "Hegotá" testnet is, as far as this repo's research turned up, the only public chain that actually accepts Frame transactions right now:

- RPC: `https://rpc1.privacy.ethrex.xyz` (chain id `8141` / `0x1fcd`)
- Explorer: https://dora.privacy.ethrex.xyz
- Faucet: https://faucet.privacy.ethrex.xyz/artifacts

It's already wired up as the `ethrexTestnet` network in [`contracts/hardhat.config.ts`](contracts/hardhat.config.ts) and as an exported `ethrexTestnet` viem chain from `viem-frame-tx`. Because this targets a Draft EIP on a fork of a fork, the wire format is not settled — before trusting any encoding against a different node, check `web3_clientVersion` yourself and re-derive from that exact commit. See `packages/viem-frame-tx/README.md`'s "Known discrepancies" section for the three (!) different wire formats found across the EIP text, ethrex's `main` branch, and the exact commit this testnet runs.

## `packages/viem-frame-tx`

[![npm](https://img.shields.io/npm/v/viem-frame-tx)](https://www.npmjs.com/package/viem-frame-tx)

The RLP encoder for Frame transactions — `serializeFrameTransaction(tx)` (the full `0x06`-prefixed envelope, ready for `sendRawTransaction`) and `computeSigHash(tx)` (the digest a signature commits to). It does not sign anything and does not hook into viem's `chain.serializers.transaction` extension point, because a Frame tx's `signatures` is an array keyed by scheme, not a single top-level `{r, s, v}` — you build your `FrameTransactionSerializable` with `signatures` already populated (sign `computeSigHash(tx)` yourself, however your scheme requires), then serialize and submit.

Published standalone on npm — usable outside this monorepo with no dependency on the contracts package:

```bash
pnpm add viem-frame-tx
```

Full usage example, the ground-truth story, and a byte-exact golden vector are in [`packages/viem-frame-tx/README.md`](packages/viem-frame-tx/README.md).

## Recipe #1: `NostrFrameAccount`

A minimal, self-verifying Frame account authorized by a **BIP-340/Nostr Schnorr signature** instead of ECDSA — the same secp256k1 keypair that signs a Nostr event can authorize a Frame transaction directly, no key derivation in between. It's built as pure Yul (`contracts/src/NostrFrameAccount/NostrFrameAccount.yul`), not Solidity, because `solc` cannot emit EIP-8141's new opcodes (`APPROVE` `0xAA`, `TXPARAM` `0xB0`, `SIGDATACOPY` `0xB5`, ...) from a normal contract — only Yul's `verbatim` builtin can. The BIP-340 verification math itself (the "ecrecover-trick": reformulating Schnorr verification so a single `ecrecover` call does the check, ~3000 gas, instead of on-chain point arithmetic) is derived and unit-tested in isolation first, as a pure Solidity library — `contracts/src/BIP340/BIP340.sol` — then re-inlined in the Yul account using only precompiles, per the validation-trace constraint above.

Both files' header docstrings carry the full derivation, the traps that were hit building this (why the witness has to live in an `ARBITRARY` signature entry and not frame `data`, why the library can't be `STATICCALL`ed from the account), and the security considerations. Start there before writing a second recipe.

- `contracts/scripts/gen-vectors.ts` / `gen-nostr-tools-vector.ts` — generate known-answer test vectors, one from `@noble/curves` directly, one from a real `nostr-tools`-signed event (an independent library, for a genuine cross-check).
- `contracts/scripts/nostr-frame-demo.ts` — the end-to-end reference: compiles the Yul account, deploys it, signs a real Frame transaction with a Nostr key, submits it to `ethrexTestnet`, and confirms both the `VERIFY` and `SENDER` frames succeeded. This is the shape any new recipe's own demo script should follow.

## Recipe #2: `LightningRSA`

A self-verifying Frame account authorized by a **real RSASSA-PKCS1-v1_5/SHA-256 signature** (RFC 8017) — unlike the grimoire's `YoloRSA` (deliberately tiny, deliberately unpadded, never safe to use regardless of modulus size), this is meant to be sound at any modulus width an operator actually deploys with. Default target: RSA-2048. The verify math is derived and forge-tested first as a pure Solidity library — `contracts/src/LightningRSA/LightningRSA.sol`, checked against real signatures produced by Node's own `crypto` module, not this repo's own math — then re-inlined in the Yul account (`contracts/src/LightningRSA/LightningRSAAccount.yul`) using only the `SHA256`/`MODEXP` precompiles.

Two things worth knowing before reading the code:

- **`n` is arbitrary width, not a fixed word count.** Solidity's own `bytes` type already gives full generality (the `MODEXP` precompile natively accepts arbitrary-length operands); the Yul account stores `n`/`e` appended directly after its own deployed runtime code (read back via cheap self-`CODECOPY` each call) rather than in storage, specifically because a real RSA-2048 modulus is 8 EVM words and `SLOAD`ing that many words is expensive enough to matter against EIP-8141's `MAX_VERIFY_GAS = 100,000` cap.
- **The public exponent is `e = 3`, not the usual `65537`.** `MODEXP`'s EIP-2565 gas cost is priced from the *exponent's* bit length — at `e = 65537` a single RSA-2048 verify costs roughly 200,000 gas by that formula, over budget before anything else runs; at `e = 3` it's roughly 13,000. Low-exponent RSA has real historical forgery bugs, but every one of them targeted verifiers that leniently *parsed* padding out of the recovered value instead of reconstructing the expected block and comparing byte-for-byte — which is exactly the discipline this library follows throughout, closing that class regardless of `e`.

The Yul translation of the (already forge-tested) padding/`MODEXP` logic is itself verified empirically, not just eyeballed: `contracts/test/yul/LightningRSAAccountVerifyHarness.yul` is a test-only mirror of the account's verify function with the EIP-8141-only witness-pulling swapped for plain calldata (so it's callable on Hardhat's ordinary network, unlike the real account), checked against the exact same real RSA-2048 vectors and confirmed to produce identical accept/reject verdicts to the Solidity original.

- `contracts/test/js/utils/pkcs1.ts` — Node-crypto-backed keygen/sign/verify reference.
- `contracts/scripts/gen-lightning-rsa-vectors.ts` → `contracts/test/vectors/lightning-rsa-vectors.json` — a fresh real RSA-2048 keypair every run; fine to commit (test fixtures only — a real deployment must generate its own keypair locally and never commit the private key).
- `contracts/test/solidity/LightningRSA/LightningRSA.t.sol`, `contracts/test/js/LightningRSAAccount.test.ts` — known-answer vectors, negative cases, and an empirical gas-budget assertion (`assertLt(gasUsed, 100_000)`).

## Adding a new recipe

A Frame account recipe is: a `VERIFY`-frame target contract, a signing scheme, and a script proving the round trip against a live (or simulated) Frame-tx-capable network.

1. **Write the account contract.** Solidity is fine unless you need EIP-8141's own opcodes directly (custom `APPROVE` scope logic, reading `TXPARAM`/`SIGDATACOPY`) — in that case it has to be Yul, compiled directly with `solc` (see `nostr-frame-demo.ts` for how — `hardhat compile` doesn't handle `.yul` files, only `.sol`). Remember the validation-trace rule: no external calls out of a `VERIFY` frame except to `tx.sender`, a default-code account, or a precompile.
2. **Decide your signature scheme.** `SECP256K1`/`P256` need no custom verification code at all (the protocol checks them) — reach for `ARBITRARY` only when you actually want bespoke verification logic, and put the witness bytes in an `ARBITRARY` signature entry with an empty `msg` (never in frame `data` — `compute_sig_hash` covers all frame data, so a witness carried there would have to sign a hash containing itself).
3. **Build and submit the transaction** with `viem-frame-tx`: construct a `FrameTransactionSerializable`, sign `computeSigHash(unsigned)` with your scheme, attach it to `signatures`, call `serializeFrameTransaction`, and submit via ordinary `sendRawTransaction`.
4. **Test it two ways**: a pure-library/no-EVM-context unit test for the verification math itself (fast iteration, easy known-answer vectors), and a real submission against `ethrexTestnet` (or a Hardhat-simulated equivalent, once one exists) for the actual account-contract integration.

## The grimoire: cryptography as poetry

`contracts/src/grimoire/` is a separate, deliberately-insecure track — not Frame-tx recipes, an excuse to get fluent in raw Yul (and, in the post-quantum survey below, plain TypeScript) by implementing classic and modern asymmetric primitives directly, as legibly as the language allows. Yul's identifier grammar is ASCII-only (verified directly against this repo's `solc` — a Han-character function name is a hard `ParserError`, not a style choice), so each Yul contract's "poetry" lives beside the code rather than inside it: ASCII-pinyin function names, each paired in a header-comment glossary with the character it transliterates, its pronunciation, and its literal meaning.

First resident: **`ToyCurveECDH`** (`contracts/src/grimoire/ToyCurveECDH/ToyCurveECDH.yul`) — elliptic-curve Diffie-Hellman over `y² = x³ + 2x + 2 (mod 17)`, the textbook toy curve from Hankerson/Menezes/Vanstone's *Guide to Elliptic Curve Cryptography*. Its group has prime order 19 — small enough to enumerate and print on one page, which is the entire point: the same chord-and-tangent geometry that powers this repo's real secp256k1/BIP-340 work (`BIP340.sol`, `NostrFrameAccount.yul`), shrunk down until a curious reader can verify it by hand, and small enough that recovering a private scalar from its public point is a nineteen-iteration `for` loop, not a research problem. Needs none of EIP-8141's opcodes — it's ordinary point arithmetic, testable entirely against a local simulated network, no live testnet or funded key required.

- `contracts/test/js/utils/toyCurve.ts` — the independent JS/bigint mirror (brute-force curve enumeration included — the group order is verified, not assumed).
- `contracts/scripts/gen-toy-curve-vectors.ts` → `contracts/test/vectors/toy-curve-vectors.json` — known-answer vectors, same discipline as the BIP-340 vectors above.
- `contracts/test/js/ToyCurveECDH.test.ts` — deploys the compiled Yul to Hardhat's local network and checks it against the vectors plus a fresh, live two-party exchange.
- `contracts/scripts/toy-curve-demo.ts` — a narrated Alice/Bob exchange, ending by brute-forcing Alice's private scalar back out of her public point, live, to make the "toy" part concrete: `pnpm contracts:execute local scripts/toy-curve-demo.ts`.

### `StarkPedersen`: Starknet's real Pedersen hash, on Ethereum

Unlike `ToyCurveECDH`, every number here is a **real** Starknet constant, not shrunk for legibility — the STARK-friendly curve (`y² = x³ + x + b mod (2^251 + 17·2^192 + 1)`), the field, and the five "nothing up my sleeve" generator points are exactly what a Starknet node uses. Prompted by a local Cairo project (ScarabSign) that leans on this exact primitive for peer-to-peer signature aggregation — this is the first grimoire step toward verifying Starknet-flavored signatures on Ethereum, not that verification itself. Cross-checked byte-for-byte against [`@scure/starknet`](https://www.npmjs.com/package/@scure/starknet), the same paulmillr/noble-family ground truth already trusted elsewhere in this repo. Measured gas for one `pedersen(x, y)` call: ~2.7M — real cost, comfortably practical, and a concrete data point in the long-running "should Ethereum have a Pedersen/Poseidon precompile" debate ([EIP-5988](https://eips.ethereum.org/EIPS/eip-5988) is stagnant).

- `contracts/src/grimoire/StarkPedersen/StarkPedersen.yul` — the contract.
- `contracts/test/js/utils/starkPedersen.ts` — the independent JS/bigint mirror.
- `contracts/scripts/gen-stark-pedersen-vectors.ts` → `contracts/test/vectors/stark-pedersen-vectors.json` — known-answer vectors, verified against `@scure/starknet` and the curve equation itself before being pinned.
- `contracts/test/js/StarkPedersen.test.ts` — pinned vectors, a fresh cross-check against `@scure/starknet`, both correctness guards (out-of-range inputs, the same-x-coordinate collision guard), and the real measured gas cost.

### `YoloRSA`: deployable crackme wallets, a difficulty ladder

A ladder of deliberately-weak textbook RSA "wallets" — deploy one, fund it with testnet ETH, publish nothing but its public key (baked directly into the contract's own bytecode), and see how long a stranger takes to factor the modulus, recover the private exponent, forge a signature, and drain it. Five tiers, each sized to a specific real-world cracking difficulty: `pencil` (mental trial division, ~12 bits) through `weekend-project` (needs a real factoring tool, ~248 bits — the largest this template supports, since `n` has to fit in a single 32-byte EVM word). One compiled account template (`YoloRSAAccount.yul`) is redeployed unmodified across every tier; only the constructor args (`e`, `n`) differ.

- `contracts/src/grimoire/YoloRSA/YoloRSA.sol` — the verify library (`s^e mod n == msgHash mod n`, via the `MODEXP` precompile), forge-tested against every tier.
- `contracts/src/grimoire/YoloRSA/YoloRSAAccount.yul` — the deployable account, re-inlining that same check using only precompiles.
- `contracts/test/js/utils/yoloRSA.ts` — both sides: keygen/sign/verify (the owner's), and `factor`/`crackPrivateExponent` (the attacker's — trial division, then Pollard's rho).
- `contracts/scripts/gen-yolo-rsa-vectors.ts` → `contracts/test/vectors/yolo-rsa-vectors.json` — generates each tier's keypair and known-answer vectors, cracking every tier through `laptop` during generation itself as a sanity check.
- `contracts/test/js/YoloRSA.test.ts` — pinned vectors plus a live sign → verify → crack → forge round trip.

See the [docs site](packages/docs) for the padding-scheme caveat (no real padding fits at these moduli sizes, which is intentional) and the full difficulty table.

**Wide tiers** extend the same ladder past 256 bits, for moduli that genuinely need to exceed a single EVM word — `n` and the signature witness each span two words (up to 512 bits) instead of one, using the `MODEXP` precompile's native arbitrary-length support. Tiers are sized against a stated, checkable attacker model — one Ethereum-validator-spec machine (ethereum.org's own CPU guidance) starting the instant a spend hits the mempool — using the actual GNFS sub-exponential cost function, not naive brute-force estimation: `ten-minute` (~384 bits) and `one-hour` (~424 bits), with the same 2-word template covering up to about a day (~502 bits) before a third word would be needed.

- `contracts/src/grimoire/YoloRSA/YoloRSAWideAccount.yul` — the 2-word account template.
- `contracts/test/js/utils/bigWord.ts` — generic big-endian word split/join, reusable for a future 3-word template.
- `contracts/scripts/gen-yolo-rsa-wide-vectors.ts` → `contracts/test/vectors/yolo-rsa-wide-vectors.json`, `contracts/test/js/YoloRSAWide.test.ts` — same discipline as the base tiers'.

The full GNFS cost-model derivation (the L-function, the RSA-768 calibration anchor, the validator-hardware assumption and its sensitivity) is documented on the [docs site](packages/docs), not repeated here. No modulus size makes unpadded RSA — either ladder — safe to actually use; that's what [Recipe #2: `LightningRSA`](#recipe-2-lightningrsa) is for.

### Post-quantum survey

Prompted by a Vitalik Buterin post surveying post-quantum cryptography families — off-chain/JS only this pass (PQC's building blocks mostly have no EVM precompile analog the way RSA/EC map onto `MODEXP`/`ecrecover`), and scoped honestly rather than evenly: six concrete schemes, each taken as far as it's actually tractable to derive correctly, not six half-finished attempts.

- **`MlKem`** (`contracts/src/grimoire/post-quantum/MlKem/`) — real ML-KEM-512 (FIPS 203), full size, nothing shrunk (Module-LWE's hardness depends on the real dimension/modulus). Byte-exact against `@noble/post-quantum` on every field, both cross-decapsulation directions, plus the implicit-rejection edge case.
- **`Lamport`** (`.../Lamport/`) — one-time hash-based signatures, full keygen/sign/verify, plus a real forgery: two live signatures over complementary digests reused into a signature over a digest that was never signed.
- **`Falcon`** (`.../Falcon/`) — verify-only. Falcon *signing* needs floating-point Gaussian sampling, a real hazard NIST's own FIPS 206 status updates cite as the reason Falcon's standardization is taking longer than ML-KEM's/ML-DSA's (FIPS 206 is still Draft as of this writing). Verification is pure integer arithmetic — derived from the original, stable Falcon submission spec, checked against real signatures from `@noble/post-quantum`.
- **`MlDsa`** (`.../MlDsa/`) — conceptual only: real FIPS 204 parameters, no working code. Documents why ML-DSA needed more than `MlKem`'s slot (Fiat-Shamir-with-Aborts, bit decomposition, hint-bit compression) rather than shipping a rushed partial implementation.
- **`ClassicMcEliece`** (`.../ClassicMcEliece/`) — a stretch goal that landed: a real toy binary Goppa code (GF(16), n=15, k=7, t=2) wrapped in actual McEliece key-scrambling, decoded via a brute-force syndrome lookup table standing in for Patterson's algorithm. Verified exhaustively — all 128 possible messages, fresh keypair each time.
- **Isogeny-based** — docs only, on the [docs site](packages/docs): CSIDH's design and the actual 2022 Castryck–Decru break of SIDH. Real isogeny arithmetic was assessed as a research-grade lift, not a survey-pass item.

## Initial Setup

### Prerequisites

- [Node.js](https://nodejs.org/) (v22+)
- [pnpm](https://pnpm.io/)

### Installation

```bash
pnpm i
```

We also recommend installing [Zellij](https://zellij.dev/) for an optimal development experience with `pnpm start`.

## Usage

### Compile Contracts

```bash
pnpm contracts:compile
```

This compiles Solidity sources under `contracts/src` (`.yul` files are compiled separately, on demand, by the scripts that need them — see `nostr-frame-demo.ts`).

### Watch Mode (Auto-Rebuild)

Run in a separate terminal for automatic recompilation on changes:

> async: `run this in a separate terminal`

```bash
pnpm contracts:compile:watch
```

### Run Tests

```bash
pnpm contracts:test
```

```bash
pnpm frame-tx:test
```

`contracts:test` runs both the Solidity tests (forge-style, `forge-std`) and the TypeScript tests (Node.js test runner, `earl` assertions) for the contracts package. `frame-tx:test` runs `viem-frame-tx`'s own encoder tests, independently — it has no dependency on the contracts package.

### Local Development

Start a local Ethereum node:

> async: `run this in a separate terminal`

```bash
pnpm contracts:node:local
```

### Deploy / run against ethrexTestnet

Frame accounts in this repo are deployed and exercised via plain scripts (`contracts/scripts/*.ts`) rather than rocketh's `deploy/` pipeline, since they need to compile Yul directly and build raw Frame transactions:

```bash skip
pnpm contracts:execute ethrexTestnet scripts/nostr-frame-demo.ts
```

Fund a throwaway key from the [faucet](https://faucet.privacy.ethrex.xyz/artifacts), set it as `PRIVATE_KEY_ethrexTestnet` in `contracts/.env.local` (not committed — see `.gitignore`'s `*.local` rule), and it takes priority over the default test mnemonic for that network.

The rocketh proxy-deploy pipeline (`deployViaProxy`, hot contract replacement, `contracts:deploy <network>`) is still there and fully usable for any contract that doesn't need Frame-tx-specific opcodes — see rocketh's own docs and `contracts/rocketh/config.ts`.

### Verify Contracts

```bash skip
pnpm contracts:verify <network>
```

## Zellij Development Environment

[Zellij](https://zellij.dev/) is a terminal multiplexer (like tmux) with a preconfigured layout for this repo.

Start the full development environment:

```bash skip
pnpm start
```

This launches a local Ethereum node, auto-compilation, auto-testing, and an interactive shell for running scripts.

## Writing Tests

### TypeScript Tests

Located in `contracts/test/js`, using Node.js's test runner and `earl` assertions. `BIP340.test.ts` is a good template for a pure verification-library test — no EVM context needed:

```typescript skip
import {expect} from 'earl';
import {describe, it} from 'node:test';
import {verifyEcrecoverTrick} from './utils/bip340.js';

describe('MyScheme', function () {
  it('accepts a valid signature', function () {
    const ok = verifyEcrecoverTrick(/* ... */);
    expect(ok).toEqual(true);
  });
});
```

### Solidity Tests

Located under `contracts/test/solidity`, using `forge-std`. `BIP340.t.sol` is the reference: known-answer vectors plus systematic negative cases (flipped bits, non-canonical values, crossed inputs):

```solidity
import {Test} from "forge-std/Test.sol";
import {BIP340} from "../../../src/BIP340/BIP340.sol";

contract MySchemeTest is Test {
    function test_validSignature() public {
        assertTrue(BIP340.verify(pAddress, px, rx, s, msgHash));
    }
}
```

## Linting

Solidity linting is configured with [slippy](https://github.com/astrodevs-labs/slippy):

```bash
pnpm contracts:lint
```

## Publishing & Consuming Contracts

### Package Exports

The contracts package (`awesome-frames-contracts`) exposes multiple entry points:

```json
{
  "exports": {
    "./deploy/*": "./dist/deploy/*",
    "./rocketh/*": "./dist/rocketh/*",
    "./artifacts/*": "./dist/generated/artifacts/*",
    "./abis/*": "./dist/generated/abis/*",
    "./deployments/*": "./deployments/*",
    "./src/*": "./src/*"
  }
}
```

### Using in Another Package

```typescript skip
// Import ABIs
import { Abi_BIP340 } from "awesome-frames-contracts/abis/BIP340.js";

// Import Solidity sources (for inheritance or verification)
// Reference: awesome-frames-contracts/src/BIP340/BIP340.sol

// Use the frame-tx encoder directly
import { serializeFrameTransaction, computeSigHash } from "viem-frame-tx";
```

### Building for Publication

```bash
pnpm contracts:build
```

## Environment Variables

| Variable                         | Description                                                    |
| --------------------------------- | ---------------------------------------------------------------|
| `ETH_NODE_URI_<network>`          | RPC endpoint for the network                                   |
| `MNEMONIC_<network>`              | Mnemonic for account derivation                                |
| `MNEMONIC`                        | Fallback mnemonic if network-specific not set                  |
| `PRIVATE_KEY_ethrexTestnet`       | Funded key for `ethrexTestnet` — put in `.env.local`, not `.env` |
| `ETHERSCAN_API_KEY`               | API key for contract verification                              |

Set `SECRET` as the value to use Hardhat's secret store:

```bash skip
ETH_NODE_URI_mainnet=SECRET  # Uses configVariable('SECRET_ETH_NODE_URI_mainnet')
```

## References

- [EIP-8141: Frame Transaction](https://eips.ethereum.org/EIPS/eip-8141) (Draft; SFI for Hegotá as of 2026-08-27)
- [BIP-340: Schnorr Signatures for secp256k1](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- [`lambdaclass/ethrex`](https://github.com/lambdaclass/ethrex) — the reference client running the Hegotá testnet
- [Hardhat v3](https://hardhat.org/) / [hardhat-deploy](https://github.com/wighawag/hardhat-deploy) / [rocketh](https://github.com/wighawag/rocketh) — the contracts tooling this repo is built on

## License

MIT
