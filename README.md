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
│   │   └── grimoire/                # NOT Frame-tx recipes — a pedagogical-crypto corner,
│   │                                 #   minimal asymmetric primitives written in raw Yul
│   ├── scripts/                     # vector generation + the live end-to-end demo
│   ├── test/                        # solidity (forge-std) + TS (node:test/earl) tests
│   ├── rocketh/                     # rocketh config (accounts, extensions)
│   └── hardhat.config.ts            # includes the `ethrexTestnet` network (chainId 8141)
├── packages/
│   └── viem-frame-tx/               # unofficial viem-based EIP-8141 encoder — own package,
│                                     #   own README, no dependency on the contracts package
├── package.json                     # root monorepo configuration
└── pnpm-workspace.yaml              # pnpm workspace definition
```

## The testnet

[`lambdaclass/ethrex`](https://github.com/lambdaclass/ethrex)'s "Hegotá" testnet is, as far as this repo's research turned up, the only public chain that actually accepts Frame transactions right now:

- RPC: `https://rpc1.privacy.ethrex.xyz` (chain id `8141` / `0x1fcd`)
- Explorer: https://dora.privacy.ethrex.xyz
- Faucet: https://faucet.privacy.ethrex.xyz/artifacts

It's already wired up as the `ethrexTestnet` network in [`contracts/hardhat.config.ts`](contracts/hardhat.config.ts) and as an exported `ethrexTestnet` viem chain from `viem-frame-tx`. Because this targets a Draft EIP on a fork of a fork, the wire format is not settled — before trusting any encoding against a different node, check `web3_clientVersion` yourself and re-derive from that exact commit. See `packages/viem-frame-tx/README.md`'s "Known discrepancies" section for the three (!) different wire formats found across the EIP text, ethrex's `main` branch, and the exact commit this testnet runs.

## `packages/viem-frame-tx`

The RLP encoder for Frame transactions — `serializeFrameTransaction(tx)` (the full `0x06`-prefixed envelope, ready for `sendRawTransaction`) and `computeSigHash(tx)` (the digest a signature commits to). It does not sign anything and does not hook into viem's `chain.serializers.transaction` extension point, because a Frame tx's `signatures` is an array keyed by scheme, not a single top-level `{r, s, v}` — you build your `FrameTransactionSerializable` with `signatures` already populated (sign `computeSigHash(tx)` yourself, however your scheme requires), then serialize and submit.

Full usage example, the ground-truth story, and a byte-exact golden vector are in [`packages/viem-frame-tx/README.md`](packages/viem-frame-tx/README.md).

## Recipe #1: `NostrFrameAccount`

A minimal, self-verifying Frame account authorized by a **BIP-340/Nostr Schnorr signature** instead of ECDSA — the same secp256k1 keypair that signs a Nostr event can authorize a Frame transaction directly, no key derivation in between. It's built as pure Yul (`contracts/src/NostrFrameAccount/NostrFrameAccount.yul`), not Solidity, because `solc` cannot emit EIP-8141's new opcodes (`APPROVE` `0xAA`, `TXPARAM` `0xB0`, `SIGDATACOPY` `0xB5`, ...) from a normal contract — only Yul's `verbatim` builtin can. The BIP-340 verification math itself (the "ecrecover-trick": reformulating Schnorr verification so a single `ecrecover` call does the check, ~3000 gas, instead of on-chain point arithmetic) is derived and unit-tested in isolation first, as a pure Solidity library — `contracts/src/BIP340/BIP340.sol` — then re-inlined in the Yul account using only precompiles, per the validation-trace constraint above.

Both files' header docstrings carry the full derivation, the traps that were hit building this (why the witness has to live in an `ARBITRARY` signature entry and not frame `data`, why the library can't be `STATICCALL`ed from the account), and the security considerations. Start there before writing a second recipe.

- `contracts/scripts/gen-vectors.ts` / `gen-nostr-tools-vector.ts` — generate known-answer test vectors, one from `@noble/curves` directly, one from a real `nostr-tools`-signed event (an independent library, for a genuine cross-check).
- `contracts/scripts/nostr-frame-demo.ts` — the end-to-end reference: compiles the Yul account, deploys it, signs a real Frame transaction with a Nostr key, submits it to `ethrexTestnet`, and confirms both the `VERIFY` and `SENDER` frames succeeded. This is the shape any new recipe's own demo script should follow.

## Adding a new recipe

A Frame account recipe is: a `VERIFY`-frame target contract, a signing scheme, and a script proving the round trip against a live (or simulated) Frame-tx-capable network.

1. **Write the account contract.** Solidity is fine unless you need EIP-8141's own opcodes directly (custom `APPROVE` scope logic, reading `TXPARAM`/`SIGDATACOPY`) — in that case it has to be Yul, compiled directly with `solc` (see `nostr-frame-demo.ts` for how — `hardhat compile` doesn't handle `.yul` files, only `.sol`). Remember the validation-trace rule: no external calls out of a `VERIFY` frame except to `tx.sender`, a default-code account, or a precompile.
2. **Decide your signature scheme.** `SECP256K1`/`P256` need no custom verification code at all (the protocol checks them) — reach for `ARBITRARY` only when you actually want bespoke verification logic, and put the witness bytes in an `ARBITRARY` signature entry with an empty `msg` (never in frame `data` — `compute_sig_hash` covers all frame data, so a witness carried there would have to sign a hash containing itself).
3. **Build and submit the transaction** with `viem-frame-tx`: construct a `FrameTransactionSerializable`, sign `computeSigHash(unsigned)` with your scheme, attach it to `signatures`, call `serializeFrameTransaction`, and submit via ordinary `sendRawTransaction`.
4. **Test it two ways**: a pure-library/no-EVM-context unit test for the verification math itself (fast iteration, easy known-answer vectors), and a real submission against `ethrexTestnet` (or a Hardhat-simulated equivalent, once one exists) for the actual account-contract integration.

## The grimoire: cryptography as poetry

`contracts/src/grimoire/` is a separate, deliberately-insecure track — not Frame-tx recipes, an excuse to get fluent in raw Yul by implementing classic asymmetric primitives directly, as legibly as the language allows. Yul's identifier grammar is ASCII-only (verified directly against this repo's `solc` — a Han-character function name is a hard `ParserError`, not a style choice), so each contract's "poetry" lives beside the code rather than inside it: ASCII-pinyin function names, each paired in a header-comment glossary with the character it transliterates, its pronunciation, and its literal meaning.

First resident: **`ToyCurveECDH`** (`contracts/src/grimoire/ToyCurveECDH/ToyCurveECDH.yul`) — elliptic-curve Diffie-Hellman over `y² = x³ + 2x + 2 (mod 17)`, the textbook toy curve from Hankerson/Menezes/Vanstone's *Guide to Elliptic Curve Cryptography*. Its group has prime order 19 — small enough to enumerate and print on one page, which is the entire point: the same chord-and-tangent geometry that powers this repo's real secp256k1/BIP-340 work (`BIP340.sol`, `NostrFrameAccount.yul`), shrunk down until a curious reader can verify it by hand, and small enough that recovering a private scalar from its public point is a nineteen-iteration `for` loop, not a research problem. Needs none of EIP-8141's opcodes — it's ordinary point arithmetic, testable entirely against a local simulated network, no live testnet or funded key required.

- `contracts/test/js/utils/toyCurve.ts` — the independent JS/bigint mirror (brute-force curve enumeration included — the group order is verified, not assumed).
- `contracts/scripts/gen-toy-curve-vectors.ts` → `contracts/test/vectors/toy-curve-vectors.json` — known-answer vectors, same discipline as the BIP-340 vectors above.
- `contracts/test/js/ToyCurveECDH.test.ts` — deploys the compiled Yul to Hardhat's local network and checks it against the vectors plus a fresh, live two-party exchange.
- `contracts/scripts/toy-curve-demo.ts` — a narrated Alice/Bob exchange, ending by brute-forcing Alice's private scalar back out of her public point, live, to make the "toy" part concrete: `pnpm contracts:execute local scripts/toy-curve-demo.ts`.

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
