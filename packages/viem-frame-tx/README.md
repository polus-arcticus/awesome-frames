# viem-frame-tx

An unofficial [viem](https://viem.sh)-based encoder for [EIP-8141](https://eips.ethereum.org/EIPS/eip-8141) frame transactions (type `0x06`) — RLP serialization and signature-hash computation.

**Status: experimental, unaudited, tracking a Draft EIP.** EIP-8141 is not finalized; field layouts, gas constants, and opcode numbers can and will change before (if) it activates. This package exists because **no JS/TS tooling for frame transactions exists anywhere yet** — not in viem (their own [developer-tooling notes](https://eip8141.io/developer-tooling) say native support "depends on confidence that frame transactions become the native AA standard," i.e. they're waiting on the fork race, not building), not in ethers, not as a standalone npm package. Even the reference client team's own Rust SDK ([`lambdaclass/rex`](https://github.com/lambdaclass/rex)) has its frame-tx docs stubbed `TODO` as of this writing.

This is also meant as a place to compare notes with anyone else independently reverse-engineering this — issues and PRs welcome, especially "your encoding disagrees with mine, here's why."

## ⚠️ Known discrepancies: three sources of truth, three different wire formats

There isn't one ground truth for this format right now — there are (at least) **three, and they disagree on the shape of the RLP payload itself**, not just constants. Confirmed by reading each primary source directly (raw markdown / raw source files, not a summarized or cached rendering), not by inference:

1. **The published EIP text** ([`eips.ethereum.org/EIPS/eip-8141`](https://eips.ethereum.org/EIPS/eip-8141)): `[chain_id, nonce, sender, frames, signatures, fees, blob_versioned_hashes]` (7 fields; `fees` and each frame's `limits = [execution, state]` are nested sub-lists), `FRAME_TX_INTRINSIC_COST = 12000`. No `nonce_keys`/`nonce_seq`, no `recent_root_references`.
2. **[`lambdaclass/ethrex`](https://github.com/lambdaclass/ethrex)'s `main` branch** (`crates/common/types/transaction.rs`, commit `007882a` as of this writing): `[chain_id, nonce, sender, frames, signatures, max_priority_fee_per_gas, max_fee_per_gas, max_fee_per_blob_gas, blob_versioned_hashes]` — **9 flat fields**, `fees` not nested at all; each frame has a **single flat `gas_limit: u64`**, no state-gas dimension; `FRAME_TX_INTRINSIC_COST = 15000`. Matches neither (1) nor (3).
3. **The exact commit the public testnet actually runs** (`rpc1.privacy.ethrex.xyz`, chain 8141 — confirmed via `web3_clientVersion`, which reports `ethrex/v23.0.0-hegota-testnet-...-31b5322665fd48f07337f6dd7cede21e7de7866a`; that commit is 79 commits ahead of and 398 behind `main` — a diverged branch, not an ancestor): `[chain_id, nonce_keys, nonce_seq, sender, frames, signatures, fees, blob_versioned_hashes, recent_root_references]` — **9 fields**, `fees` nested (matching (1)) and each frame's gas is `[gas_limit, state_limit]` nested (matching (1)'s two-dimensional model), but `nonce` is replaced by EIP-8250 keyed nonces (`nonce_keys: Vec<U256>` + `nonce_seq: u64` — absent from (1) and (2) entirely) and there's a new trailing EIP-8272 `recent_root_references` field (also absent from both). `FRAME_TX_INTRINSIC_COST = 12000`, matching (1) — and the source even carries a comment noting the value dropped from the (2)-era `15000`.

**This package matches (3)** — see `src/types.ts`/`src/rlp.ts`/`src/constants.ts` — because that's the node this package's `ethrexTestnet` chain and any real submission actually goes to. It is very likely the _most_ current of the three (it's ahead of `main` and includes machinery neither `main` nor the published EIP text mention yet), but "most current" isn't the same as "correct" or "stable" — a Draft EIP's own reference client can and does move under it. If you're targeting a different ethrex build, a different testnet, or a later revision of any of these, **check `web3_clientVersion` yourself and re-derive from that exact commit** rather than assume any of the three above still applies — this section will go stale.

Once this repo is public, discrepancies like these are exactly what its issue tracker is for — if you've hit a different mismatch, or this section is now stale because one of the three moved, please open one.

## Why this exists

Submitting a frame transaction needs no new JSON-RPC method — it's plain `eth_sendRawTransaction` with a `0x06` type-prefixed RLP blob (EIP-2718). What's missing from the ecosystem is purely the _encoding_. This package fills only that gap:

- `serializeFrameTransaction(tx)` — the full `0x06`-prefixed RLP envelope, ready for `sendRawTransaction`.
- `computeSigHash(tx)` — `keccak256(0x06 || rlp(tx))` with empty-`msg` signature bytes elided, the digest a signature with no explicit `msg` commits to (EIP-8141's `compute_sig_hash`).

It does **not** sign anything, and it does **not** hook into viem's `chain.serializers.transaction` extension point. That hook exists (see [viem's Serializers docs](https://viem.sh/docs/chains/serializers) — the same escape hatch OP-Stack deposit txs and Celo's CIP-64 use, and what pre-native EIP-7702 support was originally built on), but its `signature` argument is populated by viem's single-ECDSA-account signing pipeline (`account.signTransaction` → `{r, s, v}`), which doesn't fit a frame tx: a frame tx carries a `signatures[]` **array**, keyed by scheme (`ARBITRARY`, `SECP256K1`, `P256`), attached before serialization — there's no single top-level signature to merge in after the fact. So: build your `FrameTransactionSerializable` with `signatures` already populated (sign `computeSigHash(tx)` yourself, with whatever scheme you're using), call `serializeFrameTransaction`, then submit the raw bytes with viem's ordinary `sendRawTransaction` — which is transport-only and type-agnostic, so it needs no frame-tx-specific support at all.

## Ground truth

The EIP text carries no test vectors (no "Reference Implementation" or "Test Cases" section), and — see above — none of the three sources agree on the wire format anyway. This package's field layout, gas constants, and RLP structure are taken directly from ethrex's Rust source **at the exact commit (`31b53226…`) the target testnet reports running**, not `main`, and not the prose spec.

`test/rlp.test.ts` checks `serializeFrameTransaction`/`computeSigHash` against a byte-exact golden vector: that same commit's own `make_test_frame_tx()` test fixture, RLP-encoded independently in a from-scratch Python encoder (not this package's `viem.toRlp`-based code path) and cross-checked against this package's output. Same principle the parent repo already applies to its BIP-340 work — don't trust a single implementation as its own source of truth.

The faucet page ([`faucet.privacy.ethrex.xyz`](https://faucet.privacy.ethrex.xyz)) itself turned out to carry the same wire-format description verbatim, plus a link to a reference Python encoder/submitter on ethrex's `hegota-testnet` branch (`scripts/hegota-testnet/{frametx.py,frametx_submit.py}`) — an independent confirmation of everything above, found after re-deriving it, not instead of.

**Confirmed against the live node**, not just golden vectors: `examples/self-transfer.ts` — a self-verified transfer (`VERIFY` frame targeting the sender with `flags=0x03`, then a `SENDER` frame moving value, `SECP256K1` signature) — built, signed, dry-run via `ethrex_simulateFrameTransaction`, submitted via `sendRawTransaction`, and mined on `rpc1.privacy.ethrex.xyz` on the first attempt: [tx `0xc4d97a58a4b676b5278a3efe5d9ccbfb3c85efc4be4fcdc4544e51cfd1e9004c`](https://dora.privacy.ethrex.xyz/tx/0xc4d97a58a4b676b5278a3efe5d9ccbfb3c85efc4be4fcdc4544e51cfd1e9004c), `status: success`, both frame receipts succeeded. Run it yourself: `tsx examples/self-transfer.ts <private_key> <recipient> <amount_wei>`.

**The actual point of this package's parent repo** goes one step further: this package's `serializeFrameTransaction`/`computeSigHash` also underpin `contracts/scripts/nostr-frame-demo.ts`, which deploys a `VERIFY`-frame smart account (`NostrFrameAccount.yul`, see the design doc's §4.1) authorized by a **BIP-340 Schnorr signature** (`ARBITRARY` scheme) instead of plain ECDSA, and proves that the *same* secp256k1 keypair signs a real Nostr event *and* authorizes a real frame transaction, with no key-derivation step in between: [tx `0xeeee6794385279c3ee192da563ac44aec0a21792d9e72f7e94184179c5b6ea2e`](https://dora.privacy.ethrex.xyz/tx/0xeeee6794385279c3ee192da563ac44aec0a21792d9e72f7e94184179c5b6ea2e), `status: success`. That script lives in `contracts/` (it needs `nostr-tools` and the parent repo's BIP-340 test utilities), not in this package.

## Usage

```ts
import {createPublicClient, http} from 'viem';
import {
	SignatureScheme,
	computeSigHash,
	ethrexTestnet,
	serializeFrameTransaction,
} from 'viem-frame-tx';
import type {FrameTransactionSerializable} from 'viem-frame-tx';

const unsigned: FrameTransactionSerializable = {
	chainId: 8141,
	nonceKeys: [0n], // the plain linear nonce domain — see EIP-8250
	nonceSeq: 0n, // the account's ordinary nonce for key 0
	sender: '0x...', // the frame-tx account, e.g. a NostrFrameAccount
	frames: [
		{
			mode: 1 /* VERIFY */,
			flags: 0x03,
			target: null,
			gasLimit: 100_000n,
			stateLimit: 0n,
			value: 0n,
			data: '0x',
		},
		{
			mode: 2 /* SENDER */,
			flags: 0x00,
			target: '0x...',
			gasLimit: 21_000n,
			stateLimit: 0n,
			value: 0n,
			data: '0x',
		},
	],
	signatures: [
		{
			scheme: SignatureScheme.ARBITRARY,
			signer: null,
			msg: '0x',
			signature: '0x',
		},
	], // placeholder
	maxPriorityFeePerGas: 1_000_000_000n,
	maxFeePerGas: 30_000_000_000n,
};

const sigHash = computeSigHash(unsigned);
// sign sigHash with whatever scheme you declared above — e.g. BIP-340/Nostr
// for ARBITRARY (see the parent repo's contracts/src/BIP340) — then attach
// the resulting bytes:
const signed: FrameTransactionSerializable = {
	...unsigned,
	signatures: [
		{...unsigned.signatures[0]!, signature: '0x...' /* your signature bytes */},
	],
};

const client = createPublicClient({chain: ethrexTestnet, transport: http()});
const hash = await client.sendRawTransaction({
	serializedTransaction: serializeFrameTransaction(signed),
});
```

## What's not here yet

- No P256/SECP256K1 signing helpers built into the package — `examples/self-transfer.ts` signs with `@noble/curves` directly (viem's own low-level `sign` isn't exported publicly), and the parent repo's BIP-340 signer covers `ARBITRARY`, but there's no `viem-frame-tx`-level convenience for either yet.
- No transaction-request "populate" helper (fee estimation, nonce lookup, etc.) — `examples/self-transfer.ts` fetches those itself via the normal `publicClient` actions; there's no package-level equivalent of viem's `prepareTransactionRequest` yet.
- No decoder (RLP → `FrameTransactionSerializable`) — only encoding, since that's the side needed to submit.
- ~~No `VERIFY`-frame example wired to a real validation contract~~ — done, but lives in the parent repo (`contracts/scripts/nostr-frame-demo.ts`, see "Ground truth" above), not as a `viem-frame-tx` example, since it needs `nostr-tools` and a compiled Yul account contract.
- Not published to npm yet (`private: true` in `package.json`) — flip that and publish now that it's been exercised against a real node.
