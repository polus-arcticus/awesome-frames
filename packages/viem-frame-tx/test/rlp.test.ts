// Golden-vector test: independently hand-derived (a from-scratch RLP
// encoder written in Python, not this package's own toRlp-based code path)
// from ethrex's own `make_test_frame_tx()` fixture, pulled from the *exact*
// commit (31b5322665fd48f07337f6dd7cede21e7de7866a) the public testnet this
// package targets reports running via `web3_clientVersion` — not ethrex's
// `main` branch, which has already drifted from this commit on multiple
// structural axes (see the package README's "Known discrepancies").
// Ground-truthed against the reference implementation actually running on
// the target chain, not just internally self-consistent — same principle
// this repo already applies to BIP340 (see contracts/scripts/gen-vectors.ts).
import assert from 'node:assert/strict';
import {describe, it} from 'node:test';
import {type Address, stringToHex} from 'viem';
import {
	SignatureScheme,
	computeSigHash,
	serializeFrameTransaction,
} from '../src/index.js';
import type {FrameTransactionSerializable} from '../src/types.js';

// `Address::from_low_u64_be(0xABCD)` / `(0x1234)`: a 20-byte address with
// only the low 2 bytes set.
const ADDR_ABCD: Address = '0x000000000000000000000000000000000000abCD';
const ADDR_1234: Address = '0x0000000000000000000000000000000000001234';

const tx: FrameTransactionSerializable = {
	chainId: 1,
	nonceKeys: [0n], // vec![U256::zero()] — the plain linear nonce domain
	nonceSeq: 42n,
	sender: ADDR_ABCD,
	frames: [
		{
			mode: 1, // VERIFY
			flags: 0x03, // APPROVE_EXECUTION_AND_PAYMENT
			target: ADDR_ABCD,
			gasLimit: 100_000n,
			stateLimit: 0n,
			value: 0n,
			data: stringToHex('verify_data'),
		},
		{
			mode: 2, // SENDER
			flags: 0x00,
			target: ADDR_1234,
			gasLimit: 200_000n,
			stateLimit: 0n,
			value: 0n,
			data: stringToHex('call_data'),
		},
	],
	signatures: [
		{
			scheme: SignatureScheme.SECP256K1,
			signer: ADDR_ABCD,
			msg: '0x',
			signature: `0x${'00'.repeat(65)}`,
		},
	],
	maxPriorityFeePerGas: 1_000_000_000n,
	maxFeePerGas: 30_000_000_000n,
};

describe('serializeFrameTransaction / computeSigHash vs. ethrex ground truth', function () {
	it("matches the hand-derived RLP envelope for ethrex's make_test_frame_tx() fixture", function () {
		const expected =
			'0x06f8dc01c1802a94000000000000000000000000000000000000abcdf854ea010394000000000000000000000000000000000000abcdc5830186a080808b7665726966795f64617461e80280940000000000000000000000000000000000001234c583030d4080808963616c6c5f64617461f85cf85a0194000000000000000000000000000000000000abcd80b8410000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cc843b9aca008506fc23ac0080c0c0';

		assert.equal(serializeFrameTransaction(tx), expected);
	});

	it('matches the hand-derived sig-hash preimage/digest, with the SECP256K1 signature bytes elided (msg is empty)', function () {
		// keccak256 of the RLP preimage below, computed once via viem
		// (not re-derived — keccak256 itself isn't the part under test;
		// the RLP structure it's hashing is).
		const expected =
			'0x28406f62a8149b424c074aa84679dc72992bff401dbcf90c671465a7f7a79139';

		assert.equal(computeSigHash(tx), expected);
	});

	it("sig hash changes when a VERIFY frame's data changes (fully covered, not elided)", function () {
		const tampered: FrameTransactionSerializable = {
			...tx,
			frames: [
				{
					...tx.frames[0]!,
					data: stringToHex('completely_different_verify_data'),
				},
				tx.frames[1]!,
			],
		};
		assert.notEqual(computeSigHash(tampered), computeSigHash(tx));
	});

	it("sig hash changes when a SENDER frame's data changes", function () {
		const tampered: FrameTransactionSerializable = {
			...tx,
			frames: [
				tx.frames[0]!,
				{
					...tx.frames[1]!,
					data: stringToHex('different_call_data'),
				},
			],
		};
		assert.notEqual(computeSigHash(tampered), computeSigHash(tx));
	});

	it("sig hash changes when a frame's state_limit changes", function () {
		const tampered: FrameTransactionSerializable = {
			...tx,
			frames: [{...tx.frames[0]!, stateLimit: 1n}, tx.frames[1]!],
		};
		assert.notEqual(computeSigHash(tampered), computeSigHash(tx));
	});

	it('keeps signature bytes (does not elide) when msg is an explicit 32-byte digest', function () {
		const explicitMsg = `0x${'ab'.repeat(32)}` as const;
		const withExplicitMsg: FrameTransactionSerializable = {
			...tx,
			signatures: [{...tx.signatures[0]!, msg: explicitMsg}],
		};
		const withDifferentSigBytes: FrameTransactionSerializable = {
			...withExplicitMsg,
			signatures: [
				{...withExplicitMsg.signatures[0]!, signature: `0x${'11'.repeat(65)}`},
			],
		};
		// Elision only applies when msg is empty — with an explicit digest,
		// the raw signature bytes are real transaction content, so changing
		// them must change the sig hash.
		assert.notEqual(
			computeSigHash(withDifferentSigBytes),
			computeSigHash(withExplicitMsg),
		);
	});
});
