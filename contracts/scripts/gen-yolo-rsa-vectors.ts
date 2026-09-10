// Generates known-answer sign/verify vectors for src/YoloRSA/YoloRSA.sol
// and src/grimoire/YoloRSA/YoloRSAAccount.yul, across the yolo-wallet
// difficulty ladder. Written to test/vectors/yolo-rsa-vectors.json, read
// back by test/js/YoloRSA.test.ts. Same "derive and verify before trusting
// the Solidity/Yul" discipline as gen-toy-curve-vectors.ts.
//
// IMPORTANT: the keypairs generated here are TEST FIXTURES ONLY — fine to
// commit because their entire purpose is checking the verify math is
// correct, not staying secret. A real public yolo-wallet deployment (with
// real testnet ETH inside) must generate its own keypair locally, with the
// private exponent `d` never written to any file that gets committed —
// that's a separate deploy flow, not this script.
//
// Run: pnpm tsx scripts/gen-yolo-rsa-vectors.ts

import {writeFileSync} from 'node:fs';
import {
	generateKeypair,
	sign,
	verify,
	factor,
	crackPrivateExponent,
	messageRepresentative,
} from '../test/js/utils/yoloRSA.js';

// Bit-size-to-difficulty reasoning (balanced p, q each ~half the total
// bits, since that's the worst case for an attacker relative to n's size):
//  - trial division stays well under a second up to a smallest factor
//    around 2^21-2^25 or so -> total n up to roughly 45-50 bits.
//  - naive Pollard's rho costs ~O(sqrt(smallest factor)) ~ 2^(bits/4) for
//    balanced n -> stays a sub-second-to-low-minutes naive script up to
//    roughly 90-110 bits.
//  - beyond that, only a real general-purpose factoring tool (SIQS via
//    YAFU/msieve, or GNFS at the largest sizes) makes progress in
//    reasonable time; a few hundred bits is squarely "needs a real tool
//    and a consumer CPU core, genuine patience" territory — hence
//    weekend-project sitting as high as the protocol allows, not 80-90
//    bits (an earlier, unverified guess in conversation undersold this
//    tier by roughly 3x).
//
// weekend-project is capped at 248, not pushed closer to 300+: `n` has to
// fit in a single EVM word (everything here — storage, calldata, MODEXP
// inputs — is one 32-byte word), so 256 bits is a hard ceiling, not just a
// target. 248 leaves an 8-bit margin below that ceiling.
const TIERS = [
	{name: 'pencil', bits: 12},
	{name: 'calculator', bits: 24},
	{name: 'script-kiddie', bits: 48},
	{name: 'laptop', bits: 80},
	{name: 'weekend-project', bits: 248},
] as const;

// Stand-ins for a real compute_sig_hash(tx) output, which is always a full
// 32-byte word regardless of how small the modulus is — exactly why the
// message representative has to reduce mod n (see YoloRSA.sol's header).
const MESSAGE_HASHES = [BigInt('0x' + '11'.repeat(32)), BigInt('0x' + 'deadbeef'.repeat(8)), 0n] as const;

const tierVectors = TIERS.map(({name, bits}) => {
	const kp = generateKeypair(bits);
	console.log(`${name}: n=${kp.n} (${kp.n.toString(2).length} bits) = ${kp.p} * ${kp.q}, e=${kp.e}`);

	// Sanity-check every tier up through "laptop" is actually crackable by
	// the bundled factor() helper — if it isn't, the tier's bit size (or
	// bad luck in prime selection) made it accidentally too strong.
	// "weekend-project" is deliberately excluded: it's meant to be beyond
	// what a naive from-scratch script can do in reasonable time, not just
	// beyond what this script bothers to wait for — that's the whole point
	// of that tier.
	if (name !== 'weekend-project') {
		const {p, q} = factor(kp.n);
		const matches = (p === kp.p && q === kp.q) || (p === kp.q && q === kp.p);
		if (!matches) {
			console.error(`${name}: factor() recovered the wrong factors for n=${kp.n}.`);
			process.exit(1);
		}
		const recoveredD = crackPrivateExponent(p, q, kp.e);
		if (recoveredD !== kp.d) {
			console.error(`${name}: recovered private exponent does not match.`);
			process.exit(1);
		}
		console.log(`  -> cracked by the bundled factor() helper, as expected.`);
	}

	const signVectors = MESSAGE_HASHES.map((msgHash) => {
		const signature = sign(msgHash, kp.d, kp.n);
		if (!verify(msgHash, signature, kp.e, kp.n)) {
			console.error(`${name}: freshly-generated signature failed to verify — the math is broken.`);
			process.exit(1);
		}
		return {
			msgHash: msgHash.toString(),
			signature: signature.toString(),
			messageRepresentative: messageRepresentative(msgHash, kp.n).toString(),
		};
	});

	// One deliberately-invalid vector per tier (signature off by one) —
	// checks the contract actually rejects a bad signature, not just
	// accepts a good one.
	const badSignature = (sign(MESSAGE_HASHES[0], kp.d, kp.n) + 1n) % kp.n;

	return {
		name,
		bits,
		n: kp.n.toString(),
		e: kp.e.toString(),
		signVectors,
		invalidVector: {msgHash: MESSAGE_HASHES[0].toString(), signature: badSignature.toString()},
	};
});

console.log('\nWriting test/vectors/yolo-rsa-vectors.json ...');
writeFileSync(
	new URL('../test/vectors/yolo-rsa-vectors.json', import.meta.url),
	JSON.stringify({tiers: tierVectors}, null, 2) + '\n',
);
console.log('Done.');
