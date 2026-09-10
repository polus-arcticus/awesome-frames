// Generates known-answer vectors for
// src/grimoire/YoloRSA/YoloRSAWideAccount.yul — the 2-word (up to 512-bit)
// sibling of YoloRSAAccount.yul. Reuses YoloRSA's own keygen/sign/verify
// (test/js/utils/yoloRSA.ts) unchanged, since the RSA math itself doesn't
// care how many EVM words the modulus spans — only test/js/utils/bigWord.ts
// (splitWords/joinWords) differs, matching exactly how
// YoloRSAWideAccount.yul's calldata/storage layout widens
// YoloRSAAccount.yul's. Written to test/vectors/yolo-rsa-wide-vectors.json,
// read back by test/js/YoloRSAWide.test.ts.
//
// Tier bit-sizes come from the GNFS-cost-function estimate worked out in
// conversation (GNFS L_n[1/3, 1.923], anchored to RSA-768's published 2009
// sieving effort of ~2000 core-years, scaled to one Ethereum-validator-spec
// machine — ethereum.org's 8-core "recommended" CPU guidance — assuming a
// 10x combined hardware+tooling speedup from 2009 to now): ~384 bits for a
// ~10-minute factor, ~424 bits for ~1 hour. Both estimates, not
// measurements — see YoloRSAWideAccount.yul's header.
//
// IMPORTANT: same rule as gen-yolo-rsa-vectors.ts — these keypairs are TEST
// FIXTURES ONLY, fine to commit. A real deployed wallet using this template
// must generate its own keypair locally, with `d` never written to any
// committed file.
//
// Run: pnpm tsx scripts/gen-yolo-rsa-wide-vectors.ts

import {writeFileSync} from 'node:fs';
import {generateKeypair, sign, verify, messageRepresentative} from '../test/js/utils/yoloRSA.js';
import {splitWords} from '../test/js/utils/bigWord.js';

const TIERS = [
	{name: 'ten-minute', bits: 384},
	{name: 'one-hour', bits: 424},
] as const;

const MESSAGE_HASHES = [BigInt('0x' + '11'.repeat(32)), BigInt('0x' + 'deadbeef'.repeat(8)), 0n] as const;

function word(x: bigint) {
	return x.toString();
}

const tierVectors = TIERS.map(({name, bits}) => {
	const kp = generateKeypair(bits);
	console.log(`${name}: n=${kp.n} (${kp.n.toString(2).length} bits) = ${kp.p} * ${kp.q}, e=${kp.e}`);

	// The whole point of a 2-word modulus, per the account's header: n must
	// genuinely exceed 2^256 (a nonzero high word), which is what lets
	// "msgHash mod n" collapse to msgHash unchanged. Confirm both here.
	const [nHigh, nLow] = splitWords(kp.n, 2);
	if (nHigh === 0n) {
		console.error(`${name}: n=${kp.n} does not exceed 2^256 — bits too small for this template, use YoloRSA instead.`);
		process.exit(1);
	}
	for (const msgHash of MESSAGE_HASHES) {
		if (messageRepresentative(msgHash, kp.n) !== msgHash) {
			console.error(`${name}: messageRepresentative(msgHash, n) !== msgHash — the Yul simplification does not hold.`);
			process.exit(1);
		}
	}

	const signVectors = MESSAGE_HASHES.map((msgHash) => {
		const signature = sign(msgHash, kp.d, kp.n);
		if (!verify(msgHash, signature, kp.e, kp.n)) {
			console.error(`${name}: freshly-generated signature failed to verify — the math is broken.`);
			process.exit(1);
		}
		const [sHigh, sLow] = splitWords(signature, 2);
		return {msgHash: word(msgHash), sHigh: word(sHigh), sLow: word(sLow)};
	});

	const badSignature = (sign(MESSAGE_HASHES[0], kp.d, kp.n) + 1n) % kp.n;
	const [badHigh, badLow] = splitWords(badSignature, 2);

	return {
		name,
		bits,
		e: word(kp.e),
		nHigh: word(nHigh),
		nLow: word(nLow),
		signVectors,
		invalidVector: {msgHash: word(MESSAGE_HASHES[0]), sHigh: word(badHigh), sLow: word(badLow)},
	};
});

console.log('\nWriting test/vectors/yolo-rsa-wide-vectors.json ...');
writeFileSync(
	new URL('../test/vectors/yolo-rsa-wide-vectors.json', import.meta.url),
	JSON.stringify({tiers: tierVectors}, null, 2) + '\n',
);
console.log('Done.');
