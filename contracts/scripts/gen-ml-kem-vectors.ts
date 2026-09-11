// Generates known-answer vectors for
// src/grimoire/post-quantum/MlKem/mlKem.ts — a from-scratch ML-KEM-512
// (FIPS 203) implementation, cross-checked byte-for-byte against
// @noble/post-quantum's `ml_kem512` (a real, audited implementation) at
// every field: encapsulation key, decapsulation key, ciphertext, shared
// secret, AND full cross-interoperability (this repo's decapsulate reading
// a noble-produced ciphertext/key, and vice versa) — not just "both round-
// trip internally," which wouldn't catch a self-consistent-but-spec-wrong
// implementation. Same "derive and verify before trusting it" discipline
// as gen-vectors.ts (BIP-340) and gen-toy-curve-vectors.ts.
//
// Written to test/vectors/ml-kem-vectors.json, read back by
// test/js/MlKem.test.ts.
//
// Run: pnpm tsx scripts/gen-ml-kem-vectors.ts

import {writeFileSync} from 'node:fs';
import {randomBytes} from 'node:crypto';
import {keygen, encapsulate, decapsulate} from '../src/grimoire/post-quantum/MlKem/mlKem.js';
import {ml_kem512} from '@noble/post-quantum/ml-kem.js';

function hex(b: Uint8Array): string {
	return '0x' + Buffer.from(b).toString('hex');
}
function fromHex(h: string): Uint8Array {
	return new Uint8Array(Buffer.from(h.slice(2), 'hex'));
}
function equal(a: Uint8Array, b: Uint8Array): boolean {
	return Buffer.from(a).equals(Buffer.from(b));
}
function fail(msg: string): never {
	console.error(msg);
	process.exit(1);
}

const DETERMINISTIC_VECTORS = 3;
const keyVectors = Array.from({length: DETERMINISTIC_VECTORS}, () => {
	const seed = randomBytes(64);
	const msgRand = randomBytes(32);

	const mine = keygen(seed);
	const theirs = ml_kem512.keygen(seed);
	if (!equal(mine.ek, theirs.publicKey)) fail(`ek mismatch for seed ${hex(seed)}`);
	if (!equal(mine.dk, theirs.secretKey)) fail(`dk mismatch for seed ${hex(seed)}`);

	const mineEnc = encapsulate(mine.ek, msgRand);
	const theirsEnc = ml_kem512.encapsulate(theirs.publicKey, msgRand);
	if (!equal(mineEnc.cipherText, theirsEnc.cipherText)) fail(`cipherText mismatch for seed ${hex(seed)}`);
	if (!equal(mineEnc.sharedSecret, theirsEnc.sharedSecret)) fail(`sharedSecret mismatch for seed ${hex(seed)}`);

	// Cross-interop, both directions.
	const crossA = decapsulate(theirsEnc.cipherText, mine.dk);
	if (!equal(crossA, theirsEnc.sharedSecret)) fail('cross-decap (mine on noble ciphertext) mismatch');
	const crossB = ml_kem512.decapsulate(mineEnc.cipherText, theirs.secretKey);
	if (!equal(crossB, mineEnc.sharedSecret)) fail('cross-decap (noble on my ciphertext) mismatch');

	console.log(`vector: keygen/encaps/decaps byte-exact + cross-interop OK (seed ${hex(seed).slice(0, 10)}...)`);

	return {
		seed: hex(seed),
		msgRand: hex(msgRand),
		ek: hex(mine.ek),
		dk: hex(mine.dk),
		cipherText: hex(mineEnc.cipherText),
		sharedSecret: hex(mineEnc.sharedSecret),
	};
});

// Implicit-rejection / decapsulation-failure vector (FIPS 203 §3.2): a
// tampered ciphertext must decapsulate to a *different*, still-32-byte
// pseudorandom value — never throw, never leak a distinguishable error —
// and that fallback value must itself match a real implementation's.
const rejectionSeed = randomBytes(64);
const rejectionMsg = randomBytes(32);
const rk = keygen(rejectionSeed);
const renc = encapsulate(rk.ek, rejectionMsg);
const tampered = Uint8Array.from(renc.cipherText);
tampered[0] ^= 1;

const myRejected = decapsulate(tampered, rk.dk);
const theirRejected = ml_kem512.decapsulate(tampered, rk.dk);
if (equal(myRejected, renc.sharedSecret)) fail('implicit-rejection vector: tampered ciphertext decapsulated to the real shared secret');
if (!equal(myRejected, theirRejected)) fail('implicit-rejection vector: my fallback value does not match a real implementation');
console.log('implicit-rejection vector: tampered ciphertext correctly falls back, matches real implementation OK');

const output = {
	scheme: 'ML-KEM-512 (FIPS 203)',
	sizes: {encapsulationKey: rk.ek.length, decapsulationKey: rk.dk.length, cipherText: renc.cipherText.length, sharedSecret: 32},
	keyVectors,
	implicitRejectionVector: {
		seed: hex(rejectionSeed),
		msgRand: hex(rejectionMsg),
		ek: hex(rk.ek),
		dk: hex(rk.dk),
		tamperedCipherText: hex(tampered),
		fallbackSharedSecret: hex(myRejected),
	},
};

console.log('\nWriting test/vectors/ml-kem-vectors.json ...');
writeFileSync(new URL('../test/vectors/ml-kem-vectors.json', import.meta.url), JSON.stringify(output, null, 2) + '\n');
console.log('Done.');
