// Generates known-answer vectors for
// src/grimoire/post-quantum/Lamport/lamport.ts, plus the reuse-forgery
// case study: two real signatures over complementary digests from one
// keypair, forged into a valid signature over a third digest that was
// never actually signed — the Lamport analogue of YoloRSA's "the
// generator actually factors it" discipline (the break is demonstrated,
// not just asserted).
//
// Written to test/vectors/lamport-vectors.json, read back by
// test/js/Lamport.test.ts.
//
// Run: pnpm tsx scripts/gen-lamport-vectors.ts

import {writeFileSync} from 'node:fs';
import {keygen, hashToDigest, sign, verify, forgeFromTwoSignatures} from '../src/grimoire/post-quantum/Lamport/lamport.js';

function hex(b: Uint8Array): string {
	return '0x' + Buffer.from(b).toString('hex');
}
function fail(msg: string): never {
	console.error(msg);
	process.exit(1);
}

const kp = keygen();
console.log(`Generated a keypair: ${kp.secretKey.zero.length * 2} total preimages (32 bit-positions).`);

const MESSAGES = ['first message', 'second message', 'third message'];
const signVectors = MESSAGES.map((msg) => {
	const digest = hashToDigest(new TextEncoder().encode(msg));
	const signature = sign(digest, kp.secretKey);
	if (!verify(digest, signature, kp.publicKey)) fail(`freshly-generated signature over "${msg}" failed to verify`);
	return {message: msg, digest: hex(digest), signature: signature.map(hex)};
});
console.log('sign vectors: all verify OK.');

// Tampered vector: flip one bit of the digest, signature must be rejected.
const invalidDigest = Uint8Array.from(hashToDigest(new TextEncoder().encode(MESSAGES[0]!)));
invalidDigest[0]! ^= 1;
const invalidSignature = sign(hashToDigest(new TextEncoder().encode(MESSAGES[0]!)), kp.secretKey);
if (verify(invalidDigest, invalidSignature, kp.publicKey)) fail('tampered digest incorrectly verified');
console.log('invalid vector: correctly rejected.');

// The forgery: sign a digest and its bitwise complement (guaranteeing full
// preimage coverage across all 32 bit positions), then forge a signature
// over a THIRD digest that was never signed.
const baseDigest = hashToDigest(new TextEncoder().encode('the legitimate spend'));
const complementDigest = Uint8Array.from(baseDigest.map((b) => b ^ 0xff));
const baseSig = sign(baseDigest, kp.secretKey);
const complementSig = sign(complementDigest, kp.secretKey);
if (!verify(baseDigest, baseSig, kp.publicKey)) fail('base forgery-setup signature failed to verify');
if (!verify(complementDigest, complementSig, kp.publicKey)) fail('complement forgery-setup signature failed to verify');

const targetDigest = hashToDigest(new TextEncoder().encode('a message the real owner never signed'));
const forgedSignature = forgeFromTwoSignatures(baseDigest, baseSig, complementDigest, complementSig, targetDigest);
if (!verify(targetDigest, forgedSignature, kp.publicKey)) fail('forged signature did not verify — the break demo is broken');
console.log('forgery vector: a signature over a NEVER-SIGNED digest verifies successfully. The break is real.');

const output = {
	scheme: 'Lamport one-time signatures (toy: 32-bit digest, real 32-byte preimages, real keccak256)',
	nBits: 32,
	publicKey: {zero: kp.publicKey.zero.map(hex), one: kp.publicKey.one.map(hex)},
	signVectors,
	invalidVector: {digest: hex(invalidDigest), signature: invalidSignature.map(hex)},
	forgeryVector: {
		baseDigest: hex(baseDigest),
		baseSignature: baseSig.map(hex),
		complementDigest: hex(complementDigest),
		complementSignature: complementSig.map(hex),
		targetDigest: hex(targetDigest),
		forgedSignature: forgedSignature.map(hex),
	},
};

console.log('\nWriting test/vectors/lamport-vectors.json ...');
writeFileSync(new URL('../test/vectors/lamport-vectors.json', import.meta.url), JSON.stringify(output, null, 2) + '\n');
console.log('Done.');
