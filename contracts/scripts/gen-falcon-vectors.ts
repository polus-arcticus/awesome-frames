// Generates known-answer vectors for
// src/grimoire/post-quantum/Falcon/falcon.ts (a from-scratch, verify-only
// Falcon-512 implementation) — real keypairs and real signatures from
// @noble/post-quantum's `falcon512padded` (the fixed-length-signature
// variant matching this file's Algorithm-16-literal assumption of a
// padded sbytelen), checked against this repo's own from-scratch `verify`
// before being trusted. Same "derive and verify before trusting it"
// discipline as gen-vectors.ts (BIP-340), gen-toy-curve-vectors.ts, and
// gen-ml-kem-vectors.ts.
//
// Written to test/vectors/falcon-vectors.json, read back by
// test/js/Falcon.test.ts.
//
// Run: pnpm tsx scripts/gen-falcon-vectors.ts

import {writeFileSync} from 'node:fs';
import {verify} from '../src/grimoire/post-quantum/Falcon/falcon.js';
import {falcon512padded} from '@noble/post-quantum/falcon.js';

function hex(b: Uint8Array): string {
	return '0x' + Buffer.from(b).toString('hex');
}
function fail(msg: string): never {
	console.error(msg);
	process.exit(1);
}

const {secretKey, publicKey} = falcon512padded.keygen();
console.log(`Generated a real Falcon-512 keypair (public key ${publicKey.length} bytes).`);

const MESSAGES = ['first message', 'second message', 'third message'];
const signVectors = MESSAGES.map((msg) => {
	const message = new TextEncoder().encode(msg);
	const signature = falcon512padded.sign(message, secretKey);
	if (signature.length !== 666) fail(`vector "${msg}": expected a 666-byte padded signature, got ${signature.length}`);
	if (!falcon512padded.verify(signature, message, publicKey)) fail(`vector "${msg}": noble's own verify rejected noble's own signature — should be impossible`);
	if (!verify(message, signature, publicKey)) fail(`vector "${msg}": our from-scratch verify rejected a real, noble-verified signature — the reimplementation is wrong`);
	console.log(`vector "${msg}": real Falcon-512 signature, cross-verified (noble + from-scratch).`);
	return {message: msg, signature: hex(signature)};
});

// A deliberately-invalid vector: flip one bit deep in the compressed body.
const tamperedMessage = new TextEncoder().encode(MESSAGES[0]!);
const tamperedSignature = Uint8Array.from(falcon512padded.sign(tamperedMessage, secretKey));
tamperedSignature[100] ^= 1;
if (falcon512padded.verify(tamperedSignature, tamperedMessage, publicKey)) fail('tampered vector: noble accepted a bit-flipped signature');
if (verify(tamperedMessage, tamperedSignature, publicKey)) fail('tampered vector: our from-scratch verify accepted a bit-flipped signature');
console.log('tampered vector: rejected by both noble and our from-scratch verify, as expected.');

const output = {
	scheme: 'Falcon-512 (verify only) — real keypair/signatures from @noble/post-quantum, padded encoding',
	publicKey: hex(publicKey),
	signVectors,
	invalidVector: {message: MESSAGES[0], signature: hex(tamperedSignature)},
};

console.log('\nWriting test/vectors/falcon-vectors.json ...');
writeFileSync(new URL('../test/vectors/falcon-vectors.json', import.meta.url), JSON.stringify(output, null, 2) + '\n');
console.log('Done.');
