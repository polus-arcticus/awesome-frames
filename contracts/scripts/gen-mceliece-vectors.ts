// Generates known-answer vectors for
// src/grimoire/post-quantum/ClassicMcEliece/mcEliece.ts. Unlike MlKem/
// Falcon, there's no real external McEliece library at these toy
// parameters (n=15) to cross-check against — so the verification
// discipline here matches ToyCurveECDH's instead: exhaustively test the
// actual claim (every message, fresh keypair, correctly round-trips
// through encrypt/decrypt) rather than assume it, the same "verify the
// group order by brute-force enumeration, don't assume it" move that
// file's own generator makes.
//
// Written to test/vectors/mceliece-vectors.json, read back by
// test/js/McEliece.test.ts.
//
// Run: pnpm tsx scripts/gen-mceliece-vectors.ts

import {writeFileSync} from 'node:fs';
import {keygen, encrypt, decrypt, PARAMS} from '../src/grimoire/post-quantum/ClassicMcEliece/mcEliece.js';

function fail(msg: string): never {
	console.error(msg);
	process.exit(1);
}

console.log(`Goppa code: n=${PARAMS.n}, k=${PARAMS.k}, t=${PARAMS.t}, g(x) coefficients (low-to-high) = [${PARAMS.goppaPolynomial}]`);

// Exhaustive: every one of the 2^k=128 possible messages, a FRESH keypair
// (fresh random S, P) each time, round-tripped through encrypt/decrypt.
const EXHAUSTIVE_COUNT = 1 << PARAMS.k;
for (let m = 0; m < EXHAUSTIVE_COUNT; m++) {
	const message = Array.from({length: PARAMS.k}, (_, i) => ((m >> i) & 1) as 0 | 1);
	const kp = keygen();
	const cipherText = encrypt(message, kp.publicKey);
	const recovered = decrypt(cipherText, kp.secretKey);
	if (JSON.stringify(recovered) !== JSON.stringify(message)) {
		fail(`message ${m} (${message.join('')}) did not round-trip: got ${recovered.join('')}`);
	}
}
console.log(`Exhaustive: all ${EXHAUSTIVE_COUNT} possible messages round-trip correctly, fresh keypair each time.`);

// A pinned keypair + a few pinned vectors, for fast known-answer testing
// (the exhaustive check above is what actually proves correctness; these
// vectors just pin specific values for the test suite to assert against
// without re-running the full exhaustive sweep every time).
const kp = keygen();
const MESSAGES: (0 | 1)[][] = [
	[0, 0, 0, 0, 0, 0, 0],
	[1, 1, 1, 1, 1, 1, 1],
	[1, 0, 1, 0, 1, 0, 1],
];
const vectors = MESSAGES.map((message) => {
	const cipherText = encrypt(message, kp.publicKey);
	const recovered = decrypt(cipherText, kp.secretKey);
	if (JSON.stringify(recovered) !== JSON.stringify(message)) fail(`pinned vector ${message.join('')} failed to round-trip`);
	return {message, cipherText};
});
console.log('Pinned vectors: all round-trip correctly.');

const output = {
	scheme: `Classic McEliece toy (n=${PARAMS.n}, k=${PARAMS.k}, t=${PARAMS.t}, binary Goppa code over GF(${PARAMS.fieldOrder}))`,
	goppaPolynomial: PARAMS.goppaPolynomial,
	publicKey: kp.publicKey,
	secretKey: kp.secretKey,
	vectors,
};

console.log('\nWriting test/vectors/mceliece-vectors.json ...');
writeFileSync(new URL('../test/vectors/mceliece-vectors.json', import.meta.url), JSON.stringify(output, null, 2) + '\n');
console.log('Done.');
