// Brute-force-enumerates src/grimoire/ToyCurveECDH/ToyCurveECDH.yul's toy
// curve, verifies its group order rather than assuming it, and generates
// known-answer vectors for point addition/doubling/scalar-multiplication
// and a full two-party ECDH exchange — written to
// test/vectors/toy-curve-vectors.json, read back by
// test/js/ToyCurveECDH.test.ts. Same "derive and verify before trusting
// the Yul" discipline scripts/gen-vectors.ts already applies to BIP-340.
//
// Run: pnpm tsx scripts/gen-toy-curve-vectors.ts

import {writeFileSync} from 'node:fs';
import {
	P,
	A,
	B,
	N,
	G,
	enumeratePoints,
	add,
	tangentDouble,
	multiply,
	generate,
	unite,
	toWire,
	type AffinePoint,
} from '../test/js/utils/toyCurve.js';

function pt(p: AffinePoint) {
	return {x: p.x.toString(), y: p.y.toString()};
}

// --- Verify the group order rather than assume it ---
const points = enumeratePoints();
const order = BigInt(points.length) + 1n /* + the point at infinity */;
console.log(`E: y^2 = x^3 + ${A}x + ${B} (mod ${P})`);
console.log(`Enumerated ${points.length} affine points -> group order ${order}.`);
if (order !== N) {
	console.error(`Expected order ${N}, got ${order}. The curve constants are wrong — stop.`);
	process.exit(1);
}
console.log(`Order ${N} is prime: every non-identity point generates the whole group.`);
console.log(`Base point G = (${G.x}, ${G.y}).\n`);

// A generator's own scalar multiples should retrace the full group and
// land back on O at exactly N*G — the cheapest possible sanity check that
// `multiply`/`add` are internally consistent before they're trusted to
// produce vectors.
let cur = G as AffinePoint | null;
for (let k = 2n; k < N; k++) {
	cur = add(cur, G);
	if (cur === null) {
		console.error(`G returned to O after only ${k} additions, expected order ${N}.`);
		process.exit(1);
	}
}
cur = add(cur, G);
if (cur !== null) {
	console.error(`N*G did not return to O.`);
	process.exit(1);
}
console.log(`Confirmed ord(G) = ${N} by direct summation.\n`);

// --- Point addition (chord) vectors: any two distinct points ---
const chordAddVectors = [
	{p1: points[0]!, p2: points[2]!},
	{p1: points[4]!, p2: points[9]!},
	{p1: G, p2: points[7]!},
].map(({p1, p2}) => ({
	p1: pt(p1),
	p2: pt(p2),
	expected: pt(toWire(add(p1, p2))),
}));

// --- Point doubling (tangent) vectors ---
const tangentDoubleVectors = [points[0]!, points[3]!, G].map((p) => ({
	p: pt(p),
	expected: pt(toWire(tangentDouble(p))),
}));

// --- Scalar multiplication vectors, including the edges (0, N, N+1) ---
const scalarMultiplyVectors = [0n, 1n, 2n, 3n, 7n, 18n, 19n, 20n].map((k) => ({
	k: k.toString(),
	p: pt(G),
	expected: pt(toWire(multiply(k, G))),
}));

// --- A full two-party ECDH exchange ---
const alicePriv = 6n;
const bobPriv = 15n;
const alicePublic = generate(alicePriv)!;
const bobPublic = generate(bobPriv)!;
const aliceShared = unite(alicePriv, bobPublic)!;
const bobShared = unite(bobPriv, alicePublic)!;
if (aliceShared.x !== bobShared.x || aliceShared.y !== bobShared.y) {
	console.error('Alice and Bob did not arrive at the same shared point — the exchange is broken.');
	process.exit(1);
}
console.log(
	`Alice (priv=${alicePriv}) and Bob (priv=${bobPriv}) independently united at (${aliceShared.x}, ${aliceShared.y}).\n`,
);
const ecdhVector = {
	alicePriv: alicePriv.toString(),
	bobPriv: bobPriv.toString(),
	alicePublic: pt(alicePublic),
	bobPublic: pt(bobPublic),
	sharedSecret: pt(aliceShared),
};

const output = {
	curve: {p: P.toString(), a: A.toString(), b: B.toString(), n: N.toString(), g: pt(G)},
	allPoints: points.map(pt),
	chordAdd: chordAddVectors,
	tangentDouble: tangentDoubleVectors,
	scalarMultiply: scalarMultiplyVectors,
	ecdh: ecdhVector,
};

console.log('Writing test/vectors/toy-curve-vectors.json ...');
writeFileSync(
	new URL('../test/vectors/toy-curve-vectors.json', import.meta.url),
	JSON.stringify(output, null, 2) + '\n',
);
console.log('Done.');
