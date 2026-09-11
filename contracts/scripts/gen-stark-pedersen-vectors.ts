// Generates known-answer vectors for
// src/grimoire/StarkPedersen/StarkPedersen.yul, derived from the JS/bigint
// mirror in test/js/utils/starkPedersen.ts and cross-checked at generation
// time two independent ways before anything gets pinned:
//   1. every `pedersen(x, y)` vector is checked byte-for-byte against
//      `@scure/starknet`'s own `pedersen()` — real, audited ground truth,
//      the same role @noble/curves already plays for BIP-340 elsewhere in
//      this repo;
//   2. every point-arithmetic vector (chord addition, tangent doubling) is
//      checked against the curve equation itself via `isOnCurve` — an
//      independent check, since it uses StarkWare's published `b`
//      constant, which the addition/doubling formulas never touch.
// Same "derive, verify against ground truth, then pin" discipline as
// gen-ml-kem-vectors.ts and gen-toy-curve-vectors.ts.
//
// Written to test/vectors/stark-pedersen-vectors.json, read back by
// test/js/StarkPedersen.test.ts.
//
// Run: pnpm tsx scripts/gen-stark-pedersen-vectors.ts

import {writeFileSync} from 'node:fs';
import {pedersen as scurePedersen} from '@scure/starknet';
import {
	P,
	A,
	B,
	SHIFT_POINT,
	P0,
	P1,
	P2,
	P3,
	isOnCurve,
	chordAdd,
	tangentDouble,
	pedersen,
	type AffinePoint,
} from '../test/js/utils/starkPedersen.js';

function pt(p: AffinePoint) {
	return {x: p.x.toString(), y: p.y.toString()};
}
function fail(msg: string): never {
	console.error(msg);
	process.exit(1);
}

console.log(`Curve: y^2 = x^3 + ${A}x + b (mod p), p = 2^251 + 17*2^192 + 1`);
console.log(`p = ${P}`);

// --- Verify every published constant is actually on the curve ---
for (const [name, p] of Object.entries({SHIFT_POINT, P0, P1, P2, P3})) {
	if (!isOnCurve(p)) fail(`${name} = (${p.x}, ${p.y}) is NOT on the curve — constants are wrong, stop.`);
}
console.log('All five "nothing up my sleeve" generator points verified on-curve.\n');

// --- Point arithmetic vectors: chord addition ---
const doubledP0 = tangentDouble(P0);
const doubledP1 = tangentDouble(P1);
const chordAddVectors = [
	{p1: P0, p2: P1},
	{p1: SHIFT_POINT, p2: P2},
	{p1: doubledP0, p2: P3},
].map(({p1, p2}) => {
	const expected = chordAdd(p1, p2);
	if (!isOnCurve(expected)) fail(`chordAdd(${pt(p1).x}, ${pt(p2).x}) produced an off-curve point.`);
	return {p1: pt(p1), p2: pt(p2), expected: pt(expected)};
});

// --- Point arithmetic vectors: tangent doubling ---
const tangentDoubleVectors = [P0, P1, SHIFT_POINT].map((p) => {
	const expected = tangentDouble(p);
	if (!isOnCurve(expected)) fail(`tangentDouble(${pt(p).x}) produced an off-curve point.`);
	return {p: pt(p), expected: pt(expected)};
});
console.log(`Verified ${chordAddVectors.length} chord-addition and ${tangentDoubleVectors.length} tangent-doubling vectors land back on-curve.\n`);
void doubledP1; // computed for parity with doubledP0 above, not separately pinned

// --- Full pedersen(x, y) vectors, cross-checked against @scure/starknet ---
const pedersenCases: [bigint, bigint][] = [
	[0n, 0n],
	[1n, 2n],
	[123456789n, 987654321n],
	[P - 1n, (P - 1n) / 2n], // both inputs near the top of the field
	[2n ** 251n - 1n, 2n ** 250n], // exercises the 248-low/4-high bit split boundary
];
const pedersenVectors = pedersenCases.map(([x, y]) => {
	const mine = pedersen(x, y);
	const theirs = BigInt(scurePedersen(x, y));
	if (mine !== theirs) {
		fail(`pedersen(${x}, ${y}): mine=${mine} theirs(@scure/starknet)=${theirs} — MISMATCH, stop.`);
	}
	return {x: x.toString(), y: y.toString(), expected: mine.toString()};
});
console.log(`Verified ${pedersenVectors.length} pedersen(x, y) vectors against @scure/starknet, all match.\n`);

const output = {
	curve: {p: P.toString(), a: A.toString(), b: B.toString()},
	points: {shift: pt(SHIFT_POINT), p0: pt(P0), p1: pt(P1), p2: pt(P2), p3: pt(P3)},
	chordAdd: chordAddVectors,
	tangentDouble: tangentDoubleVectors,
	pedersen: pedersenVectors,
};

console.log('Writing test/vectors/stark-pedersen-vectors.json ...');
writeFileSync(
	new URL('../test/vectors/stark-pedersen-vectors.json', import.meta.url),
	JSON.stringify(output, null, 2) + '\n',
);
console.log('Done.');
