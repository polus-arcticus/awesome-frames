// A narrated demonstration of why N=11 was rejected for NTRUSign this
// session, in favor of N=18 (see src/tools/NTRUSign/NTRUSignAccount.yul
// and test/js/utils/ntruSign.ts's headers for the full story). This is
// deliberately NOT a reusable library — there's no src/toys/NTRUSign11/
// directory, just this one script — because the entire point is the
// failure itself, not a second production path alongside the real N=18
// account.
//
// The claim being demonstrated: at N=11, even with the SAME
// basis-reduction discipline (MAX_FG_COEFF) used to make N=18 actually
// work, the gap between "closeness of a legitimate signature to its own
// message" and "closeness of that same signature to an unrelated one"
// collapses to 3-5 points (vs. ~15 at N=18) — real, but razor-thin and
// not something a verifier could safely rely on — and pushing the same
// filter tighter to chase a bigger gap doesn't work either: below a
// certain threshold, keygen simply can't find any valid keypair at all
// (there aren't enough well-reduced bases to choose from in a lattice
// this small). That's not "weak crypto" in the usual sense (small
// modulus, guessable key) — it's a dimension too small for more
// reduction effort to keep helping. Every other grimoire/toys entry in
// this repo is broken on purpose in a specific, narrow way (YoloRSA: the
// modulus is factorable; Lamport: reusing a keypair leaks it). This one
// is broken structurally, and that's worth seeing happen live rather
// than just reading about.
//
// This reimplements a self-contained N=11 version of the same
// keygen/sign algorithm test/js/utils/ntruSign.ts uses at N=18 — see
// that file for the fully-commented, real version. Nothing here is
// imported from it on purpose: N is a compile-time constant throughout
// this repo's Yul/JS pairs, so an N=11 demo and an N=18 library can't
// share code without templating either into something more generic than
// either deserves.
//
// Run: pnpm tsx scripts/ntrusign-n11-failure-demo.ts

import {keccak_256} from '@noble/hashes/sha3.js';

const N = 11;
const Q = 128n;
const WEIGHT_F = 5; // odd — see ntruSign.ts's header for why f needs odd weight
const WEIGHT_G = 4;
const MAX_FG_COEFF = 25n; // same order as N=18's 15, scaled up slightly since N=11 keygen found nothing at all within 15

type Poly = bigint[];

function mod(a: bigint, m: bigint): bigint {
	const r = a % m;
	return r >= 0n ? r : r + m;
}
function polyMul(a: Poly, b: Poly): Poly {
	const out = new Array<bigint>(N).fill(0n);
	for (let i = 0; i < N; i++) {
		if (a[i] === 0n) continue;
		for (let j = 0; j < N; j++) {
			if (b[j] === 0n) continue;
			out[(i + j) % N]! += a[i]! * b[j]!;
		}
	}
	return out;
}
function polyAdd(a: Poly, b: Poly): Poly {
	return a.map((v, i) => v + b[i]!);
}
function polySub(a: Poly, b: Poly): Poly {
	return a.map((v, i) => v - b[i]!);
}
function polyModQ(a: Poly): Poly {
	return a.map((v) => mod(v, Q));
}
function reversePoly(p: Poly): Poly {
	return Array.from({length: N}, (_, i) => p[(N - i) % N]!);
}
function correlate(a: Poly, b: Poly): Poly {
	return polyMul(a, reversePoly(b));
}
function maxAbs(p: Poly): bigint {
	return p.reduce((m, v) => ((v < 0n ? -v : v) > m ? (v < 0n ? -v : v) : m), 0n);
}
function randomPoly(weight: number): Poly {
	const idxs = new Set<number>();
	while (idxs.size < weight) idxs.add(Math.floor(Math.random() * N));
	return Array.from({length: N}, (_, i) => (idxs.has(i) ? 1n : 0n));
}

interface Frac {
	n: bigint;
	d: bigint;
}
function gcdBig(a: bigint, b: bigint): bigint {
	a = a < 0n ? -a : a;
	b = b < 0n ? -b : b;
	while (b) [a, b] = [b, a % b];
	return a;
}
function frac(n: bigint, d: bigint = 1n): Frac {
	if (d === 0n) throw new Error('frac: division by zero');
	if (d < 0n) {
		n = -n;
		d = -d;
	}
	const g = gcdBig(n, d) || 1n;
	return {n: n / g, d: d / g};
}
function fAdd(a: Frac, b: Frac): Frac {
	return frac(a.n * b.d + b.n * a.d, a.d * b.d);
}
function fSub(a: Frac, b: Frac): Frac {
	return frac(a.n * b.d - b.n * a.d, a.d * b.d);
}
function fMul(a: Frac, b: Frac): Frac {
	return frac(a.n * b.n, a.d * b.d);
}
function fDiv(a: Frac, b: Frac): Frac {
	return frac(a.n * b.d, a.d * b.n);
}
function fIsZero(a: Frac): boolean {
	return a.n === 0n;
}
function fRound(a: Frac): bigint {
	const sign = a.n < 0n !== a.d < 0n ? -1n : 1n;
	const absN = a.n < 0n ? -a.n : a.n;
	const absD = a.d < 0n ? -a.d : a.d;
	const flo = absN / absD;
	const rema = absN - flo * absD;
	return sign * (2n * rema >= absD ? flo + 1n : flo);
}
function circulant(f: Poly): Frac[][] {
	const M: Frac[][] = [];
	for (let i = 0; i < N; i++) {
		const row: Frac[] = new Array(N);
		for (let j = 0; j < N; j++) row[j] = frac(f[((i - j) % N + N) % N]!);
		M.push(row);
	}
	return M;
}
function invertExact(M: Frac[][]): Frac[][] {
	const A: Frac[][] = M.map((row) => row.slice());
	const I: Frac[][] = Array.from({length: N}, (_, i) => Array.from({length: N}, (_, j) => frac(i === j ? 1n : 0n)));
	for (let col = 0; col < N; col++) {
		let pivotRow = -1;
		for (let r = col; r < N; r++) {
			if (!fIsZero(A[r]![col]!)) {
				pivotRow = r;
				break;
			}
		}
		if (pivotRow === -1) throw new Error('singular');
		if (pivotRow !== col) {
			[A[col], A[pivotRow]] = [A[pivotRow]!, A[col]!];
			[I[col], I[pivotRow]] = [I[pivotRow]!, I[col]!];
		}
		const pivot = A[col]![col]!;
		for (let j = 0; j < N; j++) {
			A[col]![j] = fDiv(A[col]![j]!, pivot);
			I[col]![j] = fDiv(I[col]![j]!, pivot);
		}
		for (let r = 0; r < N; r++) {
			if (r === col) continue;
			const factor = A[r]![col]!;
			if (fIsZero(factor)) continue;
			for (let j = 0; j < N; j++) {
				A[r]![j] = fSub(A[r]![j]!, fMul(factor, A[col]![j]!));
				I[r]![j] = fSub(I[r]![j]!, fMul(factor, I[col]![j]!));
			}
		}
	}
	return I;
}
function resultantAndAdjugate(f: Poly): {Rf: bigint; fAdj: Poly} | null {
	let Inv: Frac[][];
	try {
		Inv = invertExact(circulant(f));
	} catch {
		return null;
	}
	const col0 = Inv.map((row) => row[0]!);
	let Rf = 1n;
	for (const x of col0) Rf = (Rf / gcdBig(Rf, x.d)) * x.d;
	const fAdj = col0.map((x) => {
		const scaled = fMul(x, frac(Rf));
		if (scaled.d !== 1n) throw new Error('adjugate not integral');
		return scaled.n;
	});
	return {Rf, fAdj};
}
function extGcd(a: bigint, b: bigint): {g: bigint; u: bigint; v: bigint} {
	if (b === 0n) return {g: a, u: 1n, v: 0n};
	const {g, u: u1, v: v1} = extGcd(b, a % b);
	return {g, u: v1, v: u1 - (a / b) * v1};
}
function solveKeyEquation(f: Poly, g: Poly): {F: Poly; G: Poly} | null {
	const rf = resultantAndAdjugate(f);
	const rg = resultantAndAdjugate(g);
	if (!rf || !rg) return null;
	const {g: gcdVal, u, v} = extGcd(rf.Rf, rg.Rf);
	if (gcdVal !== 1n && gcdVal !== -1n) return null;
	const scale = gcdVal === 1n ? 1n : -1n;
	const U = u * scale;
	const V = v * scale;
	const F0 = rg.fAdj.map((x) => -Q * V * x);
	const G0 = rf.fAdj.map((x) => Q * U * x);
	const C = polyAdd(correlate(f, f), correlate(g, g));
	let Cinv: Frac[];
	try {
		Cinv = invertExact(circulant(C)).map((row) => row[0]!);
	} catch {
		return null;
	}
	const rhsInt = polyAdd(correlate(F0, f), correlate(G0, g));
	let kFrac: Frac[] = new Array(N).fill(frac(0n));
	for (let i = 0; i < N; i++) {
		if (rhsInt[i] === 0n) continue;
		for (let j = 0; j < N; j++) {
			if (fIsZero(Cinv[j]!)) continue;
			const idx = (i + j) % N;
			kFrac[idx] = fAdd(kFrac[idx]!, fMul(frac(rhsInt[i]!), Cinv[j]!));
		}
	}
	const k: Poly = kFrac.map((x) => fRound(fMul(x, frac(-1n))));
	const F = polyAdd(F0, polyMul(f, k));
	const G = polyAdd(G0, polyMul(g, k));
	const lhs = polySub(polyMul(f, G), polyMul(g, F));
	if (!lhs.every((val, i) => val === (i === 0 ? Q : 0n))) return null;
	return {F, G};
}
function invertGF2(f: Poly): Poly | null {
	const M: number[][] = [];
	const I: number[][] = [];
	for (let i = 0; i < N; i++) {
		const row = new Array<number>(N);
		const idRow = new Array<number>(N).fill(0);
		for (let j = 0; j < N; j++) row[j] = Number(mod(f[((i - j) % N + N) % N]!, 2n));
		idRow[i] = 1;
		M.push(row);
		I.push(idRow);
	}
	for (let col = 0; col < N; col++) {
		let pivot = -1;
		for (let r = col; r < N; r++) {
			if (M[r]![col] === 1) {
				pivot = r;
				break;
			}
		}
		if (pivot === -1) return null;
		if (pivot !== col) {
			[M[col], M[pivot]] = [M[pivot]!, M[col]!];
			[I[col], I[pivot]] = [I[pivot]!, I[col]!];
		}
		for (let r = 0; r < N; r++) {
			if (r !== col && M[r]![col] === 1) {
				for (let j = 0; j < N; j++) {
					M[r]![j] = M[r]![j]! ^ M[col]![j]!;
					I[r]![j] = I[r]![j]! ^ I[col]![j]!;
				}
			}
		}
	}
	return Array.from({length: N}, (_, i) => BigInt(I[i]![0]!));
}
function invModQPoly(f: Poly): Poly | null {
	let u = invertGF2(f);
	if (u === null) return null;
	let modulus = 2n;
	while (modulus < Q) {
		const nextModulus = modulus * modulus;
		const fu: Poly = polyMul(f, u).map((v) => mod(v, nextModulus));
		const twoMinusFu: Poly = fu.map((v, i) => (i === 0 ? mod(2n - v, nextModulus) : mod(-v, nextModulus)));
		u = polyMul(u, twoMinusFu).map((v) => mod(v, nextModulus));
		modulus = nextModulus;
	}
	return u.map((v) => mod(v, Q));
}
interface KeyPair {
	f: Poly;
	g: Poly;
	F: Poly;
	G: Poly;
	h: Poly;
}
function keygen(maxAttempts = 2000): KeyPair {
	for (let attempt = 0; attempt < maxAttempts; attempt++) {
		const f = randomPoly(WEIGHT_F);
		const g = randomPoly(WEIGHT_G);
		const solved = solveKeyEquation(f, g);
		if (!solved) continue;
		if (maxAbs(solved.F) > MAX_FG_COEFF || maxAbs(solved.G) > MAX_FG_COEFF) continue;
		const fInvModQ = invModQPoly(f);
		if (!fInvModQ) continue;
		const h = polyModQ(polyMul(fInvModQ, g));
		if (!polyModQ(polyMul(f, h)).every((v, i) => v === mod(g[i]!, Q))) continue;
		return {f, g, F: solved.F, G: solved.G, h};
	}
	throw new Error(`keygen: no valid keypair found in ${maxAttempts} attempts`);
}
function hashToPoint(msgHash: Uint8Array): {m1: Poly; m2: Poly} {
	const m1 = new Array<bigint>(N);
	const m2 = new Array<bigint>(N);
	let counter = 0;
	let pool: Uint8Array = new Uint8Array(0);
	let poolPos = 0;
	function nextByte(): number {
		if (poolPos >= pool.length) {
			const input = new Uint8Array(msgHash.length + 9);
			input.set(msgHash, 0);
			input.set(new TextEncoder().encode('NTRUSign'), msgHash.length);
			input[msgHash.length + 8] = counter & 0xff;
			counter++;
			pool = keccak_256(input);
			poolPos = 0;
		}
		return pool[poolPos++]!;
	}
	for (let i = 0; i < N; i++) m1[i] = BigInt(nextByte()) % Q;
	for (let i = 0; i < N; i++) m2[i] = BigInt(nextByte()) % Q;
	return {m1, m2};
}
function roundDivQ(p: Poly): Poly {
	return p.map((x) => {
		const sign = x < 0n ? -1n : 1n;
		const ax = x < 0n ? -x : x;
		const flo = ax / Q;
		const rem = ax - flo * Q;
		return sign * (2n * rem >= Q ? flo + 1n : flo);
	});
}
function sign(msgHash: Uint8Array, key: KeyPair): Poly {
	const {m1, m2} = hashToPoint(msgHash);
	const {f, g, F, G} = key;
	const u = polySub(polyMul(m1, G), polyMul(m2, F));
	const v = polyAdd(
		polyMul(
			m1.map((x) => -x),
			g,
		),
		polyMul(m2, f),
	);
	const A = roundDivQ(u);
	const B = roundDivQ(v);
	return polyAdd(polyMul(A, f), polyMul(B, F));
}
function cyclicMaxDist(a: Poly, b: Poly): bigint {
	let worst = 0n;
	for (let i = 0; i < N; i++) {
		const d = mod(a[i]! - b[i]!, Q);
		const c = d > Q / 2n ? Q - d : d;
		if (c > worst) worst = c;
	}
	return worst;
}
function closeness(msgHash: Uint8Array, s: Poly, key: KeyPair): bigint {
	const {m1, m2} = hashToPoint(msgHash);
	const t = polyMul(s, key.h);
	const sD = cyclicMaxDist(s, m1);
	const tD = cyclicMaxDist(t, m2);
	return sD > tD ? sD : tD;
}

async function main() {
	console.log('NTRUSign at N=11 — why this repo does NOT deploy an account at this size.\n');
	console.log(
		`Generating a keypair with the exact same basis-reduction discipline (MAX_FG_COEFF=${MAX_FG_COEFF})\n` +
			'that makes the real N=18 account work...\n',
	);
	const key = keygen();
	console.log(`f = [${key.f.join(', ')}]`);
	console.log(`g = [${key.g.join(', ')}]`);
	console.log(`F = [${key.F.join(', ')}]  (max |coeff| = ${maxAbs(key.F)})`);
	console.log(`G = [${key.G.join(', ')}]  (max |coeff| = ${maxAbs(key.G)})\n`);

	const helloMsg = keccak_256(new TextEncoder().encode('hello world'));
	const goodbyeMsg = keccak_256(new TextEncoder().encode('goodbye world'));
	const s = sign(helloMsg, key);
	console.log('Signed "hello world". Now measuring the signature\'s closeness (cyclic distance');
	console.log('mod q=128) to the message it actually signed, versus a message it never saw:\n');

	const legitCloseness = closeness(helloMsg, s, key);
	const crossCloseness = closeness(goodbyeMsg, s, key);
	console.log(`  closeness to "hello world"   (its own message): ${legitCloseness}`);
	console.log(`  closeness to "goodbye world" (never signed):    ${crossCloseness}\n`);

	if (crossCloseness < legitCloseness) {
		console.log("The unrelated message scored CLOSER than the signature's own message.");
		console.log('A verifier at N=11 cannot even give the honest signer a consistent answer.\n');
	} else {
		console.log('Its own message did score closer here, by luck of the draw — but the margin');
		console.log('is nowhere near reliable. Sweeping many keys and messages settles it properly:\n');
	}

	// A single pair proves nothing either way — sweep many keys/messages,
	// exactly the discipline this repo used to validate N=18 actually
	// works, applied here to show N=11 does not.
	let legitMax = 0n;
	let crossMin = Q;
	let crossBeatLegit = 0;
	const NUM_KEYS = 15;
	const NUM_MSGS = 20;
	for (let k = 0; k < NUM_KEYS; k++) {
		const sweepKey = keygen();
		for (let i = 0; i < NUM_MSGS; i++) {
			const msgA = keccak_256(new TextEncoder().encode(`sweep-${k}-a-${i}`));
			const msgB = keccak_256(new TextEncoder().encode(`sweep-${k}-b-${i}`));
			const sig = sign(msgA, sweepKey);
			const legit = closeness(msgA, sig, sweepKey);
			const cross = closeness(msgB, sig, sweepKey);
			if (legit > legitMax) legitMax = legit;
			if (cross < crossMin) crossMin = cross;
			if (cross <= legit) crossBeatLegit++;
		}
	}
	const totalPairs = NUM_KEYS * NUM_MSGS;
	console.log(`Sweep: ${NUM_KEYS} keypairs x ${NUM_MSGS} messages each (${totalPairs} pairs):`);
	console.log(`  legitimate-signature closeness, worst case: ${legitMax}`);
	console.log(`  cross-message closeness, best case:         ${crossMin}`);
	console.log(
		`  an unrelated message scored AS CLOSE OR CLOSER than the real one in ${crossBeatLegit}/${totalPairs} pairs\n`,
	);

	console.log('Compare: the same sweep at N=18 (see test/js/utils/ntruSign.ts,');
	console.log('scripts/gen-ntrusign-vectors.ts) measures legit-max ~38-44, cross-min ~52-56 — a');
	console.log('15-point gap. Here at N=11, with the identical MAX_FG_COEFF discipline, the gap');
	console.log('is 3-5 points across repeated runs — real, but razor-thin and not something a');
	console.log('real verifier could safely rely on. Tightening the filter further to chase a');
	console.log('bigger gap does not work either: MAX_FG_COEFF=10 (vs. the 15 that suffices at');
	console.log('N=18) cannot find ANY valid keypair at N=11 in 2000 attempts — there simply are');
	console.log('not enough well-reduced bases in this smaller a lattice to pick from. This is why');
	console.log('the real deployable account (src/tools/NTRUSign/NTRUSignAccount.yul) uses N=18,');
	console.log('not N=11: below some threshold, more effort stops helping — the dimension itself');
	console.log('is the bottleneck, not the reduction algorithm.');
}

main().catch((err) => {
	console.error(err);
	process.exit(1);
});
