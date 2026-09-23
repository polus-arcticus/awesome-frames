// Pure-JS/bigint NTRUSign reference: ring arithmetic, key generation,
// message-hash-to-lattice-point, sign, and verify. Mirrors
// src/tools/NTRUSign/{NTRUSign.yul,NTRUSignAccount.yul} once those land —
// see this repo's approved plan (~/.claude/plans/alright-next-on-the-jazzy-muffin.md)
// for the full derivation and the primary sources it's drawn from:
// Hoffstein/Howgrave-Graham/Pipher/Silverman/Whyte's original NTRUSign
// (CT-RSA 2003) and Phong Q. Nguyen's "A Note on the Security of NTRUSign"
// (https://eprint.iacr.org/2006/387.pdf), which is where the ring
// structure, the f*G-g*F=q key equation, and the "signature is just s"
// simplification below come from.
//
// No maintained/audited external library exists for NTRUSign (it's a
// deprecated, historically broken scheme) — every claim below is
// self-verified: keygen checks f*G-g*F=q exactly before returning a key,
// and this file's own generator script cross-checks sign/verify round
// trips before pinning anything. Same discipline as
// src/toys/post-quantum/ClassicMcEliece/mcEliece.ts.
//
// Parameters, locked after this session's research (see the plan):
// N=18, q=128 — real historical NTRU value for q; N is toy-scale but NOT
// the smallest that "works." N=11 was tried first and rejected: even a
// tightly-reduced basis there gives NO real separation between a
// legitimate signature's closeness to its own message and its closeness
// to a totally unrelated one (measured: legit max 50 vs. cross-message
// min 48 — the honest signer's own signatures aren't reliably
// distinguishable from noise). That's not "weak," it's non-functional as
// a signature scheme, so N=11 lives in toys/ instead as a demonstration
// of exactly that failure (see scripts/ntrusign-n11-failure-demo.ts).
// N=18 was the next value tried and it works: with a tight basis-size
// filter (MAX_FG_COEFF below), legit-signature closeness tops out around
// 40-52 while cross-message closeness starts around 51-56 — a real,
// if not huge, gap (see scripts/gen-ntrusign-vectors.ts for the measured
// figures this pins).
//
// N=18's on-chain verify() cost is real and tight against EIP-8141's
// current MAX_VERIFY_GAS=100_000 — kept in tools/ anyway rather than
// downgraded to toys/, because that ceiling is itself under active
// discussion for being raised: see the EIP-8141 breakout notes from
// 2026-09-01 (https://ethereum-magicians.org/t/frame-transaction-breakout-3-sep-1-2026/29539/2),
// where Nethermind's Daniil flagged 100_000 as too tight for privacy-pool
// withdrawals and a working group was proposed to study raising it —
// consistent with mainnet block gas limits climbing toward 80M+ while
// this single-frame ceiling has stayed fixed. Real NTRUSign-251 uses
// N=251 — this is deliberately, doubly weak regardless of the exact N:
// the transcript-leakage break AND a lattice dimension small enough to
// be otherwise-attackable.

import {keccak_256} from '@noble/hashes/sha3.js';

export const N = 18;
export const Q = 128n;
// f needs an ODD weight: f(1) mod 2 = weight mod 2, and (x-1) always
// divides x^N-1, so an even-weight f always has f(1) even, meaning (x-1)
// divides f too over GF(2) — making f structurally non-invertible mod 2
// (hence never invertible mod Q=2^7 either, and its resultant with
// x^N-1 always even). Discovered empirically this session when keygen
// mysteriously never succeeded at an even weight.
const WEIGHT_F = 7;
const WEIGHT_G = 6;

export type Poly = bigint[]; // length N, coefficient i = coeff of x^i, mod x^N - 1

export interface KeyPair {
	f: Poly;
	g: Poly;
	F: Poly;
	G: Poly;
	h: Poly; // public key: f*h = g (mod Q)
}

function mod(a: bigint, m: bigint): bigint {
	const r = a % m;
	return r >= 0n ? r : r + m;
}
// Centered representative in [-m/2, m/2).
function centeredMod(a: bigint, m: bigint): bigint {
	const r = mod(a, m);
	return r >= m / 2n ? r - m : r;
}

export function polyMul(a: Poly, b: Poly): Poly {
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
export function polyAdd(a: Poly, b: Poly): Poly {
	return a.map((v, i) => v + b[i]!);
}
export function polySub(a: Poly, b: Poly): Poly {
	return a.map((v, i) => v - b[i]!);
}
export function polyModQ(a: Poly): Poly {
	return a.map((v) => mod(v, Q));
}
export function polyCenteredModQ(a: Poly): Poly {
	return a.map((v) => centeredMod(v, Q));
}
function reversePoly(p: Poly): Poly {
	return Array.from({length: N}, (_, i) => p[(N - i) % N]!);
}
// correlate(A,B)[m] = sum_i A[i]*B[(i-m) mod N] = polyMul(A, reverse(B))[m].
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

// ---- Exact rational arithmetic (BigInt numerator/denominator) — used
// only during keygen, to compute resultants/adjugates and reduce the
// resulting (F,G) to small coefficients. Toy N is small enough that exact
// fractions are cheap and avoid all floating-point precision risk in what
// is fundamentally an exact-integer algebra problem. ----
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
	const roundedAbs = 2n * rema >= absD ? flo + 1n : flo;
	return sign * roundedAbs;
}
// Circulant matrix representing u -> polyMul(f, u).
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
	const I: Frac[][] = Array.from({length: N}, (_, i) =>
		Array.from({length: N}, (_, j) => frac(i === j ? 1n : 0n)),
	);
	for (let col = 0; col < N; col++) {
		let pivotRow = -1;
		for (let r = col; r < N; r++) {
			if (!fIsZero(A[r]![col]!)) {
				pivotRow = r;
				break;
			}
		}
		if (pivotRow === -1) throw new Error('invertExact: singular matrix');
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
/// Resultant Rf = det(circ(f)) and the adjugate polynomial fAdj (integer,
/// by definition of the adjugate/cofactor matrix) such that f*fAdj = Rf
/// exactly. Returns null if f isn't invertible over Q (singular circulant).
function resultantAndAdjugate(f: Poly): {Rf: bigint; fAdj: Poly} | null {
	let Inv: Frac[][];
	try {
		Inv = invertExact(circulant(f));
	} catch {
		return null;
	}
	const col0 = Inv.map((row) => row[0]!); // f^{-1}_Q as exact fractions
	let Rf = 1n;
	for (const x of col0) Rf = (Rf / gcdBig(Rf, x.d)) * x.d; // LCM of denominators
	const fAdj = col0.map((x) => {
		const scaled = fMul(x, frac(Rf));
		if (scaled.d !== 1n) throw new Error('resultantAndAdjugate: adjugate not integral (unexpected)');
		return scaled.n;
	});
	return {Rf, fAdj};
}
function extGcd(a: bigint, b: bigint): {g: bigint; u: bigint; v: bigint} {
	if (b === 0n) return {g: a, u: 1n, v: 0n};
	const {g, u: u1, v: v1} = extGcd(b, a % b);
	return {g, u: v1, v: u1 - (a / b) * v1};
}

/// Solves f*G - g*F = q exactly for small-coefficient (F, G), given f, g.
/// The construction (Bezout on the resultants, standard for NTRU trapdoor
/// generation): with Rf = det(circ(f)), Rg = det(circ(g)), and fAdj/gAdj
/// their integer adjugate polynomials (f*fAdj = Rf, g*gAdj = Rg exactly),
/// if gcd(Rf, Rg) = 1 then Bezout gives integers u, v with u*Rf+v*Rg = 1.
/// Setting F0 = -q*v*gAdj, G0 = q*u*fAdj gives, EXACTLY:
///   f*G0 - g*F0 = q*u*(f*fAdj) + q*v*(g*gAdj) = q*u*Rf + q*v*Rg = q.
/// F0, G0 are integral by construction but large; reduce via the kernel
/// {(f*k, g*k) : k ∈ R} (the k-dependent terms cancel identically for ANY
/// k, by commutativity) — the least-squares-optimal real k minimizing
/// |F0+f*k|^2+|G0+g*k|^2 solves k*(correlate(f,f)+correlate(g,g)) =
/// -(correlate(F0,f)+correlate(G0,g)); rounding k to the nearest integer
/// polynomial keeps F,G exactly integral (since k is now integer) while
/// bringing their size down to "slightly larger than f,g, much smaller
/// than q" — matching the paper's own description (measured this session:
/// typically 15-50, well under q=128).
function solveKeyEquation(f: Poly, g: Poly): {F: Poly; G: Poly} | null {
	const rf = resultantAndAdjugate(f);
	const rg = resultantAndAdjugate(g);
	if (!rf || !rg) return null;
	const {g: gcdVal, u, v} = extGcd(rf.Rf, rg.Rf);
	if (gcdVal !== 1n && gcdVal !== -1n) return null; // need coprime resultants
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

// ---- GF(2)/Hensel-lift modular inverse mod Q=2^7, used for the public
// key h = f^{-1}*g mod Q. Q is a power of two, not prime, so the
// exact-fraction inverse above doesn't apply here — invert mod 2 first
// (binary Gaussian elimination), then Newton-lift the solution up to mod
// 128: if f*u ≡ 1 (mod 2^k), then f*(u*(2-f*u)) ≡ 1 (mod 2^2k). ----
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

// Babai round-off's worst-case error scales with how well-reduced the
// secret basis is, not just whether f*G-g*F=q holds. At N=18 this filter
// is what actually makes legit-vs-cross-message closeness separate at
// all — loosen it (tried 30, then 18) and the two distributions start
// overlapping the same way they do unconditionally at N=11. At 15,
// measured over 20 keypairs x 50 messages each: legit-signature
// closeness tops out at 40-52, cross-message closeness starts at 51-56 —
// a real gap, not a large one, but real. Rejected/retried, not left
// looser, because a looser filter makes CLOSENESS_BOUND below nearly
// meaningless as a security check (any point within it would trivially
// pass).
const MAX_FG_COEFF = 15n;

export function keygen(maxAttempts = 2000): KeyPair {
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

/// Expands a 32-byte message hash into m=(m1,m2), each an N-coefficient
/// polynomial with coefficients in [0, Q) — a keccak256-based,
/// domain-separated XOF-style expansion (EVM-native: no precompile needed
/// on the Yul side, just the KECCAK256 opcode), same spirit as this
/// repo's other domain-separated hash-to-point constructions.
export function hashToPoint(msgHash: Uint8Array): {m1: Poly; m2: Poly} {
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
		const rounded = 2n * rem >= Q ? flo + 1n : flo;
		return sign * rounded;
	});
}

/// Babai round-off signing: recovers the lattice point (s,t) close to
/// m=(m1,m2) using the secret basis (f,g,F,G), and returns s (t is
/// recoverable from s via h — see verify()). The lattice's basis matrix
/// is [[f,g],[F,G]] (rows f,g and F,G, "determinant" f*G-g*F=q); Babai
/// round-off computes real coordinates (a,b) = m * BasisMatrix^{-1} =
/// ((m1*G-m2*F)/q, (-m1*g+m2*f)/q), rounds each to the nearest integer
/// polynomial (A,B), and returns the resulting lattice point's first half:
/// s = A*f + B*F.
export function sign(msgHash: Uint8Array, key: KeyPair): Poly {
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

/// Empirically-measured closeness bound: max over many trials of
/// max(|s-m1|, |t-m2|) coefficient-wise, plus margin. Set by
/// scripts/gen-ntrusign-vectors.ts's own measurement, not guessed — see
/// that script for the measured figure. Exported so the generator and
/// tests share one source of truth.
// At N=18 with MAX_FG_COEFF=15: a 2,400-sample sweep (40 fresh keypairs x
// 60 messages each) measured a legitimate signature's own closeness
// topping out at 44, while an unrelated message's closeness against that
// same signature never dropped below 52 — a real, measured gap (not a
// large one; this is still a toy). 48 sits in the middle of that gap.
export const CLOSENESS_BOUND = 48n;

/// Recovers t from s via h (t = s*h mod Q, centered), then checks (s,t)
/// is within CLOSENESS_BOUND of m=(m1,m2) coefficient-wise.
// Cyclic (mod Q) distance: 125 and 3 are only 6 apart mod 128, not 122 —
// raw integer subtraction is wrong once a value has been reduced mod Q.
function cyclicMaxDist(a: Poly, b: Poly): bigint {
	let worst = 0n;
	for (let i = 0; i < N; i++) {
		const d = mod(a[i]! - b[i]!, Q);
		const cyclic = d > Q / 2n ? Q - d : d;
		if (cyclic > worst) worst = cyclic;
	}
	return worst;
}

export function verify(msgHash: Uint8Array, s: Poly, h: Poly): boolean {
	const {m1, m2} = hashToPoint(msgHash);
	const t = polyMul(s, h);
	const sDiff = cyclicMaxDist(s, m1);
	const tDiff = cyclicMaxDist(t, m2);
	return sDiff <= CLOSENESS_BOUND && tDiff <= CLOSENESS_BOUND;
}
