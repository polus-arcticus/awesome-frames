// RESEARCH SPIKE — not a final deliverable, not imported by anything else.
// Finds a working method for solving NTRUSign's key equation f*G - g*F = q
// at toy scale (small N), self-verified before src/toys/NTRUSign/ gets
// built on top of it. See the approved plan
// (~/.claude/plans/alright-next-on-the-jazzy-muffin.md) for why this is
// step 1: the real NTRUSign paper's F,G construction (via resultants) is
// sized for N>=251 and wasn't fully detailed in the sources read this
// session, so this spike derives and verifies a toy-scale approach from
// first principles instead of assuming one.
//
// Run: pnpm tsx scripts/spike-ntrusign-keygen.ts

// ---- Exact rational arithmetic (BigInt numerator/denominator) ----
// Toy N is small enough that exact fractions are cheap and avoid all
// floating-point precision risk in what is fundamentally an exact-integer
// algebra problem (f*G - g*F = q must hold EXACTLY, not approximately).
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
	// round-half-to-even is overkill here; round-half-away-from-zero is fine.
	const twice = 2n * a.n;
	const q = twice / a.d;
	const r = twice % a.d;
	const base = a.n / a.d; // truncating division
	const rem = a.n - base * a.d;
	// Recompute cleanly via floating fallback-free integer math:
	const sign = a.n < 0n !== a.d < 0n ? -1n : 1n;
	void q;
	void r;
	void rem;
	const absN = a.n < 0n ? -a.n : a.n;
	const absD = a.d < 0n ? -a.d : a.d;
	const flo = absN / absD;
	const rema = absN - flo * absD;
	const roundedAbs = 2n * rema >= absD ? flo + 1n : flo;
	return sign * roundedAbs;
}

type Poly = bigint[]; // length N, coefficient i = coeff of x^i, mod x^N - 1

function polyMul(a: Poly, b: Poly, N: number): Poly {
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
function polySub(a: Poly, b: Poly): Poly {
	return a.map((v, i) => v - b[i]!);
}
function polyAdd(a: Poly, b: Poly): Poly {
	return a.map((v, i) => v + b[i]!);
}
function polyScale(a: Poly, k: bigint): Poly {
	return a.map((v) => v * k);
}

function reversePoly(p: Poly, N: number): Poly {
	return Array.from({length: N}, (_, i) => p[(N - i) % N]!);
}
// correlate(A,B)[m] = sum_i A[i]*B[(i-m) mod N] = polyMul(A, reverse(B))[m].
function correlate(a: Poly, b: Poly, N: number): Poly {
	return polyMul(a, reversePoly(b, N), N);
}

// Circulant matrix representing u -> polyMul(f, u): matrix[i][j] such that
// (M . u)[i] = sum_j M[i][j]*u[j] = polyMul(f,u)[i] = sum_j f[(i-j) mod N]*u[j].
function circulant(f: Poly, N: number): Frac[][] {
	const M: Frac[][] = [];
	for (let i = 0; i < N; i++) {
		const row: Frac[] = new Array(N);
		for (let j = 0; j < N; j++) {
			const idx = ((i - j) % N + N) % N;
			row[j] = frac(f[idx]!);
		}
		M.push(row);
	}
	return M;
}

// Exact-fraction Gauss-Jordan inverse of an N x N matrix.
function invertExact(M: Frac[][], N: number): Frac[][] {
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

// f^{-1} as a polynomial over Q, i.e. the polynomial u with u*f = 1 in
// Q[x]/(x^N-1). This is column 0 (equivalently row 0, circulant is not
// symmetric in general but its inverse's row 0 gives exactly u since
// circ(f) * u_vec = e0 <=> u * f = 1 by our circulant convention).
function polyInverseQ(f: Poly, N: number): Frac[] {
	const M = circulant(f, N);
	const Inv = invertExact(M, N);
	// circ(f) * u = e0  =>  u = Inv * e0 = column 0 of Inv
	return Inv.map((row) => row[0]!);
}

function fracVecToPoly(v: Frac[]): {poly: Poly; isIntegral: boolean} {
	let isIntegral = true;
	const poly = v.map((x) => {
		if (x.d !== 1n) isIntegral = false;
		return x.n / x.d; // only exact if d===1, else truncates (checked above)
	});
	return {poly, isIntegral};
}

function maxAbs(p: Poly): bigint {
	return p.reduce((m, v) => (v < 0n ? -v : v) > m ? (v < 0n ? -v : v) : m, 0n);
}

// Convolve a fraction-vector with an integer polynomial.
function fPolyMulInt(a: Frac[], b: Poly, N: number): Frac[] {
	const out: Frac[] = new Array(N).fill(frac(0n));
	for (let i = 0; i < N; i++) {
		if (fIsZero(a[i]!)) continue;
		for (let j = 0; j < N; j++) {
			if (b[j] === 0n) continue;
			const idx = (i + j) % N;
			out[idx] = fAdd(out[idx]!, fMul(a[i]!, frac(b[j]!)));
		}
	}
	return out;
}
// Convolve two fraction-vectors.
function fPolyMul(a: Frac[], b: Frac[], N: number): Frac[] {
	const out: Frac[] = new Array(N).fill(frac(0n));
	for (let i = 0; i < N; i++) {
		if (fIsZero(a[i]!)) continue;
		for (let j = 0; j < N; j++) {
			if (fIsZero(b[j]!)) continue;
			const idx = (i + j) % N;
			out[idx] = fAdd(out[idx]!, fMul(a[i]!, b[j]!));
		}
	}
	return out;
}

// ---- F0=0, G0 = q * f^{-1}_Q (exact fraction) — f*G0=q holds EXACTLY for
// ANY k (the f*g*k/g*f*k terms always cancel by commutativity), so k is
// free to choose purely to minimize size. Chosen via the least-squares
// continuous relaxation of min |f*k|^2 + |G0+g*k|^2, solved exactly in Q
// then rounded: setting the gradient to zero gives
//   k * (correlate(f,f) + correlate(g,g)) = -correlate(G0, g)
// (see the spike's own derivation notes / commit message for the algebra),
// solved via polynomial inversion of C = correlate(f,f)+correlate(g,g).
function attemptKeygen(f: Poly, g: Poly, N: number, q: bigint) {
	const fInvQ = polyInverseQ(f, N); // exact fractions, f*fInvQ = 1
	const G0 = fInvQ.map((x) => fMul(x, frac(q)));

	const C = polyAdd(correlate(f, f, N), correlate(g, g, N)); // integer poly
	const Cinv = polyInverseQ(C, N); // Frac[], C*Cinv = 1
	const rhs = fPolyMulInt(G0, reversePoly(g, N), N); // correlate(G0,g) = G0 * reverse(g)
	const kFrac = fPolyMul(rhs.map((x) => fMul(x, frac(-1n))), Cinv, N);
	const k: Poly = kFrac.map((x) => fRound(x));

	const F = polyMul(f, k, N);
	const Gfrac = G0.map((x, i) => fAdd(x, frac(polyMul(g, k, N)[i]!)));
	const {poly: G, isIntegral} = fracVecToPoly(Gfrac);

	return {F, G, isIntegral, fInvQ, G0};
}

function verify(f: Poly, g: Poly, F: Poly, G: Poly, N: number, q: bigint): boolean {
	const lhs = polySub(polyMul(f, G, N), polyMul(g, F, N));
	return lhs.every((v, i) => v === (i === 0 ? q : 0n));
}

// ---- Try a range of small N with simple weight-w binary f,g ----
function randomBinaryPoly(N: number, weight: number): Poly {
	const idxs = new Set<number>();
	while (idxs.size < weight) idxs.add(Math.floor(Math.random() * N));
	return Array.from({length: N}, (_, i) => (idxs.has(i) ? 1n : 0n));
}

const N = 11;
const q = 128n;
const weight = 4;

console.log(`Spike: NTRUSign toy keygen at N=${N}, q=${q}, weight=${weight}`);

const successes: {f: Poly; g: Poly; F: Poly; G: Poly; norm: bigint}[] = [];
for (let attempt = 0; attempt < 200; attempt++) {
	const f = randomBinaryPoly(N, weight);
	const g = randomBinaryPoly(N, weight);
	try {
		const {F, G, isIntegral} = attemptKeygen(f, g, N, q);
		if (!isIntegral) continue;
		if (!verify(f, g, F, G, N, q)) continue;
		const norm = maxAbs(F) > maxAbs(G) ? maxAbs(F) : maxAbs(G);
		successes.push({f, g, F, G, norm});
	} catch {
		continue;
	}
}

if (successes.length === 0) {
	console.error('No valid (f,g,F,G) found in 200 attempts — approach needs rework.');
	process.exit(1);
}
successes.sort((a, b) => Number(a.norm - b.norm));
console.log(`${successes.length}/200 attempts succeeded (integral + verified).`);
console.log(`maxAbs(F,G) — best: ${successes[0]!.norm}, median: ${successes[Math.floor(successes.length / 2)]!.norm}, worst: ${successes[successes.length - 1]!.norm}`);
const best = successes[0]!;
console.log('\nBest found:');
console.log('f =', best.f.join(','));
console.log('g =', best.g.join(','));
console.log('F =', best.F.join(','));
console.log('G =', best.G.join(','));
console.log('\nf*G - g*F = q verified exactly for the best candidate.');
