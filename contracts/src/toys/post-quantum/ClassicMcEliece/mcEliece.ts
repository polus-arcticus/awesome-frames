// Classic McEliece — a real toy binary Goppa code (length n=15, dimension
// k=7, correcting t=2 errors, over GF(2^4)=GF(16)) wrapped in the actual
// McEliece public-key structure (a scrambled generator matrix G' = S·G·P
// hides the code's error-correcting structure from anyone without the
// secret S, P, and Goppa decoder). Code-based, not lattice/isogeny-based
// like the rest of this survey — a genuinely different hard problem
// (syndrome decoding: given a parity-check matrix H and a syndrome
// H·e^T, find the low-weight error e — believed hard for a GENERIC
// linear code, which is exactly why McEliece's public key is built to
// look like one).
//
// Where this repo's own `factor()` (YoloRSA) and forgery demos exist to
// show HOW something breaks, this file's honest caveat runs the other
// way: n=15 is far too small to make any real security claim at all. A
// real Classic McEliece deployment uses n≈3488-8192; syndrome decoding a
// generic [15,7] code is already just brute force (121 weight-≤2 error
// patterns is nothing to search), so this toy doesn't distinguish
// "broken because the Goppa structure leaked" from "broken because it's
// tiny" — same disclaimer YoloRSA already makes about itself, for the
// same reason: the point is the MECHANISM (real GF(16) arithmetic, a
// real Goppa parity-check construction, a real scramble-then-decode
// cryptosystem shape), not a security claim at this size.
//
// Decoding here is a brute-force syndrome→error-pattern LOOKUP TABLE
// (all 121 weight-≤2 error patterns, precomputed), standing in for
// Patterson's algorithm — the same "brute force substitutes for the
// sophisticated algorithm" move ToyCurveECDH already makes (enumerating
// every point instead of implementing a real discrete-log algorithm).
// Patterson's algorithm is what makes n≈3488+ tractable; a lookup table
// only works because t=2 keeps the search space (121 patterns) trivial.
//
// The Goppa polynomial g(x) is found by SEARCH, not hand-picked: try
// candidate quadratics x²+g1x+g0 over GF(16) until one has no root in
// GF(16) at all (for a degree-2 polynomial, no root in the base field is
// exactly equivalent to irreducibility) — verified computationally, the
// same "verify, don't assume" discipline the group order in
// ToyCurveECDH's own JS mirror already follows.
//
// Not constant-time, not for production — same disclaimer as every other
// grimoire entry.

// ── GF(16) = GF(2^4) via x^4+x+1, generator alpha=2 ──
const GF_ORDER = 16;
const GF_EXP: number[] = new Array(30);
const GF_LOG: number[] = new Array(GF_ORDER);
{
	let x = 1;
	for (let i = 0; i < 15; i++) {
		GF_EXP[i] = x;
		GF_LOG[x] = i;
		x <<= 1;
		if (x & 0x10) x ^= 0x13; // reduce mod x^4+x+1 (0b10011)
		x &= 0xf;
	}
	for (let i = 15; i < 30; i++) GF_EXP[i] = GF_EXP[i - 15]!;
}
function gfMul(a: number, b: number): number {
	if (a === 0 || b === 0) return 0;
	return GF_EXP[GF_LOG[a]! + GF_LOG[b]!]!;
}
function gfInv(a: number): number {
	if (a === 0) throw new Error('gfInv(0)');
	return GF_EXP[(15 - GF_LOG[a]!) % 15]!;
}
function gfPow(a: number, e: number): number {
	if (e === 0) return 1;
	if (a === 0) return 0;
	return GF_EXP[(GF_LOG[a]! * e) % 15]!;
}
const gfAdd = (a: number, b: number): number => a ^ b; // GF(2^m) addition is XOR

// ── Code parameters ──
const M = 4; // GF(2^m), m=4 -> GF(16)
const N = 15; // code length (all nonzero elements of GF(16))
const T = 2; // errors corrected (Goppa polynomial degree)
const K = N - M * T; // dimension = 15 - 8 = 7
const SUPPORT = Array.from({length: N}, (_, i) => i + 1); // L = [1, 2, ..., 15]

/** Evaluate a GF(16) polynomial (low-degree-first coefficients) at x, via Horner's method. */
function evalPoly(coeffs: readonly number[], x: number): number {
	let result = 0;
	for (let i = coeffs.length - 1; i >= 0; i--) result = gfAdd(gfMul(result, x), coeffs[i]!);
	return result;
}

/** Search for an irreducible degree-2 Goppa polynomial g(x) = x^2 + g1*x + g0 over GF(16) — no root anywhere in GF(16) (0 included) is exactly irreducibility for a quadratic. */
function findGoppaPolynomial(): [number, number, number] {
	for (let g1 = 0; g1 < GF_ORDER; g1++) {
		for (let g0 = 0; g0 < GF_ORDER; g0++) {
			const coeffs = [g0, g1, 1];
			let hasRoot = false;
			for (let x = 0; x < GF_ORDER; x++) {
				if (evalPoly(coeffs, x) === 0) {
					hasRoot = true;
					break;
				}
			}
			if (!hasRoot) return [g0, g1, 1];
		}
	}
	throw new Error('findGoppaPolynomial: no irreducible quadratic found — should be impossible over GF(16)');
}

const [G0, G1] = findGoppaPolynomial();
const GOPPA = [G0, G1, 1] as const;

type Bit = 0 | 1;
type BitVec = Bit[]; // length N
type BitMatrix = Bit[][]; // rows x N

/** The Goppa parity-check matrix H' over GF(16) (T x N: H'[i][j] = L_j^i / g(L_j)), expanded into GF(2) (M*T x N, MSB-first per GF(16) value) — the code's SECRET structure. */
function buildParityCheckMatrix(): BitMatrix {
	const H: BitMatrix = [];
	for (let i = 0; i < T; i++) {
		const row: number[] = SUPPORT.map((Lj) => gfMul(gfPow(Lj, i), gfInv(evalPoly(GOPPA, Lj))));
		for (let bit = M - 1; bit >= 0; bit--) {
			H.push(row.map((v) => ((v >> bit) & 1) as Bit));
		}
	}
	return H; // (M*T) x N = 8 x 15
}

/** Row-reduce `rows` over GF(2) in place; returns the pivot column for each row (-1 if the row became all-zero — shouldn't happen for a full-rank H). */
function rref(rows: BitMatrix): number[] {
	const numRows = rows.length;
	const numCols = rows[0]!.length;
	const pivotColOf: number[] = new Array(numRows).fill(-1);
	let pivotRow = 0;
	for (let col = 0; col < numCols && pivotRow < numRows; col++) {
		let sel = -1;
		for (let r = pivotRow; r < numRows; r++) {
			if (rows[r]![col] === 1) {
				sel = r;
				break;
			}
		}
		if (sel === -1) continue;
		[rows[pivotRow], rows[sel]] = [rows[sel]!, rows[pivotRow]!];
		for (let r = 0; r < numRows; r++) {
			if (r !== pivotRow && rows[r]![col] === 1) {
				for (let c = 0; c < numCols; c++) rows[r]![c] = (rows[r]![c]! ^ rows[pivotRow]![c]!) as Bit;
			}
		}
		pivotColOf[pivotRow] = col;
		pivotRow++;
	}
	if (pivotRow !== numRows) throw new Error(`rref: matrix is not full row rank (got ${pivotRow}, expected ${numRows})`);
	return pivotColOf;
}

/** Build a generator matrix G (K x N) as a basis for H's null space, via RREF — see this file's header for the construction. */
function buildGeneratorMatrix(H: BitMatrix): {G: BitMatrix; freeColumns: number[]} {
	const rrefRows = H.map((row) => row.slice());
	const pivotColOf = rref(rrefRows);
	const pivotCols = new Set(pivotColOf);
	const freeColumns = Array.from({length: N}, (_, c) => c).filter((c) => !pivotCols.has(c));
	if (freeColumns.length !== K) throw new Error(`buildGeneratorMatrix: expected ${K} free columns, got ${freeColumns.length}`);

	const G: BitMatrix = freeColumns.map((f) => {
		const v: Bit[] = new Array(N).fill(0);
		v[f] = 1;
		for (let r = 0; r < rrefRows.length; r++) v[pivotColOf[r]!] = rrefRows[r]![f]!;
		return v;
	});
	return {G, freeColumns};
}

// ── GF(2) linear algebra helpers (vectors/matrices of Bit) ──
function vecXor(a: BitVec, b: BitVec): BitVec {
	return a.map((v, i) => (v ^ b[i]!) as Bit);
}
function vecDot(a: readonly Bit[], b: readonly Bit[]): Bit {
	let s = 0;
	for (let i = 0; i < a.length; i++) s ^= a[i]! & b[i]!;
	return s as Bit;
}
/** row vector (length rows) times matrix (rows x cols) -> row vector (length cols) */
function vecMatMul(v: readonly Bit[], M_: BitMatrix): BitVec {
	const cols = M_[0]!.length;
	const out: Bit[] = new Array(cols).fill(0);
	for (let c = 0; c < cols; c++) {
		let s = 0;
		for (let r = 0; r < v.length; r++) s ^= v[r]! & M_[r]![c]!;
		out[c] = s as Bit;
	}
	return out;
}
function matMul(A: BitMatrix, B: BitMatrix): BitMatrix {
	return A.map((row) => vecMatMul(row, B));
}
function identity(n: number): BitMatrix {
	return Array.from({length: n}, (_, i) => Array.from({length: n}, (_, j) => (i === j ? 1 : 0)) as Bit[]);
}
function invertGF2(M_: BitMatrix): BitMatrix | null {
	const n = M_.length;
	const aug: number[][] = M_.map((row, i) => [...row, ...identity(n)[i]!]);
	let pivotRow = 0;
	for (let col = 0; col < n && pivotRow < n; col++) {
		let sel = -1;
		for (let r = pivotRow; r < n; r++) {
			if (aug[r]![col] === 1) {
				sel = r;
				break;
			}
		}
		if (sel === -1) continue;
		[aug[pivotRow], aug[sel]] = [aug[sel]!, aug[pivotRow]!];
		for (let r = 0; r < n; r++) {
			if (r !== pivotRow && aug[r]![col] === 1) {
				for (let c = 0; c < 2 * n; c++) aug[r]![c] = aug[r]![c]! ^ aug[pivotRow]![c]!;
			}
		}
		pivotRow++;
	}
	if (pivotRow !== n) return null; // singular
	return aug.map((row) => row.slice(n) as Bit[]);
}

function randomBit(): Bit {
	return (Math.random() < 0.5 ? 0 : 1) as Bit;
}
function randomInvertibleMatrix(n: number): BitMatrix {
	for (;;) {
		const M_: BitMatrix = Array.from({length: n}, () => Array.from({length: n}, randomBit));
		const inv = invertGF2(M_);
		if (inv !== null) return M_;
	}
}
function randomPermutation(n: number): number[] {
	const perm = Array.from({length: n}, (_, i) => i);
	for (let i = n - 1; i > 0; i--) {
		const j = Math.floor(Math.random() * (i + 1));
		[perm[i], perm[j]] = [perm[j]!, perm[i]!];
	}
	return perm;
}
function permuteColumns(M_: BitMatrix, perm: readonly number[]): BitMatrix {
	return M_.map((row) => perm.map((p) => row[p]!));
}
function inversePermutation(perm: readonly number[]): number[] {
	const inv = new Array(perm.length);
	perm.forEach((p, i) => (inv[p] = i));
	return inv;
}
function applyPermutation(v: readonly Bit[], perm: readonly number[]): BitVec {
	return perm.map((p) => v[p]!);
}

// ── Secret Goppa structure + syndrome lookup table (the "Patterson's algorithm" stand-in) ──
const H_SECRET = buildParityCheckMatrix();
const {G: G_SECRET, freeColumns: MESSAGE_POSITIONS} = buildGeneratorMatrix(H_SECRET);

function syndromeOf(e: readonly Bit[]): number {
	let s = 0;
	for (const row of H_SECRET) s = (s << 1) | vecDot(row, e);
	return s;
}

/** All weight-<=T error patterns, indexed by syndrome (2^(M*T) = 256 possible bit patterns, only C(15,0)+C(15,1)+C(15,2)=121 are reachable at weight<=2). */
function buildSyndromeTable(): Map<number, BitVec> {
	const table = new Map<number, BitVec>();
	const zero: BitVec = new Array(N).fill(0);
	table.set(syndromeOf(zero), zero);
	for (let i = 0; i < N; i++) {
		const e = zero.slice();
		e[i] = 1;
		table.set(syndromeOf(e), e);
	}
	for (let i = 0; i < N; i++) {
		for (let j = i + 1; j < N; j++) {
			const e = zero.slice();
			e[i] = 1;
			e[j] = 1;
			table.set(syndromeOf(e), e);
		}
	}
	return table;
}
const SYNDROME_TABLE = buildSyndromeTable();

export interface McElieceKeypair {
	publicKey: BitMatrix; // G' = S . G . P, K x N — the scrambled generator matrix
	secretKey: {Sinv: BitMatrix; permInv: number[]};
}

export function keygen(): McElieceKeypair {
	const S = randomInvertibleMatrix(K);
	const perm = randomPermutation(N);
	const publicKey = permuteColumns(matMul(S, G_SECRET), perm);
	const Sinv = invertGF2(S);
	if (Sinv === null) throw new Error('keygen: S was reported invertible but its inverse failed — should be impossible');
	return {publicKey, secretKey: {Sinv, permInv: inversePermutation(perm)}};
}

/** Encrypt a K-bit message: c = m.G' + e, e a random weight-T error. */
export function encrypt(message: readonly Bit[], publicKey: BitMatrix): BitVec {
	if (message.length !== K) throw new Error(`encrypt: message must be ${K} bits`);
	const codeword = vecMatMul(message, publicKey);
	const errorPositions = new Set<number>();
	while (errorPositions.size < T) errorPositions.add(Math.floor(Math.random() * N));
	const e: BitVec = new Array(N).fill(0);
	for (const pos of errorPositions) e[pos] = 1;
	return vecXor(codeword, e);
}

export function decrypt(cipherText: readonly Bit[], secretKey: McElieceKeypair['secretKey']): BitVec {
	const c1 = applyPermutation(cipherText, secretKey.permInv); // undo P: c1 = mSG + e1
	const syndrome = syndromeOf(c1);
	const e1 = SYNDROME_TABLE.get(syndrome);
	if (e1 === undefined) throw new Error('decrypt: syndrome not in table — more than t=2 errors, or an invalid ciphertext');
	const codeword = vecXor(c1, e1); // = mSG, a genuine codeword
	const mS = MESSAGE_POSITIONS.map((pos) => codeword[pos]!); // systematic: message bits sit directly at the free-column positions
	return vecMatMul(mS, secretKey.Sinv);
}

export const PARAMS = {n: N, k: K, t: T, fieldOrder: GF_ORDER, goppaPolynomial: GOPPA} as const;
