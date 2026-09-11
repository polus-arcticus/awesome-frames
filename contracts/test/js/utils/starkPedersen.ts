// Pure-JS/bigint mirror of the point arithmetic and Pedersen-hash fold
// implemented in src/grimoire/StarkPedersen/StarkPedersen.yul — see that
// file's header for the full glossary. Used both to generate known-answer
// vectors (../../../scripts/gen-stark-pedersen-vectors.ts) and as an
// independent cross-check in ../StarkPedersen.test.ts, which additionally
// checks this file itself against `@scure/starknet`'s own `pedersen()` —
// the actual ground truth, same role @noble/curves already plays for
// BIP-340 elsewhere in this repo.
//
// Curve: y^2 = x^3 + x + b (mod p) — Starknet's "STARK-friendly" curve.
// https://docs.starkware.co/starkex/stark-curve.html
// p = 2^251 + 17*2^192 + 1. b never appears in the addition/doubling
// formulas below (same as toyCurve.ts's unused B in its own hot path) —
// it's kept only for `isOnCurve`'s independent verification, below.
//
// Pedersen hash: shift_point + (x_low*P0 + x_high*P1) + (y_low*P2 + y_high*P3),
// where "low"/"high" split each 252-bit field element into its low 248
// bits and high 4 bits, and each term is a bit-conditional subset sum
// over repeated doublings of a fixed "nothing up my sleeve" point.
// https://docs.starkware.co/starkex/pedersen-hash-function.html
// The five constant points below are StarkWare's own published constants
// (verified here against `@scure/starknet`'s source, which itself cites
// starkex-for-spot-trading's nothing_up_my_sleeve_gen.py) — not chosen or
// derived by this repo.

export const P = 2n ** 251n + 17n * 2n ** 192n + 1n;
export const A = 1n;
// StarkWare's own literal digits of pi. Never used in the add/doubling
// slope formulas below (same as toyCurve.ts's unused B) — kept only so
// scripts/gen-stark-pedersen-vectors.ts can independently verify every
// pinned point actually lies on the curve, rather than trusting the
// arithmetic that produced it.
export const B = 3141592653589793238462643383279502884197169399375105820974944592307816406665n;

export interface AffinePoint {
	x: bigint;
	y: bigint;
}
// The point at infinity never appears in this file: every addition
// performed while computing a Pedersen hash is between a running
// accumulator and one of five fixed, independent generator points, and
// StarkWare's own choice of those points is exactly what makes an
// accidental P + (-P) or a doubling of the identity cryptographically
// implausible (see the "Same point" guard in `pedersen` below for the one
// coincidence that *is* checked for).

export function mod(a: bigint, m: bigint): bigint {
	const r = a % m;
	return r >= 0n ? r : r + m;
}

export function isOnCurve(p: AffinePoint): boolean {
	const lhs = mod(p.y * p.y, P);
	const rhs = mod(p.x * p.x * p.x + A * p.x + B, P);
	return lhs === rhs;
}

export function invmod(a: bigint, m: bigint): bigint {
	// Fermat's little theorem; m (= P here) is prime.
	let base = mod(a, m);
	let result = 1n;
	let exp = m - 2n;
	while (exp > 0n) {
		if (exp & 1n) result = mod(result * base, m);
		base = mod(base * base, m);
		exp >>= 1n;
	}
	return result;
}

/// 弦 (xián) "the chord" — addition of two DISTINCT points.
export function chordAdd(p1: AffinePoint, p2: AffinePoint): AffinePoint {
	const slope = mod((p2.y - p1.y) * invmod(mod(p2.x - p1.x, P), P), P);
	const x3 = mod(slope * slope - p1.x - p2.x, P);
	const y3 = mod(slope * (p1.x - x3) - p1.y, P);
	return {x: x3, y: y3};
}

/// 切 (qiē) "the tangent" — doubling a single point. StarkWare's five
/// constant points are all off the curve's (nonexistent, since p is odd
/// and b was tuned so no low-order points arise from this construction)
/// order-2 locus, so the y=0 vertical-tangent case never arises here in
/// practice — but the guard stays, same discipline as toyCurve.ts's.
export function tangentDouble(p1: AffinePoint): AffinePoint {
	if (p1.y === 0n) throw new Error('tangentDouble: vertical tangent, not expected for Pedersen');
	const slope = mod((3n * p1.x * p1.x + A) * invmod(mod(2n * p1.y, P), P), P);
	const x3 = mod(slope * slope - 2n * p1.x, P);
	const y3 = mod(slope * (p1.x - x3) - p1.y, P);
	return {x: x3, y: y3};
}

/// 加 (jiā) "to add" — general point addition: inverse cancellation (never
/// hit while hashing, kept for completeness/symmetry with the Yul side),
/// then dispatch to chord/tangent.
export function add(p1: AffinePoint, p2: AffinePoint): AffinePoint {
	if (p1.x === p2.x && mod(p1.y + p2.y, P) === 0n) {
		throw new Error('add: P + (-P) is not expected while computing a Pedersen hash');
	}
	if (p1.x === p2.x && p1.y === p2.y) return tangentDouble(p1);
	return chordAdd(p1, p2);
}

// The five "nothing up my sleeve" constant points, in the order StarkWare
// publishes them: [shift_point, P0, P1, P2, P3].
export const SHIFT_POINT: AffinePoint = {
	x: 2089986280348253421170679821480865132823066470938446095505822317253594081284n,
	y: 1713931329540660377023406109199410414810705867260802078187082345529207694986n,
};
export const P0: AffinePoint = {
	x: 996781205833008774514500082376783249102396023663454813447423147977397232763n,
	y: 1668503676786377725805489344771023921079126552019160156920634619255970485781n,
};
export const P1: AffinePoint = {
	x: 2251563274489750535117886426533222435294046428347329203627021249169616184184n,
	y: 1798716007562728905295480679789526322175868328062420237419143593021674992973n,
};
export const P2: AffinePoint = {
	x: 2138414695194151160943305727036575959195309218611738193261179310511854807447n,
	y: 113410276730064486255102093846540133784865286929052426931474106396135072156n,
};
export const P3: AffinePoint = {
	x: 2379962749567351885752724891227938183011949129833673362440656643086021394946n,
	y: 776496453633298175483985398648758586525933812536653089401905292063708816422n,
};

/// Walks `steps` low bits of `value`, folding a running doubled `basis`
/// point into `point` whenever the current bit is set — the fused form of
/// StarkWare's separate "precompute a table of doublings" + "walk the
/// table" steps: a Yul contract has no persistent state to precompute
/// into ahead of a call, so the doubling happens inline here instead,
/// fresh every call.
function walk(point: AffinePoint, value: bigint, basis: AffinePoint, steps: number): AffinePoint {
	let acc = point;
	let b = basis;
	let v = value;
	for (let i = 0; i < steps; i++) {
		if (v & 1n) {
			if (b.x === acc.x && b.y === acc.y) {
				throw new Error(
					'walk: accumulator collided with a basis point — this would leak a discrete-log ' +
						'relation between the "nothing up my sleeve" generators and is a genuine break, ' +
						'not a toy-scale caveat',
				);
			}
			acc = add(acc, b);
		}
		v >>= 1n;
		b = tangentDouble(b);
	}
	return acc;
}

/// Starknet's Pedersen hash of two field elements, matching
/// `@scure/starknet`'s `pedersen(x, y)` (which returns the x-coordinate as
/// hex; this returns it as a bigint — the same value).
export function pedersen(x: bigint, y: bigint): bigint {
	if (!(x >= 0n && x < P)) throw new RangeError(`pedersen: x out of range [0, P): ${x}`);
	if (!(y >= 0n && y < P)) throw new RangeError(`pedersen: y out of range [0, P): ${y}`);
	let point = SHIFT_POINT;
	point = walk(point, x, P0, 248);
	point = walk(point, x >> 248n, P1, 4);
	point = walk(point, y, P2, 248);
	point = walk(point, y >> 248n, P3, 4);
	return point.x;
}
