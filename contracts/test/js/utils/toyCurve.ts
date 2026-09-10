// Pure-JS/bigint mirror of the point arithmetic implemented in
// src/grimoire/ToyCurveECDH/ToyCurveECDH.yul — see that file's header for
// the full glossary and the curve's derivation. Used both to generate
// known-answer vectors (../../../scripts/gen-toy-curve-vectors.ts) and as
// an independent cross-check in ../ToyCurveECDH.test.ts.
//
// Curve: y^2 = x^3 + 2x + 2 (mod 17) — Hankerson/Menezes/Vanstone's
// textbook toy curve. `enumeratePoints` below brute-forces the group
// rather than assuming its order: it finds exactly 18 affine points, so
// the group (points + the point at infinity) has order 19 — prime, so
// every non-identity point generates the whole group, and (since 19 is
// odd) no point ever has y = 0, which is what makes (0n, 0n) a safe,
// always-unambiguous encoding for the point at infinity O everywhere
// below.

export const P = 17n;
export const A = 2n;
export const B = 2n;
export const N = 19n; // group order — verified by enumeratePoints(), not assumed
export const G: AffinePoint = {x: 5n, y: 1n};

export interface AffinePoint {
	x: bigint;
	y: bigint;
}
// The point at infinity O is represented as `null` here (JS side) and as
// (0n, 0n) on the Yul side — see the header note above for why (0,0) is
// safe there. `toWire`/`fromWire` below convert between the two.
export type Point = AffinePoint | null;

export function mod(a: bigint, m: bigint): bigint {
	const r = a % m;
	return r >= 0n ? r : r + m;
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

/// Brute-force-enumerates every affine point on the curve — the source of
/// truth for the group's order, not a cross-check against an assumed one.
export function enumeratePoints(): AffinePoint[] {
	const pts: AffinePoint[] = [];
	for (let x = 0n; x < P; x++) {
		const rhs = mod(x * x * x + A * x + B, P);
		for (let y = 0n; y < P; y++) {
			if (mod(y * y, P) === rhs) pts.push({x, y});
		}
	}
	return pts;
}

/// 弦 (xián) "the chord" — addition of two DISTINCT points.
export function chordAdd(p1: AffinePoint, p2: AffinePoint): Point {
	const slope = mod((p2.y - p1.y) * invmod(mod(p2.x - p1.x, P), P), P);
	const x3 = mod(slope * slope - p1.x - p2.x, P);
	const y3 = mod(slope * (p1.x - x3) - p1.y, P);
	return {x: x3, y: y3};
}

/// 切 (qiē) "the tangent" — doubling a single point.
export function tangentDouble(p1: AffinePoint): Point {
	if (p1.y === 0n) return null; // vertical tangent -> O (never hit on this curve, see header)
	const slope = mod((3n * p1.x * p1.x + A) * invmod(mod(2n * p1.y, P), P), P);
	const x3 = mod(slope * slope - 2n * p1.x, P);
	const y3 = mod(slope * (p1.x - x3) - p1.y, P);
	return {x: x3, y: y3};
}

/// 加 (jiā) "to add" — general point addition: identity, inverse
/// cancellation, then dispatch to chord/tangent.
export function add(p1: Point, p2: Point): Point {
	if (p1 === null) return p2;
	if (p2 === null) return p1;
	if (p1.x === p2.x && mod(p1.y + p2.y, P) === 0n) return null; // P + (-P) = O
	if (p1.x === p2.x && p1.y === p2.y) return tangentDouble(p1);
	return chordAdd(p1, p2);
}

/// 乘 (chéng) "to multiply" — scalar multiplication via double-and-add.
export function multiply(k: bigint, p: Point): Point {
	let result: Point = null;
	let addend = p;
	let n = mod(k, N);
	while (n > 0n) {
		if (n & 1n) result = add(result, addend);
		addend = add(addend, addend);
		n >>= 1n;
	}
	return result;
}

/// 生 (shēng) "to beget" — derive a public point from a private scalar.
export function generate(priv: bigint): Point {
	return multiply(priv, G);
}

/// 合 (hé) "to unite" — the ECDH shared point.
export function unite(priv: bigint, theirPublic: Point): Point {
	return multiply(priv, theirPublic);
}

/// The Yul contract's calling convention: O is (0n, 0n), never `null`.
export function toWire(p: Point): AffinePoint {
	return p ?? {x: 0n, y: 0n};
}
export function fromWire(p: AffinePoint): Point {
	return p.x === 0n && p.y === 0n ? null : p;
}
