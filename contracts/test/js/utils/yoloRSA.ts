// Pure-JS/bigint mirror of the (deliberately broken) textbook RSA
// implemented in src/grimoire/YoloRSA/YoloRSA.sol and re-inlined in
// src/grimoire/YoloRSA/YoloRSAAccount.yul — see YoloRSA.sol's header for
// the padding-scheme caveat this all inherits. Covers both sides of the
// exercise: keygen/sign (the wallet owner's side, entirely off-chain, a
// real d never touches a contract or script argument on-chain) and
// factor/crack (the attacker's side — trial division then Pollard's rho,
// used both to size each difficulty tier and as the reference "how someone
// actually breaks this" path).

import {randomBytes} from 'node:crypto';

export function modpow(base: bigint, exponent: bigint, modulus: bigint): bigint {
	if (modulus === 1n) return 0n;
	let result = 1n;
	let b = ((base % modulus) + modulus) % modulus;
	let e = exponent;
	while (e > 0n) {
		if (e & 1n) result = (result * b) % modulus;
		e >>= 1n;
		b = (b * b) % modulus;
	}
	return result;
}

function egcd(a: bigint, b: bigint): {g: bigint; x: bigint; y: bigint} {
	if (b === 0n) return {g: a, x: 1n, y: 0n};
	const {g, x: x1, y: y1} = egcd(b, a % b);
	return {g, x: y1, y: x1 - (a / b) * y1};
}

export function modinv(a: bigint, m: bigint): bigint {
	const {g, x} = egcd(((a % m) + m) % m, m);
	if (g !== 1n) throw new Error(`modinv(${a}, ${m}): not coprime`);
	return ((x % m) + m) % m;
}

function gcd(a: bigint, b: bigint): bigint {
	while (b > 0n) {
		[a, b] = [b, a % b];
	}
	return a;
}

// Deterministic Miller-Rabin against the first 12 primes as witnesses —
// exact (not just probable) for every n this module will ever generate or
// factor, since that witness set is proven correct for n < ~2^81
// (3,317,044,064,679,887,385,961,981), comfortably above the ~90-bit
// ceiling of even the largest yolo tier.
const MR_WITNESSES = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n];

export function isProbablePrime(n: bigint): boolean {
	if (n < 2n) return false;
	for (const p of MR_WITNESSES) {
		if (n === p) return true;
		if (n % p === 0n) return false;
	}
	let d = n - 1n;
	let r = 0n;
	while (d % 2n === 0n) {
		d /= 2n;
		r += 1n;
	}
	witnessLoop: for (const a of MR_WITNESSES) {
		let x = modpow(a, d, n);
		if (x === 1n || x === n - 1n) continue;
		for (let i = 1n; i < r; i++) {
			x = (x * x) % n;
			if (x === n - 1n) continue witnessLoop;
		}
		return false;
	}
	return true;
}

function randomOddBigInt(bits: number): bigint {
	const bytes = Math.ceil(bits / 8);
	const excess = bytes * 8 - bits;
	const buf = randomBytes(bytes);
	buf[0]! &= 0xff >> excess; // clear bits above the requested width
	buf[0]! |= 1 << (7 - excess); // set the top bit -> exactly `bits` bits long
	buf[bytes - 1]! |= 1; // force odd (a prime candidate)
	let n = 0n;
	for (const byte of buf) n = (n << 8n) | BigInt(byte);
	return n;
}

export function randomPrime(bits: number): bigint {
	for (;;) {
		const candidate = randomOddBigInt(bits);
		if (isProbablePrime(candidate)) return candidate;
	}
}

export interface RSAKeypair {
	n: bigint;
	e: bigint;
	d: bigint;
	p: bigint;
	q: bigint;
}

/** 65537 if it fits and is coprime to phi (the real-world default); otherwise the smallest odd e >= 3 that is. Tiny yolo tiers never have room for 65537 — phi itself is smaller than that. */
function chooseExponent(phi: bigint): bigint {
	if (65537n < phi && gcd(65537n, phi) === 1n) return 65537n;
	for (let e = 3n; e < phi; e += 2n) {
		if (gcd(e, phi) === 1n) return e;
	}
	throw new Error(`No valid exponent found for phi=${phi}`);
}

/**
 * Generate a keypair with `n` at roughly `nBits` total bits (p, q each
 * ~nBits/2, distinct). Deliberately tiny — see YoloRSA.sol's header for why
 * that's the entire point, not a bug.
 */
export function generateKeypair(nBits: number): RSAKeypair {
	const halfLo = Math.max(2, Math.floor(nBits / 2));
	const halfHi = nBits - halfLo;
	let p: bigint, q: bigint, n: bigint, phi: bigint;
	do {
		p = randomPrime(halfLo);
		q = randomPrime(halfHi);
	} while (p === q);
	n = p * q;
	phi = (p - 1n) * (q - 1n);
	const e = chooseExponent(phi);
	const d = modinv(e, phi);
	return {n, e, d, p, q};
}

/**
 * The message representative: `m = msgHash mod n`. Not a real padding
 * scheme — see YoloRSA.sol's header for why none of these moduli have room
 * for one, and why that's an intentional extra weakness, not an oversight.
 */
export function messageRepresentative(msgHash: bigint, n: bigint): bigint {
	return ((msgHash % n) + n) % n;
}

/** Sign off-chain: s = m^d mod n. `d` must never leave this process. */
export function sign(msgHash: bigint, d: bigint, n: bigint): bigint {
	return modpow(messageRepresentative(msgHash, n), d, n);
}

/** Verify: accept iff s < n and s^e mod n == m. Mirrors YoloRSA.sol/YoloRSAAccount.yul exactly. */
export function verify(msgHash: bigint, signature: bigint, e: bigint, n: bigint): boolean {
	if (signature < 0n || signature >= n) return false;
	return modpow(signature, e, n) === messageRepresentative(msgHash, n);
}

function trialDivision(n: bigint, limit = 2_000_000n): bigint | null {
	if (n % 2n === 0n) return 2n;
	for (let f = 3n; f <= limit && f * f <= n; f += 2n) {
		if (n % f === 0n) return f;
	}
	return null;
}

function pollardRhoF(x: bigint, n: bigint): bigint {
	return (x * x + 1n) % n;
}

function pollardRho(n: bigint): bigint | null {
	if (n % 2n === 0n) return 2n;
	let x = 2n;
	let y = 2n;
	let d = 1n;
	while (d === 1n) {
		x = pollardRhoF(x, n);
		y = pollardRhoF(pollardRhoF(y, n), n);
		const diff = x > y ? x - y : y - x;
		d = gcd(diff, n);
	}
	return d === n ? null : d;
}

/**
 * The reference "attacker": factor `n` into its two prime factors via
 * trial division (catches anything with a small factor near-instantly),
 * falling back to Pollard's rho. Used both to size each tier's difficulty
 * and as the actual crack path against a deployed wallet.
 */
export function factor(n: bigint): {p: bigint; q: bigint} {
	let f = trialDivision(n);
	if (f === null) f = pollardRho(n);
	if (f === null || f === 1n || f === n) {
		throw new Error(`Failed to factor ${n} — try a stronger method (SIQS/ECM) for this tier.`);
	}
	const other = n / f;
	return f < other ? {p: f, q: other} : {p: other, q: f};
}

/** Reconstruct the private exponent from a cracked n = p*q — the step right after factor(). */
export function crackPrivateExponent(p: bigint, q: bigint, e: bigint): bigint {
	const phi = (p - 1n) * (q - 1n);
	return modinv(e, phi);
}
