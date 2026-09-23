// Falcon-512 — verify() only, not the full scheme. Where MlKem got a
// full keygen/encaps/decaps build and Lamport got a full keygen/sign/
// verify build, Falcon stops at verification, for a real reason spelled
// out in the plan this followed: Falcon *signing* needs floating-point
// Gaussian sampling over the NTRU lattice (the "Falcon tree" FFT sampler)
// — a well-documented, genuinely hard-to-get-right-and-constant-time
// hazard that NIST's own FIPS 206 status updates cite as the main reason
// Falcon's standardization took longer than ML-KEM/ML-DSA's. FIPS 206 is
// still a Draft as of this writing (NIST's Initial Public Draft, August
// 2025; final expected late 2026/2027) — not yet the stable target this
// repo would want to derive against. Verification, by contrast, is pure
// integer/ring arithmetic, no floating point anywhere: it only needs to
// recompute s1 = c - s2·h mod q and check a norm bound. So this file
// derives from the *original*, long-stable Falcon submission spec
// (falcon-sign.info/falcon.pdf, v1.2, 2020-10-01 — the NIST round-3
// submission FIPS 206 is itself based on) rather than the still-moving
// draft, and only implements the half of the scheme that spec pins down
// with the same precision MlKem's derivation needed: HashToPoint
// (Algorithm 3), signature Decompress (Algorithm 18), and Verify
// (Algorithm 16) — transcribed and checked against that PDF directly, not
// assumed from memory. Keygen/sign are delegated entirely to
// @noble/post-quantum's `falcon512`, used here purely as a source of real
// keypairs and real signatures — the ground truth this file's `verify` is
// cross-checked against.
//
// The verification equation, in one line: a genuine signature (s1, s2)
// satisfies s1 + s2·h ≈ c (mod q) — recall from KeyGen that h = g·f⁻¹ mod
// q, so s1 + s2·h ≈ s1·f + s2·g, all divided by f — meaning a valid
// signature is, underneath, a *short* vector (s1, s2) that's close to a
// specific target lattice point (c, 0) in the NTRU lattice spanned by
// (f,g)/(F,G). Verification never touches that lattice structure directly
// — it just recomputes s1 from the public h and checks the resulting pair
// is short (‖(s1,s2)‖² ≤ β²). Producing a genuine SHORT (s1,s2) pair
// without knowing the trapdoor (f,g,F,G) is exactly the hard lattice
// problem (a form of the NTRU/Shortest-Vector Problem) Falcon's security
// rests on.
//
// n=512, q=12289: unlike MlKem's ring (n=256, q=3329, only a quadratic-
// factor NTT — see that file's header), Falcon's q satisfies q ≡ 1 mod
// 1024 = 2n, so x^512+1 splits into 512 *linear* factors and a full NTT
// is available — this file doesn't bother with one, though: verification
// is called once per signature, not in a hot loop, so plain O(n²)
// schoolbook negacyclic convolution (polyMulModQ below) is simpler to get
// right and just as correct, at the cost of speed this toy doesn't need.
//
// Not constant-time, not for production — same disclaimer as every other
// grimoire entry.

import {shake256} from '@noble/hashes/sha3.js';

const N = 512;
const Q = 12289;
const PUBLIC_KEY_BYTES = 897; // 1 header byte + ceil(14*512/8) = 1 + 896
const SIGNATURE_BYTES = 666; // Falcon-512's sbytelen (Table 3.3)
const MAX_SIGNATURE_SQUARE_NORM = 34_034_726; // ⌊β²⌋, Falcon-512, Table 3.3
const PUBLIC_KEY_HEADER = 0x09; // 0000 1001: n = 2^9 = 512
const SIGNATURE_HEADER = 0x39; // 0 01 1 1001: compressed encoding, n = 2^9 = 512

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
	const total = arrays.reduce((s, a) => s + a.length, 0);
	const out = new Uint8Array(total);
	let offset = 0;
	for (const a of arrays) {
		out.set(a, offset);
		offset += a.length;
	}
	return out;
}

/** §3.11.1 "Bits and Bytes": MSB-first within each byte — the opposite convention from FIPS 203's BitsToBytes/BytesToBits. */
function bytesToBitArray(bytes: Uint8Array): number[] {
	const bits: number[] = new Array(bytes.length * 8);
	for (let i = 0; i < bytes.length; i++) {
		for (let j = 0; j < 8; j++) bits[8 * i + j] = (bytes[i]! >> (7 - j)) & 1;
	}
	return bits;
}

/** Algorithm 3: HashToPoint(str, q, n) — SHAKE-256, big-endian 16-bit chunks, rejection sampling. */
function hashToPoint(data: Uint8Array): number[] {
	const k = Math.floor(65536 / Q); // ⌊2^16/q⌋
	const xof = shake256.create({}).update(data);
	const c: number[] = new Array(N);
	let i = 0;
	while (i < N) {
		const chunk = xof.xof(2);
		const t = (chunk[0]! << 8) | chunk[1]!;
		if (t < k * Q) c[i++] = t % Q;
	}
	return c;
}

/** Algorithm 18: Decompress(str, slen) — the compressed-signature codec (sign bit, 7 low bits, unary-coded high bits). Returns null (⊥) on any invalid/non-canonical encoding. */
function decompressSignature(strBits: readonly number[]): number[] | null {
	const s: number[] = new Array(N);
	let pos = 0;
	for (let i = 0; i < N; i++) {
		if (pos + 8 > strBits.length) return null;
		const sign = strBits[pos]!;
		let low = 0;
		for (let j = 0; j < 7; j++) low = (low << 1) | strBits[pos + 1 + j]!;

		let k = 0;
		for (;;) {
			const bitIndex = pos + 8 + k;
			if (bitIndex >= strBits.length) return null;
			if (strBits[bitIndex] === 1) break;
			k++;
			if (k > 2048) return null; // defensive bound against a malformed/adversarial encoding
		}

		const magnitude = low + 128 * k;
		const value = sign === 1 ? -magnitude : magnitude;
		if (value === 0 && sign === 1) return null; // reject non-canonical "-0"
		s[i] = value;
		pos += 9 + k;
	}
	for (; pos < strBits.length; pos++) if (strBits[pos] !== 0) return null; // trailing padding must be 0
	return s;
}

/** Negacyclic convolution mod (x^N+1, q) — schoolbook, O(n^2); see header for why no NTT here. */
function polyMulModQ(a: readonly number[], b: readonly number[]): number[] {
	const result = new Array(N).fill(0);
	for (let i = 0; i < N; i++) {
		for (let j = 0; j < N; j++) {
			const k = i + j;
			const prod = (a[i]! * b[j]!) % Q;
			if (k < N) result[k] = (result[k] + prod) % Q;
			else result[k - N] = ((result[k - N]! - prod) % Q + Q) % Q;
		}
	}
	return result;
}

/** Center a mod-q residue into (-q/2, q/2] — "s1 should be normalized" per Algorithm 16's own comment. */
function centerMod(x: number): number {
	const r = ((x % Q) + Q) % Q;
	return r > Q / 2 ? r - Q : r;
}

function parsePublicKey(publicKey: Uint8Array): number[] | null {
	if (publicKey.length !== PUBLIC_KEY_BYTES) return null;
	if (publicKey[0] !== PUBLIC_KEY_HEADER) return null;
	const bits = bytesToBitArray(publicKey.slice(1));
	const h: number[] = new Array(N);
	for (let i = 0; i < N; i++) {
		let v = 0;
		for (let j = 0; j < 14; j++) v = (v << 1) | bits[i * 14 + j]!;
		if (v >= Q) return null; // encoded values must be in [0, q)
		h[i] = v;
	}
	return h;
}

/** Algorithm 16: Verify(m, sig, pk, ⌊β²⌋) — cross-checked against real @noble/post-quantum falcon512 signatures, see scripts/gen-falcon-vectors.ts. */
export function verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
	const h = parsePublicKey(publicKey);
	if (h === null) return false;

	if (signature.length !== SIGNATURE_BYTES) return false;
	if (signature[0] !== SIGNATURE_HEADER) return false;
	const nonce = signature.slice(1, 41);
	const compressed = signature.slice(41);

	const slenBits = 8 * SIGNATURE_BYTES - 328; // Algorithm 16 line 2
	const strBits = bytesToBitArray(compressed).slice(0, slenBits);
	const s2 = decompressSignature(strBits);
	if (s2 === null) return false;

	const c = hashToPoint(concatBytes(nonce, message));
	const s2ModQ = s2.map((v) => ((v % Q) + Q) % Q);
	const hs2 = polyMulModQ(h, s2ModQ);
	const s1 = c.map((ci, i) => centerMod(ci - hs2[i]!));

	let normSq = 0;
	for (const v of s1) normSq += v * v;
	for (const v of s2) normSq += v * v;
	return normSq <= MAX_SIGNATURE_SQUARE_NORM;
}
