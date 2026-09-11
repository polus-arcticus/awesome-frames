// ML-KEM-512 (FIPS 203) — a real, full-size key-encapsulation mechanism,
// not a shrunk toy. Where ToyCurveECDH/YoloRSA get their pedagogy by
// shrinking a real scheme down to hand-verifiable size, that move doesn't
// work here: Module-LWE's hardness genuinely depends on the ring dimension
// (n=256) and modulus (q=3329) FIPS 203 specifies — shrink either and
// there's no meaningful "hard problem" left to illustrate, only a broken
// toy. So this file runs the real algorithm at real size, and earns its
// place in the grimoire a different way: every algorithm below is
// commented with its exact FIPS 203 algorithm number, and every subtle
// convention choice this repo's own author got wrong on a first pass —
// the K-byte domain separator in G(d‖k), the transposed j‖i (not i‖j)
// byte order in SampleNTT's seed, Â used directly in K-PKE.KeyGen but
// Â^T in K-PKE.Encrypt — was checked against the actual FIPS 203 PDF
// (NIST.FIPS.203, csrc.nist.gov) before being trusted, not assumed from
// memory. This is deriving from the primary standard, the same discipline
// LightningRSA.sol applies to RFC 8017 — not a port of an existing
// implementation.
//
// Ground truth: every function here is cross-checked byte-for-byte against
// @noble/post-quantum's `ml_kem512` — see scripts/gen-ml-kem-vectors.ts.
// Real, audited implementation; the same role @noble/curves plays for
// BIP-340 in this repo.
//
// The hard problem (Module-LWE): given a public matrix Â and a "noisy"
// linear system t̂ = Â∘ŝ + ê (ŝ, ê small/secret), recovering ŝ is believed
// hard — Gaussian elimination fails because the noise ê prevents exact
// linear-algebra recovery. Encryption (K-PKE) encodes one bit per
// coefficient of a 256-coefficient polynomial by nudging a "combined noisy
// equation" either close to 0 (bit 0) or close to q/2 (bit 1) —
// Compress/Decompress's whole reason to exist is deciding how much of that
// nudge survives lossy serialization without corrupting which side of q/2
// a coefficient lands on. ML-KEM = K-PKE (not IND-CCA2-secure alone, FIPS
// 203 §3.3 is explicit K-PKE "shall not" be used standalone) wrapped in a
// Fujisaki-Okamoto transform: decapsulation re-encrypts and checks the
// ciphertext matches, falling back to a pseudorandom "implicit rejection"
// value on mismatch rather than ever raising a distinguishable decryption
// error — the error itself would otherwise leak information (a real,
// historical attack class against RSA-OAEP-style schemes without this
// discipline).
//
// The NTT: X^256+1 has no primitive 256th root that splits it into 256
// linear factors mod q=3329 (that would need q ≡ 1 mod 512; 3329-1=3328
// isn't a multiple of 512) — it splits into 128 *quadratic* factors
// instead (FIPS 203 eq. 4.10), so polynomial multiplication in the
// transformed domain needs a degree-2 "base case" multiply (Algorithm 12),
// not simple pointwise multiplication — the one place this NTT differs
// from a textbook full NTT.
//
// Not constant-time, not for production — same disclaimer as every other
// grimoire entry, doubly true here: real ML-KEM implementations spend
// enormous effort on timing-safe sampling/comparison this file makes no
// attempt at.

import {sha3_256, sha3_512, shake128, shake256} from '@noble/hashes/sha3.js';

// ── FIPS 203 Table 2: ML-KEM-512 parameters ──
const N = 256;
const Q = 3329;
const K = 2;
const ETA1 = 3;
const ETA2 = 2;
const DU = 10;
const DV = 4;

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

/** Forces a fresh, plain-ArrayBuffer-backed copy — only needed at the
 * exported-function boundary, where TS's `Uint8Array<ArrayBufferLike>` vs.
 * `Uint8Array<ArrayBuffer>` generic split (a typings-only distinction,
 * unrelated to the actual bytes) would otherwise leak from internal
 * `.slice()`/hash calls into values callers pass on to a stricter-typed
 * library like @noble/post-quantum. */
function strict(a: Uint8Array): Uint8Array {
	return new Uint8Array(a);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
	return diff === 0;
}

// ── §4.1 Cryptographic function wrappers ──
const H = (s: Uint8Array): Uint8Array => sha3_256(s);
const J = (s: Uint8Array): Uint8Array => shake256(s, {dkLen: 32});
function G(c: Uint8Array): [Uint8Array, Uint8Array] {
	const out = sha3_512(c);
	return [out.slice(0, 32), out.slice(32, 64)];
}
function PRF(eta: number, s: Uint8Array, b: number): Uint8Array {
	return shake256(concatBytes(s, Uint8Array.of(b)), {dkLen: 64 * eta});
}
/** XOF wrapper (§4.1): a streaming SHAKE128 context, absorb once then squeeze repeatedly. */
function xofInit(seed: Uint8Array) {
	return shake128.create({}).update(seed);
}

// ── Algorithms 3-4: BitsToBytes / BytesToBits ──
function bitsToBytes(b: Uint8Array): Uint8Array {
	const B = new Uint8Array(b.length / 8);
	for (let i = 0; i < b.length; i++) {
		B[i >> 3]! += b[i]! * 2 ** (i % 8);
	}
	return B;
}
function bytesToBits(B: Uint8Array): Uint8Array {
	const b = new Uint8Array(B.length * 8);
	for (let i = 0; i < B.length; i++) {
		let c = B[i]!;
		for (let j = 0; j < 8; j++) {
			b[8 * i + j] = c % 2;
			c = (c - b[8 * i + j]!) / 2;
		}
	}
	return b;
}

// ── §4.2.1 Compress/Decompress (4.7)/(4.8) — integer round-half-up,
// no floating point (per FIPS 203's own "shall not use floating-point
// arithmetic" requirement): round(a/b) = floor((2a+b)/(2b)). ──
function compress(x: number, d: number): number {
	const m = 1 << d;
	return Math.floor((2 * x * m + Q) / (2 * Q)) % m;
}
function decompress(y: number, d: number): number {
	const m = 1 << d;
	return Math.floor((2 * y * Q + m) / (2 * m));
}

// ── Algorithms 5-6: ByteEncode_d / ByteDecode_d ──
function byteEncode(F: readonly number[], d: number): Uint8Array {
	const bits = new Uint8Array(N * d);
	for (let i = 0; i < N; i++) {
		let a = F[i]!;
		for (let j = 0; j < d; j++) {
			bits[i * d + j] = a % 2;
			a = (a - bits[i * d + j]!) / 2; // always even, per FIPS 203's own note on this line
		}
	}
	return bitsToBytes(bits);
}
function byteDecode(B: Uint8Array, d: number): number[] {
	const bits = bytesToBits(B);
	const m = d === 12 ? Q : 1 << d;
	const F: number[] = new Array(N);
	for (let i = 0; i < N; i++) {
		let val = 0;
		for (let j = 0; j < d; j++) val += bits[i * d + j]! * (1 << j);
		F[i] = val % m;
	}
	return F;
}

// ── Algorithm 7: SampleNTT — uniform rejection sampling from a XOF stream ──
function sampleNTT(seed: Uint8Array): number[] {
	const xof = xofInit(seed);
	const a: number[] = new Array(N);
	let j = 0;
	while (j < N) {
		const C = xof.xof(3);
		const d1 = C[0]! + 256 * (C[1]! % 16);
		const d2 = Math.floor(C[1]! / 16) + 16 * C[2]!;
		if (d1 < Q) a[j++] = d1;
		if (d2 < Q && j < N) a[j++] = d2;
	}
	return a;
}

// ── Algorithm 8: SamplePolyCBD_eta — centered binomial noise ──
function samplePolyCBD(B: Uint8Array, eta: number): number[] {
	const b = bytesToBits(B);
	const f: number[] = new Array(N);
	for (let i = 0; i < N; i++) {
		let x = 0;
		let y = 0;
		for (let j = 0; j < eta; j++) x += b[2 * i * eta + j]!;
		for (let j = 0; j < eta; j++) y += b[2 * i * eta + eta + j]!;
		f[i] = (((x - y) % Q) + Q) % Q;
	}
	return f;
}

// ── §4.3: the zeta table ζ^BitRev7(i) mod q, ζ=17 — used by NTT/NTT^-1 ──
function bitRev7(x: number): number {
	let r = 0;
	for (let i = 0; i < 7; i++) {
		r = (r << 1) | (x & 1);
		x >>= 1;
	}
	return r;
}
function modPow(base: number, exp: number, mod: number): number {
	let result = 1;
	let b = base % mod;
	while (exp > 0) {
		if (exp & 1) result = (result * b) % mod;
		exp >>= 1;
		b = (b * b) % mod;
	}
	return result;
}
const ZETA = Array.from({length: 128}, (_, i) => modPow(17, bitRev7(i), Q));
// The exponent for BaseCaseMultiply's gamma (Algorithm 11's own formula,
// not a table-reuse shortcut): zeta^(2*BitRev7(i)+1) mod q, for i=0..127.
const GAMMA = Array.from({length: 128}, (_, i) => modPow(17, 2 * bitRev7(i) + 1, Q));

// ── Algorithms 9-10: NTT / NTT^-1 ──
function ntt(f: readonly number[]): number[] {
	const r = f.slice();
	let i = 1;
	for (let len = 128; len >= 2; len /= 2) {
		for (let start = 0; start < N; start += 2 * len) {
			const zeta = ZETA[i++]!;
			for (let j = start; j < start + len; j++) {
				const t = (zeta * r[j + len]!) % Q;
				r[j + len] = ((r[j]! - t) % Q + Q) % Q;
				r[j] = (r[j]! + t) % Q;
			}
		}
	}
	return r;
}
function nttInv(f: readonly number[]): number[] {
	const r = f.slice();
	let i = 127;
	for (let len = 2; len <= 128; len *= 2) {
		for (let start = 0; start < N; start += 2 * len) {
			const zeta = ZETA[i--]!;
			for (let j = start; j < start + len; j++) {
				const t = r[j]!;
				r[j] = (t + r[j + len]!) % Q;
				r[j + len] = (zeta * (((r[j + len]! - t) % Q) + Q)) % Q;
			}
		}
	}
	return r.map((c) => (c * 3303) % Q); // 3303 = 128^-1 mod q
}

// ── Algorithms 11-12: MultiplyNTTs / BaseCaseMultiply ──
function multiplyNTTs(f: readonly number[], g: readonly number[]): number[] {
	const h: number[] = new Array(N);
	for (let i = 0; i < 128; i++) {
		const [a0, a1] = [f[2 * i]!, f[2 * i + 1]!];
		const [b0, b1] = [g[2 * i]!, g[2 * i + 1]!];
		const gamma = GAMMA[i]!;
		h[2 * i] = (a0 * b0 + a1 * b1 * gamma) % Q;
		h[2 * i + 1] = (a0 * b1 + a1 * b0) % Q;
	}
	return h;
}

// ── Vector/matrix helpers over T_q (§2.4.6-2.4.8) ──
type Poly = number[];
function polyAdd(a: readonly number[], b: readonly number[]): Poly {
	return a.map((v, i) => (v + b[i]!) % Q);
}
function polySub(a: readonly number[], b: readonly number[]): Poly {
	return a.map((v, i) => (((v - b[i]!) % Q) + Q) % Q);
}
function vecNTT(v: readonly Poly[]): Poly[] {
	return v.map(ntt);
}
function vecNTTInv(v: readonly Poly[]): Poly[] {
	return v.map(nttInv);
}
/** ŵ ← Â∘û (2.12): ŵ[i] = Σ_j Â[i,j] × û[j] */
function matVecMul(M: readonly Poly[][], v: readonly Poly[]): Poly[] {
	return M.map((row) => row.reduce((acc, Mij, j) => polyAdd(acc, multiplyNTTs(Mij, v[j]!)), new Array(N).fill(0)));
}
/** ŷ ← Â^T∘û (2.13): ŷ[i] = Σ_j Â[j,i] × û[j] */
function matTransposeVecMul(M: readonly Poly[][], v: readonly Poly[]): Poly[] {
	const k = v.length;
	const out: Poly[] = [];
	for (let i = 0; i < k; i++) {
		let acc = new Array(N).fill(0);
		for (let j = 0; j < k; j++) acc = polyAdd(acc, multiplyNTTs(M[j]![i]!, v[j]!));
		out.push(acc);
	}
	return out;
}
/** ẑ ← û^T∘v̂ (2.14): dot product, single-poly result */
function vecDot(u: readonly Poly[], v: readonly Poly[]): Poly {
	return u.reduce((acc, ui, i) => polyAdd(acc, multiplyNTTs(ui, v[i]!)), new Array(N).fill(0));
}

// ── §5: K-PKE ("shall not be used standalone" — FIPS 203 §3.3; only ever
// called as an ML-KEM subroutine below) ──

/** Algorithm 13: K-PKE.KeyGen(d) -> (ekPke, dkPke) */
function kPkeKeyGen(d: Uint8Array): {ekPke: Uint8Array; dkPke: Uint8Array} {
	const [rho, sigma] = G(concatBytes(d, Uint8Array.of(K))); // byte 33 = K, domain separator (footnote, p.29)
	let n = 0;
	const Ahat: Poly[][] = [];
	for (let i = 0; i < K; i++) {
		Ahat.push([]);
		for (let j = 0; j < K; j++) {
			// j then i — "j and i are bytes 33 and 34 of the input" (Algorithm 13, line 5)
			Ahat[i]!.push(sampleNTT(concatBytes(rho, Uint8Array.of(j, i))));
		}
	}
	const s: Poly[] = [];
	const e: Poly[] = [];
	for (let i = 0; i < K; i++) {
		s.push(samplePolyCBD(PRF(ETA1, sigma, n), ETA1));
		n++;
	}
	for (let i = 0; i < K; i++) {
		e.push(samplePolyCBD(PRF(ETA1, sigma, n), ETA1));
		n++;
	}
	const sHat = vecNTT(s);
	const eHat = vecNTT(e);
	const tHat = matVecMul(Ahat, sHat).map((p, i) => polyAdd(p, eHat[i]!));
	const ekPke = concatBytes(...tHat.map((p) => byteEncode(p, 12)), rho);
	const dkPke = concatBytes(...sHat.map((p) => byteEncode(p, 12)));
	return {ekPke, dkPke};
}

/** Algorithm 14: K-PKE.Encrypt(ekPke, m, r) -> ciphertext */
function kPkeEncrypt(ekPke: Uint8Array, m: Uint8Array, r: Uint8Array): Uint8Array {
	let n = 0;
	const tHat: Poly[] = [];
	for (let i = 0; i < K; i++) tHat.push(byteDecode(ekPke.slice(i * 384, (i + 1) * 384), 12));
	const rho = ekPke.slice(384 * K, 384 * K + 32);

	const Ahat: Poly[][] = [];
	for (let i = 0; i < K; i++) {
		Ahat.push([]);
		for (let j = 0; j < K; j++) Ahat[i]!.push(sampleNTT(concatBytes(rho, Uint8Array.of(j, i))));
	}

	const y: Poly[] = [];
	const e1: Poly[] = [];
	for (let i = 0; i < K; i++) {
		y.push(samplePolyCBD(PRF(ETA1, r, n), ETA1));
		n++;
	}
	for (let i = 0; i < K; i++) {
		e1.push(samplePolyCBD(PRF(ETA2, r, n), ETA2));
		n++;
	}
	const e2 = samplePolyCBD(PRF(ETA2, r, n), ETA2);

	const yHat = vecNTT(y);
	const u = vecNTTInv(matTransposeVecMul(Ahat, yHat)).map((p, i) => polyAdd(p, e1[i]!));
	const mu = byteDecode(m, 1).map((v) => decompress(v, 1));
	const v = polyAdd(polyAdd(nttInv(vecDot(tHat, yHat)), e2), mu);

	const c1 = concatBytes(...u.map((p) => byteEncode(p.map((x) => compress(x, DU)), DU)));
	const c2 = byteEncode(v.map((x) => compress(x, DV)), DV);
	return concatBytes(c1, c2);
}

/** Algorithm 15: K-PKE.Decrypt(dkPke, c) -> message */
function kPkeDecrypt(dkPke: Uint8Array, c: Uint8Array): Uint8Array {
	const c1 = c.slice(0, 32 * DU * K);
	const c2 = c.slice(32 * DU * K, 32 * (DU * K + DV));
	const u: Poly[] = [];
	for (let i = 0; i < K; i++) {
		const chunk = c1.slice(i * 32 * DU, (i + 1) * 32 * DU);
		u.push(byteDecode(chunk, DU).map((y) => decompress(y, DU)));
	}
	const vPrime = byteDecode(c2, DV).map((y) => decompress(y, DV));
	const sHat: Poly[] = [];
	for (let i = 0; i < K; i++) sHat.push(byteDecode(dkPke.slice(i * 384, (i + 1) * 384), 12));
	const w = polySub(vPrime, nttInv(vecDot(sHat, vecNTT(u))));
	return byteEncode(
		w.map((x) => compress(x, 1)),
		1,
	);
}

// ── §6-7: ML-KEM, built on K-PKE + the Fujisaki-Okamoto transform ──

export interface MlKemKeypair {
	ek: Uint8Array; // encapsulation key, 800 bytes
	dk: Uint8Array; // decapsulation key, 1632 bytes
}

/** Algorithm 16: ML-KEM.KeyGen_internal(d, z). `seed` = d‖z, 64 bytes total (matches @noble/post-quantum's deterministic `keygen(seed)` convention). */
export function keygen(seed: Uint8Array): MlKemKeypair {
	if (seed.length !== 64) throw new Error('keygen: seed must be 64 bytes (d(32) || z(32))');
	const d = seed.slice(0, 32);
	const z = seed.slice(32, 64);
	const {ekPke, dkPke} = kPkeKeyGen(d);
	const ek = ekPke;
	const h = H(ek);
	const dk = concatBytes(dkPke, ek, h, z);
	return {ek: strict(ek), dk: strict(dk)};
}

/** Algorithm 17: ML-KEM.Encaps_internal(ek, m). Includes the §7.2 encapsulation-key check. */
export function encapsulate(ek: Uint8Array, m: Uint8Array): {sharedSecret: Uint8Array; cipherText: Uint8Array} {
	if (ek.length !== 384 * K + 32) throw new Error('encapsulate: bad encapsulation key length');
	const test = concatBytes(...Array.from({length: K}, (_, i) => byteEncode(byteDecode(ek.slice(i * 384, (i + 1) * 384), 12), 12)));
	if (!bytesEqual(test, ek.slice(0, 384 * K))) throw new Error('encapsulate: encapsulation key modulus check failed (7.2)');
	if (m.length !== 32) throw new Error('encapsulate: m must be 32 bytes');

	const [sharedSecret, r] = G(concatBytes(m, H(ek)));
	const cipherText = kPkeEncrypt(ek, m, r);
	return {sharedSecret: strict(sharedSecret), cipherText: strict(cipherText)};
}

/** Algorithm 18: ML-KEM.Decaps_internal(dk, c). Includes the §7.3 decapsulation input checks. */
export function decapsulate(c: Uint8Array, dk: Uint8Array): Uint8Array {
	if (c.length !== 32 * (DU * K + DV)) throw new Error('decapsulate: bad ciphertext length');
	if (dk.length !== 768 * K + 96) throw new Error('decapsulate: bad decapsulation key length');

	const dkPke = dk.slice(0, 384 * K);
	const ekPke = dk.slice(384 * K, 768 * K + 32);
	const h = dk.slice(768 * K + 32, 768 * K + 64);
	const z = dk.slice(768 * K + 64, 768 * K + 96);

	if (!bytesEqual(H(ekPke), h)) throw new Error('decapsulate: decapsulation key hash check failed (7.3)');

	const mPrime = kPkeDecrypt(dkPke, c);
	const [kPrime, rPrime] = G(concatBytes(mPrime, h));
	const kBar = J(concatBytes(z, c));
	const cPrime = kPkeEncrypt(ekPke, mPrime, rPrime);

	// Implicit rejection (FO transform): never raise a distinguishable
	// decryption error — fall back to a pseudorandom value on mismatch, so
	// a network attacker learns nothing from timing/error-shape alone.
	return strict(bytesEqual(c, cPrime) ? kPrime : kBar);
}
