// Lamport one-time signatures — hash-based, not lattice/code/isogeny-based
// like the rest of this grimoire's post-quantum survey. Filed under
// Vitalik's "even more esoteric" bucket, which is a little ironic once you
// look at it: hash-based signatures are the *most conservative* PQC
// family there is — security reduces entirely to the preimage resistance
// of a hash function, no number-theoretic or algebraic hardness
// assumption at all. "Esoteric" here means "structurally foreign to this
// repo's algebraic mainstream" (ToyCurveECDH/YoloRSA/LightningRSA/MlKem
// all lean on some ring or curve), not "obscure or fragile" — if
// anything, this is the one entry in the whole survey nobody seriously
// doubts the security model of.
//
// The mechanism (Lamport 1979): the secret key is 2·N_BITS random
// preimages, arranged as two parallel arrays (`zero[i]`, `one[i]`) — one
// pair per bit of whatever digest you're signing. The public key is each
// preimage hashed once. To sign a digest, reveal `secretKey.zero[i]` for
// every bit that's 0, `secretKey.one[i]` for every bit that's 1 — exactly
// N_BITS of the 2·N_BITS secrets, never both halves of any pair. To
// verify, hash each revealed preimage and check it matches the
// corresponding public value for that bit.
//
// N_BITS = 32, not the usual 256: a real Lamport keypair signs a full
// hash digest (256 bits -> 256 preimage pairs -> 512 total secrets) —
// secure, but too large to print and eyeball. Shrinking N_BITS to 32
// keeps the *preimages themselves* at a real, secure width (32 bytes
// each, hashed with real keccak256 — this repo's usual hash, tying it to
// the rest of the codebase) while cutting the *bit count being signed*
// down to something a reader can hold in their head: 32 pairs, 64 secret
// values, 64 public values. Same "shrink until human-scale, keep the real
// primitive" move YoloRSA makes with its RSA moduli.
//
// The one-time constraint IS the security model — a genuinely different
// shape of fragility than every other resident here. ToyCurveECDH/YoloRSA
// break because their *parameters* are small; a correctly-sized Lamport
// keypair never breaks from parameter size at all. It breaks the moment
// the SAME keypair signs a SECOND digest: an attacker holding two
// signatures has, for any bit position where the two digests disagree,
// *both* halves of that pair's secret — and once both halves of enough
// pairs leak, a signature for a third, never-signed digest can be forged
// outright. `forgeFromTwoSignatures` below is that attack, not a toy
// approximation of it.
//
// Not constant-time, not for production — same disclaimer as every other
// grimoire entry.

import {keccak_256} from '@noble/hashes/sha3.js';
import {randomBytes} from 'node:crypto';

const N_BITS = 32;
const PREIMAGE_BYTES = 32;

export interface LamportKeypair {
	secretKey: {zero: Uint8Array[]; one: Uint8Array[]};
	publicKey: {zero: Uint8Array[]; one: Uint8Array[]};
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
	return diff === 0;
}

/** Real preimages (32 random bytes each), real hashing (keccak256) — only the bit count signed is toy-sized. */
export function keygen(): LamportKeypair {
	const zeroSecrets = Array.from({length: N_BITS}, () => randomBytes(PREIMAGE_BYTES));
	const oneSecrets = Array.from({length: N_BITS}, () => randomBytes(PREIMAGE_BYTES));
	return {
		secretKey: {zero: zeroSecrets, one: oneSecrets},
		publicKey: {zero: zeroSecrets.map(keccak_256), one: oneSecrets.map(keccak_256)},
	};
}

/** Reduce an arbitrary-length message to the toy 32-bit digest this scheme actually signs — hash-then-sign, same shape as any real signature scheme. */
export function hashToDigest(message: Uint8Array): Uint8Array {
	return keccak_256(message).slice(0, 4); // 32 bits
}

function digestToBits(digest: Uint8Array): number[] {
	if (digest.length !== 4) throw new Error('digest must be exactly 4 bytes (32 bits)');
	const bits: number[] = [];
	for (const byte of digest) {
		for (let b = 7; b >= 0; b--) bits.push((byte >> b) & 1);
	}
	return bits;
}

/** Reveal exactly one preimage per bit position — never both halves of any pair. */
export function sign(digest: Uint8Array, secretKey: LamportKeypair['secretKey']): Uint8Array[] {
	return digestToBits(digest).map((bit, i) => (bit === 0 ? secretKey.zero[i]! : secretKey.one[i]!));
}

export function verify(digest: Uint8Array, signature: Uint8Array[], publicKey: LamportKeypair['publicKey']): boolean {
	if (signature.length !== N_BITS) return false;
	const bits = digestToBits(digest);
	for (let i = 0; i < N_BITS; i++) {
		const expected = bits[i] === 0 ? publicKey.zero[i]! : publicKey.one[i]!;
		if (!bytesEqual(keccak_256(signature[i]!), expected)) return false;
	}
	return true;
}

/**
 * The break: given two REAL signatures over two DIFFERENT digests from the
 * same keypair, forge a signature over any third digest — no factoring,
 * no discrete log, just reusing whichever of the two revealed preimages
 * happens to match each bit of the target. Guaranteed to succeed for
 * every bit position where the two source digests actually differ (that's
 * exactly where both halves of a pair got revealed); throws — rather than
 * silently failing — on any bit position where neither source digest
 * covers the target, so a caller can't mistake "forgery worked" for
 * "forgery got lucky on the bits that happened to overlap."
 */
export function forgeFromTwoSignatures(
	digest1: Uint8Array,
	sig1: Uint8Array[],
	digest2: Uint8Array,
	sig2: Uint8Array[],
	targetDigest: Uint8Array,
): Uint8Array[] {
	const bits1 = digestToBits(digest1);
	const bits2 = digestToBits(digest2);
	const targetBits = digestToBits(targetDigest);
	const forged: Uint8Array[] = [];
	for (let i = 0; i < N_BITS; i++) {
		if (targetBits[i] === bits1[i]) forged.push(sig1[i]!);
		else if (targetBits[i] === bits2[i]) forged.push(sig2[i]!);
		else throw new Error(`forgeFromTwoSignatures: bit ${i} of the target digest was never revealed by either signature`);
	}
	return forged;
}
