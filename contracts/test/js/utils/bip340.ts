// Pure-JS mirror of the ecrecover-trick reduction implemented in
// src/BIP340/BIP340.sol (see that file's header comment, and
// nostr-frame-schnorr-design.md §5.1). Used to cross-check the reduction
// against signatures produced by independent BIP-340 implementations
// *before*, or independently of, exercising the Solidity code itself.
import {secp256k1} from '@noble/curves/secp256k1.js';
import {sha256} from '@noble/hashes/sha2.js';
import {keccak_256} from '@noble/hashes/sha3.js';

const CURVE = secp256k1.CURVE;
const N = CURVE.n; // group order
const Point = secp256k1.ProjectivePoint;

export function bytesToHex(b: Uint8Array): string {
	return '0x' + Buffer.from(b).toString('hex');
}
export function beBytes(x: bigint): Uint8Array {
	return Buffer.from(x.toString(16).padStart(64, '0'), 'hex');
}
export function mod(a: bigint, m: bigint): bigint {
	const r = a % m;
	return r >= 0n ? r : r + m;
}
export function invmod(a: bigint, m: bigint): bigint {
	// Fermat: m is prime for both N and P here.
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

// BIP-340 tagged hash: sha256(sha256(tag) || sha256(tag) || data)
export function taggedHash(tag: string, ...chunks: Uint8Array[]): Uint8Array {
	const tagHash = sha256(Buffer.from(tag, 'utf8'));
	const total = Buffer.concat([tagHash, tagHash, ...chunks]);
	return sha256(total);
}

// The even-Y point at a given x-only coordinate — BIP-340's lift_x.
export function liftX(xBytes: Uint8Array): InstanceType<typeof Point> {
	const compressed = Buffer.concat([Buffer.from([0x02]), Buffer.from(xBytes)]);
	return Point.fromHex(bytesToHex(compressed).slice(2));
}

// keccak256(P.x || P.y)[12:] — what the account stores as pAddress.
export function pointAddress(pt: InstanceType<typeof Point>): string {
	const aff = pt.toAffine();
	const xy = Buffer.concat([beBytes(aff.x), beBytes(aff.y)]);
	const hash = keccak_256(xy);
	return '0x' + Buffer.from(hash.slice(12)).toString('hex');
}

export interface Bip340Signature {
	px: string; // x-only pubkey, 0x-prefixed 32 bytes
	rx: string; // signature R.x, 0x-prefixed 32 bytes
	s: string; // signature s, 0x-prefixed 32 bytes
	message: string; // 0x-prefixed 32-byte message hash
}

/// Runs the same reduction BIP340.sol's `verify` performs, purely in JS
/// bigint arithmetic, and checks the recovered point equals P *exactly*
/// (Solidity only gets to compare 20-byte addresses).
export function verifyEcrecoverTrick(v: Bip340Signature): {
	recoveredEqualsP: boolean;
	recoveredAddress: string;
} {
	const rx = BigInt(v.rx);
	const s = BigInt(v.s);
	const px = BigInt(v.px);
	const msg = Buffer.from(v.message.slice(2), 'hex');

	const e = mod(
		BigInt(
			bytesToHex(
				taggedHash('BIP0340/challenge', beBytes(rx), beBytes(px), msg),
			),
		),
		N,
	);
	if (e === 0n) throw new Error('e == 0, degenerate vector');

	const eInv = invmod(e, N);
	const sEcdsa = mod(N - mod(rx * eInv, N), N); // -Rx * e^-1 mod n
	const z = mod(sEcdsa * s, N); // s_ecdsa * s mod n

	// Emulate ecrecover(z, v=27, r=Rx, s=sEcdsa):
	//   Q = r^-1 * (s_ecdsa * R_point - z * G)
	const R_point = liftX(beBytes(rx));
	const rInv = invmod(mod(rx, N), N);
	const term1 = R_point.multiply(sEcdsa);
	const term2 = Point.BASE.multiply(z);
	const Q = term1.add(term2.negate()).multiply(rInv);

	const P_point = liftX(beBytes(px));
	const recoveredEqualsP = Q.equals(P_point);
	const recoveredAddress = pointAddress(Q);
	return {recoveredEqualsP, recoveredAddress};
}
