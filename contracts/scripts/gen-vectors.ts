// Generates real BIP-340 test vectors (via @noble/curves, an independent
// reference implementation) and numerically validates the ecrecover-trick
// reduction against them *before* it's trusted in Solidity — see design doc
// §5.1: "Do not trust the Solidity implementation as the source of truth for
// correctness."
//
// Run: pnpm tsx scripts/gen-vectors.ts

import {secp256k1, schnorr} from '@noble/curves/secp256k1.js';
import {sha256} from '@noble/hashes/sha2.js';
import {randomBytes} from '@noble/hashes/utils.js';
import {keccak_256} from '@noble/hashes/sha3.js';
import {writeFileSync} from 'node:fs';

const CURVE = secp256k1.CURVE;
const N = CURVE.n; // group order
const P = CURVE.p; // field prime
const Point = secp256k1.ProjectivePoint;

function bytesToHex(b: Uint8Array): string {
	return '0x' + Buffer.from(b).toString('hex');
}
function beBytes(x: bigint): Uint8Array {
	return Buffer.from(x.toString(16).padStart(64, '0'), 'hex');
}
function mod(a: bigint, m: bigint): bigint {
	const r = a % m;
	return r >= 0n ? r : r + m;
}
function invmod(a: bigint, m: bigint): bigint {
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
function taggedHash(tag: string, ...chunks: Uint8Array[]): Uint8Array {
	const tagHash = sha256(Buffer.from(tag, 'utf8'));
	const total = Buffer.concat([tagHash, tagHash, ...chunks]);
	return sha256(total);
}

// The even-Y point at a given x-only coordinate — BIP-340's lift_x.
function liftX(xBytes: Uint8Array): InstanceType<typeof Point> {
	const compressed = Buffer.concat([Buffer.from([0x02]), Buffer.from(xBytes)]);
	return Point.fromHex(bytesToHex(compressed).slice(2));
}

function pointAddress(pt: InstanceType<typeof Point>): string {
	const aff = pt.toAffine();
	const xy = Buffer.concat([beBytes(aff.x), beBytes(aff.y)]);
	const hash = keccak_256(xy);
	return '0x' + Buffer.from(hash.slice(12)).toString('hex');
}

interface Vector {
	description: string;
	px: string; // x-only pubkey, 32 bytes
	pAddress: string; // address(P) — precomputed, what the contract stores
	message: string; // 32-byte "message hash" the sig commits to
	rx: string; // signature R.x, 32 bytes
	s: string; // signature s, 32 bytes
	valid: boolean;
}

function makeVector(description: string, privKey: Uint8Array, msg: Uint8Array): Vector {
	const px = schnorr.getPublicKey(privKey); // 32 bytes, BIP-340 convention
	const sig = schnorr.sign(msg, privKey); // 64 bytes: Rx(32) || s(32)
	const rx = sig.slice(0, 32);
	const s = sig.slice(32, 64);

	// Sanity check against the reference implementation itself.
	if (!schnorr.verify(sig, msg, px)) {
		throw new Error('reference implementation rejected its own signature');
	}

	const P_point = liftX(px);
	const pAddress = pointAddress(P_point);

	return {
		description,
		px: bytesToHex(px),
		pAddress,
		message: bytesToHex(msg),
		rx: bytesToHex(rx),
		s: bytesToHex(s),
		valid: true,
	};
}

// --- Numerically validate the ecrecover-trick reduction (§5.1) ---
//
// BIP-340 verification equation:  s*G = R + e*P   (R, P both even-Y)
// Solve for P:                    P = e^-1 * s * G  -  e^-1 * R
// Match to ECDSA recovery Q = r^-1*(s_ecdsa*R_ecdsa - z*G), with R_ecdsa := R:
//   s_ecdsa = -Rx * e^-1        mod n     ("s" param to ecrecover)
//   z       = s_ecdsa * s       mod n     ("msgHash" param to ecrecover)
//   v = 27 (even-Y, matching R's mandatory BIP-340 parity)
// ecrecover(z, 27, Rx, s_ecdsa) should recover P; we check point equality
// directly here (Solidity only gets to compare addresses).
function verifyEcrecoverTrick(v: Vector): {recoveredEqualsP: boolean; recoveredAddress: string} {
	const rx = BigInt(v.rx);
	const s = BigInt(v.s);
	const px = BigInt(v.px);
	const msg = Buffer.from(v.message.slice(2), 'hex');

	const e = mod(BigInt(bytesToHex(taggedHash('BIP0340/challenge', beBytes(rx), beBytes(px), msg))), N);
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

const vectors: Vector[] = [];
const messages = [
	'nostr event id one, thirty two bytes!!',
	'a second distinct thirty-two byte msg!',
	Buffer.alloc(32, 0xff).toString('binary'),
];
let i = 0;
for (const m of messages) {
	const priv = i === 0 ? Buffer.alloc(32, 1) : randomBytes(32);
	const msgBytes = Buffer.from(m, 'binary').length === 32 ? Buffer.from(m, 'binary') : sha256(Buffer.from(m));
	vectors.push(makeVector(`vector-${i}`, priv, msgBytes));
	i++;
}

console.log(`Generated ${vectors.length} real BIP-340 vectors via @noble/curves.\n`);

let allOk = true;
for (const v of vectors) {
	const {recoveredEqualsP, recoveredAddress} = verifyEcrecoverTrick(v);
	const ok = recoveredEqualsP && recoveredAddress.toLowerCase() === v.pAddress.toLowerCase();
	allOk &&= ok;
	console.log(`${v.description}: ecrecover-trick reduction ${ok ? 'OK — recovered point matches P exactly' : 'FAILED'}`);
	if (!ok) {
		console.log({expected: v.pAddress, recoveredAddress, recoveredEqualsP});
	}
}

if (!allOk) {
	console.error('\nDerivation is WRONG. Do not implement this in Solidity.');
	process.exit(1);
}

console.log('\nAll vectors passed. Writing test/vectors/nostr-test-vectors.json ...');
writeFileSync(
	new URL('../test/vectors/nostr-test-vectors.json', import.meta.url),
	JSON.stringify(vectors, null, 2) + '\n',
);
console.log('Done.');
