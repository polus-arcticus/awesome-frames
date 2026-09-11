// Real RSASSA-PKCS1-v1_5 (SHA-256) signing/verification, cross-checked
// against Node's own `crypto` module — the "independent real library"
// reference for src/LightningRSA/LightningRSA.sol and
// src/LightningRSA/LightningRSAAccount.yul, the same discipline
// test/js/utils/bip340.ts applies against `nostr-tools` and Node's crypto
// module is a considerably more battle-tested reference than either.
//
// `msgHash` throughout (a 32-byte value, e.g. a Frame tx's
// compute_sig_hash(tx)) plays the role of "the message" being signed —
// exactly like any RS256-signed payload, it gets hashed *again* with
// SHA-256 internally as part of the PKCS#1 v1.5 scheme. That's standard,
// not a bug: passing an already-hashed value as "the message" to a
// hash-then-sign scheme is completely normal (JWT RS256 does exactly this
// with a JSON payload).

import {generateKeyPairSync, sign as nodeSign, verify as nodeVerify, createHash, type KeyObject} from 'node:crypto';

export interface RSAKeypair {
	publicKeyPem: string;
	privateKeyPem: string;
	n: bigint;
	e: bigint;
	modulusBytes: number;
}

/// DER encoding of the SHA-256 DigestInfo AlgorithmIdentifier prefix
/// (RFC 8017 Appendix, Note 1) — the same 19-byte constant in every
/// conformant PKCS#1 v1.5/SHA-256 implementation.
export const SHA256_DIGEST_INFO_PREFIX = Buffer.from('3031300d060960864801650304020105000420', 'hex');

function base64UrlToBigInt(b64url: string): bigint {
	const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
	return BigInt('0x' + Buffer.from(b64, 'base64').toString('hex'));
}

export function generateRsaKeypair(modulusLength = 2048, publicExponent = 65537): RSAKeypair {
	const {publicKey, privateKey} = generateKeyPairSync('rsa', {modulusLength, publicExponent});
	const jwk = (publicKey as KeyObject).export({format: 'jwk'}) as {n: string; e: string};
	return {
		publicKeyPem: (publicKey as KeyObject).export({type: 'spki', format: 'pem'}) as string,
		privateKeyPem: (privateKey as KeyObject).export({type: 'pkcs8', format: 'pem'}) as string,
		n: base64UrlToBigInt(jwk.n),
		e: base64UrlToBigInt(jwk.e),
		modulusBytes: modulusLength / 8,
	};
}

/// Sign `msgHash` with a real RSA private key — RSASSA-PKCS1-v1_5/SHA-256
/// via Node's own implementation, not our own math.
export function nodeSignMsgHash(msgHash: Buffer, privateKeyPem: string): Buffer {
	return nodeSign('RSA-SHA256', msgHash, privateKeyPem);
}

/// Verify with Node's own implementation — the reference this repo's
/// from-scratch verify (below) is checked against.
export function nodeVerifyMsgHash(msgHash: Buffer, signature: Buffer, publicKeyPem: string): boolean {
	return nodeVerify('RSA-SHA256', msgHash, publicKeyPem, signature);
}

export function modpow(base: bigint, exponent: bigint, modulus: bigint): bigint {
	if (modulus === 1n) return 0n;
	let result = 1n;
	let b = base % modulus;
	let e = exponent;
	while (e > 0n) {
		if (e & 1n) result = (result * b) % modulus;
		e >>= 1n;
		b = (b * b) % modulus;
	}
	return result;
}

function bigIntToBytes(value: bigint, length: number): Buffer {
	const hex = value.toString(16).padStart(length * 2, '0');
	if (hex.length > length * 2) throw new Error('bigIntToBytes: value too large for length');
	return Buffer.from(hex, 'hex');
}

/// EMSA-PKCS1-v1_5-ENCODE (RFC 8017 §9.2): EM = 0x00 || 0x01 || PS || 0x00 || T,
/// T = SHA256_DIGEST_INFO_PREFIX || hash. This is the exact byte layout
/// src/LightningRSA/LightningRSA.sol's `_buildEM` reconstructs on-chain.
export function buildExpectedEM(hash: Buffer, emLen: number): Buffer {
	const tLen = SHA256_DIGEST_INFO_PREFIX.length + hash.length;
	if (emLen < tLen + 11) throw new Error(`buildExpectedEM: modulus too small (emLen=${emLen}, need >= ${tLen + 11})`);
	const psLen = emLen - tLen - 3;
	const em = Buffer.alloc(emLen);
	em[0] = 0x00;
	em[1] = 0x01;
	em.fill(0xff, 2, 2 + psLen);
	em[2 + psLen] = 0x00;
	SHA256_DIGEST_INFO_PREFIX.copy(em, 2 + psLen + 1);
	hash.copy(em, 2 + psLen + 1 + SHA256_DIGEST_INFO_PREFIX.length);
	return em;
}

/// The from-scratch reference verify — re-derives the expected EM and
/// compares byte-for-byte against the MODEXP-recovered block, rather than
/// parsing padding out of the recovered value. Mirrors
/// LightningRSA.sol/LightningRSAAccount.yul exactly; see those files'
/// headers for why "recompute, don't parse" matters here.
export function verifyPkcs1v15(n: bigint, e: bigint, signature: bigint, msgHash: Buffer, modulusBytes: number): boolean {
	if (signature < 0n || signature >= n) return false;
	const h = createHash('sha256').update(msgHash).digest();
	const expectedEM = buildExpectedEM(h, modulusBytes);
	const recovered = modpow(signature, e, n);
	const recoveredBytes = bigIntToBytes(recovered, modulusBytes);
	return recoveredBytes.equals(expectedEM);
}

export function bytesToHex(buf: Buffer): string {
	return '0x' + buf.toString('hex');
}

export function bigIntToHex(value: bigint, length: number): string {
	return bytesToHex(bigIntToBytes(value, length));
}
