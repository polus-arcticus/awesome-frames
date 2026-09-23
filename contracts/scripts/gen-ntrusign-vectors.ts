// Generates known-answer vectors for src/tools/NTRUSign/{NTRUSign.yul,
// NTRUSignAccount.yul}, derived from the JS/bigint reference in
// test/js/utils/ntruSign.ts. No maintained/audited external NTRUSign
// library exists (it's a deprecated, historically broken scheme) — every
// vector here is self-verified instead: keygen's own `f*G-g*F=q` check
// (inside keygen() itself), a fresh sign/verify round trip, a
// cross-message rejection check, AND — the thing that actually matters at
// this toy scale — a real measurement of the gap between "closeness of a
// legitimate signature to its own message" and "closeness of that same
// signature to an unrelated message." N=11 was rejected earlier this
// session because that gap doesn't exist there; this script re-confirms
// the gap holds at N=18 before pinning anything, rather than assuming the
// one-off measurement from earlier in the session still applies.
//
// Written to test/vectors/ntrusign-vectors.json, read back by
// test/js/NTRUSign.test.ts.
//
// Run: pnpm tsx scripts/gen-ntrusign-vectors.ts

import {writeFileSync} from 'node:fs';
import {keccak_256} from '@noble/hashes/sha3.js';
import {keygen, sign, verify, hashToPoint, polyMul, N, Q, CLOSENESS_BOUND, type KeyPair, type Poly} from '../test/js/utils/ntruSign.js';

function fail(msg: string): never {
	console.error(msg);
	process.exit(1);
}
function polyStr(p: Poly): string[] {
	return p.map((v) => v.toString());
}
function hex(b: Uint8Array): string {
	return '0x' + Buffer.from(b).toString('hex');
}
// Packs N coefficients (each < Q=128) into a 32-byte hex word, byte i
// (from the left, matching Yul's `byte` opcode) = coefficient i — the
// exact wire/storage convention NTRUSignAccount.yul and its verify
// harness expect for both the public key `h` and a signature `s`.
function packWord(p: Poly): string {
	let packed = 0n;
	for (let i = 0; i < N; i++) packed |= (p[i]! & 0xffn) << BigInt((31 - i) * 8);
	return '0x' + packed.toString(16).padStart(64, '0');
}
// Same convention, but as exactly N raw bytes (no 32-byte padding) — the
// `bytes` witness format the account/harness's `verify(bytes,bytes32)`
// ABI and SIGDATACOPY both expect for a signature.
function packBytesN(p: Poly): string {
	return '0x' + p.map((v) => (((v % Q) + Q) % Q).toString(16).padStart(2, '0')).join('');
}
function mod(a: bigint, m: bigint): bigint {
	const r = a % m;
	return r >= 0n ? r : r + m;
}
function cyclicMaxDist(a: Poly, b: Poly): bigint {
	let worst = 0n;
	for (let i = 0; i < N; i++) {
		const d = mod(a[i]! - b[i]!, Q);
		const c = d > Q / 2n ? Q - d : d;
		if (c > worst) worst = c;
	}
	return worst;
}
function closeness(msgHash: Uint8Array, s: Poly, key: KeyPair): bigint {
	const {m1, m2} = hashToPoint(msgHash);
	const t = polyMul(s, key.h);
	const sD = cyclicMaxDist(s, m1);
	const tD = cyclicMaxDist(t, m2);
	return sD > tD ? sD : tD;
}

console.log(`Generating NTRUSign vectors at N=${N}, q=${Q}.`);

// --- Pinned keypair + sign vectors ---
const key = keygen();
console.log('Pinned keypair generated; f*G-g*F=q already verified inside keygen().');

const messages = ['hello world', 'goodbye world', 'NTRUSign vector 1', 'NTRUSign vector 2'];
const signVectors = messages.map((msg) => {
	const msgHash = keccak_256(new TextEncoder().encode(msg));
	const s = sign(msgHash, key);
	if (!verify(msgHash, s, key.h)) fail(`sign/verify round trip failed for "${msg}" — stop.`);
	return {
		message: msg,
		msgHash: hex(msgHash),
		signature: polyStr(s),
		signaturePacked: packBytesN(s),
		closeness: closeness(msgHash, s, key).toString(),
	};
});
console.log(`${signVectors.length} sign vectors generated, each round-trips through verify().`);

// --- Cross-message rejection: sign(A) must NOT verify against B ---
const sigForHello = sign(keccak_256(new TextEncoder().encode('hello world')), key);
const crossOk = verify(keccak_256(new TextEncoder().encode('goodbye world')), sigForHello, key.h);
if (crossOk) fail('BUG: signature for "hello world" verified against "goodbye world" — stop.');
console.log('Cross-message rejection confirmed: sig("hello world") does not verify against "goodbye world".');

// --- Re-confirm the closeness gap holds at N=18, not just assumed from
// earlier in the session (measured with a fresh sweep here) ---
let legitMax = 0n;
let crossMin = Q; // Q is safely above any real cyclic distance (max possible is Q/2)
const NUM_KEYS = 15;
const NUM_MSGS = 30;
for (let k = 0; k < NUM_KEYS; k++) {
	const sweepKey = keygen();
	for (let i = 0; i < NUM_MSGS; i++) {
		const msgA = keccak_256(new TextEncoder().encode(`sweep-${k}-a-${i}`));
		const msgB = keccak_256(new TextEncoder().encode(`sweep-${k}-b-${i}`));
		const s = sign(msgA, sweepKey);
		const legit = closeness(msgA, s, sweepKey);
		const cross = closeness(msgB, s, sweepKey);
		if (legit > legitMax) legitMax = legit;
		if (cross < crossMin) crossMin = cross;
	}
}
console.log(`Closeness-gap sweep: ${NUM_KEYS} keypairs x ${NUM_MSGS} messages.`);
console.log(`  legit-signature closeness max: ${legitMax}`);
console.log(`  cross-message closeness min:   ${crossMin}`);
if (legitMax >= crossMin) {
	fail(
		`No gap between legit (max ${legitMax}) and cross-message (min ${crossMin}) closeness — ` +
			`the scheme isn't distinguishing real signatures from noise at N=${N}. Stop; do not pin.`,
	);
}
if (legitMax >= CLOSENESS_BOUND || crossMin <= CLOSENESS_BOUND) {
	fail(
		`CLOSENESS_BOUND=${CLOSENESS_BOUND} doesn't sit inside the measured gap ` +
			`(legit max ${legitMax}, cross min ${crossMin}) — update the constant in ntruSign.ts. Stop.`,
	);
}
console.log(`Gap confirmed: ${crossMin - legitMax} (CLOSENESS_BOUND=${CLOSENESS_BOUND} sits inside it).\n`);

const output = {
	params: {N, Q: Q.toString(), closenessBound: CLOSENESS_BOUND.toString()},
	key: {
		f: polyStr(key.f),
		g: polyStr(key.g),
		F: polyStr(key.F),
		G: polyStr(key.G),
		h: polyStr(key.h),
		hPacked: packWord(key.h),
	},
	signVectors,
	closenessGapSweep: {
		numKeys: NUM_KEYS,
		numMessagesPerKey: NUM_MSGS,
		legitMax: legitMax.toString(),
		crossMin: crossMin.toString(),
	},
};

console.log('Writing test/vectors/ntrusign-vectors.json ...');
writeFileSync(
	new URL('../test/vectors/ntrusign-vectors.json', import.meta.url),
	JSON.stringify(output, null, 2) + '\n',
);
console.log('Done.');
