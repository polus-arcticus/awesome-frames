// Generates one deterministic BIP-340 test vector from a *real* Nostr
// event, signed with `nostr-tools` (nostr-frame-schnorr-design.md §7 item
// 3's "cross-reference test": a real Nostr signing library, not our own
// code, not even our own gen-vectors.ts's direct @noble/curves calls).
//
// nostr-tools' `finalizeEvent` builds the NIP-01 serialization, computes
// the event id (sha256 of the serialized event — this becomes the
// `msgHash` BIP340.sol verifies against) and signs it with
// `@noble/curves/secp256k1`'s schnorr (a different major version than the
// one gen-vectors.ts and BIP340.sol's own cross-checks use, so this is
// also an independent-version check, not just an independent-library one).
//
// Unlike gen-vectors.ts's vector-1/2 (random keys, regenerated every run),
// this uses a fixed secret key so the vector is reproducible — safe to
// hardcode into test/solidity/BIP340/BIP340.t.sol without it drifting out
// from under the Solidity literals on a re-run.
//
// Run: pnpm tsx scripts/gen-nostr-tools-vector.ts

import {finalizeEvent, verifyEvent, type EventTemplate} from 'nostr-tools/pure';
import {readFileSync, writeFileSync} from 'node:fs';
import {
	liftX,
	pointAddress,
	bytesToHex,
	verifyEcrecoverTrick,
} from '../test/js/utils/bip340.js';

const SECRET_KEY = Buffer.alloc(32, 2); // fixed, distinct from gen-vectors.ts's vector-0 key

const template: EventTemplate = {
	kind: 1,
	created_at: 1735689600, // 2025-01-01T00:00:00Z, fixed for reproducibility
	tags: [],
	content:
		'nostr-frame: BIP-340 ecrecover-trick cross-check vector — see BIP340.t.sol',
};

const event = finalizeEvent(template, SECRET_KEY);

if (!verifyEvent(event)) {
	throw new Error('nostr-tools rejected its own signature');
}

const px = '0x' + event.pubkey;
const rx = '0x' + event.sig.slice(0, 64);
const s = '0x' + event.sig.slice(64, 128);
const message = '0x' + event.id;

const P_point = liftX(Buffer.from(event.pubkey, 'hex'));
const pAddress = pointAddress(P_point);

const {recoveredEqualsP, recoveredAddress} = verifyEcrecoverTrick({
	px,
	rx,
	s,
	message,
});
const ok =
	recoveredEqualsP && recoveredAddress.toLowerCase() === pAddress.toLowerCase();

console.log('nostr-tools event:', JSON.stringify(event, null, 2));
console.log(
	`ecrecover-trick reduction: ${ok ? 'OK — recovered point matches P exactly' : 'FAILED'}`,
);
if (!ok) {
	console.error({pAddress, recoveredAddress, recoveredEqualsP});
	process.exit(1);
}

const vector = {
	description: 'nostr-tools-real-event',
	px,
	pAddress,
	message,
	rx,
	s,
	valid: true,
	// full event, kept for provenance / re-derivation of `message` from `id`
	nostrEvent: event,
};

const vectorsPath = new URL(
	'../test/vectors/nostr-test-vectors.json',
	import.meta.url,
);
const existing = JSON.parse(readFileSync(vectorsPath, 'utf8')) as Array<{
	description: string;
}>;
const withoutPrevious = existing.filter(
	(v) => v.description !== vector.description,
);
writeFileSync(
	vectorsPath,
	JSON.stringify([...withoutPrevious, vector], null, 2) + '\n',
);

console.log(
	`\nWrote vector "${vector.description}" to test/vectors/nostr-test-vectors.json (${existing.length === withoutPrevious.length ? 'appended' : 'replaced previous'}).`,
);
console.log(`\nSolidity vector literal:
Vector({
    px: ${px},
    pAddress: address(${pAddress}),
    message: ${message},
    rx: ${rx},
    s: ${s}
});`);
