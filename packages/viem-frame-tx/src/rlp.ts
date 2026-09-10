import {type Hex, concatHex, keccak256, numberToHex, toRlp} from 'viem';
import type {
	Frame,
	FrameSignature,
	FrameTransactionSerializable,
	RecentRootReference,
} from './types.js';

// viem's own `RecursiveArray<Hex>` (what `toRlp` actually accepts) isn't
// re-exported from the package root — only from its internal
// `utils/encoding/toRlp.js` path — so this is a local equivalent rather
// than an import of an unexported internal.
type Rlp = Hex | readonly Rlp[];

// A literal, not `numberToHex(FRAME_TX_TYPE)`: viem's `concatHex` joins hex
// strings by nibbles, not bytes, and `numberToHex(6)` is the single nibble
// "0x6" — concatenating that would misalign every byte after it. viem's own
// serializers hardcode their type-byte strings for the same reason (see
// serializeTransaction.ts's literal `'0x04'`, `'0x03'`, etc.).
const FRAME_TX_TYPE_HEX: Hex = '0x06';

// RLP encodes the integer 0 as the empty byte string, never a `0x00` byte —
// mirrors the `value ? numberToHex(value) : '0x'` idiom viem's own
// serializeTransaction.ts uses for every numeric field (see e.g. `nonce`,
// `gas`, `chainId` in its EIP-1559/7702 serializers).
function uintHex(value: number | bigint): Hex {
	return value ? numberToHex(value) : '0x';
}

// A `null` target/signer resolves to the sender at execution time and
// RLP-encodes as the empty string — exactly like a legacy transaction's
// contract-creation `to` field (ethrex's `TxKind::Create` case).
function addressOrNull(address: Hex | null): Hex {
	return address ?? '0x';
}

function encodeFrame(frame: Frame): Rlp {
	return [
		uintHex(frame.mode),
		uintHex(frame.flags),
		addressOrNull(frame.target),
		// EIP-8037 dual gas budget: [execution, state], nested, never flattened.
		[uintHex(frame.gasLimit), uintHex(frame.stateLimit)],
		uintHex(frame.value),
		frame.data,
	];
}

function encodeFrameSignature(
	signature: FrameSignature,
	{elideSignatureBytes}: {elideSignatureBytes: boolean},
): Rlp {
	return [
		uintHex(signature.scheme),
		addressOrNull(signature.signer),
		signature.msg,
		elideSignatureBytes ? '0x' : signature.signature,
	];
}

function encodeRecentRootReference(ref: RecentRootReference): Rlp {
	return [ref.sourceId, uintHex(ref.slot), ref.root];
}

/**
 * Builds the RLP field array shared by `serializeFrameTransaction` and
 * `computeSigHash`: `[chain_id, nonce_keys, nonce_seq, sender, frames,
 * signatures, fees, blob_versioned_hashes, recent_root_references]`, where
 * `fees = [max_priority_fee_per_gas, max_fee_per_gas, max_fee_per_blob_gas]`
 * — matching the exact field order (and nesting) of the ethrex commit this
 * package targets (see README's "Known discrepancies").
 */
function encodeFields(
	tx: FrameTransactionSerializable,
	{forSigHash}: {forSigHash: boolean},
): Rlp {
	return [
		uintHex(tx.chainId),
		tx.nonceKeys.map(uintHex),
		uintHex(tx.nonceSeq),
		tx.sender,
		tx.frames.map(encodeFrame),
		tx.signatures.map((s) =>
			encodeFrameSignature(s, {
				// A signature with an empty `msg` signs `computeSigHash(tx)` itself —
				// its own bytes can't be part of what it commits to, so they're
				// elided from the preimage. An explicit `msg` digest signs that
				// digest instead, so its bytes are real transaction content and stay.
				elideSignatureBytes: forSigHash && s.msg === '0x',
			}),
		),
		[
			uintHex(tx.maxPriorityFeePerGas),
			uintHex(tx.maxFeePerGas),
			uintHex(tx.maxFeePerBlobGas ?? 0n),
		],
		tx.blobVersionedHashes ?? [],
		(tx.recentRootReferences ?? []).map(encodeRecentRootReference),
	];
}

/**
 * The full `0x06`-prefixed RLP envelope, ready for `eth_sendRawTransaction`.
 * `tx.signatures` must already be populated — this package does no signing;
 * attach whatever scheme-appropriate bytes you already have (e.g. a BIP-340
 * signature for `SignatureScheme.ARBITRARY`) before calling this.
 */
export function serializeFrameTransaction(
	tx: FrameTransactionSerializable,
): Hex {
	return concatHex([
		FRAME_TX_TYPE_HEX,
		toRlp(encodeFields(tx, {forSigHash: false})),
	]);
}

/**
 * `keccak256(0x06 || rlp(tx))`, the digest a signature with an empty `msg`
 * field commits to (EIP-8141's `compute_sig_hash`). Call this to get the
 * bytes to sign, then attach the result as `signature.signature` before
 * serializing.
 */
export function computeSigHash(tx: FrameTransactionSerializable): Hex {
	const preimage = concatHex([
		FRAME_TX_TYPE_HEX,
		toRlp(encodeFields(tx, {forSigHash: true})),
	]);
	return keccak256(preimage);
}
