import type {Address, Hex} from 'viem';

/**
 * A single EIP-8141 frame: `[mode, flags, target, [gas_limit, state_limit],
 * value, data]` — the dual EIP-8037 gas budget (`gasLimit` meters execution,
 * `stateLimit` meters durable state growth; the two pools never mix).
 * `target: null` resolves to the transaction's `sender` (RLP-encodes as the
 * empty string, exactly like a legacy contract-creation `to`).
 */
export interface Frame {
	mode: number;
	flags: number;
	target: Address | null;
	gasLimit: bigint;
	stateLimit: bigint;
	/** Only meaningful on a SENDER frame — see EIP-8141's static constraints. */
	value: bigint;
	data: Hex;
}

/**
 * A single EIP-8141 outer signature: `[scheme, signer, msg, signature]`.
 *
 * - `signer: null` is required for ARBITRARY and means "resolves to
 *   `tx.sender`" for SECP256K1/P256.
 * - `msg`: empty signs `computeSigHash(tx)`; 32 bytes signs that explicit
 *   digest instead.
 * - `signature` is raw bytes; shape depends on `scheme` (see
 *   `SignatureScheme` in constants.ts).
 */
export interface FrameSignature {
	scheme: number;
	signer: Address | null;
	msg: Hex;
	signature: Hex;
}

/**
 * EIP-8272 declared recent-root reference: `[source_id, slot, root]`.
 * `root` is opaque to consensus — applications bind its meaning themselves.
 */
export interface RecentRootReference {
	sourceId: Hex;
	slot: bigint;
	root: Hex;
}

/**
 * The RLP payload of an EIP-8141 frame transaction (sans the `0x06` type
 * byte), matching the exact field order of the ethrex commit this package
 * targets (see README — this differs from both ethrex's `main` branch and
 * the published EIP text):
 * `[chain_id, nonce_keys, nonce_seq, sender, frames, signatures, fees,
 *   blob_versioned_hashes, recent_root_references]`, where
 * `fees = [max_priority_fee_per_gas, max_fee_per_gas, max_fee_per_blob_gas]`.
 *
 * `nonceKeys`/`nonceSeq` are EIP-8250 keyed nonces: 1-16 strictly increasing
 * keys, where key `0` is the plain linear (account) nonce domain — for an
 * ordinary transaction that isn't using multiple nonce domains, use
 * `nonceKeys: [0n]` and `nonceSeq` = the account's normal nonce.
 */
export interface FrameTransactionSerializable {
	chainId: number;
	nonceKeys: readonly bigint[];
	nonceSeq: bigint;
	sender: Address;
	frames: readonly Frame[];
	signatures: readonly FrameSignature[];
	maxPriorityFeePerGas: bigint;
	maxFeePerGas: bigint;
	maxFeePerBlobGas?: bigint;
	blobVersionedHashes?: readonly Hex[];
	recentRootReferences?: readonly RecentRootReference[];
}
