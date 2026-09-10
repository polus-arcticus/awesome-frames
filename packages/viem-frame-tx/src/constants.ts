/** EIP-2718 transaction type byte for the frame transaction (EIP-8141). */
export const FRAME_TX_TYPE = 0x06;

/**
 * EIP-8141 frame `mode` values (`Frame.mode`). Values are era-dependent —
 * `UTXO` only means anything once EIP-8312 is activated on a chain; a
 * pre-activation chain must treat byte `5` as reserved, not resolve it to
 * `UTXO`. Byte `3` is unassigned, `4` is reserved for the deferred
 * EIP-8288 `DEP_VERIFY` mode.
 */
export const FrameMode = {
	DEFAULT: 0,
	VERIFY: 1,
	SENDER: 2,
	UTXO: 5,
} as const;

/** EIP-8141 signature `scheme` values (`FrameSignature.scheme`). */
export const SignatureScheme = {
	/** No protocol-level validation; introspectable via `SIGDATACOPY`, verified by EVM code. */
	ARBITRARY: 0,
	/** Standard ECDSA, `signature` = 65 bytes `v || r || s`. Validated by the protocol. */
	SECP256K1: 1,
	/** ECDSA over secp256r1, `signature` = 128 bytes `r || s || qx || qy`. Validated by the protocol. */
	P256: 2,
} as const;

/** APPROVE scope values — bits 0-1 of `Frame.flags` (`APPROVE_SCOPE_MASK`). */
export const ApproveScope = {
	PAYMENT: 0x1,
	EXECUTION: 0x2,
	EXECUTION_AND_PAYMENT: 0x3,
} as const;

/** Bit 2 of `Frame.flags` — valid on DEFAULT and SENDER frames only. */
export const ATOMIC_BATCH_FLAG = 0x4;

/** Protocol-defined caller address for DEFAULT/VERIFY frames. */
export const FRAME_TX_ENTRY_POINT = 0xaa;

/** Canonical expiry-deadline checker address (`EXPIRY_VERIFIER`). */
export const FRAME_TX_EXPIRY_VERIFIER = 0x8141;

export const FRAME_TX_MAX_FRAMES = 64;

/** EIP-8250: `nonce_keys` must hold 1-16 strictly increasing keys; key `0` is the plain linear (account) nonce domain. */
export const FRAME_TX_MAX_NONCE_KEYS = 16;

/** EIP-8272: max `recent_root_references` entries (0-16). */
export const FRAME_TX_MAX_RECENT_ROOT_REFERENCES = 16;

/**
 * Gas constants, mirrored from the exact commit the public testnet this
 * package targets (`ethrexTestnet`, chain 8141) reports running via
 * `web3_clientVersion` — not ethrex's `main` branch, and not the currently
 * published EIP text, both of which disagree with that commit in different
 * ways. See this package's README ("Known discrepancies") before trusting
 * any of the three as ground truth for a different target.
 */
export const FRAME_TX_INTRINSIC_COST = 12_000n;
export const FRAME_TX_PER_FRAME_COST = 475n;
/** Charged once per value-carrying frame (recipient balance write + EIP-7708 transfer log). */
export const FRAME_TX_VALUE_COST = 6_000n;
export const FRAME_TX_MAX_VERIFY_GAS = 100_000n;

/** Gas charged per signature scheme toward `FRAME_TX_MAX_VERIFY_GAS`. */
export const SIGNATURE_VERIFICATION_COST: Record<number, bigint> = {
	[SignatureScheme.ARBITRARY]: 100n,
	[SignatureScheme.SECP256K1]: 2_800n,
	[SignatureScheme.P256]: 6_700n,
};
