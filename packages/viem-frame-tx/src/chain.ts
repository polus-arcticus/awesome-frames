import {defineChain} from 'viem';

/**
 * The ethrex (lambdaclass) public testnet that runs EIP-8141 frame
 * transactions — see https://docs.ethrex.xyz.
 *
 * This is a plain viem `Chain`, nothing frame-tx-specific about it: submit
 * frame transactions with `client.sendRawTransaction({serializedTransaction:
 * serializeFrameTransaction(tx)})` (see rlp.ts). There's no
 * `chain.serializers.transaction` hook wired here — viem populates that
 * hook's `signature` argument from its single-ECDSA-account signing
 * pipeline (`account.signTransaction` → `{r, s, v}`), which doesn't fit a
 * frame tx's model of a `signatures[]` array keyed by scheme (ARBITRARY,
 * SECP256K1, P256). Build and sign the transaction with this package's
 * `computeSigHash`/`serializeFrameTransaction` directly instead, then
 * submit the raw bytes — `sendRawTransaction` is transport-only and
 * type-agnostic, so no chain-level integration is needed for that part.
 */
export const ethrexTestnet = defineChain({
	id: 8141,
	name: 'Ethrex Frame Testnet',
	nativeCurrency: {name: 'Ether', symbol: 'ETH', decimals: 18},
	rpcUrls: {
		default: {http: ['https://rpc1.privacy.ethrex.xyz']},
	},
	blockExplorers: {
		default: {name: 'Dora', url: 'https://dora.privacy.ethrex.xyz'},
	},
	testnet: true,
});
