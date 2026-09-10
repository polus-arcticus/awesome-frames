// A self-verified frame-transaction transfer against the ethrex testnet —
// the smallest useful shape the faucet page (https://faucet.privacy.ethrex.xyz)
// documents: a VERIFY frame targeting the sender (flags=0x03, checks the
// outer SECP256K1 signature, APPROVEs both execution and payment), then a
// SENDER frame that moves the value. Mirrors the reference
// `frametx_submit.py` from lambdaclass/ethrex's `hegota-testnet` branch,
// but built with this package instead of the Python encoder.
//
// Usage: tsx examples/self-transfer.ts <sender_private_key_hex> <recipient_0x> <amount_wei>
import {secp256k1} from '@noble/curves/secp256k1.js';
import {type Hex, createPublicClient, http, numberToHex} from 'viem';
import {
	SignatureScheme,
	computeSigHash,
	ethrexTestnet,
	serializeFrameTransaction,
} from '../src/index.js';
import type {FrameTransactionSerializable} from '../src/types.js';

// EIP-8141 state budget for a value-carrying frame: funding an address that
// doesn't exist yet costs STATE_BYTES_PER_NEW_ACCOUNT * CPSB = 120 * 1530.
// Declaring it when the recipient already exists is free in practice — the
// unused budget is refunded at settlement (per the faucet page).
const NEW_ACCOUNT_STATE_GAS = 120n * 1530n;

async function main() {
	const [privateKeyArg, recipientArg, amountArg] = process.argv.slice(2);
	if (!privateKeyArg || !recipientArg || !amountArg) {
		console.error(
			'usage: tsx examples/self-transfer.ts <sender_private_key_hex> <recipient_0x> <amount_wei>',
		);
		process.exit(1);
	}
	const privateKey = privateKeyArg as Hex;
	const recipient = recipientArg as Hex;
	const amount = BigInt(amountArg);

	const client = createPublicClient({chain: ethrexTestnet, transport: http()});

	// Derive the sender address from the private key without pulling in a
	// full Account object — this package doesn't sign for you, so there's
	// no reason to route through viem's account abstractions for the rest.
	const {privateKeyToAddress} = await import('viem/accounts');
	const sender = privateKeyToAddress(privateKey);

	const [chainId, nonce, block] = await Promise.all([
		client.getChainId(),
		client.getTransactionCount({address: sender}),
		client.getBlock({blockTag: 'latest'}),
	]);

	const maxPriorityFeePerGas = 1_000_000_000n; // 1 gwei
	const maxFeePerGas = (block.baseFeePerGas ?? 0n) * 2n + maxPriorityFeePerGas;

	console.log(
		`sender=${sender} nonce=${nonce} chainId=${chainId} baseFee=${block.baseFeePerGas}`,
	);

	const unsigned: FrameTransactionSerializable = {
		chainId,
		nonceKeys: [0n],
		nonceSeq: BigInt(nonce),
		sender,
		frames: [
			{
				mode: 1 /* VERIFY */,
				flags: 0x03,
				target: sender,
				gasLimit: 80_000n,
				stateLimit: 0n,
				value: 0n,
				data: '0x',
			},
			{
				mode: 2 /* SENDER */,
				flags: 0x00,
				target: recipient,
				gasLimit: 30_000n,
				stateLimit: NEW_ACCOUNT_STATE_GAS,
				value: amount,
				data: '0x',
			},
		],
		signatures: [
			{
				scheme: SignatureScheme.SECP256K1,
				signer: sender,
				msg: '0x',
				signature: '0x',
			},
		],
		maxPriorityFeePerGas,
		maxFeePerGas,
	};

	const sigHash = computeSigHash(unsigned);
	console.log(`sigHash=${sigHash}`);

	// The faucet page's own gotcha: the signature is 65 bytes of v‖r‖s where
	// v is the *bare* recovery id (0 or 1) — not ecrecover's 27/28 form —
	// and r/s must be canonical (low-s). `@noble/curves`' `lowS: true` is
	// exactly what viem's own (unexported) low-level `sign` util sets.
	const sig = secp256k1.sign(sigHash.slice(2), privateKey.slice(2), {
		lowS: true,
	});
	const signature =
		`0x${numberToHex(sig.recovery, {size: 1}).slice(2)}${numberToHex(sig.r, {size: 32}).slice(2)}${numberToHex(sig.s, {size: 32}).slice(2)}` as Hex;

	const signed: FrameTransactionSerializable = {
		...unsigned,
		signatures: [{...unsigned.signatures[0]!, signature}],
	};

	const raw = serializeFrameTransaction(signed);
	console.log(`raw (${(raw.length - 2) / 2} bytes)=${raw}`);

	// Dry-run first — ethrex exposes a custom RPC to validate a raw frame tx
	// without submitting it, per the faucet page.
	const sim = await client.request({
		// @ts-expect-error -- not a standard viem-typed method
		method: 'ethrex_simulateFrameTransaction',
		params: [raw],
	});
	console.log('simulation:', JSON.stringify(sim, null, 2));

	const hash = await client.sendRawTransaction({serializedTransaction: raw});
	console.log('submitted:', hash);

	const receipt = await client.waitForTransactionReceipt({hash});
	console.log(
		'receipt:',
		JSON.stringify(
			receipt,
			(_key, value) => (typeof value === 'bigint' ? value.toString() : value),
			2,
		),
	);
}

main().catch((err) => {
	console.error(err);
	process.exit(1);
});
