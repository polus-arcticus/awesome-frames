// The point of this repo, end to end: ONE secp256k1 keypair (a) signs a
// real Nostr event (a NIP, via `nostr-tools`) and (b) directly authorizes a
// real EIP-8141 frame transaction (via the *same* BIP-340 Schnorr signature
// scheme — no ECDSA, no key derivation) — deployed and executed against the
// live ethrex testnet.
//
// Contrast with prior art such as Dostr: Dostr derives a *separate* Nostr
// key via HKDF from an Ethereum ECDSA signature — two different keys, one
// derived from the other, with the derivation step itself as a trust
// boundary. Here there is exactly one secp256k1 scalar, used unmodified as
// both a Nostr identity key and (via `NostrFrameAccount` — see its header
// comment) the sole authority over an Ethereum smart account.
//
// What this script does:
//   1. Generates a fresh secp256k1 keypair and treats it as a Nostr key.
//   2. Deploys NostrFrameAccount.yul (constructed with that key's even-Y
//      point address) to ethrexTestnet.
//   3. Funds the deployed account.
//   4. Signs a real NIP-01 note with the key via `nostr-tools`.
//   5. Builds an EIP-8141 frame transaction whose VERIFY frame is checked
//      by NostrFrameAccount, signs its `compute_sig_hash` with the *same*
//      key via raw BIP-340 Schnorr (`@noble/curves`' `schnorr.sign` — the
//      same primitive `nostr-tools` uses under the hood), and submits it.
//
// Run (after funding a deployer key — see .env.local — with test ETH from
// https://faucet.privacy.ethrex.xyz):
//   pnpm exec ldenv tsx scripts/nostr-frame-demo.ts
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import solc from 'solc';
import {
	finalizeEvent,
	verifyEvent,
	generateSecretKey,
	getPublicKey,
	type EventTemplate,
} from 'nostr-tools/pure';
import {schnorr} from '@noble/curves/secp256k1.js';
import {
	type Hex,
	concatHex,
	createPublicClient,
	createWalletClient,
	http,
	numberToHex,
	parseEther,
} from 'viem';
import {privateKeyToAccount} from 'viem/accounts';
import {
	SignatureScheme,
	computeSigHash,
	ethrexTestnet,
	serializeFrameTransaction,
	type FrameTransactionSerializable,
} from 'viem-frame-tx';
import {liftX, pointAddress} from '../test/js/utils/bip340.js';

const DEPLOYER_PRIVATE_KEY = process.env.PRIVATE_KEY_ethrexTestnet as
	Hex | undefined;
if (!DEPLOYER_PRIVATE_KEY) {
	throw new Error(
		'Set PRIVATE_KEY_ethrexTestnet (in contracts/.env.local) to a funded ethrexTestnet key.',
	);
}

// EIP-8141 state budget for a value-carrying frame that might create an
// account — see examples/self-transfer.ts in viem-frame-tx for the same
// constant; unused budget is refunded when the recipient already exists.
const NEW_ACCOUNT_STATE_GAS = 120n * 1530n;

function compileYul(sourcePath: string): {init: Hex; runtime: Hex} {
	const src = readFileSync(sourcePath, 'utf8');
	const input = {
		language: 'Yul',
		sources: {[sourcePath]: {content: src}},
		settings: {
			outputSelection: {
				'*': {'*': ['evm.bytecode.object', 'evm.deployedBytecode.object']},
			},
		},
	};
	const output = JSON.parse(solc.compile(JSON.stringify(input)));
	const errors = (output.errors ?? []).filter(
		(e: {severity: string}) => e.severity === 'error',
	);
	if (errors.length > 0) {
		throw new Error(
			'Yul compilation failed:\n' +
				errors
					.map((e: {formattedMessage: string}) => e.formattedMessage)
					.join('\n'),
		);
	}
	const contractName = Object.keys(output.contracts[sourcePath])[0]!;
	const c = output.contracts[sourcePath][contractName];
	return {
		init: `0x${c.evm.bytecode.object}`,
		runtime: `0x${c.evm.deployedBytecode.object}`,
	};
}

// Right-aligns a 20-byte address in a 32-byte word — matches
// NostrFrameAccount.yul's constructor decoding (`and(mload(...), <mask>)`).
function addressWord(address: Hex): Hex {
	return `0x${address.slice(2).padStart(64, '0')}` as Hex;
}

function printJson(label: string, value: unknown) {
	console.log(
		`${label}:`,
		JSON.stringify(
			value,
			(_key, v) => (typeof v === 'bigint' ? v.toString() : v),
			2,
		),
	);
}

async function main() {
	const deployer = privateKeyToAccount(DEPLOYER_PRIVATE_KEY!);
	const walletClient = createWalletClient({
		account: deployer,
		chain: ethrexTestnet,
		transport: http(),
	});
	const publicClient = createPublicClient({
		chain: ethrexTestnet,
		transport: http(),
	});
	console.log(
		`deployer (pays for setup, NOT the Nostr key) = ${deployer.address}`,
	);

	// Fetched once, reused for every transaction below (plain deploys/funding
	// AND the frame tx) — this testnet's `eth_estimateGas` runs a full binary
	// search starting from the block gas limit (200_000_000) and rejects the
	// probe outright if `probe_gas * maxFeePerGas` exceeds the sender's
	// balance, so relying on viem's automatic gas estimation here ("Vm
	// execution error: Insufficient account funds", even though the actual
	// call needs a tiny fraction of that) doesn't work. Every call below
	// passes an explicit `gas` to skip estimation entirely.
	const block = await publicClient.getBlock({blockTag: 'latest'});
	const maxPriorityFeePerGas = 1_000_000_000n; // 1 gwei
	const maxFeePerGas = (block.baseFeePerGas ?? 0n) * 2n + maxPriorityFeePerGas;

	// ── Step 1: one secp256k1 keypair, used directly as a Nostr identity ──
	const nostrSecretKey = generateSecretKey();
	const px = getPublicKey(nostrSecretKey); // x-only pubkey, hex, no 0x
	const pPoint = liftX(Buffer.from(px, 'hex'));
	const pAddress = pointAddress(pPoint) as Hex;
	console.log(`Nostr/BIP-340 key: px=0x${px} pAddress=${pAddress}`);

	// ── Step 2: deploy NostrFrameAccount.yul ──
	const yulPath = fileURLToPath(
		new URL('../src/NostrFrameAccount/NostrFrameAccount.yul', import.meta.url),
	);
	const {init: accountInit} = compileYul(yulPath);
	const accountInitWithArgs = concatHex([accountInit, addressWord(pAddress)]);
	const accountDeployHash = await walletClient.sendTransaction({
		data: accountInitWithArgs,
		gas: 1_000_000n,
		maxFeePerGas,
		maxPriorityFeePerGas,
	});
	const accountReceipt = await publicClient.waitForTransactionReceipt({
		hash: accountDeployHash,
	});
	const accountAddress = accountReceipt.contractAddress!;
	console.log(`NostrFrameAccount deployed at ${accountAddress}`);

	// Sanity-check the constructor wired storage correctly before spending a
	// frame tx on it.
	const storedPAddress = await publicClient.readContract({
		address: accountAddress,
		abi: [
			{
				type: 'function',
				name: 'pAddress',
				stateMutability: 'view',
				inputs: [],
				outputs: [{type: 'address'}],
			},
		],
		functionName: 'pAddress',
	});
	if ((storedPAddress as string).toLowerCase() !== pAddress.toLowerCase()) {
		throw new Error(
			`NostrFrameAccount.pAddress() = ${storedPAddress}, expected ${pAddress}`,
		);
	}
	console.log('NostrFrameAccount.pAddress() matches — constructor wiring OK.');

	// ── Step 3: fund the account (it pays its own gas as tx.sender) ──
	const fundHash = await walletClient.sendTransaction({
		to: accountAddress,
		value: parseEther('0.02'),
		gas: 50_000n,
		maxFeePerGas,
		maxPriorityFeePerGas,
	});
	await publicClient.waitForTransactionReceipt({hash: fundHash});
	console.log(`Funded ${accountAddress} with 0.02 test ETH.`);

	// ── Step 4: sign a real NIP-01 note with the SAME key ──
	const template: EventTemplate = {
		kind: 1,
		created_at: Math.floor(Date.now() / 1000),
		tags: [],
		content:
			'Signed with the same secp256k1 key that just authorized an EIP-8141 frame transaction on ethrex — no derivation, one keypair, two protocols. https://github.com (nostr-frame)',
	};
	const nostrEvent = finalizeEvent(template, nostrSecretKey);
	if (!verifyEvent(nostrEvent)) {
		throw new Error('nostr-tools rejected its own signature');
	}
	console.log('Signed and verified a real Nostr event with the same key:');
	printJson('nostrEvent', nostrEvent);

	// ── Step 5: build + BIP-340-sign + submit the frame transaction ──
	const [chainId, nonce] = await Promise.all([
		publicClient.getChainId(),
		publicClient.getTransactionCount({address: accountAddress}),
	]);

	const unsigned: FrameTransactionSerializable = {
		chainId,
		nonceKeys: [0n],
		nonceSeq: BigInt(nonce),
		sender: accountAddress,
		frames: [
			{
				// self_verify: this frame both authorizes execution and pays.
				mode: 1 /* VERIFY */,
				flags: 0x03,
				target: accountAddress,
				gasLimit: 95_000n, // stays under EIP-8141's MAX_VERIFY_GAS=100_000
				stateLimit: 0n,
				value: 0n,
				// signatureIndex=0, right-padded to 32 bytes — NOT the witness
				// itself (see NostrFrameAccount.yul's header comment for why
				// that would be circular).
				data: numberToHex(0n, {size: 32}),
			},
			{
				// A visible, authorized action beyond just paying gas: send a
				// token amount back to the deployer.
				mode: 2 /* SENDER */,
				flags: 0x00,
				target: deployer.address,
				gasLimit: 30_000n,
				stateLimit: NEW_ACCOUNT_STATE_GAS,
				value: parseEther('0.001'),
				data: '0x',
			},
		],
		signatures: [
			{
				scheme: SignatureScheme.ARBITRARY,
				signer: null, // ARBITRARY signer MUST be empty per EIP-8141
				msg: '0x', // empty -> signs compute_sig_hash(tx), elided from it
				signature: '0x', // placeholder; elided anyway when computing sigHash
			},
		],
		maxPriorityFeePerGas,
		maxFeePerGas,
	};

	const sigHash = computeSigHash(unsigned);
	console.log(`sigHash=${sigHash}`);

	// Sign with the SAME key, via the SAME BIP-340 Schnorr primitive
	// `nostr-tools` used above (`schnorr.sign` is what `finalizeEvent` calls
	// internally) — just over a different message: the frame tx's sig hash
	// instead of a Nostr event id.
	const sig = schnorr.sign(sigHash.slice(2), nostrSecretKey);
	const witness = `0x${px}${Buffer.from(sig).toString('hex')}` as Hex; // px‖rx‖s, 96 bytes

	const signed: FrameTransactionSerializable = {
		...unsigned,
		signatures: [{...unsigned.signatures[0]!, signature: witness}],
	};

	const raw = serializeFrameTransaction(signed);
	console.log(`raw (${(raw.length - 2) / 2} bytes) = ${raw}`);

	const sim = await publicClient.request({
		// @ts-expect-error -- not a standard viem-typed method
		method: 'ethrex_simulateFrameTransaction',
		params: [raw],
	});
	printJson('simulation', sim);

	const hash = await publicClient.sendRawTransaction({
		serializedTransaction: raw,
	});
	console.log(`submitted: ${hash}`);

	const receipt = await publicClient.waitForTransactionReceipt({hash});
	printJson('receipt', receipt);

	console.log(`
Done. The same secp256k1 keypair (Nostr pubkey npub-style hex 0x${px}):
  - signed a real Nostr event: ${nostrEvent.id}
  - authorized a real EIP-8141 frame transaction: ${hash}
Explorer: https://dora.privacy.ethrex.xyz/tx/${hash}
`);
}

main().catch((err) => {
	console.error(err);
	process.exit(1);
});
