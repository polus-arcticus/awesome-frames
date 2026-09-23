// Tests the parts of src/tools/NTRUSign/NTRUSignAccount.yul that DON'T
// need EIP-8141 opcodes and so ARE testable on Hardhat's ordinary local
// network: the constructor's public-key-embedding (hPacked into storage
// slot 0) and the h() getter's read of it. The actual verify path
// (SIGDATACOPY/TXPARAM/APPROVE) needs the live ethrex testnet, same
// reasoning as every other EIP-8141-opcode-using account in this repo —
// not covered here. The verify MATH itself (the part that actually
// matters — message hashing, convolution, the closeness check, and the
// real gas cost) is covered below via
// test/yul/NTRUSignAccountVerifyHarness.yul, the same split
// LightningRSAAccount.test.ts uses for LightningRSAAccountVerifyHarness.
import {expect} from 'earl';
import {describe, it, before} from 'node:test';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import solc from 'solc';
import {network} from 'hardhat';
import {getContract, type Hex} from 'viem';

interface Vectors {
	params: {N: number; Q: string; closenessBound: string};
	key: {f: string[]; g: string[]; F: string[]; G: string[]; h: string[]; hPacked: string};
	signVectors: {message: string; msgHash: string; signature: string[]; signaturePacked: string; closeness: string}[];
	closenessGapSweep: {numKeys: number; numMessagesPerKey: number; legitMax: string; crossMin: string};
}

const vectorsJson: Vectors = JSON.parse(
	readFileSync(fileURLToPath(new URL('../vectors/ntrusign-vectors.json', import.meta.url)), 'utf8'),
);

const abi = [
	{type: 'function', name: 'h', stateMutability: 'view', inputs: [], outputs: [{type: 'bytes32'}]},
] as const;

function compileYul(sourcePath: string): Hex {
	const src = readFileSync(sourcePath, 'utf8');
	const input = {
		language: 'Yul',
		sources: {[sourcePath]: {content: src}},
		settings: {outputSelection: {'*': {'*': ['evm.bytecode.object']}}},
	};
	const output = JSON.parse(solc.compile(JSON.stringify(input)));
	const errors = (output.errors ?? []).filter((e: {severity: string}) => e.severity === 'error');
	if (errors.length > 0) {
		throw new Error('Yul compilation failed:\n' + errors.map((e: {formattedMessage: string}) => e.formattedMessage).join('\n'));
	}
	const contractName = Object.keys(output.contracts[sourcePath])[0]!;
	return `0x${output.contracts[sourcePath][contractName].evm.bytecode.object}` as Hex;
}

/// Constructor args: [hPacked (32 bytes, right-aligned)].
function encodeConstructorArgs(hPacked: Hex): Hex {
	return hPacked;
}

const {viem} = await network.create();

describe('NTRUSignAccount — constructor public-key embedding + getter', function () {
	let contract: Awaited<ReturnType<typeof deploy>>;

	async function deploy() {
		const [wallet] = await viem.getWalletClients();
		const publicClient = await viem.getPublicClient();
		const yulPath = fileURLToPath(new URL('../../src/tools/NTRUSign/NTRUSignAccount.yul', import.meta.url));
		const initBytecode = compileYul(yulPath);
		const args = encodeConstructorArgs(vectorsJson.key.hPacked as Hex);
		const hash = await wallet!.sendTransaction({data: `${initBytecode}${args.slice(2)}` as Hex});
		const receipt = await publicClient.waitForTransactionReceipt({hash});
		if (!receipt.contractAddress) {
			throw new Error('Deployment failed — no contract address in receipt (constructor likely reverted).');
		}
		return getContract({address: receipt.contractAddress, abi, client: {public: publicClient, wallet: wallet!}});
	}

	before(async function () {
		contract = await deploy();
	});

	it('deploys successfully with the pinned public key', async function () {
		expect(contract.address).not.toEqual('0x0000000000000000000000000000000000000000');
	});

	it('h() returns the exact packed public key appended at construction', async function () {
		const h = await contract.read.h();
		expect((h as string).toLowerCase()).toEqual(vectorsJson.key.hPacked.toLowerCase());
	});
});

// The harness mirrors ntrusignVerify verbatim (see its own header) — this
// is the actual empirical check that the raw Yul port of
// test/js/utils/ntruSign.ts's `verify()` is correct, against the same
// vectors NTRUSign.test.ts checks the JS reference against, plus the
// real measured gas cost.
const harnessAbi = [
	{type: 'function', name: 'verify', stateMutability: 'view', inputs: [{type: 'bytes'}, {type: 'bytes32'}], outputs: [{type: 'bool'}]},
] as const;

describe('NTRUSignAccountVerifyHarness — the raw Yul verify math, against the same vectors NTRUSign.test.ts checks the JS reference against', function () {
	let harness: Awaited<ReturnType<typeof deployHarness>>;

	async function deployHarness() {
		const [wallet] = await viem.getWalletClients();
		const publicClient = await viem.getPublicClient();
		const yulPath = fileURLToPath(new URL('../yul/NTRUSignAccountVerifyHarness.yul', import.meta.url));
		const initBytecode = compileYul(yulPath);
		const args = encodeConstructorArgs(vectorsJson.key.hPacked as Hex);
		const hash = await wallet!.sendTransaction({data: `${initBytecode}${args.slice(2)}` as Hex});
		const receipt = await publicClient.waitForTransactionReceipt({hash});
		if (!receipt.contractAddress) {
			throw new Error('Harness deployment failed — no contract address in receipt.');
		}
		return getContract({address: receipt.contractAddress, abi: harnessAbi, client: {public: publicClient, wallet: wallet!}});
	}

	before(async function () {
		harness = await deployHarness();
	});

	for (const [i, v] of vectorsJson.signVectors.entries()) {
		it(`accepts sign vector ${i} ("${v.message}") — same verdict as NTRUSign.test.ts`, async function () {
			const ok = await harness.read.verify([v.signaturePacked as Hex, v.msgHash as Hex]);
			expect(ok).toEqual(true);
		});
	}

	it('rejects a signature crossed with the wrong message hash', async function () {
		const ok = await harness.read.verify([
			vectorsJson.signVectors[0]!.signaturePacked as Hex,
			vectorsJson.signVectors[1]!.msgHash as Hex,
		]);
		expect(ok).toEqual(false);
	});

	it('measures the real gas cost of one verify() call, honestly, rather than guessing', async function () {
		const publicClient = await viem.getPublicClient();
		const [wallet] = await viem.getWalletClients();
		const v = vectorsJson.signVectors[0]!;
		const gas = await publicClient.estimateContractGas({
			address: harness.address,
			abi: harnessAbi,
			functionName: 'verify',
			args: [v.signaturePacked as Hex, v.msgHash as Hex],
			account: wallet!.account,
		});
		// Not a hard `< 100_000` assertion: measured this session at
		// ~121,800, over EIP-8141's *current* MAX_VERIFY_GAS — a real,
		// known fact, kept in tools/ anyway per this repo's README (that
		// ceiling is itself under active discussion for being raised).
		// This is a sanity bound instead, confirming the number stays in
		// "real but not absurd" territory, not a claim it clears the
		// current public-mempool cap.
		console.log(`  measured gas for verify(): ${gas.toString()}`);
		expect(gas > 50_000n).toEqual(true);
		expect(gas < 500_000n).toEqual(true);
	});
});
