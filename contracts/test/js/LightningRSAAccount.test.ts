// Tests the parts of src/LightningRSA/LightningRSAAccount.yul that
// DON'T need EIP-8141 opcodes and so ARE testable on Hardhat's ordinary
// local network: the constructor's self-code-embedding ([n][e][nLen]
// appended after the runtime code, via CODECOPY rather than SSTORE — see
// that file's header for why) and the `e()`/`n()` getters' bootstrap read
// of that tail. This is the newest, riskiest translation from the
// forge-tested Solidity math (LightningRSA.t.sol) into raw Yul memory
// offsets — deploying for real and reading the getters back is a much
// stronger check than eyeballing the offset arithmetic.
//
// The actual verify path (SIGDATACOPY/TXPARAM/APPROVE) needs the live
// ethrex testnet, same reasoning as every other EIP-8141-opcode-using
// account in this repo — not covered here.
import {expect} from 'earl';
import {describe, it, before} from 'node:test';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import solc from 'solc';
import {network} from 'hardhat';
import {getContract, type Hex} from 'viem';

interface Vectors {
	n: string;
	e: string;
	signVectors: {msgHash: string; signature: string}[];
	invalidVector: {msgHash: string; signature: string};
}

const vectorsJson: Vectors = JSON.parse(
	readFileSync(fileURLToPath(new URL('../vectors/lightning-rsa-vectors.json', import.meta.url)), 'utf8'),
);

const abi = [
	{type: 'function', name: 'e', stateMutability: 'view', inputs: [], outputs: [{type: 'uint256'}]},
	{type: 'function', name: 'n', stateMutability: 'view', inputs: [], outputs: [{type: 'bytes'}]},
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
		throw new Error(
			'Yul compilation failed:\n' + errors.map((e: {formattedMessage: string}) => e.formattedMessage).join('\n'),
		);
	}
	const contractName = Object.keys(output.contracts[sourcePath])[0]!;
	return `0x${output.contracts[sourcePath][contractName].evm.bytecode.object}` as Hex;
}

/// Constructor args: [n (nLen bytes)] [e (32 bytes, right-aligned)] [nLen (32 bytes)].
function encodeConstructorArgs(n: Hex, e: bigint): Hex {
	const nBytes = n.slice(2);
	const nLen = nBytes.length / 2;
	const eWord = e.toString(16).padStart(64, '0');
	const nLenWord = nLen.toString(16).padStart(64, '0');
	return `0x${nBytes}${eWord}${nLenWord}` as Hex;
}

const {viem} = await network.create();

describe('LightningRSAAccount — self-code-embedding constructor + getters', function () {
	let contract: Awaited<ReturnType<typeof deploy>>;

	async function deploy() {
		const [wallet] = await viem.getWalletClients();
		const publicClient = await viem.getPublicClient();
		const yulPath = fileURLToPath(
			new URL('../../src/LightningRSA/LightningRSAAccount.yul', import.meta.url),
		);
		const initBytecode = compileYul(yulPath);
		const args = encodeConstructorArgs(vectorsJson.n as Hex, BigInt(vectorsJson.e));
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

	it('deploys successfully with a real RSA-2048 modulus (8 EVM words)', async function () {
		expect(contract.address).not.toEqual('0x0000000000000000000000000000000000000000');
	});

	it('e() returns the exact public exponent appended at construction', async function () {
		const e = await contract.read.e();
		expect(e).toEqual(BigInt(vectorsJson.e));
	});

	it("n() returns the exact modulus bytes appended at construction (proves the constructor's CODECOPY-based embedding and the getter's bootstrap read agree)", async function () {
		const n = await contract.read.n();
		expect((n as string).toLowerCase()).toEqual(vectorsJson.n.toLowerCase());
	});
});

// The harness mirrors verifyLightningRSAInner verbatim (see its own
// header) — this is the actual empirical check that the raw Yul port of
// LightningRSA.sol's forge-tested padding/MODEXP logic is correct, using
// the exact same real RSA-2048/e=3 vectors LightningRSA.t.sol checks the
// Solidity original against.
const harnessAbi = [
	{
		type: 'function',
		name: 'verify',
		stateMutability: 'view',
		inputs: [{type: 'bytes'}, {type: 'bytes32'}],
		outputs: [{type: 'bool'}],
	},
] as const;

describe("LightningRSAAccountVerifyHarness — the raw Yul verify math, against the same vectors LightningRSA.t.sol checks the Solidity original against", function () {
	let harness: Awaited<ReturnType<typeof deployHarness>>;

	async function deployHarness() {
		const [wallet] = await viem.getWalletClients();
		const publicClient = await viem.getPublicClient();
		const yulPath = fileURLToPath(
			new URL('../yul/LightningRSAAccountVerifyHarness.yul', import.meta.url),
		);
		const initBytecode = compileYul(yulPath);
		const args = encodeConstructorArgs(vectorsJson.n as Hex, BigInt(vectorsJson.e));
		const hash = await wallet!.sendTransaction({data: `${initBytecode}${args.slice(2)}` as Hex});
		const receipt = await publicClient.waitForTransactionReceipt({hash});
		if (!receipt.contractAddress) {
			throw new Error('Harness deployment failed — no contract address in receipt.');
		}
		return getContract({
			address: receipt.contractAddress,
			abi: harnessAbi,
			client: {public: publicClient, wallet: wallet!},
		});
	}

	before(async function () {
		harness = await deployHarness();
	});

	for (const [i, v] of vectorsJson.signVectors.entries()) {
		it(`accepts sign vector ${i} — same verdict as LightningRSA.t.sol's test_vector${i}_valid`, async function () {
			const ok = await harness.read.verify([v.signature as Hex, v.msgHash as Hex]);
			expect(ok).toEqual(true);
		});
	}

	it("rejects the pinned invalid vector — same verdict as LightningRSA.t.sol's test_invalidVector_rejected", async function () {
		const ok = await harness.read.verify([
			vectorsJson.invalidVector.signature as Hex,
			vectorsJson.invalidVector.msgHash as Hex,
		]);
		expect(ok).toEqual(false);
	});

	it('rejects a signature crossed with the wrong message hash', async function () {
		const ok = await harness.read.verify([
			vectorsJson.signVectors[0]!.signature as Hex,
			vectorsJson.signVectors[1]!.msgHash as Hex,
		]);
		expect(ok).toEqual(false);
	});
});
