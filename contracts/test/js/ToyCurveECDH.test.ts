// Deploys src/grimoire/ToyCurveECDH/ToyCurveECDH.yul to Hardhat's local
// simulated network (no live-network dependency — this contract needs
// none of EIP-8141's opcodes) and checks it two ways: against the
// known-answer vectors in test/vectors/toy-curve-vectors.json (generated
// by scripts/gen-toy-curve-vectors.ts from the independent JS/bigint
// mirror in test/js/utils/toyCurve.ts), and with a fresh, live two-party
// ECDH exchange run directly against the deployed contract — the actual
// "it works" proof, same spirit as BIP340.test.ts's cross-reference check.
import {expect} from 'earl';
import {describe, it, before} from 'node:test';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import solc from 'solc';
import {network} from 'hardhat';
import {getContract, type Hex} from 'viem';
import {generate, unite, toWire} from './utils/toyCurve.js';

interface WirePoint {
	x: string;
	y: string;
}
interface ToyCurveVectors {
	chordAdd: {p1: WirePoint; p2: WirePoint; expected: WirePoint}[];
	tangentDouble: {p: WirePoint; expected: WirePoint}[];
	scalarMultiply: {k: string; p: WirePoint; expected: WirePoint}[];
	ecdh: {
		alicePriv: string;
		bobPriv: string;
		alicePublic: WirePoint;
		bobPublic: WirePoint;
		sharedSecret: WirePoint;
	};
}

const vectorsJson: ToyCurveVectors = JSON.parse(
	readFileSync(
		fileURLToPath(new URL('../vectors/toy-curve-vectors.json', import.meta.url)),
		'utf8',
	),
);

const abi = [
	{
		type: 'function',
		name: 'jia_add',
		stateMutability: 'pure',
		inputs: [
			{type: 'uint256'},
			{type: 'uint256'},
			{type: 'uint256'},
			{type: 'uint256'},
		],
		outputs: [{type: 'uint256'}, {type: 'uint256'}],
	},
	{
		type: 'function',
		name: 'xian_chord',
		stateMutability: 'pure',
		inputs: [
			{type: 'uint256'},
			{type: 'uint256'},
			{type: 'uint256'},
			{type: 'uint256'},
		],
		outputs: [{type: 'uint256'}, {type: 'uint256'}],
	},
	{
		type: 'function',
		name: 'qie_tangent',
		stateMutability: 'pure',
		inputs: [{type: 'uint256'}, {type: 'uint256'}],
		outputs: [{type: 'uint256'}, {type: 'uint256'}],
	},
	{
		type: 'function',
		name: 'cheng_multiply',
		stateMutability: 'pure',
		inputs: [{type: 'uint256'}, {type: 'uint256'}, {type: 'uint256'}],
		outputs: [{type: 'uint256'}, {type: 'uint256'}],
	},
	{
		type: 'function',
		name: 'sheng_generate',
		stateMutability: 'pure',
		inputs: [{type: 'uint256'}],
		outputs: [{type: 'uint256'}, {type: 'uint256'}],
	},
	{
		type: 'function',
		name: 'he_unite',
		stateMutability: 'pure',
		inputs: [{type: 'uint256'}, {type: 'uint256'}, {type: 'uint256'}],
		outputs: [{type: 'uint256'}, {type: 'uint256'}],
	},
] as const;

function compileYul(sourcePath: string): Hex {
	const src = readFileSync(sourcePath, 'utf8');
	const input = {
		language: 'Yul',
		sources: {[sourcePath]: {content: src}},
		settings: {outputSelection: {'*': {'*': ['evm.bytecode.object']}}},
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
	return `0x${output.contracts[sourcePath][contractName].evm.bytecode.object}` as Hex;
}

const {viem} = await network.create();

describe('ToyCurveECDH (grimoire)', function () {
	let contract: Awaited<ReturnType<typeof deploy>>;

	async function deploy() {
		const [wallet] = await viem.getWalletClients();
		const publicClient = await viem.getPublicClient();
		const yulPath = fileURLToPath(
			new URL(
				'../../src/grimoire/ToyCurveECDH/ToyCurveECDH.yul',
				import.meta.url,
			),
		);
		const initBytecode = compileYul(yulPath);
		const hash = await wallet!.sendTransaction({data: initBytecode});
		const receipt = await publicClient.waitForTransactionReceipt({hash});
		return getContract({
			address: receipt.contractAddress!,
			abi,
			client: {public: publicClient, wallet: wallet!},
		});
	}

	before(async function () {
		contract = await deploy();
	});

	it('jia_add matches known-answer chord (distinct-point addition) vectors', async function () {
		for (const v of vectorsJson.chordAdd) {
			const [x3, y3] = await contract.read.jia_add([
				BigInt(v.p1.x),
				BigInt(v.p1.y),
				BigInt(v.p2.x),
				BigInt(v.p2.y),
			]);
			expect(x3).toEqual(BigInt(v.expected.x));
			expect(y3).toEqual(BigInt(v.expected.y));
		}
	});

	it('xian_chord matches the same chord vectors directly (not just via jia_add)', async function () {
		for (const v of vectorsJson.chordAdd) {
			const [x3, y3] = await contract.read.xian_chord([
				BigInt(v.p1.x),
				BigInt(v.p1.y),
				BigInt(v.p2.x),
				BigInt(v.p2.y),
			]);
			expect(x3).toEqual(BigInt(v.expected.x));
			expect(y3).toEqual(BigInt(v.expected.y));
		}
	});

	it('qie_tangent matches known-answer doubling vectors', async function () {
		for (const v of vectorsJson.tangentDouble) {
			const [x3, y3] = await contract.read.qie_tangent([
				BigInt(v.p.x),
				BigInt(v.p.y),
			]);
			expect(x3).toEqual(BigInt(v.expected.x));
			expect(y3).toEqual(BigInt(v.expected.y));
		}
	});

	it('jia_add matches the same doubling vectors when both inputs are the same point', async function () {
		for (const v of vectorsJson.tangentDouble) {
			const [x3, y3] = await contract.read.jia_add([
				BigInt(v.p.x),
				BigInt(v.p.y),
				BigInt(v.p.x),
				BigInt(v.p.y),
			]);
			expect(x3).toEqual(BigInt(v.expected.x));
			expect(y3).toEqual(BigInt(v.expected.y));
		}
	});

	it('cheng_multiply matches known-answer scalar vectors, including k=0 and k=N wrapping to O', async function () {
		for (const v of vectorsJson.scalarMultiply) {
			const [x3, y3] = await contract.read.cheng_multiply([
				BigInt(v.k),
				BigInt(v.p.x),
				BigInt(v.p.y),
			]);
			expect(x3).toEqual(BigInt(v.expected.x));
			expect(y3).toEqual(BigInt(v.expected.y));
		}
	});

	it('sheng_generate . he_unite reproduces the pinned Alice/Bob ECDH vector', async function () {
		const v = vectorsJson.ecdh;

		// Toy-curve pedagogy only: private scalars are passed as plain
		// .read() args here so we can check on-chain arithmetic against a
		// known value, over Hardhat's in-process local network. Never do
		// this against a real RPC endpoint or with a real key — the scalar
		// travels as cleartext calldata to whatever node executes the call.
		const [aliceX, aliceY] = await contract.read.sheng_generate([
			BigInt(v.alicePriv),
		]);
		expect(aliceX).toEqual(BigInt(v.alicePublic.x));
		expect(aliceY).toEqual(BigInt(v.alicePublic.y));

		const [bobX, bobY] = await contract.read.sheng_generate([
			BigInt(v.bobPriv),
		]);
		expect(bobX).toEqual(BigInt(v.bobPublic.x));
		expect(bobY).toEqual(BigInt(v.bobPublic.y));

		const [sharedX, sharedY] = await contract.read.he_unite([
			BigInt(v.alicePriv),
			bobX,
			bobY,
		]);
		expect(sharedX).toEqual(BigInt(v.sharedSecret.x));
		expect(sharedY).toEqual(BigInt(v.sharedSecret.y));
	});

	it('runs a fresh, live two-party ECDH exchange — the actual proof, not just pinned vectors', async function () {
		// Private scalars not used anywhere in the pinned vectors above.
		// Same toy-curve caveat as above: these get passed as plain .read()
		// args below purely to exercise the on-chain math. A real ECDH
		// private key must never be sent as a call argument to any node.
		const alicePriv = 4n;
		const bobPriv = 11n;

		const [aliceX, aliceY] = await contract.read.sheng_generate([alicePriv]);
		const [bobX, bobY] = await contract.read.sheng_generate([bobPriv]);

		const [aliceSharedX, aliceSharedY] = await contract.read.he_unite([
			alicePriv,
			bobX,
			bobY,
		]);
		const [bobSharedX, bobSharedY] = await contract.read.he_unite([
			bobPriv,
			aliceX,
			aliceY,
		]);

		// Alice and Bob, computing independently, unite at the same point.
		expect(aliceSharedX).toEqual(bobSharedX);
		expect(aliceSharedY).toEqual(bobSharedY);

		// And it matches the independent JS/bigint mirror, not just itself.
		const jsShared = toWire(unite(alicePriv, generate(bobPriv)));
		expect(aliceSharedX).toEqual(jsShared.x);
		expect(aliceSharedY).toEqual(jsShared.y);
	});
});
