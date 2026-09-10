// A narrated Alice/Bob key exchange against the deployed
// src/grimoire/ToyCurveECDH/ToyCurveECDH.yul — see that file's header for
// the curve and the glossary. Needs no live network (no EIP-8141 opcodes
// involved at all): runs against whatever network `contracts:execute`
// points at, `local`/`default` included.
//
// Run: pnpm contracts:execute local scripts/toy-curve-demo.ts
// (or: pnpm contracts:execute default scripts/toy-curve-demo.ts)
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import solc from 'solc';
import {network} from 'hardhat';
import {getContract, type Hex} from 'viem';

const N = 19n; // group order — see ToyCurveECDH.yul's header for the derivation

const abi = [
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

// Toy RNG, deliberately: this whole contract is insecure by design (see
// its header), so there's no reason to reach for anything cryptographic
// just to pick a demo scalar.
function randomScalar(): bigint {
	return 1n + BigInt(Math.floor(Math.random() * Number(N - 1n)));
}

async function main() {
	console.log('E: y^2 = x^3 + 2x + 2 (mod 17), group order 19, G = (5, 1).\n');

	const {viem} = await network.create();
	const [wallet] = await viem.getWalletClients();
	const publicClient = await viem.getPublicClient();

	const yulPath = fileURLToPath(
		new URL('../src/grimoire/ToyCurveECDH/ToyCurveECDH.yul', import.meta.url),
	);
	const initBytecode = compileYul(yulPath);
	const deployHash = await wallet!.sendTransaction({data: initBytecode});
	const deployReceipt = await publicClient.waitForTransactionReceipt({
		hash: deployHash,
	});
	const address = deployReceipt.contractAddress!;
	console.log(`ToyCurveECDH deployed at ${address}\n`);

	const contract = getContract({
		address,
		abi,
		client: {public: publicClient, wallet: wallet!},
	});

	// ── Alice and Bob each pick a private scalar and beget (生) a public point ──
	const alicePriv = randomScalar();
	const bobPriv = randomScalar();
	console.log(`Alice's private scalar:  ${alicePriv}`);
	console.log(`Bob's private scalar:    ${bobPriv}\n`);

	const [aliceX, aliceY] = await contract.read.sheng_generate([alicePriv]);
	const [bobX, bobY] = await contract.read.sheng_generate([bobPriv]);
	console.log(`Alice's public point:    (${aliceX}, ${aliceY})`);
	console.log(`Bob's public point:      (${bobX}, ${bobY})\n`);

	console.log('They exchange public points over an open channel...\n');

	// ── Each unites (合) their own private scalar with the other's public point ──
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
	console.log(`Alice arrives at:        (${aliceSharedX}, ${aliceSharedY})`);
	console.log(`Bob arrives at:          (${bobSharedX}, ${bobSharedY})`);

	if (aliceSharedX !== bobSharedX || aliceSharedY !== bobSharedY) {
		throw new Error('Alice and Bob did not unite at the same point!');
	}
	console.log('\nSame point, arrived at independently — the exchange worked.\n');

	// ── The point of a TOY curve: the whole group fits in one breath, so
	// the "hard" problem (recover the private scalar from the public
	// point) is just a for-loop, not a research project. Recover Alice's
	// scalar the way any attacker with the public point could. ──
	console.log(
		"Now the part a real curve doesn't let you do: brute-forcing Alice's",
	);
	console.log('private scalar back out of her public point alone...\n');
	let recovered: bigint | null = null;
	for (let k = 1n; k < N; k++) {
		const [x, y] = await contract.read.sheng_generate([k]);
		if (x === aliceX && y === aliceY) {
			recovered = k;
			break;
		}
	}
	console.log(
		recovered === alicePriv
			? `Recovered k=${recovered} in at most ${N - 1n} tries — matches Alice's real scalar.`
			: `Something is wrong: recovered ${recovered}, expected ${alicePriv}.`,
	);
	console.log(
		'\nThis is the whole lesson: shrink the group enough to read as a poem,',
	);
	console.log('and you shrink it enough to break by hand. Never reuse these numbers.');
}

main().catch((err) => {
	console.error(err);
	process.exit(1);
});
