/// @title NTRUSignAccount
/// @notice A self-verifying EIP-8141 account authorized by an **NTRUSign**
/// signature — the predecessor to Falcon, and a real, historically broken
/// lattice signature scheme: Nguyen & Regev's 2006 "learning a
/// parallelepiped" attack recovers the secret key from as few as 400
/// ordinary signatures at the scheme's real parameters. Deliberately
/// weak, on purpose, the same way `src/toys/YoloRSA`'s crackme accounts
/// are — the difference is `NTRUSign` lives in `tools/`, not `toys/`,
/// because unlike a toy that's never meant to be used, this account is
/// real and deployable: the whole premise of this repo's
/// weak-crypto-marketplace pivot is that Frame transactions make it cheap
/// to deploy cryptography that's weak *on purpose* and stake
/// correspondingly little on it.
///
/// @dev Ring: N=18, q=128. See test/js/utils/ntruSign.ts's header for the
/// full derivation, including why N=18 and not the gas-optimal N=11:
/// N=11 was tried first and rejected — even with a tightly-reduced secret
/// basis, a legitimate signature's closeness to its own message and its
/// closeness to a totally unrelated message turned out to be statistically
/// indistinguishable there (that's not "weak," it's non-functional as a
/// signature scheme). N=18 is the smallest tried that actually works,
/// confirmed by a real "sign and verify 'hello world', reject 'goodbye
/// world'" check. See src/toys/ for the N=11 failure, kept as a
/// demonstration of exactly this.
///
/// @dev Gas: measured (this repo's own harness,
/// test/yul/NTRUSignAccountVerifyHarness.yul, run against ordinary
/// Hardhat) at ~121,800 for one verify() call — over EIP-8141's *current*
/// `MAX_VERIFY_GAS=100_000` public-mempool cap. Kept in `tools/` anyway:
/// that ceiling is itself under active discussion for being raised (see
/// the EIP-8141 breakout-call notes from 2026-09-01,
/// https://ethereum-magicians.org/t/frame-transaction-breakout-3-sep-1-2026/29539/2,
/// where Nethermind's Daniil flagged 100_000 as already too tight for
/// privacy-pool withdrawals), consistent with mainnet block gas limits
/// climbing toward 80M+ while this single-frame ceiling has stayed fixed.
/// This account is real and correct; whether it clears the *current*
/// public-mempool ceiling is a separate, evolving question, stated here
/// honestly rather than hidden.
///
/// @dev Every coefficient handled here is reduced mod 128 — a signature
/// only needs to be transmitted/verified mod q (the closeness check and
/// t=s*h are both mod-q operations; the raw, unreduced Babai-rounding
/// output the private key computes during signing is never needed on the
/// wire, only its mod-128 residue) — so every value fits in one unsigned
/// byte and no negative-number handling appears anywhere in this file.
///
/// @dev Public key `h`: 18 coefficients (< 128 each), packed into one
/// 32-byte word — `byte(i, hPacked)` (Yul's `byte` opcode, most
/// significant byte first) gives coefficient `i`; the low 14 bytes of the
/// word are unused. Small enough to keep in storage (one SLOAD per call),
/// unlike LightningRSAAccount.yul's much larger RSA modulus, which needed
/// code-embedding instead — see that file's header for why that
/// distinction matters against the gas budget.
///
/// @dev Message-to-lattice-point hashing: keccak256(msgHash \|\| "NTRUSign"
/// \|\| counter_byte), consumed 1 byte per coefficient, re-hashing with an
/// incremented counter once a 32-byte digest is exhausted — a direct port
/// of ntruSign.ts's `hashToPoint`, EVM-native (KECCAK256 is an opcode, not
/// a precompile call, so it's admissible from a `VERIFY` frame without
/// violating the "only precompiles" validation-trace rule). For N=18 this
/// needs exactly two keccak256 calls.
///
/// @dev Closeness check: recovers t = s*h mod q, then checks the CYCLIC
/// (mod-q) distance from s to m1 and from t to m2 is within
/// CLOSENESS_BOUND=48 for every coefficient — cyclic, not raw
/// subtraction (a value already reduced mod q wraps: 125 and 3 are 6
/// apart mod 128, not 122) — see ntruSign.ts's `cyclicMaxDist`.
/// `submodQ` reuses the exact "(a-b) mod Q, guard against EVM's wrapping
/// SUB" idiom this repo's other Yul entries already use (see e.g.
/// src/toys/StarkPedersen/StarkPedersen.yul's `submodP`).
///
/// @dev Every piece of this file's verify math (message hashing,
/// convolution, closeness check) is copied structurally from
/// test/yul/NTRUSignAccountVerifyHarness.yul, which is what was actually
/// tested against test/js/utils/ntruSign.ts before this file was written
/// — the only difference here is pulling the witness via `SIGDATACOPY`
/// instead of plain calldata, per every other self-verifying account in
/// this repo (see NostrFrameAccount.yul's header for the full
/// witness-placement rationale: the signature must live in an
/// `ARBITRARY` signature entry, never frame `data`, or `compute_sig_hash`
/// would have to sign a hash containing itself).
///
/// Storage layout: slot 0 = hPacked (the public key, packed as above).
///
/// Constructor: hPacked, right-aligned in a 32-byte word, appended after
/// initcode — same convention as every other account in this repo.
///
/// Functions:
///   (32-byte calldata)   — the verify path: a uint256 `signatureIndex`
///                          identifying which `ARBITRARY` entry in
///                          `tx.signatures` carries the packed 18-byte
///                          signature.
///   h()                0xb8c9d365 — read the stored public key (packed).
///   receive()             (no selector) — accept ETH funding.
object "NTRUSignAccount" {
	code {
		let argOffset := sub(codesize(), 32)
		codecopy(0, argOffset, 32)
		let hPacked := mload(0)
		if iszero(hPacked) { revert(0, 0) }
		sstore(0, hPacked)

		datacopy(0, dataoffset("runtime"), datasize("runtime"))
		return(0, datasize("runtime"))
	}
	object "runtime" {
		code {
			// receive() — accept ETH funding.
			if iszero(calldatasize()) { stop() }

			// ── Verify path: exactly 32 bytes = signatureIndex (uint256) ──
			if eq(calldatasize(), 32) {
				let signatureIndex := calldataload(0)

				// SIGDATACOPY(memOffset=0x60, dataOffset=0, length=18,
				// signatureIndex) -> the packed signature bytes, left-aligned
				// at memory 0x60. Only valid for ARBITRARY-scheme entries
				// (enforced on-chain); reverts on out-of-bounds signatureIndex.
				verbatim_4i_0o(hex"B5", 0x60, 0x00, 18, signatureIndex)

				// TXPARAM(0x08) -> compute_sig_hash(tx). Safe to read here:
				// the witness above was elided from this hash (empty-`msg`
				// ARBITRARY entry), so no circularity.
				let sigHash := verbatim_1i_1o(hex"B0", 0x08)

				if iszero(ntrusignVerify(0x60, sload(0), sigHash)) {
					revert(0, 0)
				}

				// APPROVE(scope=3 = APPROVE_EXECUTION_AND_PAYMENT) — self_verify.
				verbatim_3i_0o(hex"AA", 0, 0, 3)
				stop()
			}

			// ── Function selector routing (debug getters) ──
			if lt(calldatasize(), 4) { revert(0, 0) }
			let selector := shr(224, calldataload(0))

			switch selector
			// h() 0xb8c9d365
			case 0xb8c9d365 {
				mstore(0, sload(0))
				return(0, 0x20)
			}
			default { revert(0, 0) }

			// ── Memory layout for the coefficient arrays below — each
			// region holds N=18 coefficients, one per 32-byte word, spaced
			// far enough apart (0x400=1024 bytes) that none overlap N*32=
			// 576 bytes of real content.
			// m1Base=0x1000 m2Base=0x1400 hBase=0x1800 sBase=0x1c00 tBase=0x2000

			function loadCoeff(base, i) -> v {
				v := mload(add(base, mul(i, 32)))
			}
			function storeCoeff(base, i, v) {
				mstore(add(base, mul(i, 32)), v)
			}

			// (a - b) mod 128, guarding against EVM's wrapping `sub` — same
			// idiom as StarkPedersen.yul's `submodP`.
			function submodQ(a, b) -> r {
				r := mod(add(a, sub(128, b)), 128)
			}
			// Cyclic distance mod 128: min(d, 128-d).
			function cyclicDist(a, b) -> d {
				d := submodQ(a, b)
				if gt(d, 64) { d := sub(128, d) }
			}

			// 18-coefficient schoolbook convolution mod 128: t = s*h.
			function computeT(sBase, hBase, tBase) {
				for { let i := 0 } lt(i, 18) { i := add(i, 1) } {
					storeCoeff(tBase, i, 0)
				}
				for { let i := 0 } lt(i, 18) { i := add(i, 1) } {
					let si := loadCoeff(sBase, i)
					for { let j := 0 } lt(j, 18) { j := add(j, 1) } {
						let hj := loadCoeff(hBase, j)
						let idx := mod(add(i, j), 18)
						storeCoeff(tBase, idx, and(add(loadCoeff(tBase, idx), mul(si, hj)), 127))
					}
				}
			}

			function unpackH(hPacked, hBase) {
				for { let i := 0 } lt(i, 18) { i := add(i, 1) } {
					storeCoeff(hBase, i, byte(i, hPacked))
				}
			}
			// The signature was SIGDATACOPY'd as 18 raw bytes, left-aligned
			// at sigMemOffset — mload reads it (plus zero-initialized
			// trailing memory) as one word, same big-endian "byte i =
			// coefficient i" convention as h.
			function unpackS(sigMemOffset, sBase) {
				let sigWord := mload(sigMemOffset)
				for { let i := 0 } lt(i, 18) { i := add(i, 1) } {
					storeCoeff(sBase, i, byte(i, sigWord))
				}
			}

			// Message-to-lattice-point hash: keccak256(msgHash || "NTRUSign"
			// || counter), 1 byte consumed per coefficient, re-hashing with
			// counter+1 once a digest is exhausted. "NTRUSign" as 8
			// big-endian ASCII bytes, left-aligned in the word placed right
			// after msgHash.
			function computeHashToPoint(msgHash, m1Base, m2Base) {
				let inBase := 0x4000
				mstore(inBase, msgHash)
				mstore(add(inBase, 32), shl(192, 0x4E5452555369676E)) // "NTRUSign"
				mstore8(add(inBase, 40), 0)
				let pool0 := keccak256(inBase, 41)
				for { let i := 0 } lt(i, 18) { i := add(i, 1) } {
					storeCoeff(m1Base, i, and(byte(i, pool0), 127))
				}
				for { let i := 0 } lt(i, 14) { i := add(i, 1) } {
					storeCoeff(m2Base, i, and(byte(add(18, i), pool0), 127))
				}
				mstore8(add(inBase, 40), 1)
				let pool1 := keccak256(inBase, 41)
				for { let i := 0 } lt(i, 4) { i := add(i, 1) } {
					storeCoeff(m2Base, add(14, i), and(byte(i, pool1), 127))
				}
			}

			// ── NTRUSign verification, using only the KECCAK256 opcode
			// (not a precompile call, but not an external contract call
			// either — admissible from a VERIFY frame either way) — a
			// direct Yul port of ntruSign.ts's `verify`; see that file and
			// this object's header for the derivation. Clobbers memory
			// 0x1000 upward; caller must not rely on scratch memory across
			// this call.
			function ntrusignVerify(sigMemOffset, hPacked, msgHash) -> ok {
				let m1Base := 0x1000
				let m2Base := 0x1400
				let hBase := 0x1800
				let sBase := 0x1c00
				let tBase := 0x2000

				computeHashToPoint(msgHash, m1Base, m2Base)
				unpackH(hPacked, hBase)
				unpackS(sigMemOffset, sBase)
				computeT(sBase, hBase, tBase)

				let maxDist := 0
				for { let i := 0 } lt(i, 18) { i := add(i, 1) } {
					let sd := cyclicDist(loadCoeff(sBase, i), loadCoeff(m1Base, i))
					if gt(sd, maxDist) { maxDist := sd }
					let td := cyclicDist(loadCoeff(tBase, i), loadCoeff(m2Base, i))
					if gt(td, maxDist) { maxDist := td }
				}
				ok := iszero(gt(maxDist, 48)) // CLOSENESS_BOUND
			}
		}
	}
}
