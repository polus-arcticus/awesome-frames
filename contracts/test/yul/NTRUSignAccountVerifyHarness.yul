/// @title NTRUSignAccountVerifyHarness
/// @notice TEST-ONLY. Not a tool, not deployed anywhere real — a mirror of
/// src/tools/NTRUSign/NTRUSignAccount.yul's verify math with the
/// EIP-8141-only witness-pulling (SIGDATACOPY/TXPARAM/APPROVE) swapped
/// out for plain calldata, so it's callable and testable on Hardhat's
/// ordinary local network — unlike the real account, which needs the
/// live ethrex testnet. Same role as
/// ../../src/tools/LightningRSA/../../test/yul/LightningRSAAccountVerifyHarness.yul
/// plays for LightningRSA: this is what actually empirically checks the
/// Yul port of test/js/utils/ntruSign.ts's `verify()` (message hashing,
/// convolution, cyclic-distance closeness check) is correct, and — the
/// main open question this file exists to answer — what it actually
/// costs in gas.
///
/// @dev Ring: N=18, q=128 — see test/js/utils/ntruSign.ts's header for
/// the full derivation (why N=11 was rejected, why N=18 works, the
/// MAX_VERIFY_GAS-under-discussion context). Every coefficient here is
/// reduced mod 128 (a signature only needs to be transmitted/verified mod
/// q — see the header of ntruSign.ts's `sign()`: the closeness check and
/// t=s*h are both mod-q operations, so the raw unreduced Babai-rounding
/// output is never needed on the wire, only its mod-128 residue), so
/// every value here fits in one unsigned byte — no negative-number
/// handling needed anywhere in this file.
///
/// @dev Public key `h`: 18 coefficients, each < 128, packed into a single
/// 32-byte word — `byte(i, hPacked)` (Yul's `byte` opcode, which reads
/// from the MOST significant byte first) gives coefficient `i`, matching
/// exactly how the message-hash-to-point expansion below reads bytes out
/// of a keccak256 digest. The low 14 bytes of the word are unused.
///
/// @dev Message-to-lattice-point hashing: keccak256(msgHash \|\| "NTRUSign"
/// \|\| counter_byte), consumed 1 byte per coefficient, re-hashing with an
/// incremented counter once a 32-byte digest is exhausted — a direct
/// port of ntruSign.ts's `hashToPoint`. For N=18 this needs exactly two
/// keccak256 calls: the first digest covers all 18 bytes of m1 plus the
/// first 14 bytes of m2; the second covers m2's remaining 4 bytes.
///
/// @dev Closeness check: recovers t = s*h mod q, then checks the CYCLIC
/// (mod-q) distance from s to m1 and from t to m2 is within
/// CLOSENESS_BOUND=48 for every coefficient — cyclic, not raw
/// subtraction, because a value already reduced mod q wraps (125 and 3
/// are 6 apart mod 128, not 122); see ntruSign.ts's `cyclicMaxDist` for
/// the same logic in JS. `submodQ` reuses the exact "(a-b) mod Q, guard
/// against EVM's wrapping SUB" idiom this repo's other Yul entries
/// already use (see e.g. src/toys/StarkPedersen/StarkPedersen.yul's
/// `submodP`).
///
/// Functions:
///   verify(bytes signature, bytes32 msgHash)   0x6b406341 -> bool
///   hashToPointPacked(bytes32 msgHash)         0x4d1fddc5 -> (bytes32 m1Packed, bytes32 m2Packed)
object "NTRUSignAccountVerifyHarness" {
	code {
		let argOffset := sub(codesize(), 32)
		codecopy(0, argOffset, 32)
		let hPacked := mload(0)
		sstore(0, hPacked)

		datacopy(0, dataoffset("runtime"), datasize("runtime"))
		return(0, datasize("runtime"))
	}
	object "runtime" {
		code {
			if lt(calldatasize(), 4) { revert(0, 0) }
			let selector := shr(224, calldataload(0))

			switch selector
			// verify(bytes,bytes32) 0x6b406341
			case 0x6b406341 {
				// ABI: [selector][offsetToSig][msgHash][sigLen][sigBytes...]
				let sigOffset := add(4, calldataload(4))
				let msgHash := calldataload(0x24)
				let sigLen := calldataload(sigOffset)
				let sigDataOffset := add(sigOffset, 0x20)
				if iszero(eq(sigLen, 18)) {
					mstore(0, 0)
					return(0, 0x20)
				}
				let ok := ntrusignVerify(sigDataOffset, sload(0), msgHash)
				mstore(0, ok)
				return(0, 0x20)
			}
			// hashToPointPacked(bytes32) 0x4d1fddc5
			case 0x4d1fddc5 {
				let msgHash := calldataload(4)
				let m1Base := 0x1000
				let m2Base := 0x1400
				computeHashToPoint(msgHash, m1Base, m2Base)
				mstore(0x00, packCoeffs(m1Base))
				mstore(0x20, packCoeffs(m2Base))
				return(0x00, 0x40)
			}
			default { revert(0, 0) }

			// ── Memory layout for the coefficient arrays used below — each
			// region holds N=18 coefficients, one per 32-byte word,
			// spaced far enough apart (0x400=1024 bytes) that none
			// overlap N*32=576 bytes of real content. ──
			// m1Base=0x1000 m2Base=0x1400 hBase=0x1800 sBase=0x1c00 tBase=0x2000

			function loadCoeff(base, i) -> v {
				v := mload(add(base, mul(i, 32)))
			}
			function storeCoeff(base, i, v) {
				mstore(add(base, mul(i, 32)), v)
			}
			// Packs 18 coefficients (each < 128) into one word, byte i
			// (from the left, matching Yul's `byte` opcode) = coefficient i.
			function packCoeffs(base) -> packed {
				for { let i := 0 } lt(i, 18) { i := add(i, 1) } {
					packed := or(packed, shl(mul(sub(31, i), 8), loadCoeff(base, i)))
				}
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
			// Signature is ABI `bytes`, 18 bytes long (checked by the caller);
			// the first calldata word already holds all 18 bytes left-aligned,
			// the same big-endian "byte i = coefficient i" convention as h.
			function unpackS(sigOffset, sBase) {
				let sigWord := calldataload(sigOffset)
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

			function ntrusignVerify(sigOffset, hPacked, msgHash) -> ok {
				let m1Base := 0x1000
				let m2Base := 0x1400
				let hBase := 0x1800
				let sBase := 0x1c00
				let tBase := 0x2000

				computeHashToPoint(msgHash, m1Base, m2Base)
				unpackH(hPacked, hBase)
				unpackS(sigOffset, sBase)
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
