/// @title LightningRSAAccountVerifyHarness
/// @notice TEST-ONLY. Not a recipe, not deployed anywhere real — a mirror
/// of src/LightningRSA/LightningRSAAccount.yul's verify math
/// (readKeyHeader / verifyLightningRSAInner, copied verbatim) with the
/// EIP-8141-only witness-pulling (SIGDATACOPY/TXPARAM/APPROVE) swapped out
/// for plain calldata, so it's callable and testable on Hardhat's ordinary
/// local network — unlike the real account, which needs the live ethrex
/// testnet. This is what actually empirically checks the raw Yul port of
/// LightningRSA.sol's forge-tested padding/MODEXP logic (offset
/// arithmetic, mstore8 sequencing) is correct, not just the constructor's
/// code-embedding mechanics (covered separately in LightningRSAAccount.test.ts).
///
/// Same deployed-code layout and constructor convention as the real
/// account: [runtime code][e, 32 bytes][nLen, 32 bytes][n, nLen bytes].
///
/// Functions:
///   verify(bytes signature, bytes32 msgHash)   0x6b406341 -> bool
object "LightningRSAAccountVerifyHarness" {
	code {
		let nLenPtr := sub(codesize(), 32)
		codecopy(0, nLenPtr, 32)
		let nLen := mload(0)
		if iszero(nLen) { revert(0, 0) }
		if mod(nLen, 32) { revert(0, 0) }
		if lt(nLen, 62) { revert(0, 0) }

		let tailLen := add(64, nLen)
		let tailPtr := sub(codesize(), tailLen)

		let runtimeSize := datasize("runtime")
		datacopy(0, dataoffset("runtime"), runtimeSize)
		codecopy(runtimeSize, tailPtr, tailLen)
		return(0, add(runtimeSize, tailLen))
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

				let nLen, e := readKeyHeader()
				if iszero(eq(sigLen, nLen)) {
					mstore(0, 0)
					return(0, 0x20)
				}

				// Place the signature exactly where verifyLightningRSAInner
				// expects it (`base = 0x60`), copied from calldata instead
				// of via SIGDATACOPY — the only difference from the real
				// account's witness-pulling.
				calldatacopy(0x60, sigDataOffset, sigLen)

				let nPtr := sub(sub(codesize(), 64), nLen)
				let nWords := div(nLen, 32)
				let ok := verifyLightningRSAInnerFromMemory(nLen, nWords, nPtr, e, msgHash)
				mstore(0, ok)
				return(0, 0x20)
			}
			default { revert(0, 0) }

			function readKeyHeader() -> nLen, e {
				let nLenPtr := sub(codesize(), 32)
				codecopy(0, nLenPtr, 32)
				nLen := mload(0)
				codecopy(0, sub(nLenPtr, 32), 32)
				e := mload(0)
			}

			// Identical to LightningRSAAccount.yul's verifyLightningRSAInner,
			// except the signature is assumed already placed at `base` by
			// the caller (calldatacopy above) instead of via SIGDATACOPY.
			function verifyLightningRSAInnerFromMemory(nLen, nWords, nPtr, e, msgHash) -> ok {
				let base := 0x60
				let expOff := add(base, nLen)
				let modOff := add(expOff, 32)
				let recoveredOff := add(modOff, nLen)
				let expectedOff := add(recoveredOff, nLen)
				let hashScratch := add(expectedOff, nLen)

				codecopy(modOff, nPtr, nLen)

				let isLess := 0
				let done := 0
				for { let i := 0 } lt(i, nWords) { i := add(i, 1) } {
					if iszero(done) {
						let sw := mload(add(base, mul(i, 32)))
						let nw := mload(add(modOff, mul(i, 32)))
						if lt(sw, nw) {
							isLess := 1
							done := 1
						}
						if gt(sw, nw) { done := 1 }
					}
				}
				if iszero(isLess) { leave }

				mstore(0x00, nLen)
				mstore(0x20, 0x20)
				mstore(0x40, nLen)
				mstore(expOff, e)
				if iszero(staticcall(gas(), 0x05, 0x00, add(modOff, nLen), recoveredOff, nLen)) {
					revert(0, 0)
				}

				mstore(hashScratch, msgHash)
				if iszero(staticcall(gas(), 0x02, hashScratch, 32, hashScratch, 32)) {
					revert(0, 0)
				}
				let h := mload(hashScratch)

				mstore8(expectedOff, 0x00)
				mstore8(add(expectedOff, 1), 0x01)
				let psLen := sub(nLen, 54)
				for { let i := 0 } lt(i, psLen) { i := add(i, 1) } {
					mstore8(add(add(expectedOff, 2), i), 0xff)
				}
				let afterPS := add(add(expectedOff, 2), psLen)
				mstore8(afterPS, 0x00)
				let p := add(afterPS, 1)
				mstore8(p, 0x30)
				mstore8(add(p, 1), 0x31)
				mstore8(add(p, 2), 0x30)
				mstore8(add(p, 3), 0x0d)
				mstore8(add(p, 4), 0x06)
				mstore8(add(p, 5), 0x09)
				mstore8(add(p, 6), 0x60)
				mstore8(add(p, 7), 0x86)
				mstore8(add(p, 8), 0x48)
				mstore8(add(p, 9), 0x01)
				mstore8(add(p, 10), 0x65)
				mstore8(add(p, 11), 0x03)
				mstore8(add(p, 12), 0x04)
				mstore8(add(p, 13), 0x02)
				mstore8(add(p, 14), 0x01)
				mstore8(add(p, 15), 0x05)
				mstore8(add(p, 16), 0x00)
				mstore8(add(p, 17), 0x04)
				mstore8(add(p, 18), 0x20)
				mstore(add(p, 19), h)

				ok := eq(keccak256(recoveredOff, nLen), keccak256(expectedOff, nLen))
			}
		}
	}
}
