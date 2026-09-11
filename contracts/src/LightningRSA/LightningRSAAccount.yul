/// @title LightningRSAAccount
/// @notice A self-verifying EIP-8141 account authorized by a real
/// RSASSA-PKCS1-v1_5/SHA-256 signature (RFC 8017 §9.2/§8.2) — unlike
/// src/grimoire/YoloRSA/{YoloRSAAccount,YoloRSAWideAccount}.yul, this is
/// meant to be sound at any modulus width, not a toy. Its VERIFY frame
/// references an `ARBITRARY` signature entry (the raw RSA signature,
/// exactly `n`'s byte length) via `SIGDATACOPY`; on success it APPROVEs
/// both execution and payment (the `self_verify` shape) — same overall
/// structure as NostrFrameAccount.yul and the YoloRSA accounts.
///
/// @dev The math is derived and forge-tested first as a pure Solidity
/// library — src/LightningRSA/LightningRSA.sol, checked against real
/// RSA-2048 signatures produced by Node's own `crypto` module — then
/// re-inlined here using only precompiles (SHA256 `0x02`, MODEXP `0x05`),
/// per EIP-8141's Validation Trace Rules (see the primer doc / other
/// accounts' headers for why). See that file's header for the padding
/// derivation and the "recompute the expected EM, don't parse the
/// recovered one" rationale (closes the historical Bleichenbacher-class
/// low-exponent forgery bugs).
///
/// @dev Why `n`/`e` live in the deployed CODE, not storage: a real RSA-2048
/// modulus is 8 EVM words. Reading 8 words via SLOAD (even warm) costs far
/// more than reading the same 8 words via CODECOPY from this contract's own
/// bytecode — and it matters here: EIP-8141 caps a VERIFY frame's total
/// public-mempool-admissible execution at `MAX_VERIFY_GAS = 100_000`
/// (confirmed against the EIP text, not assumed). A forge-measured run of
/// the Solidity reference library's `verify` (test_gasCost_underVerify
/// FrameBudget in LightningRSA.t.sol) costs ~92_187 gas at e=3 — already
/// close to that ceiling using Solidity's `bytes memory` overhead, which
/// this file avoids by working in raw memory throughout. `e`, `nLen`, and
/// `n`'s bytes are appended directly after this object's own runtime code
/// at deployment (see the constructor) and read back each call via
/// self-CODECOPY, bootstrapped the same "read from the end of codesize()"
/// way the constructor itself reads its append constructor args.
///
/// @dev Why e=3, not the usual 65537: EIP-2565's MODEXP gas formula prices
/// `iteration_count` from the *exponent's* bit length, not the modulus's —
/// e=65537 (17 bits) costs roughly 200_000 gas for an RSA-2048 MODEXP call
/// alone by that formula, well over MAX_VERIFY_GAS; e=3 (2 bits) costs
/// roughly 13_000. Low-public-exponent RSA has real historical forgery
/// bugs (Bleichenbacher-style), but every one of them targeted verifiers
/// that leniently *parsed* padding out of the recovered value instead of
/// reconstructing the expected block and comparing — which is exactly the
/// discipline this account (and LightningRSA.sol) follows throughout.
///
/// @dev n must be word-aligned (`nLen % 32 == 0`) and at least 62 bytes
/// (RFC 8017's minimum for SHA-256 padding room) — enforced at
/// construction. True for every standard RSA modulus size (512/1024/2048/
/// 3072/4096 bits); this account isn't meant for anything smaller (use the
/// grimoire's YoloRSA for that, on purpose).
///
/// Deployed code layout: [runtime code][e, 32 bytes][nLen, 32 bytes][n, nLen bytes].
///
/// Constructor: n, then e, then nLen — each right-aligned, appended after
/// initcode ([n (nLen bytes)][e (32 bytes)][nLen (32 bytes)], nLen last so
/// it's always locatable at a fixed offset from `codesize()` regardless of
/// its own value) — copied verbatim onto the end of the deployed runtime
/// code, unchanged, so the runtime's own bootstrap read (below) can use
/// the exact same layout.
///
/// Functions:
///   (32-byte calldata)   — the verify path: a uint256 `signatureIndex`
///                          identifying which `ARBITRARY` entry in
///                          `tx.signatures` carries the raw RSA signature
///                          (exactly `n`'s byte length).
///   e()                0xffae15ba — read the stored public exponent (32 bytes).
///   n()                0x2e52d606 — read the stored public modulus, ABI-encoded
///                          as `bytes` (dynamic length).
///   receive()             (no selector) — accept ETH funding.
object "LightningRSAAccount" {
	code {
		let nLenPtr := sub(codesize(), 32)
		codecopy(0, nLenPtr, 32)
		let nLen := mload(0)
		if iszero(nLen) { revert(0, 0) }
		if mod(nLen, 32) { revert(0, 0) } // word-aligned - see header
		if lt(nLen, 62) { revert(0, 0) } // RFC 8017 minimum for SHA-256 padding room

		let tailLen := add(64, nLen) // [n][e][nLen]
		let tailPtr := sub(codesize(), tailLen)

		let runtimeSize := datasize("runtime")
		datacopy(0, dataoffset("runtime"), runtimeSize)
		codecopy(runtimeSize, tailPtr, tailLen)
		return(0, add(runtimeSize, tailLen))
	}
	object "runtime" {
		code {
			// receive() — accept ETH funding.
			if iszero(calldatasize()) { stop() }

			// ── Verify path: exactly 32 bytes = signatureIndex (uint256) ──
			if eq(calldatasize(), 32) {
				let signatureIndex := calldataload(0)

				// TXPARAM(0x08) -> compute_sig_hash(tx). Safe to read here:
				// the witness is elided from this hash (empty-`msg`
				// ARBITRARY entry), so no circularity.
				let sigHash := verbatim_1i_1o(hex"B0", 0x08)

				if iszero(verifyLightningRSA(signatureIndex, sigHash)) {
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
			// e() 0xffae15ba
			case 0xffae15ba {
				let nLen, e := readKeyHeader()
				mstore(0, e)
				return(0, 0x20)
			}
			// n() 0x2e52d606 — ABI-encoded `bytes`: offset word, length word, data.
			case 0x2e52d606 {
				let nLen, e := readKeyHeader()
				let nPtr := sub(sub(codesize(), 64), nLen)
				mstore(0x00, 0x20)
				mstore(0x20, nLen)
				codecopy(0x40, nPtr, nLen)
				return(0x00, add(0x40, nLen))
			}
			default { revert(0, 0) }

			// ── Bootstraps nLen and e by reading the last 64 bytes of this
			// contract's OWN deployed code — see this object's header for
			// why CODE, not storage. `n`'s own bytes are then locatable at
			// codesize()-64-nLen, read directly by callers that need them.
			function readKeyHeader() -> nLen, e {
				let nLenPtr := sub(codesize(), 32)
				codecopy(0, nLenPtr, 32)
				nLen := mload(0)
				codecopy(0, sub(nLenPtr, 32), 32)
				e := mload(0)
			}

			// ── Real RSASSA-PKCS1-v1_5/SHA-256 verification, using only
			// the SHA256 (0x02) and MODEXP (0x05) precompiles — a direct
			// Yul port of LightningRSA.sol's `verify`/`_buildEM`; see that
			// file's header for the padding/"recompute don't parse"
			// derivation. Clobbers memory freely from 0x00 onward; caller
			// must not rely on scratch memory across this call.
			function verifyLightningRSA(signatureIndex, msgHash) -> ok {
				let nLen, e := readKeyHeader()
				let nPtr := sub(sub(codesize(), 64), nLen)
				let nWords := div(nLen, 32)
				ok := verifyLightningRSAInner(nLen, nWords, nPtr, e, signatureIndex, msgHash)
			}

			function verifyLightningRSAInner(nLen, nWords, nPtr, e, signatureIndex, msgHash) -> ok {
				let base := 0x60
				let expOff := add(base, nLen)
				let modOff := add(expOff, 32)
				let recoveredOff := add(modOff, nLen)
				let expectedOff := add(recoveredOff, nLen)
				let hashScratch := add(expectedOff, nLen)

				// SIGDATACOPY(memOffset=base, dataOffset=0, length=nLen,
				// signatureIndex) -> the raw RSA signature, directly into
				// the MODEXP call's base-operand position.
				verbatim_4i_0o(hex"B5", base, 0x00, nLen, signatureIndex)

				// Modulus, copied straight from this contract's own code.
				codecopy(modOff, nPtr, nLen)

				// Canonical range check: signature must be < n (RFC 8017
				// RSAVP1) — compare word-by-word from the most significant
				// word.
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

				// MODEXP(signature, e, n) -> recoveredOff, nLen bytes.
				mstore(0x00, nLen) // Bsize
				mstore(0x20, 0x20) // Esize (e right-aligned in one word)
				mstore(0x40, nLen) // Msize
				mstore(expOff, e)
				if iszero(staticcall(gas(), 0x05, 0x00, add(modOff, nLen), recoveredOff, nLen)) {
					revert(0, 0)
				}

				// H = SHA256(msgHash), via precompile 0x02.
				mstore(hashScratch, msgHash)
				if iszero(staticcall(gas(), 0x02, hashScratch, 32, hashScratch, 32)) {
					revert(0, 0)
				}
				let h := mload(hashScratch)

				// Reconstruct the expected EM = 0x00 || 0x01 || PS(0xff *
				// psLen) || 0x00 || (19-byte SHA-256 DigestInfo prefix) ||
				// H, tLen = 19+32 = 51, psLen = nLen-54. Never parse the
				// recovered value's padding — see this object's header.
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
