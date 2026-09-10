/// @title YoloRSAAccount
/// @notice A minimal EIP-8141 self-verifying account authorized by
/// deliberately-weak textbook RSA instead of ECDSA/Schnorr — see
/// src/YoloRSA/YoloRSA.sol for the verification math (padding caveat and
/// all) and that file's header for why this is toy-only. Its VERIFY frame
/// references an `ARBITRARY` signature entry (the raw RSA signature
/// integer `s`, 32 bytes) via `SIGDATACOPY`; on success it APPROVEs both
/// execution and payment (the `self_verify` shape) — same overall
/// structure as NostrFrameAccount.yul, just with the RSA check swapped in
/// for BIP-340. See that file's header for the general rationale
/// (constructor-arg convention, why the witness lives in an ARBITRARY
/// entry and not frame data, why the math is inlined instead of
/// STATICCALLed) — not repeated here.
///
/// @dev Same compiled initcode is meant to be redeployed, unmodified,
/// across every difficulty tier — only the constructor args (`e`, `n`)
/// differ per deployment. This is deliberately the OPPOSITE of keeping
/// keys off-chain: the entire point of a yolo wallet is that its public
/// key sits in plain sight in its own bytecode, daring anyone to factor
/// `n` and forge a signature. The PRIVATE exponent `d` never appears
/// anywhere in this file, any deploy script, or any transaction — only
/// `(e, n)` are ever public, exactly like a real RSA keypair.
///
/// Storage layout: slot 0 = e (public exponent), slot 1 = n (public modulus).
///
/// Constructor: e, then n, each right-aligned in its own 32-byte word,
/// appended after initcode (64 bytes total) — same convention as
/// NostrFrameAccount.yul, just two words instead of one.
///
/// Functions:
///   (32-byte calldata)   — the verify path: a uint256 `signatureIndex`
///                          identifying which `ARBITRARY` entry in
///                          `tx.signatures` carries the raw RSA signature.
///   e()                0xffae15ba — read the stored public exponent.
///   n()                0x2e52d606 — read the stored public modulus.
///   receive()             (no selector) — accept ETH funding.
object "YoloRSAAccount" {
	code {
		let argOffset := sub(codesize(), 64)
		codecopy(0, argOffset, 64)
		let e := mload(0)
		let n := mload(0x20)
		if iszero(n) { revert(0, 0) }
		sstore(0, e)
		sstore(1, n)

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

				// SIGDATACOPY(memOffset=0, dataOffset=0, length=32,
				// signatureIndex) -> the raw RSA signature `s` at mem 0x00.
				// Only valid for ARBITRARY-scheme entries (enforced
				// on-chain); reverts on out-of-bounds signatureIndex.
				verbatim_4i_0o(hex"B5", 0x00, 0x00, 32, signatureIndex)
				let s := mload(0x00)

				// TXPARAM(0x08) -> compute_sig_hash(tx). Safe to read
				// here: the witness above was elided from this hash
				// (empty-`msg` ARBITRARY entry), so no circularity.
				let sigHash := verbatim_1i_1o(hex"B0", 0x08)

				if iszero(verifyYoloRSA(sload(0), sload(1), s, sigHash)) {
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
				mstore(0, sload(0))
				return(0, 0x20)
			}
			// n() 0x2e52d606
			case 0x2e52d606 {
				mstore(0, sload(1))
				return(0, 0x20)
			}
			default { revert(0, 0) }

			// ── Deliberately-broken textbook RSA verify, using only the
			// MODEXP precompile (0x05) — a direct Yul port of
			// YoloRSA.sol's `verify`/`_modexp`; see that file's header for
			// the padding-scheme rationale. Clobbers memory 0x00-0xBF;
			// caller must not rely on scratch memory across this call.
			function verifyYoloRSA(e, n, s, msgHash) -> ok {
				if iszero(n) { leave }
				if iszero(lt(s, n)) { leave } // reject s >= n

				let m := mod(msgHash, n)

				mstore(0x00, 0x20)
				mstore(0x20, 0x20)
				mstore(0x40, 0x20)
				mstore(0x60, s)
				mstore(0x80, e)
				mstore(0xa0, n)
				if iszero(staticcall(gas(), 0x05, 0x00, 0xc0, 0x00, 0x20)) {
					revert(0, 0)
				}
				ok := eq(mload(0x00), m)
			}
		}
	}
}
