/// @title YoloRSAWideAccount
/// @notice The wide-modulus sibling of YoloRSAAccount.yul: same
/// deliberately-broken textbook RSA scheme (see YoloRSA.sol's header for
/// the padding-scheme caveat — it applies unchanged here), but with `n`
/// spanning TWO 32-byte words (up to 512 bits) instead of one. Where
/// YoloRSAAccount's tiers are "small enough to factor with a naive
/// script," this template's tiers are sized to survive a specific
/// real-world attacker clock: a modulus whose GNFS factoring time, run on
/// Ethereum-validator-spec hardware (ethereum.org's own CPU guidance)
/// starting the instant a spend hits the mempool, lands at a target
/// duration (`ten-minute`, `one-hour`, ...) — the same shape of assumption
/// Bitcoin's own P2PK mempool exposure already rests on informally: a
/// wallet whose security window is measured against how long a
/// transaction can plausibly sit exposed before confirmation, not
/// "infeasible forever."
///
/// @dev This was originally its own top-level module ("LightningRSA") —
/// relocated here once it became clear the thing distinguishing it from
/// YoloRSA was never "deployability" (both are equally deployable) but
/// modulus width, and once the `LightningRSA` name was needed for an
/// actual production-shaped recipe (see src/LightningRSA/) built on
/// real PKCS#1 v1.5 padding — a scheme unpadded textbook RSA, at any
/// modulus size, never graduates to.
///
/// @dev Structurally this is YoloRSAAccount.yul widened from 1 word to 2
/// words for `n` and the signature witness — same overall account shape
/// (constructor-arg convention, ARBITRARY-signature witness via
/// SIGDATACOPY, inlined-precompile-only verification, self_verify APPROVE)
/// — see that file's header for the parts not repeated here.
///
/// @dev Why `n` MUST have a nonzero high word (enforced at construction):
/// the message representative is `m = msgHash mod n`. msgHash is always
/// < 2^256 (it's `compute_sig_hash(tx)`, one word). Once n > 2^256 — i.e.
/// its high word is nonzero — `msgHash mod n` is msgHash itself, no actual
/// reduction ever happens. That's what lets `verifyYoloRSAWide` skip
/// implementing genuine 512-bit modular reduction: it only has to check
/// that MODEXP's 64-byte result has a zero high word and msgHash as its
/// low word. Deploying with a high word of zero (n <= 2^256, not actually
/// using the second word) would silently break that shortcut — hence the
/// constructor revert rather than falling back to correct-but-unwritten
/// general reduction. Use YoloRSAAccount.yul instead for anything that
/// small; that's exactly the case it already covers.
///
/// @dev MODEXP (0x05) call shape: Bsize=0x40 (signature, 2 words),
/// Esize=0x20 (e always fits in one word — 65537 or similar), Msize=0x40
/// (modulus, 2 words). Input is 0x100 bytes total (3 length words + 64 +
/// 32 + 64); output is the 64-byte Msize-wide result.
///
/// Storage layout: slot 0 = e, slot 1 = n's high word, slot 2 = n's low word.
///
/// Constructor: e, n's high word, n's low word — each right-aligned in its
/// own 32-byte word, appended after initcode (96 bytes total).
///
/// Functions:
///   (32-byte calldata)   — the verify path: a uint256 `signatureIndex`
///                          identifying which `ARBITRARY` entry in
///                          `tx.signatures` carries the 64-byte signature
///                          (high word || low word).
///   e()                0xffae15ba — read the stored public exponent.
///   n()                0x2e52d606 — read the stored public modulus, as
///                          64 bytes (high word || low word).
///   receive()             (no selector) — accept ETH funding.
object "YoloRSAWideAccount" {
	code {
		let argOffset := sub(codesize(), 96)
		codecopy(0, argOffset, 96)
		let e := mload(0)
		let nHigh := mload(0x20)
		let nLow := mload(0x40)
		if iszero(nHigh) { revert(0, 0) } // n must genuinely exceed 2^256 - see header
		sstore(0, e)
		sstore(1, nHigh)
		sstore(2, nLow)

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

				// SIGDATACOPY(memOffset=0, dataOffset=0, length=64,
				// signatureIndex) -> the raw RSA signature (sHigh || sLow)
				// at mem 0x00. Only valid for ARBITRARY-scheme entries
				// (enforced on-chain); reverts on out-of-bounds
				// signatureIndex.
				verbatim_4i_0o(hex"B5", 0x00, 0x00, 64, signatureIndex)
				let sHigh := mload(0x00)
				let sLow := mload(0x20)

				// TXPARAM(0x08) -> compute_sig_hash(tx). Safe to read
				// here: the witness above was elided from this hash
				// (empty-`msg` ARBITRARY entry), so no circularity.
				let sigHash := verbatim_1i_1o(hex"B0", 0x08)

				if iszero(verifyYoloRSAWide(sload(0), sload(1), sload(2), sHigh, sLow, sigHash)) {
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
			// n() 0x2e52d606 — returns 64 bytes: high word || low word.
			case 0x2e52d606 {
				mstore(0, sload(1))
				mstore(0x20, sload(2))
				return(0, 0x40)
			}
			default { revert(0, 0) }

			// ── Deliberately-broken textbook RSA verify, widened to a
			// 2-word (up to 512-bit) modulus — see this object's header
			// for the MODEXP call shape and why no general modular
			// reduction is needed for `msgHash`. Clobbers memory
			// 0x00-0xFF; caller must not rely on scratch memory across
			// this call.
			function verifyYoloRSAWide(e, nHigh, nLow, sHigh, sLow, msgHash) -> ok {
				if iszero(nHigh) { leave } // n must genuinely exceed 2^256 - see header

				// Reject signature >= n (2-word unsigned comparison).
				let sLtN := or(lt(sHigh, nHigh), and(eq(sHigh, nHigh), lt(sLow, nLow)))
				if iszero(sLtN) { leave }

				mstore(0x00, 0x40) // Bsize = 64 (signature, 2 words)
				mstore(0x20, 0x20) // Esize = 32 (e always fits in 1 word)
				mstore(0x40, 0x40) // Msize = 64 (modulus, 2 words)
				mstore(0x60, sHigh)
				mstore(0x80, sLow)
				mstore(0xa0, e)
				mstore(0xc0, nHigh)
				mstore(0xe0, nLow)
				if iszero(staticcall(gas(), 0x05, 0x00, 0x100, 0x00, 0x40)) {
					revert(0, 0)
				}

				// s^e mod n must equal msgHash exactly: n > 2^256 always
				// here, so "msgHash mod n" is msgHash unchanged (header
				// note) — the 64-byte result must have a zero high word
				// and msgHash as its low word.
				ok := and(iszero(mload(0x00)), eq(mload(0x20), msgHash))
			}
		}
	}
}
