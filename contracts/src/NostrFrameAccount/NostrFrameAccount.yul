/// @title NostrFrameAccount
/// @notice A minimal EIP-8141 self-verifying account authorized by a
/// BIP-340 (Nostr) Schnorr signature instead of ECDSA — the "same key,
/// two protocols" account this repo is named after (see
/// nostr-frame-schnorr-design.md). Its VERIFY frame references an
/// `ARBITRARY` signature entry (px‖rx‖s, 96 bytes) via `SIGDATACOPY`; on
/// success it APPROVEs both execution and payment (the `self_verify` shape).
///
/// @dev Pure Yul, not Solidity: solc does not support the `verbatim`
/// builtin inside a normal contract's inline assembly, and `verbatim` is
/// the only way to emit EIP-8141's new opcodes (`APPROVE` 0xAA, `TXPARAM`
/// 0xB0, `SIGDATACOPY` 0xB5) — they have no Solidity mnemonic. This mirrors
/// ethrex's own reference validation contracts for this exact testnet
/// (scripts/hegota-testnet/contracts/OpenSponsor.yul on lambdaclass/ethrex's
/// `hegota-testnet` branch) — same constructor-arg convention, same
/// "check a fixed-length calldata shape before selector parsing" idiom,
/// same `verbatim_Ni_Mo` calls.
///
/// @dev Why the witness is NOT in the VERIFY frame's calldata: an earlier
/// version of this contract put px‖rx‖s directly in frame `data` and read
/// it via plain `calldataload`, mirroring ethrex's own
/// `CanonicalPaymaster.yul`. That is circular and broken: `compute_sig_hash`
/// (what `TXPARAM(0x08)` returns) commits to ALL frame data verbatim, so a
/// signature carried in frame data would have to sign a hash that already
/// contains itself — an unsatisfiable ECDSA/Schnorr fixed point. OpenSponsor
/// .yul's own header comment flags exactly this ("do not port [Canonical
/// Paymaster] verbatim"), and EIP-8141 §"Transaction Signatures" is explicit:
/// "Bespoke signature schemes must place their witness bytes in an
/// ARBITRARY signature entry rather than in frame data when the witness
/// signs the canonical transaction signature hash." An `ARBITRARY` entry
/// with empty `msg` has its raw `signature` bytes elided before hashing
/// (`compute_sig_hash`'s whole point), breaking the circularity — the
/// witness is read back at *execution* time via `SIGDATACOPY`, which
/// exposes the real (non-elided) bytes.
///
/// @dev Why the BIP-340 math is inlined here instead of `STATICCALL`ing the
/// already-tested `BIP340.sol` library (via a thin external wrapper, as a
/// first version of this contract did): EIP-8141's public-mempool
/// "Validation Trace Rules" reject `CALL*`/`EXTCODE*` from a VERIFY frame to
/// anything but `tx.sender`, an existing default-code account, or a
/// *precompile* — a plain external contract call is rejected outright
/// (`CallToNonexistentOrDelegated`) regardless of how old or side-effect-free
/// it is. This is exactly the constraint OpenSponsor.yul's own header
/// documents for its own design ("no external calls... admissible via the
/// public mempool"). So the reduction from BIP340.sol's `verify` (see that
/// file's header for the derivation) is reproduced here using only
/// precompiles: SHA256 (0x02) for the tagged challenge hash, MODEXP (0x05)
/// for the modular inverse, and ECRECOVER (0x01) for the final recovery —
/// all three are explicitly exempt from the external-call ban.
///
/// Storage layout: slot 0 = pAddress (address(P), the even-Y BIP-340
/// pubkey's address — computed off-chain once, at setup).
///
/// Constructor: pAddress, right-aligned in a 32-byte word, appended after
/// initcode — same convention as OpenSponsor.yul.
///
/// Functions:
///   (32-byte calldata)   — the verify path: a uint256 `signatureIndex`
///                          identifying which `ARBITRARY` entry in
///                          `tx.signatures` carries px‖rx‖s.
///   pAddress()        0xe71f83c5 — read the stored account pubkey address.
///   receive()            (no selector) — accept ETH funding.
object "NostrFrameAccount" {
	code {
		let argOffset := sub(codesize(), 32)
		codecopy(0, argOffset, 32)
		let pAddress := and(mload(0), 0xffffffffffffffffffffffffffffffffffffffff)
		if iszero(pAddress) { revert(0, 0) }
		sstore(0, pAddress)

		datacopy(0, dataoffset("runtime"), datasize("runtime"))
		return(0, datasize("runtime"))
	}
	object "runtime" {
		code {
			// receive() — accept ETH funding.
			if iszero(calldatasize()) { stop() }

			// ── Verify path: exactly 32 bytes = signatureIndex (uint256) ──
			// Checked before selector parsing, same reason OpenSponsor.yul
			// checks calldatasize before reading a selector: a fixed-shape
			// payload would otherwise be misread as a 4-byte selector plus
			// garbage arguments.
			if eq(calldatasize(), 32) {
				let signatureIndex := calldataload(0)

				// SIGDATACOPY(memOffset=0, dataOffset=0, length=96,
				// signatureIndex) -> px(32) || rx(32) || s(32) at mem 0x00.
				// Only valid for ARBITRARY-scheme entries (enforced
				// on-chain); reverts on out-of-bounds signatureIndex.
				verbatim_4i_0o(hex"B5", 0x00, 0x00, 96, signatureIndex)
				let px := mload(0x00)
				let rx := mload(0x20)
				let s := mload(0x40)

				// TXPARAM(0x08) -> compute_sig_hash(tx). Safe to read
				// here: the witness above was elided from this hash
				// (empty-`msg` ARBITRARY entry), so no circularity.
				let sigHash := verbatim_1i_1o(hex"B0", 0x08)

				if iszero(verifyBip340(sload(0), px, rx, s, sigHash)) {
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
			// pAddress() 0xe71f83c5
			case 0xe71f83c5 {
				mstore(0, sload(0))
				return(0, 0x20)
			}
			default { revert(0, 0) }

			// ── BIP-340 verification via the ecrecover-trick, using only
			// precompiles (see this object's header for why) — a direct
			// Yul port of BIP340.sol's `verify`/`challenge`/`taggedHash`;
			// see that file for the derivation and its own gas/range-check
			// rationale. Clobbers memory 0x00-0xBF; caller must not rely on
			// scratch memory across this call.
			function verifyBip340(pAddress, px, rx, s, msgHash) -> ok {
				let N := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

				if iszero(pAddress) { leave }
				if iszero(rx) { leave }
				if iszero(lt(rx, N)) { leave } // reject rx >= N
				if iszero(lt(s, N)) { leave } // reject s >= N

				// e = sha256(TAG || TAG || rx || px || msgHash) mod N, TAG =
				// sha256("BIP0340/challenge") (constant-folded, matches
				// BIP340.sol's CHALLENGE_TAG_HASH).
				let tag := 0x7bb52d7a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48d37c
				mstore(0x00, tag)
				mstore(0x20, tag)
				mstore(0x40, rx)
				mstore(0x60, px)
				mstore(0x80, msgHash)
				if iszero(staticcall(gas(), 0x02, 0x00, 0xa0, 0x00, 0x20)) {
					revert(0, 0)
				}
				let e := mod(mload(0x00), N)
				if iszero(e) { leave }

				// eInv = e^(N-2) mod N via MODEXP (0x05).
				mstore(0x00, 0x20)
				mstore(0x20, 0x20)
				mstore(0x40, 0x20)
				mstore(0x60, e)
				mstore(0x80, sub(N, 2))
				mstore(0xa0, N)
				if iszero(staticcall(gas(), 0x05, 0x00, 0xc0, 0x00, 0x20)) {
					revert(0, 0)
				}
				let eInv := mload(0x00)

				let sEcdsa := sub(N, mulmod(rx, eInv, N))
				let z := mulmod(sEcdsa, s, N)

				// ecrecover(z, v=27, r=rx, s=sEcdsa) via precompile 0x01.
				mstore(0x00, z)
				mstore(0x20, 27)
				mstore(0x40, rx)
				mstore(0x60, sEcdsa)
				if iszero(staticcall(gas(), 0x01, 0x00, 0x80, 0x00, 0x20)) {
					leave
				}
				let recovered := mload(0x00)
				ok := and(iszero(iszero(recovered)), eq(recovered, pAddress))
			}
		}
	}
}
