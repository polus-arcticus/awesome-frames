// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title YoloRSA — deliberately-tiny textbook RSA verification
/// @notice Verifies signatures over deliberately small RSA moduli. This is
/// a toy, not a library to reuse for anything real — see
/// src/grimoire/YoloRSA/YoloRSAAccount.yul for the self-verifying EIP-8141
/// account that inlines this exact check using only the MODEXP precompile,
/// and test/js/utils/yoloRSA.ts for the matching keygen/sign/factor
/// tooling this was checked against.
///
/// @dev Padding: real RSA signature schemes (PKCS#1 v1.5, PSS) need the
/// modulus to be significantly wider than the digest they embed — a
/// 2048-bit modulus for a 256-bit SHA-256 digest, with room to spare for
/// padding bytes. None of the moduli this toy targets (roughly 12-90 bits,
/// see yoloRSA.ts's tier list) have anywhere near that room, so there is no
/// structured padding here at all: the message representative is simply
/// `m = msgHash mod n`. This is deliberately *more* broken than "just" a
/// factorable modulus — textbook RSA without padding has malleability/
/// forgery issues independent of factoring (e.g. multiplicativity:
/// sig(m1) * sig(m2) mod n == sig(m1*m2 mod n)) — which is fine, even
/// desirable, for a wallet whose whole purpose is getting cracked. Do not
/// use this padding (non-)scheme, or anything else here, as a template for
/// real RSA-authenticated code.
library YoloRSA {
	/// @notice Verify signature `s` over `msgHash` against public key `(e, n)`.
	/// @dev m = msgHash mod n; accepts iff s < n and s^e mod n == m.
	function verify(uint256 n, uint256 e, uint256 signature, uint256 msgHash) internal view returns (bool) {
		if (n == 0 || signature >= n) {
			return false;
		}
		uint256 m = msgHash % n;
		return _modexp(signature, e, n) == m;
	}

	/// @dev base^exponent mod modulus via the MODEXP precompile (0x05).
	function _modexp(uint256 base, uint256 exponent, uint256 modulus) private view returns (uint256 result) {
		assembly ("memory-safe") {
			let ptr := mload(0x40)
			mstore(ptr, 0x20) // base length
			mstore(add(ptr, 0x20), 0x20) // exponent length
			mstore(add(ptr, 0x40), 0x20) // modulus length
			mstore(add(ptr, 0x60), base)
			mstore(add(ptr, 0x80), exponent)
			mstore(add(ptr, 0xa0), modulus)
			let ok := staticcall(gas(), 0x05, ptr, 0xc0, ptr, 0x20)
			if iszero(ok) {
				revert(0, 0)
			}
			result := mload(ptr)
		}
	}
}
