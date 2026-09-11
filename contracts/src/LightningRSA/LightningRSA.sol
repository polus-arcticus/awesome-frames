// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title LightningRSA — RSASSA-PKCS1-v1_5 (SHA-256) signature verification
/// @notice Unlike src/grimoire/YoloRSA/YoloRSA.sol (deliberately-tiny, deliberately
/// unpadded — see that file's header), this is meant to be sound at any
/// modulus size an operator actually deploys with: real EMSA-PKCS1-v1_5
/// padding (RFC 8017 §9.2), arbitrary modulus width via Solidity's native
/// `bytes` (no fixed word count baked in — this is what "N words" turns
/// into once the type system handles it for you). Default target:
/// RSA-2048 (`n` = 256 bytes = 8 EVM words), verified against real
/// signatures produced by Node's own `crypto` module — see
/// test/js/utils/pkcs1.ts and scripts/gen-lightning-rsa-vectors.ts.
///
/// @dev `msgHash` plays the role of "the message" — it gets hashed *again*
/// with SHA-256 internally, exactly like any RS256-signed payload. That's
/// standard, not a bug: passing an already-hashed value (a Frame tx's
/// compute_sig_hash(tx)) into a hash-then-sign scheme is completely normal.
///
/// @dev Verification re-derives the expected padded block (EM) from the
/// message hash and compares it byte-for-byte against MODEXP's recovered
/// output — it does NOT parse padding out of the recovered value. This is
/// deliberate: implementations that leniently *parse* PKCS#1 v1.5 padding
/// (permitting garbage after the DigestInfo, or a too-short PS) instead of
/// reconstructing-and-comparing are exactly the ones that have
/// historically been broken (Bleichenbacher-style low-exponent forgeries
/// against sloppy verifiers — real bugs in OpenSSL/NSS/Firefox in the
/// 2000s-2010s). Recompute, don't parse.
library LightningRSA {
    /// @dev DER encoding of the SHA-256 DigestInfo AlgorithmIdentifier
    /// prefix (RFC 8017 Appendix, Note 1) — this exact 19-byte constant
    /// appears in every conformant PKCS#1 v1.5/SHA-256 implementation, and
    /// was cross-checked against Node's own signatures before being
    /// trusted here (see gen-lightning-rsa-vectors.ts).
    bytes internal constant SHA256_DIGEST_INFO_PREFIX = hex"3031300d060960864801650304020105000420";

    /// @notice Verify an RSASSA-PKCS1-v1_5/SHA-256 signature over `msgHash`
    /// against public key `(e, n)`.
    /// @param n modulus, big-endian bytes, any length (RSA-2048 -> 256 bytes)
    /// @param e public exponent, big-endian bytes (typically 3 bytes: 0x010001)
    /// @param signature big-endian bytes, must be exactly n.length bytes
    function verify(bytes memory n, bytes memory e, bytes memory signature, bytes32 msgHash) internal view returns (bool) {
        uint256 k = n.length;
        if (k == 0 || signature.length != k) return false;
        if (!_lessThan(signature, n)) return false; // canonical: signature must be < n

        bytes32 h = sha256(abi.encodePacked(msgHash));
        bytes memory expectedEM = _buildEM(h, k);
        bytes memory recoveredEM = _modexp(signature, e, n);
        return keccak256(recoveredEM) == keccak256(expectedEM);
    }

    /// @dev EMSA-PKCS1-v1_5-ENCODE (RFC 8017 §9.2):
    /// EM = 0x00 || 0x01 || PS (0xff * psLen) || 0x00 || T,
    /// T = SHA256_DIGEST_INFO_PREFIX || hash.
    function _buildEM(bytes32 h, uint256 emLen) private pure returns (bytes memory em) {
        uint256 tLen = SHA256_DIGEST_INFO_PREFIX.length + 32;
        require(emLen >= tLen + 11, "LightningRSA: modulus too small for SHA-256");
        uint256 psLen = emLen - tLen - 3;

        em = new bytes(emLen);
        em[0] = 0x00;
        em[1] = 0x01;
        for (uint256 i = 0; i < psLen; i++) {
            em[2 + i] = 0xff;
        }
        uint256 offset = 2 + psLen;
        em[offset] = 0x00;
        offset += 1;
        for (uint256 i = 0; i < SHA256_DIGEST_INFO_PREFIX.length; i++) {
            em[offset + i] = SHA256_DIGEST_INFO_PREFIX[i];
        }
        offset += SHA256_DIGEST_INFO_PREFIX.length;
        for (uint256 i = 0; i < 32; i++) {
            em[offset + i] = h[i];
        }
    }

    /// @dev Big-endian byte-string less-than, for two equal-length arrays.
    function _lessThan(bytes memory a, bytes memory b) private pure returns (bool) {
        uint256 len = a.length;
        for (uint256 i = 0; i < len; i++) {
            if (a[i] < b[i]) return true;
            if (a[i] > b[i]) return false;
        }
        return false; // equal -> not less than
    }

    /// @dev base^exponent mod modulus via the MODEXP precompile (0x05),
    /// arbitrary byte lengths — `MCOPY` (Cancun) keeps the exact-byte-length
    /// copies below correct regardless of 32-byte alignment.
    function _modexp(bytes memory base, bytes memory exponent, bytes memory modulus) private view returns (bytes memory result) {
        uint256 bLen = base.length;
        uint256 eLen = exponent.length;
        uint256 mLen = modulus.length;
        result = new bytes(mLen);
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, bLen)
            mstore(add(ptr, 0x20), eLen)
            mstore(add(ptr, 0x40), mLen)
            let cursor := add(ptr, 0x60)
            mcopy(cursor, add(base, 0x20), bLen)
            cursor := add(cursor, bLen)
            mcopy(cursor, add(exponent, 0x20), eLen)
            cursor := add(cursor, eLen)
            mcopy(cursor, add(modulus, 0x20), mLen)
            cursor := add(cursor, mLen)
            let inputLen := sub(cursor, ptr)
            let ok := staticcall(gas(), 0x05, ptr, inputLen, add(result, 0x20), mLen)
            if iszero(ok) {
                revert(0, 0)
            }
        }
    }
}
