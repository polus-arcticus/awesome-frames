// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title BIP-340 Schnorr verification via the ecrecover-trick
/// @notice Verifies BIP-340 (the scheme Nostr uses for event signing)
/// Schnorr signatures over secp256k1 using a single `ecrecover` call
/// (~3000 gas) instead of native point arithmetic, which the EVM has no
/// cheap precompile for.
///
/// Derivation (nostr-frame-schnorr-design.md §5.1): the BIP-340
/// verification equation `s*G = R + e*P` (R, P both even-Y points) is
/// solved for P and matched against the ECDSA recovery formula
/// `Q = r^-1 * (s_ecdsa*R_ecdsa - z*G)`, setting `R_ecdsa := R`:
///
///   s_ecdsa = -Rx * e^-1   mod n
///   z       = s_ecdsa * s  mod n
///   v = 27 (BIP-340 mandates R always has even Y)
///
/// `ecrecover(z, 27, Rx, s_ecdsa)` then recovers P; verification succeeds
/// iff the recovered address matches the account's precomputed
/// `address(P)` — computed off-chain once, at setup, from the even-Y point
/// at the account's x-only pubkey. This sidesteps on-chain point
/// decompression entirely: `ecrecover` decompresses R internally, and P is
/// only ever compared by address.
///
/// This derivation has been checked numerically against a noble-curves
/// reference implementation — see scripts/gen-vectors.ts.
library BIP340 {
    /// @dev secp256k1 group order
    uint256 internal constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /// @dev sha256("BIP0340/challenge"), constant-folded so `challenge`
    /// only pays for one sha256 call instead of two (design doc §5.3).
    bytes32 internal constant CHALLENGE_TAG_HASH = 0x7bb52d7a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48d37c;

    /// @notice BIP-340's tagged hash, given an already-hashed tag:
    /// sha256(tagHash || tagHash || data)
    function taggedHash(bytes32 tagHash, bytes memory data) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(tagHash, tagHash, data));
    }

    /// @notice e = taggedHash("BIP0340/challenge", rx || px || msgHash) mod n
    function challenge(bytes32 rx, bytes32 px, bytes32 msgHash) internal pure returns (uint256) {
        return uint256(taggedHash(CHALLENGE_TAG_HASH, abi.encodePacked(rx, px, msgHash))) % N;
    }

    /// @notice Verify a BIP-340 signature (rx, s) over `msgHash` against the
    /// account's precomputed `pAddress = address(P)`.
    /// @param pAddress keccak256(P.x || P.y)[12:] for the even-Y point at
    /// the account's x-only pubkey — computed and stored once, off-chain.
    /// @param px the account's x-only pubkey (32 bytes)
    /// @param rx signature R.x (32 bytes)
    /// @param s signature s (32 bytes)
    /// @param msgHash the 32-byte message the signature commits to
    function verify(
        address pAddress,
        bytes32 px,
        bytes32 rx,
        bytes32 s,
        bytes32 msgHash
    ) internal view returns (bool) {
        if (pAddress == address(0)) {
            return false;
        }

        uint256 rxi = uint256(rx);
        uint256 si = uint256(s);

        // Canonical-range checks (§5.4 malleability): BIP-340 requires
        // 0 <= Rx < p and 0 <= s < n. We additionally require Rx < N (not
        // just < the field prime p): the reduction below uses Rx both as a
        // curve x-coordinate and, mod N, as an ECDSA scalar. A real BIP-340
        // signature has Rx in [N, p) with probability ~2^-128 — this only
        // narrows the accepted range within that negligible sliver, it
        // cannot admit a forgery.
        if (rxi == 0 || rxi >= N) {
            return false;
        }
        if (si >= N) {
            return false;
        }

        uint256 e = challenge(rx, px, msgHash);
        if (e == 0) {
            return false; // degenerate; would leave P unconstrained
        }

        uint256 eInv = _invmodN(e);
        uint256 sEcdsa = N - mulmod(rxi, eInv, N);
        uint256 z = mulmod(sEcdsa, si, N);

        address recovered = ecrecover(bytes32(z), 27, rx, bytes32(sEcdsa));
        return recovered != address(0) && recovered == pAddress;
    }

    /// @dev Modular inverse mod N via Fermat's little theorem (N is prime):
    /// a^(N-2) mod N, computed with the MODEXP precompile (0x05).
    function _invmodN(uint256 a) private view returns (uint256 result) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, 0x20) // base length
            mstore(add(ptr, 0x20), 0x20) // exponent length
            mstore(add(ptr, 0x40), 0x20) // modulus length
            mstore(add(ptr, 0x60), a) // base
            mstore(add(ptr, 0x80), sub(N, 2)) // exponent = N - 2
            mstore(add(ptr, 0xa0), N) // modulus
            let ok := staticcall(gas(), 0x05, ptr, 0xc0, ptr, 0x20)
            if iszero(ok) {
                revert(0, 0)
            }
            result := mload(ptr)
        }
    }
}
