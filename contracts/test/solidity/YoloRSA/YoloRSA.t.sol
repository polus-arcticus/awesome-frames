// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {YoloRSA} from "src/YoloRSA/YoloRSA.sol";

/// @notice Known-answer + negative tests for YoloRSA.verify, across the
/// whole yolo-wallet difficulty ladder (see test/js/utils/yoloRSA.ts's
/// header for the bit-size-to-difficulty reasoning). Every vector below was
/// generated and cross-checked (sign -> verify round-trip, plus a
/// factor()-and-recover-d round-trip up through the "laptop" tier) by
/// scripts/gen-yolo-rsa-vectors.ts — see test/vectors/yolo-rsa-vectors.json
/// for the source of truth these are transcribed from. "weekend-project"
/// sits at 248 bits, not higher: n has to fit in a single EVM word
/// (uint256's hard 256-bit ceiling), so 248 is as strong as this ladder can
/// go with margin to spare.
contract YoloRSATest is Test {
    struct Vector {
        uint256 n;
        uint256 e;
        uint256 signature;
        uint256 msgHash;
    }

    function _verify(Vector memory v) internal view returns (bool) {
        return YoloRSA.verify(v.n, v.e, v.signature, v.msgHash);
    }

    // ==================== pencil (12-bit n) ====================

    function test_pencil_vector0_valid() public view {
        assertTrue(
            _verify(
                Vector({
                    n: 2257,
                    e: 7,
                    signature: 704,
                    msgHash: 7719472615821079694904732333912527190217998977709370935963838933860875309329
                })
            )
        );
    }

    function test_pencil_vector1_valid() public view {
        assertTrue(
            _verify(
                Vector({
                    n: 2257,
                    e: 7,
                    signature: 524,
                    msgHash: 100720434726375746010458024839911619878118703404436202866098422983289408962287
                })
            )
        );
    }

    function test_pencil_zeroHash_valid() public view {
        assertTrue(_verify(Vector({n: 2257, e: 7, signature: 0, msgHash: 0})));
    }

    function test_pencil_invalidVector_rejected() public view {
        assertFalse(
            _verify(
                Vector({
                    n: 2257,
                    e: 7,
                    signature: 705,
                    msgHash: 7719472615821079694904732333912527190217998977709370935963838933860875309329
                })
            )
        );
    }

    // ==================== calculator (23-bit n) ====================

    function test_calculator_vector0_valid() public view {
        assertTrue(
            _verify(
                Vector({
                    n: 6394429,
                    e: 65537,
                    signature: 5585873,
                    msgHash: 7719472615821079694904732333912527190217998977709370935963838933860875309329
                })
            )
        );
    }

    function test_calculator_vector1_valid() public view {
        assertTrue(
            _verify(
                Vector({
                    n: 6394429,
                    e: 65537,
                    signature: 5303968,
                    msgHash: 100720434726375746010458024839911619878118703404436202866098422983289408962287
                })
            )
        );
    }

    function test_calculator_invalidVector_rejected() public view {
        assertFalse(
            _verify(
                Vector({
                    n: 6394429,
                    e: 65537,
                    signature: 5585874,
                    msgHash: 7719472615821079694904732333912527190217998977709370935963838933860875309329
                })
            )
        );
    }

    // ==================== script-kiddie (48-bit n) ====================

    function test_scriptKiddie_vector0_valid() public view {
        assertTrue(
            _verify(
                Vector({
                    n: 151004653136431,
                    e: 65537,
                    signature: 148114970507758,
                    msgHash: 7719472615821079694904732333912527190217998977709370935963838933860875309329
                })
            )
        );
    }

    function test_scriptKiddie_vector1_valid() public view {
        assertTrue(
            _verify(
                Vector({
                    n: 151004653136431,
                    e: 65537,
                    signature: 65636652797911,
                    msgHash: 100720434726375746010458024839911619878118703404436202866098422983289408962287
                })
            )
        );
    }

    function test_scriptKiddie_invalidVector_rejected() public view {
        assertFalse(
            _verify(
                Vector({
                    n: 151004653136431,
                    e: 65537,
                    signature: 148114970507759,
                    msgHash: 7719472615821079694904732333912527190217998977709370935963838933860875309329
                })
            )
        );
    }

    // ==================== laptop (80-bit n) ====================

    function test_laptop_vector0_valid() public view {
        assertTrue(
            _verify(
                Vector({
                    n: 651410082561307435465837,
                    e: 65537,
                    signature: 621180052772341154389427,
                    msgHash: 7719472615821079694904732333912527190217998977709370935963838933860875309329
                })
            )
        );
    }

    function test_laptop_vector1_valid() public view {
        assertTrue(
            _verify(
                Vector({
                    n: 651410082561307435465837,
                    e: 65537,
                    signature: 347099458538109087518313,
                    msgHash: 100720434726375746010458024839911619878118703404436202866098422983289408962287
                })
            )
        );
    }

    function test_laptop_invalidVector_rejected() public view {
        assertFalse(
            _verify(
                Vector({
                    n: 651410082561307435465837,
                    e: 65537,
                    signature: 621180052772341154389428,
                    msgHash: 7719472615821079694904732333912527190217998977709370935963838933860875309329
                })
            )
        );
    }

    // ==================== weekend-project (248-bit n) ====================

    function test_weekendProject_vector0_valid() public view {
        assertTrue(
            _verify(
                Vector({
                    n: 281067118105482210536264156688052567470643086352722106495818500035383891851,
                    e: 65537,
                    signature: 89923322201294355434786566591379117336014609954368640501794231411010108965,
                    msgHash: 7719472615821079694904732333912527190217998977709370935963838933860875309329
                })
            )
        );
    }

    function test_weekendProject_invalidVector_rejected() public view {
        assertFalse(
            _verify(
                Vector({
                    n: 281067118105482210536264156688052567470643086352722106495818500035383891851,
                    e: 65537,
                    signature: 89923322201294355434786566591379117336014609954368640501794231411010108966,
                    msgHash: 7719472615821079694904732333912527190217998977709370935963838933860875309329
                })
            )
        );
    }

    // ==================== Structural edge cases ====================

    function test_zeroModulus_rejected() public view {
        assertFalse(_verify(Vector({n: 0, e: 3, signature: 0, msgHash: 0})));
    }

    function test_signatureEqualsModulus_rejected() public view {
        // s must be strictly < n, even though s == n would reduce to the
        // same residue mathematically — same canonical-range discipline as
        // BIP340.sol's Rx/s range checks.
        assertFalse(_verify(Vector({n: 2257, e: 7, signature: 2257, msgHash: 0})));
    }
}
