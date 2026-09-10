// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test, console} from "forge-std/Test.sol";
import {LightningRSA} from "src/LightningRSA/LightningRSA.sol";

/// @notice Known-answer + negative tests for LightningRSA.verify, against a
/// real RSA-2048 keypair (e=3, not the usual 65537 — see
/// LightningRSAAccount.yul's header for the gas-budget reason) and real
/// RSASSA-PKCS1-v1_5/SHA-256 signatures produced by Node's own crypto
/// module (not this repo's math) and cross-checked by Node's own
/// crypto.verify before being trusted here — see
/// scripts/gen-lightning-rsa-vectors.ts and
/// test/vectors/lightning-rsa-vectors.json for the source of truth these
/// are transcribed from.
contract LightningRSATest is Test {
    bytes internal constant N =
        hex"99e08239c2933a4689ceffa68fd50a3c4c0475248c687624beafb641a1de3114a113247a84455d8aa1aa16db620f161f5fec177e2fd9be0b42b607eaf1b68b429647c28f4938f52b16c907a47a8ad0d2b324ce78ae02f1eb322341ce80dd640aee2e5e4aa4dbf5761e4a0db244efa373f6d31637dc3cb5817bf447d69a923368e41a013a54682528573a88edaabd911c303e468f2dfbbbbe2a9f8b1996b565b7e99820dd2770ef588ab00aa0bf6333935866460d309b4c914b3ab14e7641ab7f42cd93c0e4d7ddfd0247dde0366194b68e5ba1e9470df8540743379b244c7d234092ab41b15d2a7603d2f8573944f12e6e3761dd27a047bb4c0b9f9e21864cf3";
    bytes internal constant E = hex"03";

    function _verify(bytes memory signature, bytes32 msgHash) internal view returns (bool) {
        return LightningRSA.verify(N, E, signature, msgHash);
    }

    function test_vector0_valid() public view {
        bytes memory sig =
            hex"8b3db3721342d9b53fc3f5f64b37f423a2b1c567bf9e08be48c77ad194f38df308a849f499b4db984d9a6248e8fe866d7079803f1b42fb71b847c2fe381af437f22578ed4e66bdb3ba1c4340a54358b077cb05c0d338421665db2a53b64e792377352a12429162e0fdde50382c0fe8c72bfad58ac7f34455ffdf87198c531bf6276231b9d52123fff9c4669f38faa3bd0cce97a9088c6a749370d8b7a07764daf1bcb23b6e860cb4501b8e900442f243b396470fca1826d16a66f835ae8841538817a18e9a56ee74a3ec8ec027d77038656e8a64381b403c06fee9dd09a36cf32b14506c39bd2d4122d0313faf62af0600bba7edda2f5d561d36828d2367ba62";
        assertTrue(_verify(sig, 0x1111111111111111111111111111111111111111111111111111111111111111));
    }

    function test_vector1_valid() public view {
        bytes memory sig =
            hex"6cf649abaa917e68878f0230f5a5215fa8585a8a3ef254feccbe66226a5730261e208e8fccc5603c97fa80827d0acf09624d16517f234d97fb493502f11576820a363e15fb1e261344487db8b544afee30ef57a2c1de48a25c94992009d5304aad93b29fa58e77e724e797779a7895b24dc8a4bce026ec03ab9e2c941d6b897a594054874ed07b1b98b95dc5f18174df2159393c16423ada17916c46cd1235f822b53845ac199a4df9c94ac5cf9f555f21205f72876c4bf79917308702c2ab408d64eb1ebb2f1118609b759962f7592651ab2f86c8b30eb04dac41097a0781b8674d1e3942220010cd4178fa87dfed051c7e3ebf6f85f45f5647833a5772d891";
        assertTrue(_verify(sig, 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef));
    }

    function test_vector2_valid() public view {
        bytes memory sig =
            hex"129c30e40b55853ae56f0d9792e2bed4c7190443886676763b20f5590f0464fe578b7e0629111c0f4924c9dece3ddc9d1893a42a208fde4e31673401fed84a29287ff436c5c2e1e8e68b28b787738ff063647b9a902d467f4e51230790753e8e38851795b7e7cf1819b0ff1b118f0a1e1ae1bafc707540af1029aa4102be4da65f16ed8e940b2e42d337523b7ef899633f5eb55155c842c9ebed1d07f613ac23b24f692555ce1581750b1ed7f759f1b7585aed371abafc8533cc97bd9ebc9ff2e385ac587222f50085517f1ae7386e8ec1033b29fa2701659f0db6c701c64c34c1fd8db41dc5e143466d9ad6eb101d53ee6fccd3056cf2296e68a8326d58068d";
        assertTrue(_verify(sig, 0x0000000000000000000000000000000000000000000000000000000000000000));
    }

    function test_invalidVector_rejected() public view {
        bytes memory sig =
            hex"8b3db3721342d9b53fc3f5f64b37f423a2b1c567bf9e08be48c77ad194f38df308a849f499b4db984d9a6248e8fe866d7079803f1b42fb71b847c2fe381af437f22578ed4e66bdb3ba1c4340a54358b077cb05c0d338421665db2a53b64e792377352a12429162e0fdde50382c0fe8c72bfad58ac7f34455ffdf87198c531bf6276231b9d52123fff9c4669f38faa3bd0cce97a9088c6a749370d8b7a07764daf1bcb23b6e860cb4501b8e900442f243b396470fca1826d16a66f835ae8841538817a18e9a56ee74a3ec8ec027d77038656e8a64381b403c06fee9dd09a36cf32b14506c39bd2d4122d0313faf62af0600bba7edda2f5d561d36828d2367ba63";
        assertFalse(_verify(sig, 0x1111111111111111111111111111111111111111111111111111111111111111));
    }

    function test_wrongMsgHash_rejected() public view {
        bytes memory sig =
            hex"8b3db3721342d9b53fc3f5f64b37f423a2b1c567bf9e08be48c77ad194f38df308a849f499b4db984d9a6248e8fe866d7079803f1b42fb71b847c2fe381af437f22578ed4e66bdb3ba1c4340a54358b077cb05c0d338421665db2a53b64e792377352a12429162e0fdde50382c0fe8c72bfad58ac7f34455ffdf87198c531bf6276231b9d52123fff9c4669f38faa3bd0cce97a9088c6a749370d8b7a07764daf1bcb23b6e860cb4501b8e900442f243b396470fca1826d16a66f835ae8841538817a18e9a56ee74a3ec8ec027d77038656e8a64381b403c06fee9dd09a36cf32b14506c39bd2d4122d0313faf62af0600bba7edda2f5d561d36828d2367ba62";
        assertFalse(_verify(sig, 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef));
    }

    function test_zeroLengthModulus_rejected() public view {
        bytes memory emptyN = new bytes(0);
        bytes memory sig = new bytes(0);
        assertFalse(LightningRSA.verify(emptyN, E, sig, 0x1111111111111111111111111111111111111111111111111111111111111111));
    }

    function test_signatureWrongLength_rejected() public view {
        bytes memory shortSig = hex"01020304";
        assertFalse(_verify(shortSig, 0x1111111111111111111111111111111111111111111111111111111111111111));
    }

    function test_signatureEqualsModulus_rejected() public view {
        // s must be strictly < n, even at the byte-string level.
        assertFalse(_verify(N, 0x1111111111111111111111111111111111111111111111111111111111111111));
    }

    /// @notice Empirical check on the gas-budget reasoning in
    /// LightningRSAAccount.yul's header: this must stay comfortably under
    /// EIP-8141's MAX_VERIFY_GAS=100_000 public-mempool ceiling for the
    /// account to actually be usable, which is the entire reason e=3 was
    /// chosen over the usual 65537.
    function test_gasCost_underVerifyFrameBudget() public {
        bytes memory sig =
            hex"8b3db3721342d9b53fc3f5f64b37f423a2b1c567bf9e08be48c77ad194f38df308a849f499b4db984d9a6248e8fe866d7079803f1b42fb71b847c2fe381af437f22578ed4e66bdb3ba1c4340a54358b077cb05c0d338421665db2a53b64e792377352a12429162e0fdde50382c0fe8c72bfad58ac7f34455ffdf87198c531bf6276231b9d52123fff9c4669f38faa3bd0cce97a9088c6a749370d8b7a07764daf1bcb23b6e860cb4501b8e900442f243b396470fca1826d16a66f835ae8841538817a18e9a56ee74a3ec8ec027d77038656e8a64381b403c06fee9dd09a36cf32b14506c39bd2d4122d0313faf62af0600bba7edda2f5d561d36828d2367ba62";
        bytes32 msgHash = 0x1111111111111111111111111111111111111111111111111111111111111111;
        uint256 gasBefore = gasleft();
        bool ok = LightningRSA.verify(N, E, sig, msgHash);
        uint256 gasUsed = gasBefore - gasleft();
        assertTrue(ok);
        console.log("LightningRSA.verify gas used:", gasUsed);
        assertLt(gasUsed, 100_000);
    }
}
