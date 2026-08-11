// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IZkApiProofAdapter} from "../interfaces/IZkApiProofAdapter.sol";
import {Types} from "../libraries/Types.sol";
import {Errors} from "../libraries/Errors.sol";

/// @title Groth16ProofAdapter
/// @notice Circuit-specific zkAPI v2 verifier generated from the selected setup.
contract Groth16ProofAdapter is IZkApiProofAdapter {
    uint256 private constant SCALAR_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 private constant BASE_MODULUS =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct G1Point {
        uint256 x;
        uint256 y;
    }

    // Coordinates use arkworks order: c0 (real), then c1 (imaginary).
    struct G2Point {
        uint256[2] x;
        uint256[2] y;
    }

    struct Proof {
        G1Point a;
        G2Point b;
        G1Point c;
    }

    function assertValidRequest(Types.RequestPublicInputs calldata inputs, bytes calldata proof)
        external
        view
        override
    {
        uint256[12] memory values = [
            uint256(inputs.protocolVersion),
            uint256(inputs.chainId),
            uint256(uint160(inputs.contractAddress)),
            inputs.activeRoot,
            inputs.stateSigningKeyX,
            inputs.stateSigningKeyY,
            uint256(inputs.requestTime),
            uint256(inputs.solvencyBound),
            inputs.requestNullifier,
            inputs.authorizationTag,
            inputs.anonymousCommitmentX,
            inputs.anonymousCommitmentY
        ];
        (Proof memory parsed, bool validEncoding) = _decodeProof(proof);
        if (!validEncoding || !_verifyRequest(values, parsed)) revert Errors.InvalidProof();
    }

    function assertValidWithdrawal(Types.WithdrawalPublicInputs calldata inputs, bytes calldata proof)
        external
        view
        override
    {
        uint256[14] memory values = [
            uint256(inputs.protocolVersion),
            uint256(inputs.chainId),
            uint256(uint160(inputs.contractAddress)),
            inputs.activeRoot,
            inputs.stateSigningKeyX,
            inputs.stateSigningKeyY,
            inputs.clearanceSigningKeyX,
            inputs.clearanceSigningKeyY,
            uint256(inputs.noteId),
            uint256(inputs.finalBalance),
            uint256(uint160(inputs.destination)),
            inputs.withdrawalNullifier,
            inputs.hasClearance ? uint256(1) : uint256(0),
            inputs.withdrawalTag
        ];
        (Proof memory parsed, bool validEncoding) = _decodeProof(proof);
        if (!validEncoding || !_verifyWithdrawal(values, parsed)) revert Errors.InvalidProof();
    }

    function _verifyRequest(uint256[12] memory values, Proof memory proof) private view returns (bool) {
        G1Point memory accumulator = _requestIc(0);
        for (uint256 i = 0; i < 12; ++i) {
            if (values[i] >= SCALAR_MODULUS) return false;
            (G1Point memory term, bool mulOk) = _scalarMul(_requestIc(i + 1), values[i]);
            if (!mulOk) return false;
            bool addOk;
            (accumulator, addOk) = _add(accumulator, term);
            if (!addOk) return false;
        }
        return _pairing(
            _negate(proof.a),
            proof.b,
            _requestAlpha(),
            _requestBeta(),
            accumulator,
            _requestGamma(),
            proof.c,
            _requestDelta()
        );
    }

    function _verifyWithdrawal(uint256[14] memory values, Proof memory proof) private view returns (bool) {
        G1Point memory accumulator = _withdrawalIc(0);
        for (uint256 i = 0; i < 14; ++i) {
            if (values[i] >= SCALAR_MODULUS) return false;
            (G1Point memory term, bool mulOk) = _scalarMul(_withdrawalIc(i + 1), values[i]);
            if (!mulOk) return false;
            bool addOk;
            (accumulator, addOk) = _add(accumulator, term);
            if (!addOk) return false;
        }
        return _pairing(
            _negate(proof.a),
            proof.b,
            _withdrawalAlpha(),
            _withdrawalBeta(),
            accumulator,
            _withdrawalGamma(),
            proof.c,
            _withdrawalDelta()
        );
    }

    function _decodeProof(bytes calldata encoded) private pure returns (Proof memory proof, bool valid) {
        if (encoded.length != 256) return (proof, false);
        uint256[8] memory words;
        assembly ("memory-safe") {
            let start := encoded.offset
            mstore(words, calldataload(start))
            mstore(add(words, 0x20), calldataload(add(start, 0x20)))
            mstore(add(words, 0x40), calldataload(add(start, 0x40)))
            mstore(add(words, 0x60), calldataload(add(start, 0x60)))
            mstore(add(words, 0x80), calldataload(add(start, 0x80)))
            mstore(add(words, 0xa0), calldataload(add(start, 0xa0)))
            mstore(add(words, 0xc0), calldataload(add(start, 0xc0)))
            mstore(add(words, 0xe0), calldataload(add(start, 0xe0)))
        }
        for (uint256 i = 0; i < 8; ++i) {
            if (words[i] >= BASE_MODULUS) return (proof, false);
        }
        proof.a = G1Point(words[0], words[1]);
        proof.b = G2Point([words[2], words[3]], [words[4], words[5]]);
        proof.c = G1Point(words[6], words[7]);
        return (proof, true);
    }

    function _negate(G1Point memory point) private pure returns (G1Point memory) {
        if (point.x == 0 && point.y == 0) return G1Point(0, 0);
        return G1Point(point.x, BASE_MODULUS - (point.y % BASE_MODULUS));
    }

    function _add(G1Point memory a, G1Point memory b) private view returns (G1Point memory result, bool ok) {
        uint256[4] memory input = [a.x, a.y, b.x, b.y];
        assembly ("memory-safe") { ok := staticcall(gas(), 6, input, 0x80, result, 0x40) }
    }

    function _scalarMul(G1Point memory point, uint256 scalar) private view returns (G1Point memory result, bool ok) {
        uint256[3] memory input = [point.x, point.y, scalar];
        assembly ("memory-safe") { ok := staticcall(gas(), 7, input, 0x60, result, 0x40) }
    }

    function _pairing(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2,
        G1Point memory c1,
        G2Point memory c2,
        G1Point memory d1,
        G2Point memory d2
    ) private view returns (bool) {
        uint256[24] memory input;
        _writePair(input, 0, a1, a2);
        _writePair(input, 6, b1, b2);
        _writePair(input, 12, c1, c2);
        _writePair(input, 18, d1, d2);
        uint256[1] memory output;
        bool ok;
        assembly ("memory-safe") { ok := staticcall(gas(), 8, input, 0x300, output, 0x20) }
        return ok && output[0] == 1;
    }

    function _writePair(uint256[24] memory input, uint256 offset, G1Point memory g1, G2Point memory g2) private pure {
        input[offset] = g1.x;
        input[offset + 1] = g1.y;
        // EIP-197 expects the imaginary coefficient before the real coefficient.
        input[offset + 2] = g2.x[1];
        input[offset + 3] = g2.x[0];
        input[offset + 4] = g2.y[1];
        input[offset + 5] = g2.y[0];
    }

    function _requestAlpha() private pure returns (G1Point memory) {
        return G1Point(
            0x11b256754ad1a09a216d4ab26d216531c2bdcce96018c5ed405b8b9d3ec339fe,
            0x2936e99a14545f3813216032801961cf193a396c39915f94695f654a90a528b2
        );
    }

    function _requestBeta() private pure returns (G2Point memory) {
        return G2Point(
            [
                0x24613dce8fd99dbf272c8861e6369cb6c5a95e01e5b6074fe7a71725117ccaad,
                0x072e248f71d4c29b332ff56c43e718ab33c3e26594bd9ddf6dc568ad248b15d1
            ],
            [
                0x0cc839b7974421a72b5ae16ff61a97ec3fbfdc1ee1d67baaf4613f1eb8d42f25,
                0x22f6d37e54cc0a8381fb9bcc51af9caf3283a4f8cd1c858e907ea6efe2e788ee
            ]
        );
    }

    function _requestGamma() private pure returns (G2Point memory) {
        return G2Point(
            [
                0x12f27321e540a7d3eb7ed6df68c2a3e56d194d464dae7e504c81a3d2248a0dbe,
                0x28a97129cb3b13ed4efc15925be4798c65dfe3466fb4de2ec7bd3607cbaa4248
            ],
            [
                0x02697d5ce223d0c2611d648de6847965500903fd901e7b984c0e1a18cba2c7ef,
                0x0ce8225ffa1aceabc0f0a442fe5dce48da6252a710a7ffd1803db547549fffe8
            ]
        );
    }

    function _requestDelta() private pure returns (G2Point memory) {
        return G2Point(
            [
                0x2eddaeb363a63dbb9e95ad51e718670cd262564929d49185919a0fd4673a5dd0,
                0x2b271e5ae6a45a86cdf42da0227a78dc3ab32a5bdffabb7d4c7c21d2478e1304
            ],
            [
                0x2ec67dceac38e779d7e2bed4fa5b68c759aa25bef74131cb8269de3ae997bc8d,
                0x22e442c435d42e46ea8fcbbd125e7daa4cae0c19571ec889b34357a0cb75a8c6
            ]
        );
    }

    function _requestIc(uint256 index) private pure returns (G1Point memory) {
        if (index == 0) {
            return G1Point(
                0x2e7db11f498c025203d0641a1e0f2f20a12d32b3bf6d68d5465fc938dd511cf6,
                0x3058c685736f9f26592af5e0bc5074a8eb63f9ec40aac84a8b07501266230418
            );
        }
        if (index == 1) {
            return G1Point(
                0x08f234adbfe85d5b838340605eec7a24433bffed3cb2c3d10d50641f969bbe3b,
                0x1669ebd3ada104ff8c2ed6ba8ff9fff1a1ac6242ac6d28a9102ce13ae0863d2b
            );
        }
        if (index == 2) {
            return G1Point(
                0x05d2d24cf0f6adf6c487b517581da94c3831189331af26b5ebcb403ff3936458,
                0x0e7e5a7e94b6ee0d30038f6e57b20566806466aed8e19b6a69f00550e83c0f33
            );
        }
        if (index == 3) {
            return G1Point(
                0x1316a689e6fbbe24119e2e53b545d2d82a1ad340479c73add3c5624b0317c133,
                0x1894b60660542981732e72c3ad160a0836d82eca0316b2e3897e5ed040b42108
            );
        }
        if (index == 4) {
            return G1Point(
                0x18b8b485f32c89722957341630615702e45a4256fe48bd158776317a2b1a167e,
                0x2de86e701760940f20abb523f876017c7e5bec963fef49e905d72e77633e9d71
            );
        }
        if (index == 5) {
            return G1Point(
                0x14e54316b38e34da3d6c01d8da8d28247d47e06a2d45e838e9524e1b08e4fbf6,
                0x04ef9b99b5837480ee8def9858f4f4f77cf4c239b5fc889113a7e3c28e1b9703
            );
        }
        if (index == 6) {
            return G1Point(
                0x145573a86b774d175276f3238462165b9ad9a77f20d873fb7ae581e5d44e2834,
                0x20825a3765f5f5b12f046eca85e230f0029b8a7e4c5cd1505053b241a32aa536
            );
        }
        if (index == 7) {
            return G1Point(
                0x1ce0b6941dab5655cf6234cdd5db303dc048c605f4b77737e30163a3b499d758,
                0x2f3f6a4097b314cdf9d0804dce23bb5fa3a0f7f6cb3be851cdcb3fedd3bc5463
            );
        }
        if (index == 8) {
            return G1Point(
                0x0da056c78b61e05915a71839837f1aab757ec9ad212dbc95522677b597c80328,
                0x1a1e9b5ffef46c8b1eae433f9ac15f8eb16ce7800a52c2e86dad4201b12a222d
            );
        }
        if (index == 9) {
            return G1Point(
                0x1c5431c481c5a0a30b1edde5678d1bb799847c23c38d09a01159f0e64174a8c0,
                0x28914a7b5247c703399a1d0b7d3d98d9d94b24eb987fce98d99c12c1213e7413
            );
        }
        if (index == 10) {
            return G1Point(
                0x29fa2969999682fe55241c87309b3dc40de4401fafedb75f31f26e2b7b47bc95,
                0x1098b405459d06e4a499b4a72a437ecf92f4b4c1cce9da3b5cc5e55add842ba0
            );
        }
        if (index == 11) {
            return G1Point(
                0x2859a20e4a1cc67dbb93697eb4e9972c2a5cc94e52bbb75aefa0491f7c25d961,
                0x1d00ba4d7dc2b5f94dc40af6a4ca7ff68466aa7d031caada11383e77a6242946
            );
        }
        if (index == 12) {
            return G1Point(
                0x03d7fc9ed06efdf3cd688fb07bb8cf27af52323045b85b0a5a0f4c99a37cdfc3,
                0x1cdf68f2b94ffb3c7b502808b6ed8d89ab8efb1c2f25e22970c09e86be6021e7
            );
        }
        revert Errors.InvalidProof();
    }

    function _withdrawalAlpha() private pure returns (G1Point memory) {
        return G1Point(
            0x17c5325bd51bb1b364fef46c9e2fe55ad97ac771216505ffd552bedb86a11411,
            0x2006dea6ebb5da7c25955f8fc64f9856dd42fc12477add7cb076714d9c3b5ca5
        );
    }

    function _withdrawalBeta() private pure returns (G2Point memory) {
        return G2Point(
            [
                0x153ab2c5c3c23f9df18e7294bbd38759a46c4d30a121dfc6921b7b8ee5df6601,
                0x2a5ebf596044e1d48727fe44596fb7b8c848bc7aa393f9a8cbb051c3fbc7d36e
            ],
            [
                0x2fbb30a879e138565b5e7ba9cfb87bb041fc4523755aff4ee0aeb27283cb5905,
                0x167ebedf40f908ea8a888c779bc0fdc8500dbd0f587b9aa67308fc8e773f385a
            ]
        );
    }

    function _withdrawalGamma() private pure returns (G2Point memory) {
        return G2Point(
            [
                0x2885ece896b15ee3bf00df4a18450cc0a4e8a009db263e958a035aa3a85ab03f,
                0x014d518f47ec1a43e6a1f45db5aa39b81a3ed54b077f465b0f76f5bc8fd3e045
            ],
            [
                0x003f13170e545bb1dfc8dd0fe5d18b71c679b21a09da3f6edca99e267e7b752e,
                0x20ff776b57d340c6febe641834a2a533576e668df91e56ebef53a65e8a458fcf
            ]
        );
    }

    function _withdrawalDelta() private pure returns (G2Point memory) {
        return G2Point(
            [
                0x2d57b20f73c6a9835d87a5c1acffa7331d2187704d0f68e2cd68db469937441d,
                0x21df2dede5065268d4a2c6df100159765ac25bfbb373bc9c00967802f6f65022
            ],
            [
                0x1aab7323adabc3aa6e810e0987c4370fe761b2953b0a0604c95c95d2b90a2c01,
                0x0b0f96130c1bff0a68d33c44a0852ee1122ba5d8a7bcfd969bedb7fbf7abc818
            ]
        );
    }

    function _withdrawalIc(uint256 index) private pure returns (G1Point memory) {
        if (index == 0) {
            return G1Point(
                0x0bc145d3d9084202b0b305a620e62f4725b5efa3e51b79f8e52912d79175a483,
                0x1673bd76b0f6f9bcf3d7c6f936d787304655e7698d0a77a7f4e3b909fdf32cbb
            );
        }
        if (index == 1) {
            return G1Point(
                0x06f9b8b4fb2478a7c686e5cf4dce0e23645193cdf9ef478964c18b9c340b71fd,
                0x2b07ea7ed1883403a67f621b107d9e7ae777f5c4a94b3ee0a2e63682c4263e78
            );
        }
        if (index == 2) {
            return G1Point(
                0x25c07e73c0446354c136b9e1fa447c7b9c49112ea753427d5ac1e31380d92223,
                0x038500000cd6becdf932bd77667c93feab15a14bf5e06015ae23632a621b290e
            );
        }
        if (index == 3) {
            return G1Point(
                0x1c721774532d857edec9a9e9e0ead19b980076b917cb27f9d552619737112dd4,
                0x22eed93dd2832406c30a21e0f5c341e7e3d944ef286eca8f1351480d2c8d3d7e
            );
        }
        if (index == 4) {
            return G1Point(
                0x2f1926bd2cbd347c9dc776d1c5701df7fa8a772fb6ee6900226f73d1ee278726,
                0x3008f62b4e9d27edb8d159cb731fe21c5ce3e76a249b1866c5232f292eeeb082
            );
        }
        if (index == 5) {
            return G1Point(
                0x18da0e2f595bcdec1f4da1be6e3c814d554074321739d3439b0b9145e5016c6a,
                0x036925911c05cef48613806fa95d567c234eec4ac680c5512bf164acabafdd6b
            );
        }
        if (index == 6) {
            return G1Point(
                0x02c35294d950b5c60b4d66ac4364a3f96a079ad579b28a9a594579374f47ef84,
                0x176c18882c5b9b78f45fb864a2c0b09d7d67cc33d85c6911522475af4919373f
            );
        }
        if (index == 7) {
            return G1Point(
                0x020f9d0abb97eee62aa59b20dffcc1ca07caf1f4ea507a275a9f3a89a63ae3fc,
                0x00e078183985b920db97a7a3c24872334f775ddd6d387c9530d51b401ae83a36
            );
        }
        if (index == 8) {
            return G1Point(
                0x25af82c9fee7b26dd7624d720b2e9cfe18a5ddaf73f6f722001c0f72967e6e1a,
                0x1736663a8732a3859337410629761ff6a773b3a50ee35bf4f7372c0e8f68185c
            );
        }
        if (index == 9) {
            return G1Point(
                0x0376b2553e22a13f8375a8b2132f06de0629b1c92046558801c0ac73178eea39,
                0x17e7a9ba64ba85a8f570dec81dd830336c4e2c77f5cb8cbeb141f36bb7ec61c2
            );
        }
        if (index == 10) {
            return G1Point(
                0x227c8897d524def6baec339d8305ab39dd59664ecfecf1e54d2c9be1ba6b4dd5,
                0x2a188076b582186f9cb1b4a02a3d8333c6c4780c60d22221dc8d5a2f7a38660c
            );
        }
        if (index == 11) {
            return G1Point(
                0x275cd30bd90b04e9364227ad51080265e80d67832d7325e8a08dd82a673da22c,
                0x2c345968dea2ffd073f488c91eafabf2267e66fc32b850b63889d7c2eeecff95
            );
        }
        if (index == 12) {
            return G1Point(
                0x1fc5c08a3b77c23de3197dbd57f6f758068989f81f42889c60714ab04d7a080f,
                0x1a28fef3daed120739cccc5f26adf8ed98e68e7ccdfa1b95631adb9b12818cb0
            );
        }
        if (index == 13) {
            return G1Point(
                0x00ddb4ee25e79cc2fdee1b56fc849cd3f7f304a81403dde612d5a59a0ef5b6fe,
                0x1f961c4020d6ab8cc37697233155bb079e7688a5b5977807daff2a868c746b36
            );
        }
        if (index == 14) {
            return G1Point(
                0x28dcaf8694f4a62d156c51770f13830b6108cdb8f14d3c88463a161713e81f4d,
                0x0e609ad569580f2590570b1ef765109f7287f0525fd14eb868ecf4c32667aff3
            );
        }
        revert Errors.InvalidProof();
    }
}
