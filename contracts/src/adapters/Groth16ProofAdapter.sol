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
            0x10ba3e5ba8596ba51db06e46d7da8e8979772e7e6d3cf4bf317643e0dddb0620,
            0x123da26d22d43331e967ff8e114fb59f189899e8cb9ceddc4da353d5999aa271
        );
    }

    function _requestBeta() private pure returns (G2Point memory) {
        return G2Point(
            [
                0x1528aeec4a0d86a0f1872a82d6a1561f7fa141c3876db6ba3b0fefd9b31b919e,
                0x018b3ac8da743666eac86ed526d014109edb3c8d28bc881db744ca3ec4d2aa1d
            ],
            [
                0x093d1c4cbe931e02fed65443c168b1e9dbf52dc7585c662b65662f83145e65c0,
                0x110036c8d501478c54d8b2e29a9179f5fd8d02aa75ac2c3ae354350a5fb1f17a
            ]
        );
    }

    function _requestGamma() private pure returns (G2Point memory) {
        return G2Point(
            [
                0x03a58bd945e92b664b8910fd16d46a5774df2281bd4fb02f69de93709eff1282,
                0x1d2e2b5507dceb20c1627ca160f0991ec59e97bbcce6b415c15faa567a69c46c
            ],
            [
                0x1c8314036c37a5238a26b2128f7b36b7820f388ca3f4b446442e410e12c0dda8,
                0x29f52c12bd0e399248d80cd27f4d316b2f85832efb74e3d668d61fef82ed14f6
            ]
        );
    }

    function _requestDelta() private pure returns (G2Point memory) {
        return G2Point(
            [
                0x2edc223d533aa01cd4fbd64b973070fa5d09a4c4a5219690efe7d1ebcc6f6696,
                0x15de832e84f776aa038a07f6282e1c94129c4ba0a207b79d25db8d833b5fd4f2
            ],
            [
                0x11039fadaf696374e6d1f5a5a78c40a3b3f73ed2cf9ae764047479fe6797d33f,
                0x290a4105af46eeecbe32fc842d8bc9b5a6c6499c88aff6c79cf2ea2f6eb45ff4
            ]
        );
    }

    function _requestIc(uint256 index) private pure returns (G1Point memory) {
        if (index == 0) {
            return G1Point(
                0x174aee0b310184c85f0cc09a7797573c8121914ba0d1cdcc07ec8bc3126a46bc,
                0x2d361922636dcbde6c1eb17d0d7f8338b14605fedf1276f2ce809cea6a53ac57
            );
        }
        if (index == 1) {
            return G1Point(
                0x14b762f8fb4c93344ab0fc0e0c72df252646dc0f2a6ca4c9807d406637fb0623,
                0x226ad0a46ea2024e71e24e87b6f4e5b839c530431440d76cb856dd8cad064ba3
            );
        }
        if (index == 2) {
            return G1Point(
                0x15375b2c3434be5e3146bbcd35a24a53a16c9cd7c11a21cdcd6adef5864f32dc,
                0x1d4788d03f950fe789b64cdba7e9cbceea70cb6a03f04e312bdd0b508e11311a
            );
        }
        if (index == 3) {
            return G1Point(
                0x04c4222205a81c127d0ac2cc4dd958a9b410f4e04d45ee54f50843d70d218da7,
                0x27085ed594c715cb9bbc96a6754eb116cbaa4c1a3da28eba81d196953d40621a
            );
        }
        if (index == 4) {
            return G1Point(
                0x2544865c8d55cf2fcad8c1dbf05e7b4d43dea4de9ed68de0b809975f62df3c02,
                0x1ec27bf0d2572be8fc969cc21591f19647968fef95e5e263535f2be6c9bed4f6
            );
        }
        if (index == 5) {
            return G1Point(
                0x2376bf76dc45478e9f47b4e2151e479eda388155bae81bf7d1feb138b1a7d474,
                0x13f2853847210b7500e92e9bef2150fcac8d380d4ddb7e509eb989d7b4b69f51
            );
        }
        if (index == 6) {
            return G1Point(
                0x2d6e51a3adb76cd1735b0ad411c42e447e90a6be4a33f99dadcf13a4d9eeaf31,
                0x255f507d0b179b8fe0316ff75784da578af0ac7844d32ab9ea5ba420c66ffc15
            );
        }
        if (index == 7) {
            return G1Point(
                0x245a76ef7b13667e7693c8dcbf0e91a1d958c66e0bf24ebc10c519d469eb9274,
                0x083b088bfedc67f72b53dd54b48fe1acedfc6b5d25fb0dabf0fd1de9ae9a64c3
            );
        }
        if (index == 8) {
            return G1Point(
                0x042ec83ce0538c0f56f3eb1f534acbaab56f44fc040fb22f03129244f47a4c8e,
                0x16c767075f65958a08c481fd53d54b40c95a914e0444f8377486526fbbc51c37
            );
        }
        if (index == 9) {
            return G1Point(
                0x2a247dcc1c285b0f4e31e96c622566fcd34bf23444dee957d0827773cfc458c4,
                0x2ced1e1bf83caa086cb74a30601bc0cc9fa675d45189d62e107f30d394fdec84
            );
        }
        if (index == 10) {
            return G1Point(
                0x090219e32321331209f5b2cf6e74f41b254e3655f8d63b8e101472443cd83e48,
                0x044ad923155f1c8d283efdab696ebc309da12340c1eb47011fca17aa4b803d5b
            );
        }
        if (index == 11) {
            return G1Point(
                0x037968a077509d5db62d0d15ec78531e4581519b4085dc9d1120f1c491f85007,
                0x09b1608c468e6d3759e4ccca0abc8a361332605116dc52a3e050dde479746696
            );
        }
        if (index == 12) {
            return G1Point(
                0x21ace17e82c5c9e36243f5aa05f705ce0c811942ca9c85ebc8a4da875decf52b,
                0x13fcd96f7d5eb7a3fb68a7bf34390fc393af1e8642a32ddb7b36eac1159f3dcc
            );
        }
        revert Errors.InvalidProof();
    }

    function _withdrawalAlpha() private pure returns (G1Point memory) {
        return G1Point(
            0x1b68f243a5120511f84c88daaf020016c4ccc552efac97db30e202964a0f97c6,
            0x1c6c644b440b3d672f121fe14e191cd61aeee4336fa9000557ae3cd0a5b6a3b4
        );
    }

    function _withdrawalBeta() private pure returns (G2Point memory) {
        return G2Point(
            [
                0x14e880b05dab34ab9d8e2859eac18465303588648542266dbccf4d12fe613f80,
                0x28e6870b066b8d6787b6a58dd65fe24b8740880589ff227934cc58fe666f3cef
            ],
            [
                0x1390d942e685b7f9ab55a8dcdf0d102693c2250697dfa65bef54491173aa2b16,
                0x22358fd10742e5486a1eea3c0201142616a6e28dfa8ceb27f47481f866e9cb7a
            ]
        );
    }

    function _withdrawalGamma() private pure returns (G2Point memory) {
        return G2Point(
            [
                0x0fb1b8fb2f8546e4f051ee63d95077529f6a38d5309f09fd77294c7f51d991de,
                0x11d1e24c5678701cd8a0307fb43b76f74f8f32d5c57189106387594c19f9426a
            ],
            [
                0x0f29505fb8c56780294020ce185649986d7319a52fecf9f9b8ae37da7824e17b,
                0x27e9a4ed2f4ef4efeb6a41a0bc077b0c815678a914ae4e5b52c0779823c5fc3c
            ]
        );
    }

    function _withdrawalDelta() private pure returns (G2Point memory) {
        return G2Point(
            [
                0x000dcd58940f740d08041c957d4ed647ac1bcd47aa79413078a3c8c67c2bf97a,
                0x2ae3d495d8a41db13d7b6cfdb779e736281fc9cf82aff7b2148dd31622b64408
            ],
            [
                0x1f2d271fa1cdef48f60395b6c34ff202aca2e4bfe9a830ee13462fa1ed7741c0,
                0x0610c280e78c787de109eebe744b678d15fe4b2983e81fea3c259904cb08a19d
            ]
        );
    }

    function _withdrawalIc(uint256 index) private pure returns (G1Point memory) {
        if (index == 0) {
            return G1Point(
                0x23bcf00d9cb8869b3c4049e0d31fe1c01166635ae33eadf2dcf0664a3b6a5f7a,
                0x085a22accb9ddaa7de10dbb6db5a1dcaa5aa43bd6868024b096875b4fc4f97fb
            );
        }
        if (index == 1) {
            return G1Point(
                0x0cf771a769ac19b9d94e52bd219efb1c7d857ae38331ae91b04502bcc1351441,
                0x1e13f96a68e67625d29042e5a56dba939241e4ffbb2c644f4f31e9211de12578
            );
        }
        if (index == 2) {
            return G1Point(
                0x2f7bf4395880097fad5e558726c149ac96bfc8c80d556996716601ca42fe2eee,
                0x072033d3eb57ec50403d57c7dcf372e75461af3864db17781b7dd3e13bd22f20
            );
        }
        if (index == 3) {
            return G1Point(
                0x119f446f1e059715aa3726db63094b54af436c4ebb853bde084ae4aa6da5d1ec,
                0x1f46255071e48a87e8921fe55face923de4d179eaf16bcc1d78a1feafe42c3de
            );
        }
        if (index == 4) {
            return G1Point(
                0x0cf355372151e0226f2aae2f73ca849c4506f5794a551353a9be997abe9f18bf,
                0x02653477629494a85df2289b64e70cd39cf6e6b61ca7f71fbe49e4f266e64a51
            );
        }
        if (index == 5) {
            return G1Point(
                0x10d7380431997375db7343bb63d19aa2fdc7a074e70c604a2a14bd8c13c5a01f,
                0x228c44eda5c853b54ccb56fb27f5fc08675d07924372e3703d09c909d525919a
            );
        }
        if (index == 6) {
            return G1Point(
                0x20481997027f5a3f1aa5f701770ddc85d72a04f6ff71f24e9ede9f3c44a7b063,
                0x0b4aeb8e2110985c4369aa819d4f1a90bf981c618b82aa3311a7dced86656fea
            );
        }
        if (index == 7) {
            return G1Point(
                0x09626f2649c660c659d9c033d2040b9dd48d6a163bd55f72e9156104509e13a1,
                0x19d311f67aeeb9cce576064e6b3aac9b284edf19665cdc10409f5bbec888cd42
            );
        }
        if (index == 8) {
            return G1Point(
                0x1841f89c356bd239098b64939203b61f50c126649589b6f7b4eb02bb966504a1,
                0x0f384c41b3c6cf49adb6ea32d6d5eb7423aa6464d5be566ee337b9747077143b
            );
        }
        if (index == 9) {
            return G1Point(
                0x0691e96a90fe638eec94cf392f09e42a210dfb9a4051cb8a998c795739c721c2,
                0x15491bfec0a280a816393ffc8abd685dd7a4453cbcb07cb2faacc97f1f829f08
            );
        }
        if (index == 10) {
            return G1Point(
                0x1118135f7bd7642a3f4a97cc65a753de1a3edcb8ce038b349eb0002d8765a527,
                0x17bc505eed6159b0441af30157f9f2a0f44dfebe281012bda0f6ddb5b6f3d8f6
            );
        }
        if (index == 11) {
            return G1Point(
                0x178b8641c7d4c8878d2ea2e1112a6e6431aa297f8600c492022706d70e8592a8,
                0x2ffad292edae7bf627d7fbeb963821cb2a27a16f186dd2b7ec6c23d5781acc80
            );
        }
        if (index == 12) {
            return G1Point(
                0x29f9884b6578bfe504209a3d06d7ed895b6a566a53ad63a8c4f6f7e110f4ced6,
                0x0dbd57c26240585cac2765e563d26dded5f7cad6b2afad23c164bc59d6977e5a
            );
        }
        if (index == 13) {
            return G1Point(
                0x03516852c6b425644ae6878e532c12d2ede06086a1533c6d2e696f7e0fb0a1f0,
                0x0fbf07f2e7af142fb38ec1c65269abff2015d6862769ef367cecf7dd481387a6
            );
        }
        if (index == 14) {
            return G1Point(
                0x049e373bc04913bef644e77d51b6e92ed0cb1970dfa08d5679fcea088d6e7229,
                0x04fef570797d750fec4d65d20c6ec5af25f726fadf54ce261e4d3e6c6c4e08bb
            );
        }
        revert Errors.InvalidProof();
    }
}
