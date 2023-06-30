// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.9.0;

// Verify that the signer and the signer are the same person
contract VerifySig {

    function recover(bytes32 _messageHash, bytes memory _sig) internal pure returns (address) {
        // r,s,v belongs to the knowledge of asymmetric encryption algorithms, and there are extensions in the article
        (bytes32 r, bytes32 s, uint8 v) = _split(_sig);
        // ecrecover is a solidity function that reverses the restored address
        return ecrecover(_messageHash, v, r, s);
    }

    // Splits the r,s,v variables
    function _split(bytes memory _sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(_sig.length == 65, "invalid signature length");
        // The signed bytes are stitched together with three elements of rsv, so the first r occupies the first 32 bits, the second s occupies the last 32 bits, and the last v occupies the last bit
        assembly {
            r := mload(add(_sig, 32))
            s := mload(add(_sig, 64))
            v := byte(0, mload(add(_sig, 96)))
        }
    }


    // Splits the r,s,v variables
    function split(bytes memory _sig) external pure returns (bytes32 r, bytes32 s, uint8 v) {
        return _split(_sig);
    }

    /**
    * Verify signature
    *
    * @param _signer The address of the signer
    * @param _messageHash The hash of the message
    * @param _sig The signature of the message
    * @return bool
    *
    * example
    *   - Address: 0xa8f6bdd89c0a73ed00b39e0b19769a55a320510e
    *   - Message: 0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8
    *   - Signature: 0x99cecefcf270a48acb89990b1b387abc0c342ae93567ecd646644567a265610f1e057e75e75e297b1a5294328c4718617cca23d71911203ea8068f9fcedda43c1c
    */
    function verify(address _signer, bytes32 _messageHash, bytes memory _sig) external pure returns (bool) {
        return recover(_messageHash, _sig) == _signer;
    }

    /**
    * Verify signature
    *
    * @param _signer The address of the signer
    * @param _messageHash The hash of the message
    * @param r The r of the signature
    * @param s The s of the signature
    * @param v The v of the signature
    * @return bool
    *
    * example
    *   - Address: 0xf1f9dcd46b5234c14b9ae70fdd2582167257aced
    *   - Message Hash: 0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8
    *   - Signature: 0xd1d5e54d52200350ca80095833df90c8c88e55763939bc48d6126dff959bf26d57b427d2672ac43362013faa9ae1ce9601fe514c36bc437c662b9623aafa5d7d1b
    *   - r: 0xd1d5e54d52200350ca80095833df90c8c88e55763939bc48d6126dff959bf26d
    *   - s: 0x57b427d2672ac43362013faa9ae1ce9601fe514c36bc437c662b9623aafa5d7d
    *   - v: 27
    */
    function verify(address _signer, bytes32 _messageHash, bytes32 r, bytes32 s, uint8 v) external pure returns (bool) {
        return ecrecover(_messageHash, v, r, s) == _signer;
    }

}