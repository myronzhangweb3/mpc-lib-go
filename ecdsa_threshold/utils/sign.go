package utils

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/okx/threshold-lib/tss"
	"github.com/okx/threshold-lib/tss/ecdsa/sign"
	"golang.org/x/crypto/sha3"
	"math/big"
	"okx-threshold-lib-demo/ecdsa_threshold/model"
)

// SignByKey Only for unit test
func SignByKey(p1MsgFromData *tss.KeyStep3Data, p2MsgToData *tss.KeyStep3Data, messageHashBytes []byte) ([]byte, error) {
	// Initialize both parties' private keys
	p1FromKey := &model.ECDSAKeyFrom{}
	p2ToKey := &model.ECDSAKeyTo{}

	p1FromKey.NewEcdsaKey()
	p2ToKey.NewEcdsaKey()

	p1FromKey.KeyStep3Data = p1MsgFromData
	p2ToKey.KeyStep3Data = p2MsgToData

	// The initiator requests a co-signature from the receiver and needs to initialize the necessary keys in preparation for sending the message to the receiver
	message, err := p1FromKey.KeyGenRequestMessage(p2MsgToData.Id)
	if err != nil {
		return []byte(""), err
	}

	// TODO p1 send message to p2 via API
	// The receiver generates the receiver's private data SaveData based on the message and the initiator's public data
	err = p2ToKey.GenSaveData(message, p1FromKey.KeyStep3Data.Id)
	if err != nil {
		return []byte(""), err
	}

	// The receiver generates the threshold signed public key based on the private data SaveData
	pubKey, x2, err := p2ToKey.GenPublicKeyAndShareI()
	if err != nil {
		return []byte(""), err
	}

	// TODO p2 send pubKey to p1 via API
	// The initiator generates a random number k1
	p1 := sign.NewP1(pubKey, hex.EncodeToString(messageHashBytes), p1FromKey.PaillierPrivateKey)

	// The receiver generates a random number k2
	p2 := sign.NewP2(x2, p2ToKey.SaveData.E_x1, pubKey, p2ToKey.SaveData.PaiPubKey, hex.EncodeToString(messageHashBytes))

	// First step
	// The initiator calculates the elliptic curve point (k1*G,public key) based on k1
	commit, _ := p1.Step1()
	// TODO p1 send commit to p2 via API
	// The receiver computes the elliptic curve point (k2*G,public key) based on k2 and gives the commitment of k2*G
	bobProof, R2, _ := p2.Step1(commit)
	// Step 2
	// TODO p2 send bobProof and R2 to p1 via API
	// The initiator zk schnorr verifies the receiver's proof and then gives a k1*G promise
	proof, cmtD, _ := p1.Step2(bobProof, R2)
	// TODO p1 send proof and cmtD to p2 via API
	// The receiver zk schnorr verifies the initiator's proof and then computes the signed cipher
	E_k2_h_xr, _ := p2.Step2(cmtD, proof)
	// Step 3: The initiator decrypts the signature using the homomorphic encryption algorithm and finally verifies that the signature is correct
	// TODO p2 send E_k2_h_xr to p1 via API
	r, s, _ := p1.Step3(E_k2_h_xr)

	signHex, err := getSignByRS(pubKey, common.BytesToHash(messageHashBytes), r, s)
	if err != nil {
		return []byte(""), err
	}
	signBytes, err := hex.DecodeString(signHex)
	if err != nil {
		return []byte(""), err
	}

	return signBytes, nil
}

func getSignByRS(pubKey *ecdsa.PublicKey, messageHash common.Hash, r *big.Int, s *big.Int) (string, error) {
	// Convert the signature to a byte array
	signature := append(r.Bytes(), s.Bytes()...)

	// encode the signature as a hexadecimal string
	signatureHex := hex.EncodeToString(signature)

	// Decode the signature into a byte array
	signatureBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return "", err
	}

	// Extract the r and s values from the byte array
	rBytes := signatureBytes[:32]
	sBytes := signatureBytes[32:]
	rInt := new(big.Int).SetBytes(rBytes)
	sInt := new(big.Int).SetBytes(sBytes)

	// Create an ethereum signature from r, s and v values
	ethSignature := append(rInt.Bytes(), sInt.Bytes()...)
	ethSignature = append(ethSignature, 0)
	originalV := recoverV(rInt, sInt, messageHash.Bytes(), common.BytesToAddress(publicKeyToAddressBytes(pubKey)))
	ethSignature[64] = originalV

	return hex.EncodeToString(ethSignature), err
}

func recoverV(r, s *big.Int, hash []byte, address common.Address) uint8 {
	ethSignature := append(r.Bytes(), s.Bytes()...)
	for i := uint8(0); i < 4; i++ {
		sign2 := append(ethSignature, i)
		uncompressedPubKey, err := crypto.Ecrecover(hash, sign2)
		if err != nil {
			continue
		}
		pubKey, _ := crypto.UnmarshalPubkey(uncompressedPubKey)
		if bytes.Equal(address.Bytes(), crypto.PubkeyToAddress(*pubKey).Bytes()) {
			return i
		}
	}
	return 0
}

func publicKeyToAddressBytes(publicKey *ecdsa.PublicKey) []byte {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y)[1:])
	return hash.Sum(nil)[12:]
}
