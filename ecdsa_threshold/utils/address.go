package utils

import (
	"crypto/ecdsa"
	"github.com/okx/threshold-lib/tss"
	"okx-threshold-lib-demo/ecdsa_threshold/model"
)

func GetPubKey(p1MsgFromData *tss.KeyStep3Data, p2MsgToData *tss.KeyStep3Data) (*ecdsa.PublicKey, error) {
	// Initialize both parties' private keys
	p1FromKey := &model.ECDSAKeyFrom{}
	p2ToKey := &model.ECDSAKeyTo{}

	p1FromKey.NewEcdsaKey()
	p2ToKey.NewEcdsaKey()

	p1FromKey.KeyStep3Data = p1MsgFromData
	p2ToKey.KeyStep3Data = p2MsgToData

	// The originator requests a co-signature from the receiver and needs to initialize the necessary keys in preparation for sending the message to the receiver
	message, err := p1FromKey.KeyGenRequestMessage(p2MsgToData.Id)
	if err != nil {
		return nil, err
	}

	// TODO p1 send message to p2 via API
	// The receiver generates the receiver's private data SaveData based on the message and the initiator's public data
	err = p2ToKey.GenSaveData(message, p1FromKey.KeyStep3Data.Id)
	if err != nil {
		return nil, err
	}

	// The recipient generates a public key with a threshold signature based on the private data SaveData
	pubKey, _, err := p2ToKey.GenPublicKeyAndShareI()
	return pubKey, err
}
