package utils

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/okx/threshold-lib/tss"
	"okx-threshold-lib-demo/ecdsa_threshold/model"
)

func GetAddress(p1MsgFromData *tss.KeyStep3Data, p2MsgToData *tss.KeyStep3Data) (*common.Address, error) {
	// 初始化双方私钥
	p1FromKey := &model.ECDSAKeyFrom{}
	p2ToKey := &model.ECDSAKeyTo{}

	p1FromKey.NewEcdsaKey()
	p2ToKey.NewEcdsaKey()

	p1FromKey.KeyStep3Data = p1MsgFromData
	p2ToKey.KeyStep3Data = p2MsgToData

	// 发起方向接收方请求共同签名，需要初始化必要的密钥，准备向接收方发送消息
	message, err := p1FromKey.KeyGenRequestMessage(p2MsgToData.Id)
	if err != nil {
		return nil, err
	}

	// 接收方根据消息和发起方公开的数据生成接收方的私有数据SaveData
	err = p2ToKey.GenSaveData(message, p1FromKey.KeyStep3Data.Id)
	if err != nil {
		return nil, err
	}

	// 接收方根据私有数据SaveData生成阈值签名的公钥
	pubKey, _, err := p2ToKey.GenPublicKeyAndShareI()
	if err != nil {
		return nil, err
	}

	address := common.BytesToAddress(publicKeyToAddressBytes(pubKey))
	return &address, nil
}
