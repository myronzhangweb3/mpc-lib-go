package utils

import (
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/okx/threshold-lib/tss"
	"math/big"
	"okx-threshold-lib-demo/common_utils"
	"okx-threshold-lib-demo/ecdsa_threshold/model"
	"testing"
)

func TestSendMainToken(t *testing.T) {
	chainId := big.NewInt(80001)
	toAddress := common.HexToAddress("0x27a01491d86F3F3b3085a0Ebe3F640387DBdb0EC")
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainId,
		Nonce:     4,
		To:        &toAddress,
		Value:     big.NewInt(1000000),
		Gas:       21000,
		GasTipCap: big.NewInt(500000000000),
		GasFeeCap: big.NewInt(500000000000),
		Data:      []byte{},
	})
	s := types.NewLondonSigner(chainId)
	h := s.Hash(tx)
	println(h.Hex())

	p1FromKeyStep3Data := tss.KeyStep3Data{}
	p2FromKeyStep3Data := tss.KeyStep3Data{}

	p1JsonDataRecover, _ := common_utils.ReadFromFile("../key/p1JsonData.json")
	p2JsonDataRecover, _ := common_utils.ReadFromFile("../key/p2JsonData.json")
	err := json.Unmarshal([]byte(p1JsonDataRecover), &p1FromKeyStep3Data)
	if err != nil {
		fmt.Println(err)
		return
	}
	err = json.Unmarshal([]byte(p2JsonDataRecover), &p2FromKeyStep3Data)
	if err != nil {
		fmt.Println(err)
		return
	}

	signBytes, _ := SignByKey(&p1FromKeyStep3Data, &p2FromKeyStep3Data, h[:])
	signedTx, _ := tx.WithSignature(s, signBytes)
	txData, err := signedTx.MarshalBinary()
	if err != nil {
		panic(err)
	}

	txDataHex := hexutil.Encode(txData)
	fmt.Printf("tx data: %s\n", txDataHex)
}

func TestSerialize(t *testing.T) {
	c := &model.ECDSAKeyCommon{}
	c.NewEcdsaKey()
	p1FromKeyStep3Data, p2FromKeyStep3Data, _, _ := c.GenKeyStep3DataForPartners()
	p1JsonData, err := json.Marshal(p1FromKeyStep3Data)
	if err != nil {
		panic(err)
	}
	common_utils.Save2File("./key/p1JsonData.json", string(p1JsonData))
	p2JsonData, err := json.Marshal(p2FromKeyStep3Data)
	if err != nil {
		fmt.Println(err)
		return
	}
	common_utils.Save2File("./key/p2JsonData.json", string(p2JsonData))
	hash1, _ := SignByKey(p1FromKeyStep3Data, p2FromKeyStep3Data, []byte("hello world"))

	p1FromKeyStep3DataRecover := tss.KeyStep3Data{}
	p2FromKeyStep3DataRecover := tss.KeyStep3Data{}

	p1JsonDataRecover, _ := common_utils.ReadFromFile("./key/p1JsonData.json")
	p2JsonDataRecover, _ := common_utils.ReadFromFile("./key/p2JsonData.json")
	// deserialize the JSON data to an object
	err = json.Unmarshal([]byte(p1JsonDataRecover), &p1FromKeyStep3DataRecover)
	if err != nil {
		fmt.Println(err)
		return
	}
	err = json.Unmarshal([]byte(p2JsonDataRecover), &p2FromKeyStep3DataRecover)
	if err != nil {
		fmt.Println(err)
		return
	}
	hash2, _ := SignByKey(&p1FromKeyStep3DataRecover, &p2FromKeyStep3DataRecover, []byte("hello world"))
	fmt.Println(hash1)
	fmt.Println(hash2)
}

func TestSignAndRefreshKey(t *testing.T) {
	c := &model.ECDSAKeyCommon{}
	c.NewEcdsaKey()

	// 生成三方密钥的数据 ShareI字段为私密字段
	p1FromKeyStep3Data, p2ToKeyStep3Data, p3KeyStep3Data, err := c.GenKeyStep3DataForPartners()
	if err != nil {
		panic(err)
	}
	// 签名验证
	messageHash := crypto.Keccak256Hash([]byte("hello"))
	messageHashBytes := messageHash.Bytes()
	println(messageHash.Hex())
	SignByKey(p1FromKeyStep3Data, p2ToKeyStep3Data, messageHashBytes)
	SignByKey(p1FromKeyStep3Data, p3KeyStep3Data, messageHashBytes)
	SignByKey(p2ToKeyStep3Data, p3KeyStep3Data, messageHashBytes)

	// 刷新 根据p1FromPrivateData、p3PrivateData和p2ToPrivateData的公钥重新生成ShareI
	p1FromKeyStep3DataNew, p2ToKeyStep3DataNew, p3ToKeyStep3DataNew := c.RefreshKey(
		[2]int{1, 3},
		[3]*tss.KeyStep3Data{p1FromKeyStep3Data, {PublicKey: p2ToKeyStep3Data.PublicKey}, p3KeyStep3Data},
	)
	// 使用刷新后的私钥签名验证
	SignByKey(p1FromKeyStep3DataNew, p2ToKeyStep3DataNew, messageHashBytes)
	SignByKey(p1FromKeyStep3DataNew, p3ToKeyStep3DataNew, messageHashBytes)
	SignByKey(p2ToKeyStep3DataNew, p3ToKeyStep3DataNew, messageHashBytes)

	// 使用旧私钥签名验证
	SignByKey(p1FromKeyStep3Data, p2ToKeyStep3Data, messageHashBytes)
	SignByKey(p1FromKeyStep3Data, p3KeyStep3Data, messageHashBytes)
	SignByKey(p2ToKeyStep3Data, p3KeyStep3Data, messageHashBytes)
}
