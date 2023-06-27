package main

import (
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/okx/threshold-lib/tss"
	"math/big"
	"okx-threshold-lib-demo/ecdsa_threshold/model"
	"okx-threshold-lib-demo/utils"
	"testing"
)

// https://goerli.etherscan.io/tx/0x9be9369eacef39729431418385f8a0f040b9f5385d1e1f075189b27023c71da3
//
func TestSendMainToken(t *testing.T) {
	chainId := big.NewInt(80001)
	toAddress := common.HexToAddress("0xed5449e7ffec8bbb53c8a0d1ec7671fe2a44b719")
	//toAddress := common.HexToAddress("0xBDeE6Cc0277cef5671bCd8B15AA4Fa9CDd41A058")
	tx := types.NewTx(&types.LegacyTx{
		//ChainID:   chainId,
		Nonce:    0,
		To:       &toAddress,
		Value:    big.NewInt(0 * 1e8),
		Gas:      21000,
		GasPrice: big.NewInt(50000000000),
		//GasFeeCap: big.NewInt(38000000000),
		Data: []byte{},
	})
	s := types.NewEIP155Signer(chainId)
	h := s.Hash(tx)

	p1FromKeyStep3Data := tss.KeyStep3Data{}
	p2FromKeyStep3Data := tss.KeyStep3Data{}

	p1JsonDataRecover, _ := utils.ReadFromFile("p1JsonData.json")
	p2JsonDataRecover, _ := utils.ReadFromFile("p2JsonData.json")
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

	signBytes, _ := signByKey(&p1FromKeyStep3Data, &p2FromKeyStep3Data, h[:])
	//signBytes[64] += 27
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
	utils.Save2File("p1JsonData.json", string(p1JsonData))
	p2JsonData, err := json.Marshal(p2FromKeyStep3Data)
	if err != nil {
		fmt.Println(err)
		return
	}
	utils.Save2File("p2JsonData.json", string(p2JsonData))
	hash1, _ := signByKey(p1FromKeyStep3Data, p2FromKeyStep3Data, []byte("hello world"))

	p1FromKeyStep3DataRecover := tss.KeyStep3Data{}
	p2FromKeyStep3DataRecover := tss.KeyStep3Data{}

	p1JsonDataRecover, _ := utils.ReadFromFile("p1JsonData.json")
	p2JsonDataRecover, _ := utils.ReadFromFile("p2JsonData.json")
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
	hash2, _ := signByKey(&p1FromKeyStep3DataRecover, &p2FromKeyStep3DataRecover, []byte("hello world"))
	fmt.Println(hash1)
	fmt.Println(hash2)
}
