package main

import (
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"math/big"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) < 6 {
		panic("invalid args")
	}

	chainIdInt, err := strconv.Atoi(os.Args[1])
	if err != nil {
		panic(err)
	}
	toAddressStr := os.Args[2]
	valueInt, err := strconv.Atoi(os.Args[3])
	if err != nil {
		panic(err)
	}
	nonceInt, err := strconv.Atoi(os.Args[4])
	if err != nil {
		panic(err)
	}
	gasPriceInt, err := strconv.Atoi(os.Args[5])
	if err != nil {
		panic(err)
	}

	containsSign := false
	sign := ""
	if len(os.Args) == 7 {
		// contains sign
		sign = os.Args[6]
		if err != nil {
			panic(err)
		}
		containsSign = true
	}

	chainId := big.NewInt(int64(chainIdInt))
	toAddress := common.HexToAddress(toAddressStr)
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainId,
		Nonce:     uint64(nonceInt),
		To:        &toAddress,
		Value:     big.NewInt(int64(valueInt)),
		Gas:       21000,
		GasTipCap: big.NewInt(int64(gasPriceInt)),
		GasFeeCap: big.NewInt(int64(gasPriceInt)),
		Data:      []byte{},
	})
	s := types.NewLondonSigner(chainId)
	h := s.Hash(tx)

	fmt.Printf("tx hex data: %s\n", hex.EncodeToString(h[:]))

	if containsSign {
		signBytes, err := hex.DecodeString(sign)
		if err != nil {
			panic(err)
		}
		signedTx, err := tx.WithSignature(s, signBytes)
		if err != nil {
			panic(err)
		}
		txData, err := signedTx.MarshalBinary()
		if err != nil {
			panic(err)
		}
		txDataHex := hexutil.Encode(txData)
		fmt.Printf("tx raw data: %s\n", txDataHex)
	}

}
