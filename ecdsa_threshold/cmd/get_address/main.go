package main

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"okx-threshold-lib-demo/ecdsa_threshold/utils"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		panic("please input p1key and p2key file paths")
	}

	p1FromKeyStep3Data, err := utils.GenKeyStep3DataByFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	p2FromKeyStep3Data, err := utils.GenKeyStep3DataByFile(os.Args[2])
	if err != nil {
		panic(err)
	}

	pubKey, err := utils.GetPubKey(p1FromKeyStep3Data, p2FromKeyStep3Data)
	address := common.BytesToAddress(utils.PublicKeyToAddressBytes(pubKey))
	fmt.Println("address: ", address.Hex())
}
