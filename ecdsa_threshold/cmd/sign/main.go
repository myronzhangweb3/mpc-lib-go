package main

import (
	"encoding/hex"
	"fmt"
	"okx-threshold-lib-demo/ecdsa_threshold/utils"
	"os"
)

func main() {
	if len(os.Args) != 4 {
		panic("please input p1key and p2key file paths and sign content")
	}

	p1FromKeyStep3Data, err := utils.GenKeyStep3DataByFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	p2FromKeyStep3Data, err := utils.GenKeyStep3DataByFile(os.Args[2])
	if err != nil {
		panic(err)
	}

	messageHashHexStr, err := hex.DecodeString(os.Args[3])
	if err != nil {
		panic(err)
	}
	signBytes, err := utils.SignByKey(p1FromKeyStep3Data, p2FromKeyStep3Data, messageHashHexStr)
	if err != nil {
		panic(err)
	}

	fmt.Printf("sign: %s\n", hex.EncodeToString(signBytes))
}
