package main

import (
	"fmt"
	"okx-threshold-lib-demo/ecdsa_threshold/model"
	"okx-threshold-lib-demo/ecdsa_threshold/utils"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		panic("please input key file path")
	}
	c := &model.ECDSAKeyCommon{}
	c.NewEcdsaKey()
	p1FromKeyStep3Data, p2ToKeyStep3Data, p3KeyStep3Data, err := c.GenKeyStep3DataForPartners()
	if err != nil {
		panic(err)
	}

	err = utils.OutputKeyStep3Data(p1FromKeyStep3Data, os.Args[1], "p1JsonData.json")
	if err != nil {
		panic(err)
	}
	err = utils.OutputKeyStep3Data(p2ToKeyStep3Data, os.Args[1], "p2JsonData.json")
	if err != nil {
		panic(err)
	}
	err = utils.OutputKeyStep3Data(p3KeyStep3Data, os.Args[1], "p3JsonData.json")
	if err != nil {
		panic(err)
	}

	// TODO need output three parties's public data to a file and then all parties save them to their local devices

	fmt.Println("Success. Please check the key file in " + os.Args[1])
}
