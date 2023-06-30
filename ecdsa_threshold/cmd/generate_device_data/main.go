package main

import (
	"fmt"
	"okx-threshold-lib-demo/ecdsa_threshold/source/utils"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		panic("please input key file path")
	}

	keyDir := os.Args[1]
	p1FromKeyStep3Data, p2FromKeyStep3Data, p3FromKeyStep3Data, err := utils.GenerateDeviceData()
	if err != nil {
		panic(err)
	}

	err = utils.OutputKeyStep3Data(p1FromKeyStep3Data, keyDir, "p1JsonData.json")
	if err != nil {
		panic(err)
	}
	err = utils.OutputKeyStep3Data(p2FromKeyStep3Data, keyDir, "p2JsonData.json")
	if err != nil {
		panic(err)
	}
	err = utils.OutputKeyStep3Data(p3FromKeyStep3Data, keyDir, "p3JsonData.json")
	if err != nil {
		panic(err)
	}
	// TODO need output three party's public data to a file and then all parties save them to their local devices
	fmt.Println("Success. Please check the key file in " + keyDir)
}
