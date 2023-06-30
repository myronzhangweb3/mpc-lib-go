package main

import (
	"fmt"
	"github.com/okx/threshold-lib/tss"
	"okx-threshold-lib-demo/ecdsa_threshold/source/model"
	"okx-threshold-lib-demo/ecdsa_threshold/source/utils"
	"os"
)

func main() {
	if len(os.Args) != 5 {
		panic("please input p1key and p2key and p2key file paths and new key output path")
	}

	c := &model.ECDSAKeyCommon{}
	c.NewEcdsaKey()
	p1FromKeyStep3Data, err := utils.GenKeyStep3DataByFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	p2ToKeyStep3Data, err := utils.GenKeyStep3DataByFile(os.Args[2])
	if err != nil {
		panic(err)
	}
	p3ToKeyStep3Data, err := utils.GenKeyStep3DataByFile(os.Args[3])
	if err != nil {
		panic(err)
	}

	// TODO devoteList and datas should from args
	// 刷新 根据p1FromPrivateData、p3PrivateData和p2ToPrivateData的公钥重新生成ShareI
	p1FromKeyStep3DataNew, p2ToKeyStep3DataNew, p3ToKeyStep3DataNew := c.RefreshKey(
		[2]int{1, 3},
		[3]*tss.KeyStep3Data{p1FromKeyStep3Data, {PublicKey: p2ToKeyStep3Data.PublicKey}, p3ToKeyStep3Data},
	)

	err = utils.OutputKeyStep3Data(p1FromKeyStep3DataNew, os.Args[4], "p1JsonData_new.json")
	if err != nil {
		panic(err)
	}
	err = utils.OutputKeyStep3Data(p2ToKeyStep3DataNew, os.Args[4], "p2JsonData_new.json")
	if err != nil {
		panic(err)
	}
	err = utils.OutputKeyStep3Data(p3ToKeyStep3DataNew, os.Args[4], "p3JsonData_new.json")
	if err != nil {
		panic(err)
	}

	fmt.Println("Success. Please check the key file in " + os.Args[4])
}
