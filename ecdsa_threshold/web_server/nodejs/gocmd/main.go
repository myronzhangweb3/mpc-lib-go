package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"github.com/ethereum/go-ethereum/common"
	"github.com/okx/threshold-lib/crypto/commitment"
	"github.com/okx/threshold-lib/crypto/schnorr"
	"github.com/okx/threshold-lib/tss"
	tsssign "github.com/okx/threshold-lib/tss/ecdsa/sign"
	"math/big"
	"okx-threshold-lib-demo/ecdsa_threshold/source/model"
	utils2 "okx-threshold-lib-demo/ecdsa_threshold/source/utils"
	"syscall/js"
)

var (
	ResponseSuccess = 200
	ResponseError   = 500
)

var (
	globalP1FromKey   *model.ECDSAKeyFrom
	globalECDSAPubKey *ecdsa.PublicKey

	globalP1 *tsssign.P1Context
)

type WASMResponse struct {
	Code int         `json:"code"`
	Msg  string      `json:"msg"`
	Data interface{} `json:"data"`
}

func handlerResponse2Str() func(response interface{}) string {
	return func(response interface{}) string {
		responseBytes, err := json.Marshal(response)
		if err != nil {
			panic(err)
		}
		response = string(responseBytes)
		return response.(string)
	}
}

func generateDeviceData(this js.Value, i []js.Value) (response interface{}) {
	defer func() {
		response = handlerResponse2Str()(response)
	}()

	p1FromKeyStep3Data, p2FromKeyStep3Data, p3FromKeyStep3Data, err := utils2.GenerateDeviceData()

	globalP1FromKey.KeyStep3Data = p1FromKeyStep3Data

	if err != nil {
		response = &WASMResponse{
			Code: ResponseError,
			Msg:  err.Error(),
		}
		return
	}
	response = &WASMResponse{
		Code: ResponseSuccess,
		Data: struct {
			P1JsonData *tss.KeyStep3Data `json:"p1JsonData"`
			P2JsonData *tss.KeyStep3Data `json:"p2JsonData"`
			P3JsonData *tss.KeyStep3Data `json:"p3JsonData"`
		}{p1FromKeyStep3Data, p2FromKeyStep3Data, p3FromKeyStep3Data},
	}
	return
}

func keyGenRequestMessage(this js.Value, i []js.Value) (response interface{}) {
	defer func() {
		response = handlerResponse2Str()(response)
	}()

	partnerDataId := i[0].Int()
	prime1 := i[1].String()
	prime2 := i[2].String()

	tssMessage, err := globalP1FromKey.KeyGenRequestMessageByPrime(partnerDataId, prime1, prime2)
	if err != nil {
		response = &WASMResponse{
			Code: ResponseError,
			Msg:  err.Error(),
		}
		return
	} else {
		response = &WASMResponse{
			Code: ResponseSuccess,
			Data: tssMessage,
		}
	}

	return
}

func initP1KeyData(this js.Value, i []js.Value) (response interface{}) {
	defer func() {
		response = handlerResponse2Str()(response)
	}()

	p1KeyJson := i[0].String()

	key, err := utils2.Json2TssKeyStep3Data(p1KeyJson)
	if err != nil {
		response = &WASMResponse{
			Code: ResponseError,
			Msg:  err.Error(),
		}
		return
	}
	globalP1FromKey.KeyStep3Data = key
	response = &WASMResponse{
		Code: ResponseSuccess,
		Data: true,
	}
	return
}

func initPubKey(this js.Value, i []js.Value) (response interface{}) {
	defer func() {
		response = handlerResponse2Str()(response)
	}()

	pubKeyJson, err := hex.DecodeString(i[0].String())
	if err != nil {
		response = &WASMResponse{
			Code: ResponseError,
			Msg:  err.Error(),
		}

		return
	}

	pubKey := utils2.UnMarshalJSONCDSAPubKey(pubKeyJson)
	response = &WASMResponse{
		Code: ResponseSuccess,
		Data: true,
	}

	globalECDSAPubKey = pubKey

	return
}

func initP1Context(this js.Value, i []js.Value) (response interface{}) {
	defer func() {
		response = handlerResponse2Str()(response)
	}()

	message := i[0].String()

	globalP1 = tsssign.NewP1(globalECDSAPubKey, message, globalP1FromKey.PaillierPrivateKey)

	response = &WASMResponse{
		Code: ResponseSuccess,
		Data: true,
	}

	return
}

func p1Step1(this js.Value, i []js.Value) (response interface{}) {
	defer func() {
		response = handlerResponse2Str()(response)
	}()

	step1, err := globalP1.Step1()
	if err != nil {
		response = &WASMResponse{
			Code: ResponseError,
			Msg:  err.Error(),
		}
		return
	}
	response = &WASMResponse{
		Code: ResponseSuccess,
		Data: (*step1).String(),
	}

	return
}

func p1Step2(this js.Value, i []js.Value) (response interface{}) {
	defer func() {
		response = handlerResponse2Str()(response)
	}()

	schnorrProofJson := i[0].String()
	curvesECPointJson := i[1].String()

	schnorrProof, err := utils2.Json2SchnorrProof(schnorrProofJson)
	if err != nil {
		response = &WASMResponse{
			Code: ResponseError,
			Msg:  err.Error(),
		}
		return
	}
	curvesECPoint, err := utils2.Json2CurvesECPoint(curvesECPointJson)
	if err != nil {
		response = &WASMResponse{
			Code: ResponseError,
			Msg:  err.Error(),
		}
		return
	}

	schnorrProofOutput, witness, err := globalP1.Step2(schnorrProof, curvesECPoint)
	if err != nil {
		response = &WASMResponse{
			Code: ResponseError,
			Msg:  err.Error(),
		}
		return
	}
	response = &WASMResponse{
		Code: ResponseSuccess,
		Data: struct {
			SchnorrProofOutput *schnorr.Proof
			Witness            *commitment.Witness
		}{schnorrProofOutput, witness},
	}

	return
}

func p1Step3(this js.Value, i []js.Value) (response interface{}) {
	defer func() {
		response = handlerResponse2Str()(response)
	}()

	E_k2_h_xr_Str := i[0].String()
	messageHash := i[1].String()

	r, s, err := globalP1.Step3(utils2.Str2BigInt(E_k2_h_xr_Str))
	if err != nil {
		response = &WASMResponse{
			Code: ResponseError,
			Msg:  err.Error(),
		}
		return
	}

	signHex, _ := utils2.GetSignByRS(globalECDSAPubKey, common.HexToHash(messageHash), r, s)

	response = &WASMResponse{
		Code: ResponseSuccess,
		Data: struct {
			R       *big.Int
			S       *big.Int
			SignHex string
		}{r, s, signHex},
	}

	return
}

func main() {
	js.Global().Get("console").Call("log", "Init threshold web assembly!")
	done := make(chan int, 0)

	js.Global().Get("console").Call("log", "Init P1 assembly!")
	globalP1FromKey = &model.ECDSAKeyFrom{}
	globalP1FromKey.NewEcdsaKey()

	// test
	js.Global().Set("add", js.FuncOf(func(this js.Value, i []js.Value) interface{} { return i[0].Int() + i[1].Int() }))

	// generate three parties keys
	js.Global().Set("generateDeviceData", js.FuncOf(generateDeviceData))
	// init p1 data by p1 key
	js.Global().Set("initP1KeyData", js.FuncOf(initP1KeyData))
	// get tssMessage for request communicate
	js.Global().Set("keyGenRequestMessage", js.FuncOf(keyGenRequestMessage))
	// init public key in go
	js.Global().Set("initPubKey", js.FuncOf(initPubKey))
	// init p1 content in go
	js.Global().Set("initP1Context", js.FuncOf(initP1Context))
	// sign step for p1
	js.Global().Set("p1Step1", js.FuncOf(p1Step1))
	js.Global().Set("p1Step2", js.FuncOf(p1Step2))
	js.Global().Set("p1Step3", js.FuncOf(p1Step3))

	<-done
}
