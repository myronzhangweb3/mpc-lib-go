package internal

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/schnorr"
	"github.com/okx/threshold-lib/tss"
	"github.com/okx/threshold-lib/tss/ecdsa/sign"
	"net/http"
	"okx-threshold-lib-demo/ecdsa_threshold/model"
	"okx-threshold-lib-demo/ecdsa_threshold/utils"
	"okx-threshold-lib-demo/ecdsa_threshold/web_server/server/global"
	"path/filepath"
)

var (
	err                 error
	userECDSAKeyToCache = make(map[string]*model.ECDSAKeyTo)
	userP2ContentCache  = make(map[string]*sign.P2Context)
)

type HTTPResponse struct {
	Code int         `json:"code"`
	Msg  string      `json:"msg"`
	Data interface{} `json:"data"`
}

func jsonResponse(c *gin.Context, data interface{}, err error) {
	if err == nil {
		res := HTTPResponse{
			Code: http.StatusOK,
			Msg:  "",
			Data: data,
		}
		c.JSON(http.StatusOK, res)
		return
	}
	res := HTTPResponse{
		Code: http.StatusInternalServerError,
		Msg:  err.Error(),
		Data: data,
	}
	c.JSON(http.StatusInternalServerError, res)
	return
}

func HealthHandler(c *gin.Context) {
	jsonResponse(c, "ok", nil)
	return
}

func BindUserAndP2(c *gin.Context) {
	params := &GetAddressRequest{}
	c.BindJSON(params)

	p2ToKey := &model.ECDSAKeyTo{}
	p2ToKey.NewEcdsaKey()
	p2ToKey.KeyStep3Data, err = utils.GenKeyStep3DataByFile(filepath.Join(global.RootDir, params.P2KeyFileName))
	if err != nil {
		jsonResponse(c, nil, err)
		return
	}

	// The receiver generates the receiver's private data SaveData based on the message and the initiator's public data
	err = p2ToKey.GenSaveData(&tss.Message{
		From: params.P1MessageDto.From,
		To:   params.P1MessageDto.To,
		Data: params.P1MessageDto.Data,
	}, params.P1DataId)
	if err != nil {
		jsonResponse(c, nil, err)
		return
	}

	userECDSAKeyToCache[params.UserName] = p2ToKey

	jsonResponse(c, "success", nil)
	return
}

func GetAddressMessageHandler(c *gin.Context) {
	params := &RequestBase{}
	c.BindJSON(params)

	p2ToKey, ok := userECDSAKeyToCache[params.UserName]
	if !ok {
		jsonResponse(c, nil, errors.New(fmt.Sprintf("user(%s) not register", params.UserName)))
		return
	}

	// The recipient generates a public key with a threshold signature based on the private data SaveData
	pubKey, _, err := p2ToKey.GenPublicKeyAndShareI()
	if err != nil {
		jsonResponse(c, nil, err)
		return
	}
	pubKeyBytes := utils.MarshalJSONCDSAPubKey(pubKey)

	address := common.BytesToAddress(utils.PublicKeyToAddressBytes(pubKey))
	jsonResponse(c, struct {
		PubKey  string `json:"pub_key"`
		Address string `json:"address"`
	}{hex.EncodeToString(pubKeyBytes), address.Hex()}, nil)

	return
}

func InitP2ContentHandler(c *gin.Context) {
	params := &InitP2ContentRequest{}
	c.BindJSON(params)

	p2ToKey, ok := userECDSAKeyToCache[params.UserName]
	if !ok {
		jsonResponse(c, nil, errors.New(fmt.Sprintf("user(%s) not register", params.UserName)))
		return
	}

	// The recipient generates a public key with a threshold signature based on the private data SaveData
	pubKey, _, err := p2ToKey.GenPublicKeyAndShareI()
	if err != nil {
		jsonResponse(c, nil, err)
		return
	}

	// The receiver generates the threshold signed public key based on the private data SaveData
	pubKey, x2, err := p2ToKey.GenPublicKeyAndShareI()
	if err != nil {
		jsonResponse(c, nil, err)
		return
	}

	p2 := sign.NewP2(x2, p2ToKey.SaveData.E_x1, pubKey, p2ToKey.SaveData.PaiPubKey, params.Message)

	userP2ContentCache[params.UserName] = p2

	jsonResponse(c, "success", nil)

	return
}

func P2Step1Handler(c *gin.Context) {
	params := &P2Step1Request{}
	c.BindJSON(params)

	p2Content, ok := userP2ContentCache[params.UserName]
	if !ok {
		jsonResponse(c, nil, errors.New(fmt.Sprintf("user(%s) not register", params.UserName)))
		return
	}
	commitment := utils.Str2BigInt(params.Commitment)
	proof, ecpoint, err := p2Content.Step1(&commitment)
	if err != nil {
		jsonResponse(c, nil, err)
		return
	}

	jsonResponse(c, struct {
		Proof   *schnorr.Proof  `json:"proof"`
		ECPoint *curves.ECPoint `json:"ecpoint"`
	}{proof, ecpoint}, nil)
	return
}

func P2Step2Handler(c *gin.Context) {
	params := &P2Step2Request{}
	c.BindJSON(params)

	p2Content, ok := userP2ContentCache[params.UserName]
	if !ok {
		jsonResponse(c, nil, errors.New(fmt.Sprintf("user(%s) not register", params.UserName)))
		return
	}
	E_k2_h_xr, err := p2Content.Step2(params.CmtD, params.P1Proof)
	if err != nil {
		jsonResponse(c, nil, err)
		return
	}

	jsonResponse(c, E_k2_h_xr.String(), nil)
	return
}
