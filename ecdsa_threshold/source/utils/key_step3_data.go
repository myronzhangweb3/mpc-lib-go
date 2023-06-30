package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/schnorr"
	"github.com/okx/threshold-lib/tss"
	"math/big"
	"okx-threshold-lib-demo/common_utils"
	"okx-threshold-lib-demo/ecdsa_threshold/source/model"
	"path/filepath"
)

func OutputKeyStep3Data(keyStep3Data *tss.KeyStep3Data, dirPath string, fileName string) error {
	p1JsonData, err := json.Marshal(keyStep3Data)
	if err != nil {
		return err
	}

	err = common_utils.Save2File(filepath.Join(dirPath, fileName), string(p1JsonData))
	if err != nil {
		return err
	}
	return nil
}

func GenKeyStep3DataByFile(filePath string) (*tss.KeyStep3Data, error) {
	keyStep3Data := tss.KeyStep3Data{}

	readFromFile, err := common_utils.ReadFromFile(filePath)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal([]byte(readFromFile), &keyStep3Data)
	if err != nil {
		return nil, err
	}

	return &keyStep3Data, nil
}

func GenerateDeviceData() (*tss.KeyStep3Data, *tss.KeyStep3Data, *tss.KeyStep3Data, error) {
	c := &model.ECDSAKeyCommon{}
	c.NewEcdsaKey()
	p1FromKeyStep3Data, p2ToKeyStep3Data, p3KeyStep3Data, err := c.GenKeyStep3DataForPartners()
	return p1FromKeyStep3Data, p2ToKeyStep3Data, p3KeyStep3Data, err
}

func Json2TssKeyStep3Data(keyJson string) (*tss.KeyStep3Data, error) {
	res := &tss.KeyStep3Data{}
	err := json.Unmarshal([]byte(keyJson), &res)
	return res, err
}

func Json2ECDSAPubKey(keyJson string) (*ecdsa.PublicKey, error) {
	res := &ecdsa.PublicKey{}
	err := json.Unmarshal([]byte(keyJson), &res)
	return res, err
}

func MarshalJSONCDSAPubKey(pubKey *ecdsa.PublicKey) []byte {
	return elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y)
}

func UnMarshalJSONCDSAPubKey(data []byte) *ecdsa.PublicKey {
	X, Y := elliptic.Unmarshal(secp256k1.S256(), data)
	return &ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     X,
		Y:     Y,
	}
}

func Json2SchnorrProof(schnorrProofJson string) (*schnorr.Proof, error) {
	res := &schnorr.Proof{}
	err := json.Unmarshal([]byte(schnorrProofJson), &res)
	return res, err
}

func Json2CurvesECPoint(curvesECPointJson string) (*curves.ECPoint, error) {
	res := &curves.ECPoint{}
	err := json.Unmarshal([]byte(curvesECPointJson), &res)
	return res, err
}

func Str2BigInt(str string) *big.Int {
	// 将字符串转换为大整数
	num := new(big.Int)
	num.SetString(str, 10)
	return num
}
