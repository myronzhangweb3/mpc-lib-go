package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/okx/threshold-lib/tss"
	"github.com/okx/threshold-lib/tss/ecdsa/sign"
	"golang.org/x/crypto/sha3"
	"math/big"
	"okx-threshold-lib-demo/ecdsa_threshold/model"
)

func main() {
	// 初始化双方私钥
	p1FromKey := &model.ECDSAKeyFrom{}
	p2ToKey := &model.ECDSAKeyTo{}
	p1FromKey.NewEcdsaKey()
	p2ToKey.NewEcdsaKey()

	// 生成三方密钥的数据 ShareI字段为私钥
	p1FromPrivateData, p2ToPrivateData, p3PrivateData, err := p1FromKey.GenKeyStep3DataForPartners()
	if err != nil {
		panic(err)
	}
	p1FromKey.KeyStep3Data = p1FromPrivateData
	p2ToKey.KeyStep3Data = p2ToPrivateData
	// 签名验证
	signByRefreshKey(p1FromPrivateData, p2ToPrivateData)

	// 刷新 根据p1FromPrivateData、p3PrivateData和p2ToPrivateData的公钥重新生成ShareI
	p1MsgFromDataNew, p2MsgToDataNew, _ := p1FromKey.RefreshKey(
		[2]int{1, 3},
		[3]*tss.KeyStep3Data{p1FromPrivateData, {PublicKey: p2ToPrivateData.PublicKey}, p3PrivateData},
	)
	// 签名验证
	signByRefreshKey(p1MsgFromDataNew, p2MsgToDataNew)

	// 使用旧私钥签名验证
	signByRefreshKey(p1FromPrivateData, p2ToPrivateData)
}

// signByRefreshKey From和To只需要对方的ID即可，不需要其他内容
func signByRefreshKey(p1MsgFromData *tss.KeyStep3Data, p2MsgToData *tss.KeyStep3Data) {
	// 初始化双方私钥
	p1FromKey := &model.ECDSAKeyFrom{}
	p2ToKey := &model.ECDSAKeyTo{}

	p1FromKey.NewEcdsaKey()
	p2ToKey.NewEcdsaKey()

	p1FromKey.KeyStep3Data = p1MsgFromData
	p2ToKey.KeyStep3Data = p2MsgToData

	// 发起方向接收方请求共同签名，需要初始化必要的密钥，准备向接收方发送消息
	message, err := p1FromKey.KeyGenRequestMessage(p2MsgToData.Id)
	if err != nil {
		panic(err)
	}

	// 接收方根据消息和发起方公开的数据生成接收方的私有数据SaveData
	err = p2ToKey.GenSaveData(message, p1FromKey.KeyStep3Data.Id)
	if err != nil {
		panic(err)
	}

	// 接收方根据私有数据SaveData生成阈值签名的公钥
	pubKey, x2, err := p2ToKey.GenPublicKeyAndShareI()
	if err != nil {
		panic(err)
	}

	// 发起方生成随机数k1
	messageHash := crypto.Keccak256Hash([]byte("hello"))
	p1 := sign.NewP1(pubKey, hex.EncodeToString(messageHash.Bytes()), p1FromKey.PaillierPrivateKey)

	// 接收方生成随机数k2
	p2 := sign.NewP2(x2, p2ToKey.SaveData.E_x1, pubKey, p2ToKey.SaveData.PaiPubKey, hex.EncodeToString(messageHash.Bytes()))

	// 第一步
	// 发起方根据k1计算椭圆曲线点(k1*G,公钥)
	commit, _ := p1.Step1()
	// 接收方根据k2计算椭圆曲线点(k2*G,公钥)，并给出k2*G的承诺
	bobProof, R2, _ := p2.Step1(commit)
	// 第二步
	// 发起方zk schnorr验证接收方的证明，然后给出k1*G的承诺
	proof, cmtD, _ := p1.Step2(bobProof, R2)
	// 接收方zk schnorr验证发起方的证明，
	E_k2_h_xr, _ := p2.Step2(cmtD, proof)
	// 第三步：发起方使用同态加密算法解密获得签名，最后验证签名是否正确
	r, s, _ := p1.Step3(E_k2_h_xr)

	fmt.Println("=========verify by solidity==========")
	fmt.Println("Address:", "0x"+hex.EncodeToString(publicKeyToAddressBytes(pubKey)))
	fmt.Println("Message Hash: " + messageHash.Hex())
	signHex, _ := getSignByRS(pubKey, messageHash, r, s)
	signBytes, _ := hex.DecodeString(signHex[2:])
	fmt.Println("Signature: " + signHex)
	fmt.Println("r: " + hexutil.EncodeBig(r))
	fmt.Println("s: " + hexutil.EncodeBig(s))
	fmt.Println("v: " + fmt.Sprintf("%v", signBytes[64]))
	fmt.Println("=========verify by solidity==========")
}

func getSignByRS(pubKey *ecdsa.PublicKey, messageHash common.Hash, r *big.Int, s *big.Int) (string, error) {
	// 将签名转换为字节数组
	signature := append(r.Bytes(), s.Bytes()...)

	// 将签名编码为十六进制字符串
	signatureHex := hex.EncodeToString(signature)

	// 将签名解码为字节数组
	signatureBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		fmt.Println("签名解码失败：", err)
		return "", err
	}

	// 从字节数组中提取r和s值
	rBytes := signatureBytes[:32]
	sBytes := signatureBytes[32:]
	rInt := new(big.Int).SetBytes(rBytes)
	sInt := new(big.Int).SetBytes(sBytes)

	// 通过r、s和v值创建以太坊签名
	ethSignature := append(rInt.Bytes(), sInt.Bytes()...)
	ethSignature = append(ethSignature, 0)
	originalV := recoverV(rInt, sInt, messageHash.Bytes(), common.BytesToAddress(publicKeyToAddressBytes(pubKey)))
	ethSignature[64] = originalV + 27

	return "0x" + hex.EncodeToString(ethSignature), err
}

func recoverV(r, s *big.Int, hash []byte, address common.Address) uint8 {
	ethSignature := append(r.Bytes(), s.Bytes()...)
	for i := uint8(0); i < 4; i++ {
		sign2 := append(ethSignature, i)
		uncompressedPubKey, err := crypto.Ecrecover(hash, sign2)
		if err != nil {
			continue
		}
		pubKey, _ := crypto.UnmarshalPubkey(uncompressedPubKey)
		if bytes.Equal(address.Bytes(), crypto.PubkeyToAddress(*pubKey).Bytes()) {
			return i
		}
	}
	return 0
}

func publicKeyToAddressBytes(publicKey *ecdsa.PublicKey) []byte {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y)[1:])
	return hash.Sum(nil)[12:]
}
