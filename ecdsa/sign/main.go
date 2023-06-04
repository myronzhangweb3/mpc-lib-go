package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"math/big"

	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/paillier"

	"github.com/okx/threshold-lib/tss"
	"github.com/okx/threshold-lib/tss/ecdsa/keygen"
	"github.com/okx/threshold-lib/tss/ecdsa/sign"
	"github.com/okx/threshold-lib/tss/key/bip32"
	"github.com/okx/threshold-lib/tss/key/dkg"

	"golang.org/x/crypto/sha3"

	"github.com/ethereum/go-ethereum/crypto"
)

const (
	preParamsStr = "{\"NTildei\":24471520908795186059871345359891817090375082425235011162673163562293216820664510789828605476260176115517411842055396836257208343639030995277175322263758084624457414755788632175712521955658505919013279743494979368113272203677789463548602565981118301653800716121189384752156994925287997166225339564621441206438778955740393180221057367383300037154792187952963218391388563468946645409334612971210896085905056280930519856946112538908255424632924121317632150416586598586793214306932742138260070923446615537142905564533718729288946652140359207920360574975200706166078989291834969251532287540567858173716968846357015270138349,\"H1i\":20525427855544097812900242461323906064694844566721127908596308189362139634932796351990338037155331859755165166468225804820912268858944197770981804143947455994501442981149428098822310447470928457374682794682110850354710456200518000366554808847135225010507970105885978332438055746828580641608638198174105260354736906195605319753574667723013578689012516753815219539851516961366236404521980593518182365012603240654581994925529765101249024754689309931635963810794661571475581905272286571260842205785767159676205901368018463391470835581427837444426656612683690455228541028875229228051625995552836658561731443995968771287788,\"H2i\":14561886462801513025229647032463855918071292086106088637653093122443632316900764053418831163999153989988643257167279826735804838683222492162945450354760976026539895948631486301719383942423900097939116970423123551167467739873293443276733568908835651175478613657226786889798591766941448274568403953774018961350069278513251708000024532723935518612136374339804631761356041438752219980855367614912814730211618900394962484968025879140621313034875912024520604802101951780131868299628079385785798916363779339123951610598183476830672767548597981792629985786029649395570390192737424564998427393536184577476205531938017713907537,\"Alpha\":15562395633401930119640319530685053105534487592669191131770549017020512836227813395433398013401899672808149896260415156005395650961577495248684112199870239290842042560405884222603358515341370868923091465869971181089036403932954215982530133253275808649915955629978395955053483946662714544209903814385313430160541625128661561277888916430771363680920637690494652922130604979659273437231654682379800477479474793339467647687163077730878952413184314085561763375724610716711310748898159971608300807004602791622905928075714005483877645756072135214117404734704436395780584072358660771347598146098721453405712285848600410929912,\"Beta\":2395165474635562375328345168197470419270712853015774984255058066914332835031654638443038211809208885507287294824752534870350008496826826350516586118916243850537128710018544377070657961787021005710261809699685606781195081429046500235631252686233860824641938201591401143177392380699803128257310699979970380819582013645704325217394895352558949906568690971372208643798583918394057857288004538171668501365327120899644543818081629047710813539155106955681360755489819630513934947888711688521552671506732141320287584388268958167835966566882566177748042701818683114194170779163415799948893004383756208873564628601506303306733,\"P\":78946358809465488657785646401276462719477605320468420301685497279392498318081224458347091460869018078980790500414678741720386595780837578599171293477368521302224467006469988809257162522761685335900641074366451195515153523873921985410903393962006195879192213513994867756111011843999943944429711391222186861091,\"Q\":77494140571626675280459642381974308521056398681316094978062801680359479201622037388948094745850542427491783310684134503735540058334580018731497272439023435198860202702815565075741003080812047756218005315134111060182393701088010552028153733171070602610292439056776957470549025846108495103549355647541809857301}"
)

var (
	curve = secp256k1.S256()
)

func KeyGen() (*tss.KeyStep3Data, *tss.KeyStep3Data, *tss.KeyStep3Data) {
	setUp1 := dkg.NewSetUp(1, 3, curve)
	setUp2 := dkg.NewSetUp(2, 3, curve)
	setUp3 := dkg.NewSetUp(3, 3, curve)

	msgs1_1, _ := setUp1.DKGStep1()
	msgs2_1, _ := setUp2.DKGStep1()
	msgs3_1, _ := setUp3.DKGStep1()

	msgs1_2_in := []*tss.Message{msgs2_1[1], msgs3_1[1]}
	msgs2_2_in := []*tss.Message{msgs1_1[2], msgs3_1[2]}
	msgs3_2_in := []*tss.Message{msgs1_1[3], msgs2_1[3]}

	msgs1_2, _ := setUp1.DKGStep2(msgs1_2_in)
	msgs2_2, _ := setUp2.DKGStep2(msgs2_2_in)
	msgs3_2, _ := setUp3.DKGStep2(msgs3_2_in)

	msgs1_3_in := []*tss.Message{msgs2_2[1], msgs3_2[1]}
	msgs2_3_in := []*tss.Message{msgs1_2[2], msgs3_2[2]}
	msgs3_3_in := []*tss.Message{msgs1_2[3], msgs2_2[3]}

	p1SaveData, _ := setUp1.DKGStep3(msgs1_3_in)
	p2SaveData, _ := setUp2.DKGStep3(msgs2_3_in)
	p3SaveData, _ := setUp3.DKGStep3(msgs3_3_in)

	fmt.Println("setUp1", p1SaveData, p1SaveData.PublicKey)
	fmt.Println("setUp2", p2SaveData, p2SaveData.PublicKey)
	fmt.Println("setUp3", p3SaveData, p3SaveData.PublicKey)
	return p1SaveData, p2SaveData, p3SaveData
}

func publicKeyToAddressBytes(publicKey *ecdsa.PublicKey) []byte {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y)[1:])
	return hash.Sum(nil)[12:]
}

func main() {
	// p1Data and p2Data need to save local
	p1Data, p2Data, _ := KeyGen()

	fmt.Println("=========2/2 keygen==========")
	preParams := &keygen.PreParams{}
	err := json.Unmarshal([]byte(preParamsStr), preParams)
	if err != nil {
		fmt.Println("preParams Unmarshal error, ", err)
		return
	}

	paiPrivate, _, _ := paillier.NewKeyPair(8)
	p1Dto, _ := keygen.P1(p1Data.ShareI, paiPrivate, p1Data.Id, p2Data.Id, preParams)
	publicKey, _ := curves.NewECPoint(curve, p2Data.PublicKey.X, p2Data.PublicKey.Y)
	p2SaveData, err := keygen.P2(p2Data.ShareI, publicKey, p1Dto, p1Data.Id, p2Data.Id)
	fmt.Println(p2SaveData, err)

	fmt.Println("=========bip32==========")
	tssKey, err := bip32.NewTssKey(p2SaveData.X2, p2Data.PublicKey, p2Data.ChainCode)
	tssKey, err = tssKey.NewChildKey(996)
	x2 := tssKey.ShareI()
	pubKey := &ecdsa.PublicKey{Curve: curve, X: tssKey.PublicKey().X, Y: tssKey.PublicKey().Y}
	fmt.Println("=========2/2 sign==========")
	messageHash := crypto.Keccak256Hash([]byte("hello"))

	p1 := sign.NewP1(pubKey, hex.EncodeToString(messageHash.Bytes()), paiPrivate)
	p2 := sign.NewP2(x2, p2SaveData.E_x1, pubKey, p2SaveData.PaiPubKey, hex.EncodeToString(messageHash.Bytes()))

	commit, _ := p1.Step1()
	bobProof, R2, _ := p2.Step1(commit)

	proof, cmtD, _ := p1.Step2(bobProof, R2)
	E_k2_h_xr, _ := p2.Step2(cmtD, proof)

	r, s, _ := p1.Step3(E_k2_h_xr)
	fmt.Println(r, s)

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
