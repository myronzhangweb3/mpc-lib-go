package model

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/paillier"
	"github.com/okx/threshold-lib/tss"
	"github.com/okx/threshold-lib/tss/ecdsa/keygen"
	"github.com/okx/threshold-lib/tss/key/bip32"
	"github.com/okx/threshold-lib/tss/key/dkg"
	"github.com/okx/threshold-lib/tss/key/reshare"
	"math/big"
)

type ECDSAKeyCommon struct {
	preParamsStr string
	curve        *secp256k1.KoblitzCurve

	// KeyStep3Data ShareI is private share key
	KeyStep3Data *tss.KeyStep3Data
}

func (e *ECDSAKeyCommon) NewEcdsaKey() *ECDSAKeyCommon {
	e.preParamsStr = "{\"NTildei\":24471520908795186059871345359891817090375082425235011162673163562293216820664510789828605476260176115517411842055396836257208343639030995277175322263758084624457414755788632175712521955658505919013279743494979368113272203677789463548602565981118301653800716121189384752156994925287997166225339564621441206438778955740393180221057367383300037154792187952963218391388563468946645409334612971210896085905056280930519856946112538908255424632924121317632150416586598586793214306932742138260070923446615537142905564533718729288946652140359207920360574975200706166078989291834969251532287540567858173716968846357015270138349,\"H1i\":20525427855544097812900242461323906064694844566721127908596308189362139634932796351990338037155331859755165166468225804820912268858944197770981804143947455994501442981149428098822310447470928457374682794682110850354710456200518000366554808847135225010507970105885978332438055746828580641608638198174105260354736906195605319753574667723013578689012516753815219539851516961366236404521980593518182365012603240654581994925529765101249024754689309931635963810794661571475581905272286571260842205785767159676205901368018463391470835581427837444426656612683690455228541028875229228051625995552836658561731443995968771287788,\"H2i\":14561886462801513025229647032463855918071292086106088637653093122443632316900764053418831163999153989988643257167279826735804838683222492162945450354760976026539895948631486301719383942423900097939116970423123551167467739873293443276733568908835651175478613657226786889798591766941448274568403953774018961350069278513251708000024532723935518612136374339804631761356041438752219980855367614912814730211618900394962484968025879140621313034875912024520604802101951780131868299628079385785798916363779339123951610598183476830672767548597981792629985786029649395570390192737424564998427393536184577476205531938017713907537,\"Alpha\":15562395633401930119640319530685053105534487592669191131770549017020512836227813395433398013401899672808149896260415156005395650961577495248684112199870239290842042560405884222603358515341370868923091465869971181089036403932954215982530133253275808649915955629978395955053483946662714544209903814385313430160541625128661561277888916430771363680920637690494652922130604979659273437231654682379800477479474793339467647687163077730878952413184314085561763375724610716711310748898159971608300807004602791622905928075714005483877645756072135214117404734704436395780584072358660771347598146098721453405712285848600410929912,\"Beta\":2395165474635562375328345168197470419270712853015774984255058066914332835031654638443038211809208885507287294824752534870350008496826826350516586118916243850537128710018544377070657961787021005710261809699685606781195081429046500235631252686233860824641938201591401143177392380699803128257310699979970380819582013645704325217394895352558949906568690971372208643798583918394057857288004538171668501365327120899644543818081629047710813539155106955681360755489819630513934947888711688521552671506732141320287584388268958167835966566882566177748042701818683114194170779163415799948893004383756208873564628601506303306733,\"P\":78946358809465488657785646401276462719477605320468420301685497279392498318081224458347091460869018078980790500414678741720386595780837578599171293477368521302224467006469988809257162522761685335900641074366451195515153523873921985410903393962006195879192213513994867756111011843999943944429711391222186861091,\"Q\":77494140571626675280459642381974308521056398681316094978062801680359479201622037388948094745850542427491783310684134503735540058334580018731497272439023435198860202702815565075741003080812047756218005315134111060182393701088010552028153733171070602610292439056776957470549025846108495103549355647541809857301}"
	e.curve = secp256k1.S256()
	return e
}

// GenKeyStep3DataForPartners generates private data for partners
func (e *ECDSAKeyCommon) GenKeyStep3DataForPartners() (*tss.KeyStep3Data, *tss.KeyStep3Data, *tss.KeyStep3Data, error) {
	setUp1 := dkg.NewSetUp(1, 3, e.curve)
	setUp2 := dkg.NewSetUp(2, 3, e.curve)
	setUp3 := dkg.NewSetUp(3, 3, e.curve)

	msgs1_1, err := setUp1.DKGStep1()
	if err != nil {
		return nil, nil, nil, err
	}
	msgs2_1, err := setUp2.DKGStep1()
	if err != nil {
		return nil, nil, nil, err
	}
	msgs3_1, err := setUp3.DKGStep1()
	if err != nil {
		return nil, nil, nil, err
	}

	msgs1_2_in := []*tss.Message{msgs2_1[1], msgs3_1[1]}
	msgs2_2_in := []*tss.Message{msgs1_1[2], msgs3_1[2]}
	msgs3_2_in := []*tss.Message{msgs1_1[3], msgs2_1[3]}

	msgs1_2, err := setUp1.DKGStep2(msgs1_2_in)
	if err != nil {
		return nil, nil, nil, err
	}
	msgs2_2, err := setUp2.DKGStep2(msgs2_2_in)
	if err != nil {
		return nil, nil, nil, err
	}
	msgs3_2, err := setUp3.DKGStep2(msgs3_2_in)
	if err != nil {
		return nil, nil, nil, err
	}

	msgs1_3_in := []*tss.Message{msgs2_2[1], msgs3_2[1]}
	if err != nil {
		return nil, nil, nil, err
	}
	msgs2_3_in := []*tss.Message{msgs1_2[2], msgs3_2[2]}
	if err != nil {
		return nil, nil, nil, err
	}
	msgs3_3_in := []*tss.Message{msgs1_2[3], msgs2_2[3]}
	if err != nil {
		return nil, nil, nil, err
	}

	p1Data, err := setUp1.DKGStep3(msgs1_3_in)
	if err != nil {
		return nil, nil, nil, err
	}
	p2Data, err := setUp2.DKGStep3(msgs2_3_in)
	if err != nil {
		return nil, nil, nil, err
	}
	p3Data, err := setUp3.DKGStep3(msgs3_3_in)
	if err != nil {
		return nil, nil, nil, err
	}

	return p1Data, p2Data, p3Data, nil
}

func (e *ECDSAKeyCommon) RefreshKey(devoteList [2]int, datas [3]*tss.KeyStep3Data) (*tss.KeyStep3Data, *tss.KeyStep3Data, *tss.KeyStep3Data) {
	refresh1 := reshare.NewRefresh(1, 3, devoteList, datas[0].ShareI, datas[0].PublicKey)
	refresh2 := reshare.NewRefresh(2, 3, devoteList, datas[1].ShareI, datas[1].PublicKey)
	refresh3 := reshare.NewRefresh(3, 3, devoteList, datas[2].ShareI, datas[2].PublicKey)

	msgs1_1, _ := refresh1.DKGStep1()
	msgs2_1, _ := refresh2.DKGStep1()
	msgs3_1, _ := refresh3.DKGStep1()

	msgs1_2_in := []*tss.Message{msgs2_1[1], msgs3_1[1]}
	msgs2_2_in := []*tss.Message{msgs1_1[2], msgs3_1[2]}
	msgs3_2_in := []*tss.Message{msgs1_1[3], msgs2_1[3]}

	msgs1_2, _ := refresh1.DKGStep2(msgs1_2_in)
	msgs2_2, _ := refresh2.DKGStep2(msgs2_2_in)
	msgs3_2, _ := refresh3.DKGStep2(msgs3_2_in)

	msgs1_3_in := []*tss.Message{msgs2_2[1], msgs3_2[1]}
	msgs2_3_in := []*tss.Message{msgs1_2[2], msgs3_2[2]}
	msgs3_3_in := []*tss.Message{msgs1_2[3], msgs2_2[3]}

	p1Data, _ := refresh1.DKGStep3(msgs1_3_in)
	p2Data, _ := refresh2.DKGStep3(msgs2_3_in)
	p3Data, _ := refresh3.DKGStep3(msgs3_3_in)

	// chaincode is same
	p1Data.ChainCode = datas[devoteList[0]-1].ChainCode
	p2Data.ChainCode = datas[devoteList[0]-1].ChainCode
	p3Data.ChainCode = datas[devoteList[0]-1].ChainCode
	return p1Data, p2Data, p3Data
}

type ECDSAKeyFrom struct {
	ECDSAKeyCommon
	PaillierPrivateKey *paillier.PrivateKey
	PaillierPublicKey  *paillier.PublicKey
}

// KeyGenRequestMessage p1 send message to p2 for keygen
func (e *ECDSAKeyFrom) KeyGenRequestMessage(partnerDataId int) (*tss.Message, error) {
	preParams := &keygen.PreParams{}
	err := json.Unmarshal([]byte(e.preParamsStr), preParams)
	if err != nil {
		return nil, err
	}
	fmt.Println("start NewKeyPair")
	e.PaillierPrivateKey, e.PaillierPublicKey, err = paillier.NewKeyPair(8)
	if err != nil {
		return nil, err
	}
	fmt.Println("start keygen.P1")
	p1Dto, err := keygen.P1(e.KeyStep3Data.ShareI, e.PaillierPrivateKey, e.KeyStep3Data.Id, partnerDataId, preParams)
	return p1Dto, err
}

// KeyGenRequestMessageByPrime p1 send message to p2 for keygen
func (e *ECDSAKeyFrom) KeyGenRequestMessageByPrime(partnerDataId int, prime1, prime2 string) (*tss.Message, error) {
	preParams := &keygen.PreParams{}
	err := json.Unmarshal([]byte(e.preParamsStr), preParams)
	if err != nil {
		return nil, err
	}
	e.PaillierPrivateKey, e.PaillierPublicKey, err = PaillierNewKeyPair(prime1, prime2)
	if err != nil {
		return nil, err
	}
	p1Dto, err := keygen.P1(e.KeyStep3Data.ShareI, e.PaillierPrivateKey, e.KeyStep3Data.Id, partnerDataId, preParams)
	return p1Dto, err
}

func String2BigInt(str string) (*big.Int, error) {
	n := new(big.Int)
	n, ok := n.SetString(str, 10)
	if !ok {
		return nil, errors.New("SetString: error")
	}
	return n, nil
}

// PaillierNewKeyPair generate paillier key pair
func PaillierNewKeyPair(prime1, prime2 string) (*paillier.PrivateKey, *paillier.PublicKey, error) {
	p, err := String2BigInt(prime1)
	if err != nil {
		return nil, nil, err
	}
	q, err := String2BigInt(prime2)
	if err != nil {
		return nil, nil, err
	}

	// n = p*q
	n := new(big.Int).Mul(p, q)

	// phi = (p-1) * (q-1)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
	phi := new(big.Int).Mul(pMinus1, qMinus1)

	// lambda = lcm(p−1, q−1)
	gcd := new(big.Int).GCD(nil, nil, pMinus1, qMinus1)
	lambda := new(big.Int).Div(phi, gcd)

	publicKey := &paillier.PublicKey{N: n}
	privateKey := &paillier.PrivateKey{PublicKey: *publicKey, Lambda: lambda, Phi: phi}
	return privateKey, publicKey, nil
}

type ECDSAKeyTo struct {
	ECDSAKeyCommon
	SaveData *keygen.P2SaveData
}

func (e *ECDSAKeyTo) GenSaveData(p1Dto *tss.Message, p1DataId int) error {
	publicKey, err := curves.NewECPoint(e.curve, e.KeyStep3Data.PublicKey.X, e.KeyStep3Data.PublicKey.Y)
	if err != nil {
		return err
	}
	e.SaveData, err = keygen.P2(e.KeyStep3Data.ShareI, publicKey, p1Dto, p1DataId, e.KeyStep3Data.Id)
	return err
}

func (e *ECDSAKeyTo) GenPublicKeyAndShareI() (*ecdsa.PublicKey, *big.Int, error) {
	tssKey, err := bip32.NewTssKey(e.SaveData.X2, e.KeyStep3Data.PublicKey, e.KeyStep3Data.ChainCode)
	if err != nil {
		return nil, nil, err
	}
	tssKey, err = tssKey.NewChildKey(996)
	x2 := tssKey.ShareI()
	pubKey := &ecdsa.PublicKey{Curve: e.curve, X: tssKey.PublicKey().X, Y: tssKey.PublicKey().Y}
	return pubKey, x2, nil
}
