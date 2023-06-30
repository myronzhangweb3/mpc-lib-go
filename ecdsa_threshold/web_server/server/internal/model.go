package internal

import (
	"github.com/okx/threshold-lib/crypto/commitment"
	"github.com/okx/threshold-lib/crypto/schnorr"
)

type TssMessageRequest struct {
	From int    `json:"from"`
	To   int    `json:"to"`
	Data string `json:"data"`
}

type RequestBase struct {
	UserName string `json:"user_name"`
}

type GetAddressRequest struct {
	RequestBase
	P1MessageDto  *TssMessageRequest `json:"p1_message_dto"`
	P1DataId      int                `json:"p1_data_id"`
	P2KeyFileName string             `json:"p2_key_file_name"`
}

type InitP2ContentRequest struct {
	RequestBase
	Message string `json:"message"`
}

type P2Step1Request struct {
	RequestBase
	// TODO commitment.Witness is better than string
	Commitment string `json:"commitment"`
}

type P2Step2Request struct {
	RequestBase
	CmtD    *commitment.Witness `json:"cmt_d"`
	P1Proof *schnorr.Proof      `json:"p1_proof"`
}

type P2Step3Request struct {
	RequestBase
}
