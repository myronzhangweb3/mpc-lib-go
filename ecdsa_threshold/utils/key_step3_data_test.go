package utils

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestGenerateDeviceData(t *testing.T) {
	p1FromKeyStep3Data, p2FromKeyStep3Data, p3FromKeyStep3Data, _ := GenerateDeviceData()
	p1JsonData, _ := json.Marshal(p1FromKeyStep3Data)
	p2JsonData, _ := json.Marshal(p2FromKeyStep3Data)
	p3JsonData, _ := json.Marshal(p3FromKeyStep3Data)
	fmt.Println(string(p1JsonData))
	fmt.Println(string(p2JsonData))
	fmt.Println(string(p3JsonData))
}
