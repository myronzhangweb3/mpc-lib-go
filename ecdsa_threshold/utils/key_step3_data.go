package utils

import (
	"encoding/json"
	"github.com/okx/threshold-lib/tss"
	"okx-threshold-lib-demo/common_utils"
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
