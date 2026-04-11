package model

import (
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestUpdateOption_ReturnsDatabaseError(t *testing.T) {
	oldDB := DB
	oldOptionMap := common.OptionMap
	common.OptionMap = map[string]string{}
	t.Cleanup(func() {
		DB = oldDB
		common.OptionMap = oldOptionMap
	})

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	DB = db

	err = UpdateOption("FINGERPRINT_WEIGHT_JA4", "0.5")
	require.Error(t, err)
}
