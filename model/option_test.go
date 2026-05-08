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

func TestUpdateOption_InviteOnlyRegistrationEnabled(t *testing.T) {
	oldOptionMap := common.OptionMap
	common.OptionMap = map[string]string{}
	t.Cleanup(func() {
		common.OptionMap = oldOptionMap
	})

	oldInviteOnly := common.InviteOnlyRegistrationEnabled
	t.Cleanup(func() {
		common.InviteOnlyRegistrationEnabled = oldInviteOnly
	})

	err := updateOptionMap("InviteOnlyRegistrationEnabled", "true")
	require.NoError(t, err)
	require.True(t, common.InviteOnlyRegistrationEnabled)

	err = updateOptionMap("InviteOnlyRegistrationEnabled", "false")
	require.NoError(t, err)
	require.False(t, common.InviteOnlyRegistrationEnabled)
}
