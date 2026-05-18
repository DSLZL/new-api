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

func TestUpdateOption_InviteCodeSettingsValidation(t *testing.T) {
	oldOptionMap := common.OptionMap
	common.OptionMap = map[string]string{}
	t.Cleanup(func() {
		common.OptionMap = oldOptionMap
	})

	tests := []struct {
		name  string
		key   string
		value string
	}{
		{
			name:  "invalid max uses limit",
			key:   "invite_code_max_uses_limit",
			value: "not-a-number",
		},
		{
			name:  "invalid max expire days",
			key:   "invite_code_max_expire_days",
			value: "invalid",
		},
		{
			name:  "invalid default max uses",
			key:   "invite_code_default_max_uses",
			value: "NaN",
		},
		{
			name:  "invalid default max expire days",
			key:   "invite_code_default_max_expire_days",
			value: "bad",
		},
		{
			name:  "invalid preserve history flag",
			key:   "invite_code_preserve_history_enabled",
			value: "maybe",
		},
		{
			name:  "invalid audit flag",
			key:   "invite_code_audit_enabled",
			value: "sometimes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := updateOptionMap(tt.key, tt.value)
			require.Error(t, err)
		})
	}
}

func TestUpdateOption_InviteCodeSettingsRejectInvalidRanges(t *testing.T) {
	oldOptionMap := common.OptionMap
	common.OptionMap = map[string]string{
		"invite_code_max_uses_limit":            "100",
		"invite_code_max_expire_days":           "365",
		"invite_code_default_max_uses":          "1",
		"invite_code_default_max_expire_days":   "30",
		"invite_code_preserve_history_enabled":  "true",
		"invite_code_audit_enabled":             "false",
	}
	t.Cleanup(func() {
		common.OptionMap = oldOptionMap
	})

	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "max uses limit cannot be zero", key: "invite_code_max_uses_limit", value: "0"},
		{name: "max expire days cannot be zero", key: "invite_code_max_expire_days", value: "0"},
		{name: "default max uses cannot be zero", key: "invite_code_default_max_uses", value: "0"},
		{name: "default expire days cannot be zero", key: "invite_code_default_max_expire_days", value: "0"},
		{name: "default max uses cannot exceed limit", key: "invite_code_default_max_uses", value: "101"},
		{name: "default expire days cannot exceed limit", key: "invite_code_default_max_expire_days", value: "366"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := updateOptionMap(tt.key, tt.value)
			require.Error(t, err)
		})
	}
}

func TestUpdateOption_InviteCodeSettingsRollbackAfterValidationFailure(t *testing.T) {
	oldDB := DB
	oldOptionMap := common.OptionMap
	common.OptionMap = map[string]string{
		"invite_code_max_uses_limit":            "100",
		"invite_code_max_expire_days":           "365",
		"invite_code_default_max_uses":          "1",
		"invite_code_default_max_expire_days":   "30",
		"invite_code_preserve_history_enabled":  "true",
		"invite_code_audit_enabled":             "false",
	}
	t.Cleanup(func() {
		DB = oldDB
		common.OptionMap = oldOptionMap
	})

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&Option{}))
	DB = db

	err = UpdateOption("invite_code_default_max_uses", "101")
	require.Error(t, err)
	require.Equal(t, "1", common.OptionMap["invite_code_default_max_uses"])

	var count int64
	require.NoError(t, DB.Model(&Option{}).Where("key = ?", "invite_code_default_max_uses").Count(&count).Error)
	require.Equal(t, int64(0), count)
}
