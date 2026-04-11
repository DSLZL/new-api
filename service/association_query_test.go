package service

import (
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func initAssociationQueryTestDB(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&model.User{},
		&model.Fingerprint{},
		&model.AccountLink{},
		&model.IPUAHistory{},
		&model.UserRiskScore{},
		&model.LinkWhitelist{},
		&model.UserDeviceProfile{},
	))
	model.DB = db
}

func createAssociationTestUser(t *testing.T, id int, username string) {
	t.Helper()
	require.NoError(t, model.DB.Create(&model.User{
		Id:          id,
		Username:    username,
		Password:    "pwd",
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
		DisplayName: username,
		Group:       "default",
		AffCode:     username + "_aff",
	}).Error)
}

func TestQueryUserAssociations_IncludesMediaDeviceGroupHashCandidate(t *testing.T) {
	initAssociationQueryTestDB(t)

	oldEnabled := common.FingerprintEnabled
	oldRedis := common.RedisEnabled
	oldJA4 := common.FingerprintEnableJA4
	oldETag := common.FingerprintEnableETag
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.RedisEnabled = oldRedis
		common.FingerprintEnableJA4 = oldJA4
		common.FingerprintEnableETag = oldETag
	})

	common.FingerprintEnabled = true
	common.RedisEnabled = false
	common.FingerprintEnableJA4 = false
	common.FingerprintEnableETag = false

	createAssociationTestUser(t, 101, "u101")
	createAssociationTestUser(t, 102, "u102")

	targetFP := &model.Fingerprint{
		UserID:                101,
		LocalDeviceID:         "device-101",
		CanvasHash:            "canvas-101",
		WebGLHash:             "webgl-101",
		AudioHash:             "audio-101",
		CompositeHash:         "composite-101",
		MediaDeviceGroupHash:  "media-group-shared",
		MediaDeviceCount:      "2-1-1",
		SpeechVoiceCount:      9,
		SpeechLocalVoiceCount: 3,
		IPAddress:             "10.0.0.1",
	}
	require.NoError(t, model.DB.Create(targetFP).Error)

	candidateFP := &model.Fingerprint{
		UserID:                102,
		LocalDeviceID:         "device-102",
		CanvasHash:            "canvas-102",
		WebGLHash:             "webgl-102",
		AudioHash:             "audio-102",
		CompositeHash:         "composite-102",
		MediaDeviceGroupHash:  "media-group-shared",
		MediaDeviceCount:      "2-1-1",
		SpeechVoiceCount:      9,
		SpeechLocalVoiceCount: 3,
		IPAddress:             "20.0.0.2",
	}
	require.NoError(t, model.DB.Create(candidateFP).Error)

	res, err := QueryUserAssociations(101, 0.0, 20, true, nil)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotEmpty(t, res.Associations)

	found := false
	for _, assoc := range res.Associations {
		if assoc.User.ID == 102 {
			found = true
			break
		}
	}
	require.True(t, found, "expected candidate user discovered via media_device_group_hash")
}
