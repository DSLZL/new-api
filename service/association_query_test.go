package service

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func initAssociationQueryTestDB(t *testing.T) {
	t.Helper()
	dsn := fmt.Sprintf("file:%s_%d?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"), time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
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
	require.NoError(t, model.EnsureAccountLinkUniqueIndex(db))
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

func withAssociationFingerprintFlags(t *testing.T) {
	t.Helper()
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
}

func createCandidateWithSharedFingerprint(t *testing.T, userID int, ip string, mediaDeviceGroupHash string) {
	t.Helper()
	if strings.TrimSpace(mediaDeviceGroupHash) == "" {
		mediaDeviceGroupHash = "media-group-shared"
	}
	require.NoError(t, model.DB.Create(&model.Fingerprint{
		UserID:                userID,
		LocalDeviceID:         fmt.Sprintf("device-%d", userID),
		CanvasHash:            fmt.Sprintf("canvas-%d", userID),
		WebGLHash:             fmt.Sprintf("webgl-%d", userID),
		AudioHash:             fmt.Sprintf("audio-%d", userID),
		CompositeHash:         fmt.Sprintf("composite-%d", userID),
		MediaDeviceGroupHash:  mediaDeviceGroupHash,
		MediaDeviceCount:      "2-1-1",
		SpeechVoiceCount:      9,
		SpeechLocalVoiceCount: 3,
		IPAddress:             ip,
	}).Error)
}

func seedIPHistory(t *testing.T, userID int, ips ...string) {
	t.Helper()
	for _, ip := range ips {
		require.NoError(t, model.DB.Create(&model.IPUAHistory{
			UserID:    userID,
			IPAddress: ip,
			UABrowser: "chrome",
			UAOS:      "windows",
			UserAgent: "test-agent",
		}).Error)
	}
}

func TestQueryUserAssociations_IncludesMediaDeviceGroupHashCandidate(t *testing.T) {
	initAssociationQueryTestDB(t)
	withAssociationFingerprintFlags(t)

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

func TestBuildAssociationCacheKey_IncludesQueryOptions(t *testing.T) {
	baseFingerprint := &model.Fingerprint{ID: 8899, UserID: 101}

	defaultOptions := normalizeAssociationQueryOptions(nil)
	lightweightOptions := normalizeAssociationQueryOptions(&AssociationQueryOptions{
		IncludeDetails:   true,
		IncludeSharedIPs: false,
	})
	modeOnlyOptions := normalizeAssociationQueryOptions(&AssociationQueryOptions{
		IncludeDetails:           false,
		IncludeSharedIPs:         false,
		Mode:                     associationModeFull,
		TargetFingerprintLimit:   defaultOptions.TargetFingerprintLimit,
		CandidateFingerprintLimit: defaultOptions.CandidateFingerprintLimit,
	})
	candidateOptions := normalizeAssociationQueryOptions(&AssociationQueryOptions{
		IncludeDetails:   true,
		IncludeSharedIPs: true,
		CandidateUserID:  202,
		Mode:             associationModeFull,
	})

	keyDefault := buildAssociationCacheKey(101, 0.3, 20, baseFingerprint, defaultOptions)
	keyLightweight := buildAssociationCacheKey(101, 0.3, 20, baseFingerprint, lightweightOptions)
	keyModeOnly := buildAssociationCacheKey(101, 0.3, 20, baseFingerprint, modeOnlyOptions)
	keyCandidate := buildAssociationCacheKey(101, 0.3, 20, baseFingerprint, candidateOptions)

	require.NotEqual(t, keyDefault, keyLightweight)
	require.NotEqual(t, keyDefault, keyModeOnly)
	require.NotEqual(t, keyDefault, keyCandidate)
	require.NotEqual(t, keyLightweight, keyCandidate)
	require.NotEqual(t, keyModeOnly, keyCandidate)
}

func TestQueryUserAssociationsWithOptions_LimitAndBatchHydration(t *testing.T) {
	initAssociationQueryTestDB(t)
	withAssociationFingerprintFlags(t)

	createAssociationTestUser(t, 201, "u201")
	createAssociationTestUser(t, 202, "u202")
	createAssociationTestUser(t, 203, "u203")
	createAssociationTestUser(t, 204, "u204")

	require.NoError(t, model.DB.Create(&model.Fingerprint{
		UserID:                201,
		LocalDeviceID:         "device-201",
		CanvasHash:            "canvas-201",
		WebGLHash:             "webgl-201",
		AudioHash:             "audio-201",
		CompositeHash:         "composite-201",
		MediaDeviceGroupHash:  "media-group-shared-batch",
		MediaDeviceCount:      "2-1-1",
		SpeechVoiceCount:      8,
		SpeechLocalVoiceCount: 3,
		IPAddress:             "10.20.0.1",
	}).Error)

	createCandidateWithSharedFingerprint(t, 202, "10.20.0.2", "media-group-shared-batch")
	createCandidateWithSharedFingerprint(t, 203, "10.20.0.3", "media-group-shared-batch")
	createCandidateWithSharedFingerprint(t, 204, "10.20.0.4", "media-group-shared-batch")
	require.NoError(t, model.DB.Model(&model.Fingerprint{}).
		Where("user_id = ?", 203).
		Updates(&model.Fingerprint{
			LocalDeviceID: "device-201",
			CanvasHash:    "canvas-201",
			WebGLHash:     "webgl-201",
			AudioHash:     "audio-201",
			CompositeHash: "composite-201",
		}).Error)

	require.NoError(t, model.UpsertLink(201, 203, 0.93, 5, 6, `[{"dimension":"device_key","score":0.93}]`))
	require.NoError(t, model.UpsertLink(201, 204, 0.65, 4, 6, `[{"dimension":"canvas","score":0.65}]`))

	seedIPHistory(t, 201, "172.16.1.1", "172.16.1.2")
	seedIPHistory(t, 203, "172.16.1.2", "172.16.1.3")
	seedIPHistory(t, 204, "172.16.1.9")

	res, err := QueryUserAssociationsWithOptions(201, 0.0, 1, true, nil, &AssociationQueryOptions{
		IncludeDetails:   false,
		IncludeSharedIPs: false,
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res.Associations, 1)

	top := res.Associations[0]
	require.Equal(t, 203, top.User.ID)
	require.Equal(t, "u203", top.User.Username)
	require.Empty(t, top.Details)
	require.Empty(t, top.SharedIPs)
	require.NotNil(t, top.ExistingLink)
	require.Equal(t, "pending", top.ExistingLink.Status)
	require.Greater(t, top.ExistingLink.LinkID, int64(0))
}

func TestQueryUserAssociationsWithOptions_CandidateFilterAndSharedIPs(t *testing.T) {
	initAssociationQueryTestDB(t)
	withAssociationFingerprintFlags(t)

	createAssociationTestUser(t, 301, "u301")
	createAssociationTestUser(t, 302, "u302")
	createAssociationTestUser(t, 303, "u303")

	require.NoError(t, model.DB.Create(&model.Fingerprint{
		UserID:                301,
		LocalDeviceID:         "device-301",
		CanvasHash:            "canvas-301",
		WebGLHash:             "webgl-301",
		AudioHash:             "audio-301",
		CompositeHash:         "composite-301",
		MediaDeviceGroupHash:  "media-group-filter",
		MediaDeviceCount:      "2-1-1",
		SpeechVoiceCount:      7,
		SpeechLocalVoiceCount: 2,
		IPAddress:             "10.30.0.1",
	}).Error)

	createCandidateWithSharedFingerprint(t, 302, "10.30.0.2", "media-group-filter")
	createCandidateWithSharedFingerprint(t, 303, "10.30.0.3", "media-group-filter")

	seedIPHistory(t, 301, "192.168.10.7")
	seedIPHistory(t, 302, "192.168.10.7")
	seedIPHistory(t, 303, "192.168.10.8")

	res, err := QueryUserAssociationsWithOptions(301, 0.0, 20, true, nil, &AssociationQueryOptions{
		IncludeDetails:   false,
		IncludeSharedIPs: true,
		CandidateUserID:  302,
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res.Associations, 1)
	require.Equal(t, 302, res.Associations[0].User.ID)
	require.Equal(t, []string{"192.168.10.7"}, res.Associations[0].SharedIPs)
	require.Empty(t, res.Associations[0].Details)
}
