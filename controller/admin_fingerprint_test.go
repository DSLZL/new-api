package controller

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func initAdminFingerprintTestDB(t *testing.T) {
	t.Helper()
	oldDB := model.DB
	dsn := "file:" + t.Name() + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&model.Option{},
		&model.Fingerprint{},
		&model.UserDeviceProfile{},
		&model.KeystrokeProfile{},
		&model.MouseProfile{},
	))
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	model.DB = db
	t.Cleanup(func() {
		model.DB = oldDB
		_ = sqlDB.Close()
	})
}

func TestFPRepairAccountLinks_RepairsLegacyRows(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initAdminFingerprintTestDB(t)

	require.NoError(t, model.DB.AutoMigrate(&model.AccountLink{}))
	require.NoError(t, model.DB.Create(&model.AccountLink{UserIDA: 9, UserIDB: 4, Confidence: 0.4, Status: model.AccountLinkStatusPending, MatchDetails: `[]`}).Error)
	require.NoError(t, model.DB.Create(&model.AccountLink{UserIDA: 4, UserIDB: 9, Confidence: 0.8, Status: model.AccountLinkStatusConfirmed, MatchDetails: `[]`}).Error)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/admin/fingerprint/account-links/repair", nil)

	FPRepairAccountLinks(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"success":true`)
	require.True(t, model.DB.Migrator().HasIndex(&model.AccountLink{}, "uk_link_pair"))

	var links []model.AccountLink
	require.NoError(t, model.DB.Order("id ASC").Find(&links).Error)
	require.Len(t, links, 1)
	require.Equal(t, 4, links[0].UserIDA)
	require.Equal(t, 9, links[0].UserIDB)
}

func TestFPRepairAccountLinks_RejectsConcurrentRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)
	fingerprintAccountLinksRepairRunning.Store(true)
	defer fingerprintAccountLinksRepairRunning.Store(false)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/admin/fingerprint/account-links/repair", nil)

	FPRepairAccountLinks(ctx)

	require.Equal(t, http.StatusConflict, recorder.Code)
	require.Contains(t, recorder.Body.String(), "already running")
}

func TestFPGetWeights_ReturnsCurrentWeights(t *testing.T) {
	gin.SetMode(gin.TestMode)
	oldOptionMap := common.OptionMap
	common.OptionMap = map[string]string{
		"FINGERPRINT_WEIGHT_JA4": "0.61",
	}
	t.Cleanup(func() {
		common.OptionMap = oldOptionMap
	})

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/admin/fingerprint/weights", nil)

	FPGetWeights(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"success":true`)
	require.Contains(t, recorder.Body.String(), `"ja4":0.61`)
}

func TestFPUpdateWeights_ValidatesAndHotUpdates(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initAdminFingerprintTestDB(t)

	oldOptionMap := common.OptionMap
	common.OptionMap = map[string]string{}
	t.Cleanup(func() {
		common.OptionMap = oldOptionMap
	})

	t.Run("invalid key rejected", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodPut, "/api/admin/fingerprint/weights", strings.NewReader(`{"weights":{"unknown":0.5}}`))
		ctx.Request.Header.Set("Content-Type", "application/json")

		FPUpdateWeights(ctx)

		require.Equal(t, http.StatusBadRequest, recorder.Code)
		require.Contains(t, recorder.Body.String(), "invalid weight key")
	})

	t.Run("invalid weight value rejected", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodPut, "/api/admin/fingerprint/weights", strings.NewReader(`{"weights":{"ja4":0}}`))
		ctx.Request.Header.Set("Content-Type", "application/json")

		FPUpdateWeights(ctx)

		require.Equal(t, http.StatusBadRequest, recorder.Code)
		require.Contains(t, recorder.Body.String(), "invalid weight value")
	})

	t.Run("valid update persisted to option map and db", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodPut, "/api/admin/fingerprint/weights", strings.NewReader(`{"weights":{"ja4":0.62,"persistent_id":0.88}}`))
		ctx.Request.Header.Set("Content-Type", "application/json")

		FPUpdateWeights(ctx)

		require.Equal(t, http.StatusOK, recorder.Code)
		require.Contains(t, recorder.Body.String(), `"success":true`)
		require.Equal(t, "0.62", common.OptionMap["FINGERPRINT_WEIGHT_JA4"])
		require.Equal(t, "0.88", common.OptionMap["FINGERPRINT_WEIGHT_PERSISTENT_ID"])

		var optJA4 model.Option
		require.NoError(t, model.DB.First(&optJA4, "key = ?", "FINGERPRINT_WEIGHT_JA4").Error)
		require.Equal(t, "0.62", optJA4.Value)
	})

	t.Run("invalid json rejected", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodPut, "/api/admin/fingerprint/weights", strings.NewReader("not-json"))
		ctx.Request.Header.Set("Content-Type", "application/json")

		FPUpdateWeights(ctx)

		require.Equal(t, http.StatusBadRequest, recorder.Code)
		require.Contains(t, recorder.Body.String(), "invalid request")
	})
}

func TestFPUpdateWeights_RejectsOutOfRange(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initAdminFingerprintTestDB(t)

	oldOptionMap := common.OptionMap
	common.OptionMap = map[string]string{}
	t.Cleanup(func() {
		common.OptionMap = oldOptionMap
	})

	cases := []struct {
		name  string
		value string
	}{
		{name: "negative", value: "-0.1"},
		{name: "too_large", value: "1.2"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			body := fmt.Sprintf(`{"weights":{"ja4":%s}}`, tc.value)
			ctx.Request = httptest.NewRequest(http.MethodPut, "/api/admin/fingerprint/weights", strings.NewReader(body))
			ctx.Request.Header.Set("Content-Type", "application/json")

			FPUpdateWeights(ctx)

			require.Equal(t, http.StatusBadRequest, recorder.Code)
			require.Contains(t, recorder.Body.String(), "invalid weight value")
		})
	}
}

func TestFPCompareUsers_ValidatesInput(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cases := []struct {
		name string
		body string
	}{
		{name: "negative user id", body: `{"user_a":-1,"user_b":2}`},
		{name: "same user", body: `{"user_a":2,"user_b":2}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(http.MethodPost, "/api/admin/fingerprint/compare", strings.NewReader(tc.body))
			ctx.Request.Header.Set("Content-Type", "application/json")

			FPCompareUsers(ctx)

			require.Equal(t, http.StatusBadRequest, recorder.Code)
			require.Contains(t, recorder.Body.String(), "invalid compare users")
		})
	}
}

func TestFPUpdateWeights_DoesNotPartiallyApplyWhenRequestInvalid(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initAdminFingerprintTestDB(t)

	oldOptionMap := common.OptionMap
	common.OptionMap = map[string]string{}
	t.Cleanup(func() {
		common.OptionMap = oldOptionMap
	})

	require.NoError(t, model.DB.Create(&model.Option{Key: "FINGERPRINT_WEIGHT_JA4", Value: "0.41"}).Error)
	common.OptionMap["FINGERPRINT_WEIGHT_JA4"] = "0.41"

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/api/admin/fingerprint/weights", strings.NewReader(`{"weights":{"ja4":0.62,"unknown":0.5}}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	FPUpdateWeights(ctx)

	require.Equal(t, http.StatusBadRequest, recorder.Code)
	require.Equal(t, "0.41", common.OptionMap["FINGERPRINT_WEIGHT_JA4"])

	var opt model.Option
	require.NoError(t, model.DB.First(&opt, "key = ?", "FINGERPRINT_WEIGHT_JA4").Error)
	require.Equal(t, "0.41", opt.Value)
}

func TestFPGetUserAssociations_RejectsForeignDeviceProfile(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initAdminFingerprintTestDB(t)

	t.Run("invalid device_profile_id rejected", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Params = gin.Params{{Key: "id", Value: "88"}}
		ctx.Request = httptest.NewRequest(http.MethodGet, "/api/admin/fingerprint/user/88/associations?device_profile_id=abc", nil)

		FPGetUserAssociations(ctx)

		require.Equal(t, http.StatusBadRequest, recorder.Code)
		require.Contains(t, recorder.Body.String(), `"success":false`)
		require.Contains(t, recorder.Body.String(), "invalid device_profile_id")
	})

	profile := &model.UserDeviceProfile{UserID: 99, DeviceKey: "foreign-device"}
	require.NoError(t, model.DB.Create(profile).Error)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Params = gin.Params{{Key: "id", Value: "88"}}
	ctx.Request = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/admin/fingerprint/user/88/associations?device_profile_id=%d", profile.ID), nil)

	FPGetUserAssociations(ctx)

	require.Equal(t, http.StatusBadRequest, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"success":false`)
	require.Contains(t, recorder.Body.String(), "设备档案")
}

func TestFPGetUserAssociations_InternalFailureReturnsGenericError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	oldEnabled := common.FingerprintEnabled
	common.FingerprintEnabled = false
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
	})

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Params = gin.Params{{Key: "id", Value: "88"}}
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/admin/fingerprint/user/88/associations", nil)

	FPGetUserAssociations(ctx)

	require.Equal(t, http.StatusInternalServerError, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"success":false`)
	require.Contains(t, recorder.Body.String(), `"error_code":"ASSOCIATION_QUERY_FAILED"`)
	require.Contains(t, recorder.Body.String(), "association query failed")
}

func TestFPGetUserAssociations_DefaultsIncludeDetailsAndSharedIPs(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initAdminFingerprintTestDB(t)
	oldEnabled := common.FingerprintEnabled
	oldRedis := common.RedisEnabled
	common.FingerprintEnabled = true
	common.RedisEnabled = false
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.RedisEnabled = oldRedis
	})

	require.NoError(t, model.DB.AutoMigrate(&model.User{}, &model.AccountLink{}, &model.IPUAHistory{}, &model.LinkWhitelist{}))
	require.NoError(t, model.EnsureAccountLinkUniqueIndex(model.DB))
	require.NoError(t, model.DB.Create(&model.User{Id: 501, Username: "u501", Password: "pwd", Status: common.UserStatusEnabled, Role: common.RoleCommonUser, DisplayName: "u501", Group: "default", AffCode: "u501_aff"}).Error)
	require.NoError(t, model.DB.Create(&model.User{Id: 502, Username: "u502", Password: "pwd", Status: common.UserStatusEnabled, Role: common.RoleCommonUser, DisplayName: "u502", Group: "default", AffCode: "u502_aff"}).Error)
	require.NoError(t, model.DB.Create(&model.Fingerprint{UserID: 501, LocalDeviceID: "device-501", CanvasHash: "canvas-501", WebGLHash: "webgl-501", AudioHash: "audio-501", CompositeHash: "composite-501", MediaDeviceGroupHash: "media-group-defaults", MediaDeviceCount: "2-1-1", SpeechVoiceCount: 7, SpeechLocalVoiceCount: 2, IPAddress: "10.50.0.1"}).Error)
	require.NoError(t, model.DB.Create(&model.Fingerprint{UserID: 502, LocalDeviceID: "device-501", CanvasHash: "canvas-501", WebGLHash: "webgl-501", AudioHash: "audio-501", CompositeHash: "composite-501", MediaDeviceGroupHash: "media-group-defaults", MediaDeviceCount: "2-1-1", SpeechVoiceCount: 7, SpeechLocalVoiceCount: 2, IPAddress: "10.50.0.2"}).Error)
	require.NoError(t, model.DB.Create(&model.IPUAHistory{UserID: 501, IPAddress: "172.18.0.8", UABrowser: "chrome", UAOS: "windows", UserAgent: "test-agent"}).Error)
	require.NoError(t, model.DB.Create(&model.IPUAHistory{UserID: 502, IPAddress: "172.18.0.8", UABrowser: "chrome", UAOS: "windows", UserAgent: "test-agent"}).Error)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Params = gin.Params{{Key: "id", Value: "501"}}
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/admin/fingerprint/user/501/associations?refresh=true", nil)

	FPGetUserAssociations(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"success":true`)
	require.Contains(t, recorder.Body.String(), `"details":[`)
	require.Contains(t, recorder.Body.String(), `"shared_ips":["172.18.0.8"]`)
}

func TestFPGetUserAssociations_RequestCanceledReturns408(t *testing.T) {
	gin.SetMode(gin.TestMode)
	oldEnabled := common.FingerprintEnabled
	oldRedis := common.RedisEnabled
	common.FingerprintEnabled = true
	common.RedisEnabled = false
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.RedisEnabled = oldRedis
	})

	requestCtx, cancel := context.WithCancel(context.Background())
	cancel()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Params = gin.Params{{Key: "id", Value: "88"}}
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/admin/fingerprint/user/88/associations", nil).WithContext(requestCtx)

	FPGetUserAssociations(ctx)

	require.Equal(t, http.StatusRequestTimeout, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"success":false`)
	require.Contains(t, recorder.Body.String(), "request cancelled")
}

func TestFPGetUserAssociations_RequestDeadlineExceededReturns504(t *testing.T) {
	gin.SetMode(gin.TestMode)
	oldEnabled := common.FingerprintEnabled
	oldRedis := common.RedisEnabled
	common.FingerprintEnabled = true
	common.RedisEnabled = false
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.RedisEnabled = oldRedis
	})

	requestCtx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Params = gin.Params{{Key: "id", Value: "88"}}
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/admin/fingerprint/user/88/associations", nil).WithContext(requestCtx)

	FPGetUserAssociations(ctx)

	require.Equal(t, http.StatusGatewayTimeout, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"success":false`)
	require.Contains(t, recorder.Body.String(), `"error_code":"ASSOCIATION_QUERY_TIMEOUT"`)
}

func TestFPGetUserAssociations_ExplicitFalseDisablesDetailsAndSharedIPs(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initAdminFingerprintTestDB(t)
	oldEnabled := common.FingerprintEnabled
	oldRedis := common.RedisEnabled
	common.FingerprintEnabled = true
	common.RedisEnabled = false
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.RedisEnabled = oldRedis
	})

	require.NoError(t, model.DB.AutoMigrate(&model.User{}, &model.AccountLink{}, &model.IPUAHistory{}, &model.LinkWhitelist{}))
	require.NoError(t, model.EnsureAccountLinkUniqueIndex(model.DB))
	require.NoError(t, model.DB.Create(&model.User{Id: 511, Username: "u511", Password: "pwd", Status: common.UserStatusEnabled, Role: common.RoleCommonUser, DisplayName: "u511", Group: "default", AffCode: "u511_aff"}).Error)
	require.NoError(t, model.DB.Create(&model.User{Id: 512, Username: "u512", Password: "pwd", Status: common.UserStatusEnabled, Role: common.RoleCommonUser, DisplayName: "u512", Group: "default", AffCode: "u512_aff"}).Error)
	require.NoError(t, model.DB.Create(&model.Fingerprint{UserID: 511, LocalDeviceID: "device-511", CanvasHash: "canvas-511", WebGLHash: "webgl-511", AudioHash: "audio-511", CompositeHash: "composite-511", MediaDeviceGroupHash: "media-group-explicit-false", MediaDeviceCount: "2-1-1", SpeechVoiceCount: 7, SpeechLocalVoiceCount: 2, IPAddress: "10.51.0.1"}).Error)
	require.NoError(t, model.DB.Create(&model.Fingerprint{UserID: 512, LocalDeviceID: "device-511", CanvasHash: "canvas-511", WebGLHash: "webgl-511", AudioHash: "audio-511", CompositeHash: "composite-511", MediaDeviceGroupHash: "media-group-explicit-false", MediaDeviceCount: "2-1-1", SpeechVoiceCount: 7, SpeechLocalVoiceCount: 2, IPAddress: "10.51.0.2"}).Error)
	require.NoError(t, model.DB.Create(&model.IPUAHistory{UserID: 511, IPAddress: "172.19.0.9", UABrowser: "chrome", UAOS: "windows", UserAgent: "test-agent"}).Error)
	require.NoError(t, model.DB.Create(&model.IPUAHistory{UserID: 512, IPAddress: "172.19.0.9", UABrowser: "chrome", UAOS: "windows", UserAgent: "test-agent"}).Error)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Params = gin.Params{{Key: "id", Value: "511"}}
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/admin/fingerprint/user/511/associations?refresh=true&include_details=false&include_shared_ips=false", nil)

	FPGetUserAssociations(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"success":true`)
	require.Contains(t, recorder.Body.String(), `"details":null`)
	require.Contains(t, recorder.Body.String(), `"shared_ips":null`)
}

func TestFPUpdateWeights_DoesNotPartiallyApplyWhenPersistenceFailsMidway(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initAdminFingerprintTestDB(t)

	oldOptionMap := common.OptionMap
	common.OptionMap = map[string]string{}
	t.Cleanup(func() {
		common.OptionMap = oldOptionMap
	})

	require.NoError(t, model.DB.Create(&model.Option{Key: "FINGERPRINT_WEIGHT_JA4", Value: "0.41"}).Error)
	require.NoError(t, model.DB.Create(&model.Option{Key: "FINGERPRINT_WEIGHT_PERSISTENT_ID", Value: "0.77"}).Error)
	common.OptionMap["FINGERPRINT_WEIGHT_JA4"] = "0.41"
	common.OptionMap["FINGERPRINT_WEIGHT_PERSISTENT_ID"] = "0.77"

	const failOnPersistentID = "fp_update_weights_fail_on_persistent_id"
	require.NoError(t, model.DB.Callback().Update().Before("gorm:update").Register(failOnPersistentID, func(tx *gorm.DB) {
		if tx.Statement == nil || tx.Statement.Schema == nil || tx.Statement.Schema.Name != "Option" {
			return
		}
		dest, ok := tx.Statement.Dest.(*model.Option)
		if !ok || dest == nil {
			return
		}
		if dest.Key == "FINGERPRINT_WEIGHT_PERSISTENT_ID" {
			tx.AddError(errors.New("forced persistent_id update failure"))
		}
	}))
	t.Cleanup(func() {
		model.DB.Callback().Update().Remove(failOnPersistentID)
	})

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/api/admin/fingerprint/weights", strings.NewReader(`{"weights":{"ja4":0.62,"persistent_id":0.88}}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	FPUpdateWeights(ctx)

	require.Equal(t, http.StatusInternalServerError, recorder.Code)
	require.Equal(t, "0.41", common.OptionMap["FINGERPRINT_WEIGHT_JA4"])
	require.Equal(t, "0.77", common.OptionMap["FINGERPRINT_WEIGHT_PERSISTENT_ID"])

	var optJA4 model.Option
	require.NoError(t, model.DB.First(&optJA4, "key = ?", "FINGERPRINT_WEIGHT_JA4").Error)
	require.Equal(t, "0.41", optJA4.Value)

	var optPersistentID model.Option
	require.NoError(t, model.DB.First(&optPersistentID, "key = ?", "FINGERPRINT_WEIGHT_PERSISTENT_ID").Error)
	require.Equal(t, "0.77", optPersistentID.Value)
}

func TestFPGetUserFingerprints_ReturnsPlanFieldsAndTopLevelBehaviorSummary(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initAdminFingerprintTestDB(t)

	const userID = 321
	require.NoError(t, (&model.Fingerprint{
		UserID:                userID,
		IPAddress:             "1.1.1.1",
		JA4:                   "ja4-plan",
		HTTPHeaderHash:        "hdr-plan",
		WebRTCLocalIPs:        ` ["192.168.1.9"] `,
		WebRTCPublicIPs:       ` ["8.8.8.8"] `,
		WebGLRenderer:         "NVIDIA RTX",
		WebGLVendor:           "NVIDIA",
		MediaDeviceCount:      "3/5",
		MediaDeviceTotal:      5,
		SpeechVoiceCount:      12,
		SpeechLocalVoiceCount: 4,
	}).Insert())
	require.NoError(t, model.UpsertBehaviorProfilesAtomic(
		&model.KeystrokeProfile{UserID: userID, TypingSpeed: 87.5, SampleCount: 21},
		&model.MouseProfile{UserID: userID, AvgSpeed: 144.2, SampleCount: 34},
	))

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Params = gin.Params{{Key: "id", Value: "321"}}
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/admin/fingerprint/user/321/fingerprints?limit=1", nil)

	FPGetUserFingerprints(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)

	var payload struct {
		Success         bool              `json:"success"`
		Data            []map[string]any  `json:"data"`
		BehaviorProfile map[string]any    `json:"behavior_profile"`
	}
	require.NoError(t, common.Unmarshal(recorder.Body.Bytes(), &payload))
	require.True(t, payload.Success)
	require.Len(t, payload.Data, 1)
	require.Equal(t, "ja4-plan", payload.Data[0]["ja4"])
	require.Equal(t, "hdr-plan", payload.Data[0]["http_header_hash"])
	require.Equal(t, `["8.8.8.8"]`, payload.Data[0]["webrtc_public_ips"])
	require.Equal(t, `["192.168.1.9"]`, payload.Data[0]["webrtc_local_ips"])
	require.Equal(t, "NVIDIA RTX", payload.Data[0]["webgl_renderer"])
	require.Equal(t, "NVIDIA", payload.Data[0]["webgl_vendor"])
	require.EqualValues(t, 12, payload.Data[0]["speech_voice_count"])
	require.EqualValues(t, 4, payload.Data[0]["speech_local_voice_count"])
	_, hasRowBehaviorProfile := payload.Data[0]["behavior_profile"]
	require.False(t, hasRowBehaviorProfile)
	require.Equal(t, 87.5, payload.BehaviorProfile["typing_speed"])
	require.EqualValues(t, 21, payload.BehaviorProfile["typing_samples"])
	require.Equal(t, 144.2, payload.BehaviorProfile["mouse_avg_speed"])
	require.EqualValues(t, 34, payload.BehaviorProfile["mouse_samples"])
}

func TestFPGetUserFingerprints_OmitsMissingBehaviorMetrics(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initAdminFingerprintTestDB(t)

	t.Run("missing mouse profile omitted", func(t *testing.T) {
		const userID = 654
		require.NoError(t, model.DB.Create(&model.Fingerprint{
			UserID:         userID,
			IPAddress:      "2.2.2.2",
			JA4:            "ja4-partial",
			HTTPHeaderHash: "hdr-partial",
		}).Error)
		require.NoError(t, model.UpsertBehaviorProfilesAtomic(
			&model.KeystrokeProfile{UserID: userID, TypingSpeed: 66.6, SampleCount: 9},
			nil,
		))

		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Params = gin.Params{{Key: "id", Value: "654"}}
		ctx.Request = httptest.NewRequest(http.MethodGet, "/api/admin/fingerprint/user/654/fingerprints?limit=1", nil)

		FPGetUserFingerprints(ctx)

		require.Equal(t, http.StatusOK, recorder.Code)

		var payload struct {
			Success         bool             `json:"success"`
			Data            []map[string]any `json:"data"`
			BehaviorProfile map[string]any   `json:"behavior_profile"`
		}
		require.NoError(t, common.Unmarshal(recorder.Body.Bytes(), &payload))
		require.True(t, payload.Success)
		require.Len(t, payload.Data, 1)
		require.Equal(t, 66.6, payload.BehaviorProfile["typing_speed"])
		require.EqualValues(t, 9, payload.BehaviorProfile["typing_samples"])
		_, hasMouseSpeed := payload.BehaviorProfile["mouse_avg_speed"]
		_, hasMouseSamples := payload.BehaviorProfile["mouse_samples"]
		require.False(t, hasMouseSpeed)
		require.False(t, hasMouseSamples)
		_, hasRowBehaviorProfile := payload.Data[0]["behavior_profile"]
		require.False(t, hasRowBehaviorProfile)
	})

	t.Run("zero sample profiles omitted", func(t *testing.T) {
		const userID = 655
		require.NoError(t, model.DB.Create(&model.Fingerprint{
			UserID:         userID,
			IPAddress:      "2.2.2.3",
			JA4:            "ja4-zero-sample",
			HTTPHeaderHash: "hdr-zero-sample",
		}).Error)
		require.NoError(t, model.UpsertBehaviorProfilesAtomic(
			&model.KeystrokeProfile{UserID: userID, TypingSpeed: 88.8, SampleCount: 0},
			&model.MouseProfile{UserID: userID, AvgSpeed: 123.4, SampleCount: 0},
		))

		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Params = gin.Params{{Key: "id", Value: "655"}}
		ctx.Request = httptest.NewRequest(http.MethodGet, "/api/admin/fingerprint/user/655/fingerprints?limit=1", nil)

		FPGetUserFingerprints(ctx)

		require.Equal(t, http.StatusOK, recorder.Code)

		var payload struct {
			Success         bool             `json:"success"`
			Data            []map[string]any `json:"data"`
			BehaviorProfile map[string]any   `json:"behavior_profile"`
		}
		require.NoError(t, common.Unmarshal(recorder.Body.Bytes(), &payload))
		require.True(t, payload.Success)
		require.Len(t, payload.Data, 1)
		require.Nil(t, payload.BehaviorProfile)
		var raw map[string]any
		require.NoError(t, common.Unmarshal(recorder.Body.Bytes(), &raw))
		_, hasTopLevelBehaviorProfile := raw["behavior_profile"]
		require.False(t, hasTopLevelBehaviorProfile)
		_, hasRowBehaviorProfile := payload.Data[0]["behavior_profile"]
		require.False(t, hasRowBehaviorProfile)
	})
}
