package controller

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func newFingerprintReportTestContext(method string, target string, body string) (*gin.Context, *httptest.ResponseRecorder) {
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(method, target, strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	return ctx, recorder
}

func initFingerprintReportTestDB(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&model.Fingerprint{},
		&model.UserDeviceProfile{},
		&model.UserTemporalProfile{},
		&model.UserSession{},
		&model.KeystrokeProfile{},
		&model.MouseProfile{},
		&model.AccountLink{},
		&model.IPUAHistory{},
		&model.UserRiskScore{},
		&model.LinkWhitelist{},
	))
	require.NoError(t, model.EnsureUserSessionUniqueIndex(db))
	model.DB = db
}

func TestReportFingerprint_RejectsBodyTooLarge(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousEnabled := common.FingerprintEnabled
	common.FingerprintEnabled = true
	t.Cleanup(func() {
		common.FingerprintEnabled = previousEnabled
	})

	oversized := "{\"canvas_hash\":\"" + strings.Repeat("a", fingerprintReportRequestBodyLimit) + "\"}"
	ctx, recorder := newFingerprintReportTestContext(http.MethodPost, "/api/fingerprint/report", oversized)
	ctx.Set("id", 1)

	ReportFingerprint(ctx)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, recorder.Code)
	}
}

func TestApplyFingerprintFeatureSwitches_DisablesSignals(t *testing.T) {
	oldJA4 := common.FingerprintEnableJA4
	oldETag := common.FingerprintEnableETag
	oldWebRTC := common.FingerprintEnableWebRTC
	t.Cleanup(func() {
		common.FingerprintEnableJA4 = oldJA4
		common.FingerprintEnableETag = oldETag
		common.FingerprintEnableWebRTC = oldWebRTC
	})

	common.FingerprintEnableJA4 = false
	common.FingerprintEnableETag = false
	common.FingerprintEnableWebRTC = false

	fp := &model.Fingerprint{
		JA4:             "ja4-x",
		ETagID:          "etag-x",
		WebRTCLocalIPs:  `["10.0.0.2"]`,
		WebRTCPublicIPs: `["8.8.8.8"]`,
	}

	applyFingerprintFeatureSwitches(fp)

	if fp.JA4 != "" {
		t.Fatalf("expected JA4 empty when disabled, got %q", fp.JA4)
	}
	if fp.ETagID != "" {
		t.Fatalf("expected ETagID empty when disabled, got %q", fp.ETagID)
	}
	if fp.WebRTCLocalIPs != "" || fp.WebRTCPublicIPs != "" {
		t.Fatalf("expected WebRTC fields empty when disabled, got local=%q public=%q", fp.WebRTCLocalIPs, fp.WebRTCPublicIPs)
	}
}

func TestReportFingerprint_DisabledSignalsNotPersisted(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)

	oldEnabled := common.FingerprintEnabled
	oldJA4 := common.FingerprintEnableJA4
	oldETag := common.FingerprintEnableETag
	oldWebRTC := common.FingerprintEnableWebRTC
	oldRedis := common.RedisEnabled
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.FingerprintEnableJA4 = oldJA4
		common.FingerprintEnableETag = oldETag
		common.FingerprintEnableWebRTC = oldWebRTC
		common.RedisEnabled = oldRedis
	})

	common.FingerprintEnabled = true
	common.FingerprintEnableJA4 = false
	common.FingerprintEnableETag = false
	common.FingerprintEnableWebRTC = false
	common.RedisEnabled = false

	body := `{"etag_id":"etag-raw","http_header_hash":"hdr-body","persistent_id":"pid-raw","webrtc_local_ips":["10.0.0.2"],"webrtc_public_ips":["8.8.8.8"]}`
	ctx, recorder := newFingerprintReportTestContext(http.MethodPost, "/api/fingerprint/report", body)
	ctx.Set("id", 7)
	ctx.Set("real_ip", "1.2.3.4")
	ctx.Set("ja4_fingerprint", "ja4-raw")
	ctx.Set("http_header_fingerprint", "hdr-context")

	ReportFingerprint(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}

	fps := model.GetLatestFingerprints(7, 1)
	require.Len(t, fps, 1)
	assert := require.New(t)
	assert.Equal("", fps[0].JA4)
	assert.Equal("hdr-context", fps[0].HTTPHeaderHash)
	assert.Equal("", fps[0].ETagID)
	assert.Equal("", fps[0].WebRTCLocalIPs)
	assert.Equal("", fps[0].WebRTCPublicIPs)
	assert.Equal("pid-raw", fps[0].PersistentID)
}

func TestReportFingerprint_IgnoresBodyHTTPHeaderHashWithoutContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)

	oldEnabled := common.FingerprintEnabled
	oldRedis := common.RedisEnabled
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.RedisEnabled = oldRedis
	})

	common.FingerprintEnabled = true
	common.RedisEnabled = false

	ctx, recorder := newFingerprintReportTestContext(http.MethodPost, "/api/fingerprint/report", `{"http_header_hash":"hdr-body-only"}`)
	ctx.Set("id", 8)
	ctx.Set("real_ip", "1.2.3.4")

	ReportFingerprint(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)

	fps := model.GetLatestFingerprints(8, 1)
	require.Len(t, fps, 1)
	require.Equal(t, "", fps[0].HTTPHeaderHash)
}

func TestFPResetUserFingerprintTestData_Disabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)

	oldEnabled := common.FingerprintTestResetEnabled
	common.FingerprintTestResetEnabled = false
	t.Cleanup(func() {
		common.FingerprintTestResetEnabled = oldEnabled
	})

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Params = gin.Params{{Key: "id", Value: "7"}}
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/admin/fingerprint/user/7/reset-test-data", nil)

	FPResetUserFingerprintTestData(ctx)

	require.Equal(t, http.StatusForbidden, recorder.Code)
}

func TestFPResetUserFingerprintTestData_DeletesFingerprintTables(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&model.Fingerprint{},
		&model.AccountLink{},
		&model.IPUAHistory{},
		&model.UserRiskScore{},
		&model.UserDeviceProfile{},
		&model.KeystrokeProfile{},
		&model.MouseProfile{},
		&model.UserTemporalProfile{},
		&model.UserSession{},
	))
	model.DB = db

	uid := 7
	require.NoError(t, model.DB.Create(&model.Fingerprint{UserID: uid, IPAddress: "1.2.3.4", CompositeHash: "abc"}).Error)
	require.NoError(t, model.DB.Create(&model.AccountLink{UserIDA: uid, UserIDB: 8, Confidence: 0.8, MatchDetails: "[]", Status: "pending"}).Error)
	require.NoError(t, model.DB.Create(&model.IPUAHistory{UserID: uid, IPAddress: "1.2.3.4"}).Error)
	require.NoError(t, model.DB.Create(&model.UserRiskScore{UserID: uid, RiskLevel: "low"}).Error)
	require.NoError(t, model.DB.Create(&model.UserDeviceProfile{UserID: uid, DeviceKey: "lid:abc"}).Error)
	require.NoError(t, model.DB.Create(&model.KeystrokeProfile{UserID: uid, SampleCount: 12}).Error)
	require.NoError(t, model.DB.Create(&model.MouseProfile{UserID: uid, SampleCount: 18}).Error)
	require.NoError(t, model.DB.Create(&model.UserTemporalProfile{UserID: uid, SampleCount: 6}).Error)
	require.NoError(t, model.DB.Create(&model.UserSession{UserID: uid, SessionID: "sess-7", DeviceKey: "lid:abc", IPAddress: "1.2.3.4", StartedAt: time.Now().UTC(), EndedAt: time.Now().UTC().Add(time.Minute), DurationSeconds: 60, EventCount: 1, Source: "fingerprint"}).Error)

	oldEnabled := common.FingerprintTestResetEnabled
	common.FingerprintTestResetEnabled = true
	t.Cleanup(func() {
		common.FingerprintTestResetEnabled = oldEnabled
	})

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Params = gin.Params{{Key: "id", Value: "7"}}
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/admin/fingerprint/user/7/reset-test-data", nil)

	FPResetUserFingerprintTestData(ctx)
	require.Equal(t, http.StatusOK, recorder.Code)

	var fpCount int64
	require.NoError(t, model.DB.Model(&model.Fingerprint{}).Where("user_id = ?", uid).Count(&fpCount).Error)
	require.Equal(t, int64(0), fpCount)

	var linkCount int64
	require.NoError(t, model.DB.Model(&model.AccountLink{}).Where("user_id_a = ? OR user_id_b = ?", uid, uid).Count(&linkCount).Error)
	require.Equal(t, int64(0), linkCount)

	var ipCount int64
	require.NoError(t, model.DB.Model(&model.IPUAHistory{}).Where("user_id = ?", uid).Count(&ipCount).Error)
	require.Equal(t, int64(0), ipCount)

	var riskCount int64
	require.NoError(t, model.DB.Model(&model.UserRiskScore{}).Where("user_id = ?", uid).Count(&riskCount).Error)
	require.Equal(t, int64(0), riskCount)

	var deviceCount int64
	require.NoError(t, model.DB.Model(&model.UserDeviceProfile{}).Where("user_id = ?", uid).Count(&deviceCount).Error)
	require.Equal(t, int64(0), deviceCount)

	var keystrokeCount int64
	require.NoError(t, model.DB.Model(&model.KeystrokeProfile{}).Where("user_id = ?", uid).Count(&keystrokeCount).Error)
	require.Equal(t, int64(0), keystrokeCount)

	var mouseCount int64
	require.NoError(t, model.DB.Model(&model.MouseProfile{}).Where("user_id = ?", uid).Count(&mouseCount).Error)
	require.Equal(t, int64(0), mouseCount)

	var temporalCount int64
	require.NoError(t, model.DB.Model(&model.UserTemporalProfile{}).Where("user_id = ?", uid).Count(&temporalCount).Error)
	require.Equal(t, int64(0), temporalCount)

	var sessionCount int64
	require.NoError(t, model.DB.Model(&model.UserSession{}).Where("user_id = ?", uid).Count(&sessionCount).Error)
	require.Equal(t, int64(0), sessionCount)
}

func TestReportFingerprint_PersistsMediaSpeechFieldsAndDeviceProfile(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)

	oldEnabled := common.FingerprintEnabled
	oldJA4 := common.FingerprintEnableJA4
	oldETag := common.FingerprintEnableETag
	oldWebRTC := common.FingerprintEnableWebRTC
	oldRedis := common.RedisEnabled
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.FingerprintEnableJA4 = oldJA4
		common.FingerprintEnableETag = oldETag
		common.FingerprintEnableWebRTC = oldWebRTC
		common.RedisEnabled = oldRedis
	})

	common.FingerprintEnabled = true
	common.FingerprintEnableJA4 = true
	common.FingerprintEnableETag = true
	common.FingerprintEnableWebRTC = true
	common.RedisEnabled = false

	body := `{"local_device_id":"lid-media-speech","canvas_hash":"canvas-x","webgl_hash":"webgl-x","audio_hash":"audio-x","media_devices_hash":"media-devices-hash","media_device_count":"1-1-1","media_device_group_hash":"media-group-hash","media_device_total":3,"speech_voices_hash":"speech-voices-hash","speech_voice_count":12,"speech_local_voice_count":5,"composite_hash":"composite-x"}`
	ctx, recorder := newFingerprintReportTestContext(http.MethodPost, "/api/fingerprint/report", body)
	ctx.Set("id", 9)
	ctx.Set("real_ip", "1.2.3.4")
	ctx.Set("ja4_fingerprint", "ja4-raw")
	ctx.Set("http_header_fingerprint", "hdr-context")
	ctx.Request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36")

	ReportFingerprint(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)

	fps := model.GetLatestFingerprints(9, 1)
	require.Len(t, fps, 1)
	require.Equal(t, "media-devices-hash", fps[0].MediaDevicesHash)
	require.Equal(t, "1-1-1", fps[0].MediaDeviceCount)
	require.Equal(t, "media-group-hash", fps[0].MediaDeviceGroupHash)
	require.Equal(t, 3, fps[0].MediaDeviceTotal)
	require.Equal(t, "speech-voices-hash", fps[0].SpeechVoicesHash)
	require.Equal(t, 12, fps[0].SpeechVoiceCount)
	require.Equal(t, 5, fps[0].SpeechLocalVoiceCount)

	profiles := model.GetDeviceProfiles(9)
	require.Len(t, profiles, 1)
	require.Equal(t, "media-devices-hash", profiles[0].MediaDevicesHash)
	require.Equal(t, "1-1-1", profiles[0].MediaDeviceCount)
	require.Equal(t, "media-group-hash", profiles[0].MediaDeviceGroupHash)
	require.Equal(t, 3, profiles[0].MediaDeviceTotal)
	require.Equal(t, "speech-voices-hash", profiles[0].SpeechVoicesHash)
	require.Equal(t, 12, profiles[0].SpeechVoiceCount)
	require.Equal(t, 5, profiles[0].SpeechLocalVoiceCount)
	require.Equal(t, "hdr-context", profiles[0].HTTPHeaderHash)
}

func TestFingerprintModels_AutoMigrateIncludesMediaSpeechColumns(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&model.Fingerprint{}, &model.UserDeviceProfile{}))

	hasColumn := func(table string, column string) bool {
		return db.Migrator().HasColumn(table, column)
	}

	require.True(t, hasColumn((&model.Fingerprint{}).TableName(), "media_devices_hash"))
	require.True(t, hasColumn((&model.Fingerprint{}).TableName(), "media_device_group_hash"))
	require.True(t, hasColumn((&model.Fingerprint{}).TableName(), "speech_voices_hash"))
	require.True(t, hasColumn((&model.UserDeviceProfile{}).TableName(), "media_devices_hash"))
	require.True(t, hasColumn((&model.UserDeviceProfile{}).TableName(), "media_device_group_hash"))
	require.True(t, hasColumn((&model.UserDeviceProfile{}).TableName(), "speech_voices_hash"))
}

func TestReportFingerprint_PersistsDNSResolverAndSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)

	oldEnabled := common.FingerprintEnabled
	oldJA4 := common.FingerprintEnableJA4
	oldETag := common.FingerprintEnableETag
	oldWebRTC := common.FingerprintEnableWebRTC
	oldDNS := common.FingerprintEnableDNSLeak
	oldRedis := common.RedisEnabled
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.FingerprintEnableJA4 = oldJA4
		common.FingerprintEnableETag = oldETag
		common.FingerprintEnableWebRTC = oldWebRTC
		common.FingerprintEnableDNSLeak = oldDNS
		common.RedisEnabled = oldRedis
	})

	common.FingerprintEnabled = true
	common.FingerprintEnableJA4 = true
	common.FingerprintEnableETag = true
	common.FingerprintEnableWebRTC = true
	common.FingerprintEnableDNSLeak = true
	common.RedisEnabled = false

	start := time.Now().UTC().Add(-5 * time.Minute).Unix()
	end := start - 10
	body := fmt.Sprintf(`{"local_device_id":"lid-dns-session","canvas_hash":"canvas-dns","webgl_hash":"webgl-dns","audio_hash":"audio-dns","composite_hash":"composite-dns","dns_resolver_ip":" 8.8.8.8 ","dns_probe_id":"probe-123","session_id":"session-123","session_start_at":%d,"session_end_at":%d}`,
		start,
		end,
	)
	ctx, recorder := newFingerprintReportTestContext(http.MethodPost, "/api/fingerprint/report", body)
	ctx.Set("id", 11)
	ctx.Set("real_ip", "1.2.3.4")
	ctx.Request.Header.Set("User-Agent", "Mozilla/5.0")

	ReportFingerprint(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)

	fps := model.GetLatestFingerprints(11, 1)
	require.Len(t, fps, 1)
	require.Equal(t, "8.8.8.8", fps[0].DNSResolverIP)
	require.Equal(t, "session-123", fps[0].SessionID)

	sessions := model.GetLatestUserSessions(11, 10)
	require.Len(t, sessions, 1)
	require.Equal(t, "session-123", sessions[0].SessionID)
	require.Equal(t, "lid:lid-dns-session", sessions[0].DeviceKey)
	require.Equal(t, "1.2.3.4", sessions[0].IPAddress)
	require.Equal(t, "fingerprint", sessions[0].Source)
	require.Equal(t, 0, sessions[0].DurationSeconds)
	require.True(t, sessions[0].EndedAt.Equal(sessions[0].StartedAt))
}

func TestReportFingerprint_DNSDisabledSkipsResolverPersistence(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)

	oldEnabled := common.FingerprintEnabled
	oldDNS := common.FingerprintEnableDNSLeak
	oldRedis := common.RedisEnabled
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.FingerprintEnableDNSLeak = oldDNS
		common.RedisEnabled = oldRedis
	})

	common.FingerprintEnabled = true
	common.FingerprintEnableDNSLeak = false
	common.RedisEnabled = false

	body := `{"local_device_id":"lid-dns-off","canvas_hash":"canvas-dns-off","webgl_hash":"webgl-dns-off","audio_hash":"audio-dns-off","composite_hash":"composite-dns-off","dns_resolver_ip":"8.8.8.8","dns_probe_id":"probe-disabled"}`
	ctx, recorder := newFingerprintReportTestContext(http.MethodPost, "/api/fingerprint/report", body)
	ctx.Set("id", 111)
	ctx.Set("real_ip", "1.2.3.4")
	ctx.Request.Header.Set("User-Agent", "Mozilla/5.0")

	ReportFingerprint(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)
	fps := model.GetLatestFingerprints(111, 1)
	require.Len(t, fps, 1)
	require.Equal(t, "", fps[0].DNSResolverIP)
}

func TestFPGetUserTemporalProfile_ReturnsProfileBins(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)

	now := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, model.DB.Create(&model.Fingerprint{UserID: 88, IPAddress: "1.2.3.4", CompositeHash: "c1", CreatedAt: now}).Error)
	require.NoError(t, model.DB.Create(&model.Fingerprint{UserID: 88, IPAddress: "1.2.3.4", CompositeHash: "c2", CreatedAt: now.Add(30 * time.Minute)}).Error)
	require.NoError(t, model.DB.Create(&model.Fingerprint{UserID: 88, IPAddress: "1.2.3.4", CompositeHash: "c3", CreatedAt: now.Add(2 * time.Hour)}).Error)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Params = gin.Params{{Key: "id", Value: "88"}}
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/admin/fingerprint/user/88/temporal", nil)

	FPGetUserTemporalProfile(ctx)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"success":true`)
	require.Contains(t, recorder.Body.String(), `"sample_count":3`)
	require.Contains(t, recorder.Body.String(), `"profile_bins"`)
	require.Contains(t, recorder.Body.String(), now.Add(2*time.Hour).Format(time.RFC3339))
}

func TestFPGetUserTemporalProfile_InvalidUserID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)

	t.Run("non numeric", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Params = gin.Params{{Key: "id", Value: "bad-id"}}
		ctx.Request = httptest.NewRequest(http.MethodGet, "/api/admin/fingerprint/user/bad-id/temporal", nil)

		FPGetUserTemporalProfile(ctx)
		require.Equal(t, http.StatusBadRequest, recorder.Code)
		require.Contains(t, recorder.Body.String(), `"success":false`)
	})

	t.Run("non positive", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Params = gin.Params{{Key: "id", Value: "0"}}
		ctx.Request = httptest.NewRequest(http.MethodGet, "/api/admin/fingerprint/user/0/temporal", nil)

		FPGetUserTemporalProfile(ctx)
		require.Equal(t, http.StatusBadRequest, recorder.Code)
		require.Contains(t, recorder.Body.String(), `"success":false`)
	})
}

func TestReportFingerprint_PersistsKeystrokeProfile(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)

	oldEnabled := common.FingerprintEnabled
	oldRedis := common.RedisEnabled
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.RedisEnabled = oldRedis
	})

	common.FingerprintEnabled = true
	common.RedisEnabled = false

	body := `{"local_device_id":"lid-key","canvas_hash":"canvas-key","webgl_hash":"webgl-key","audio_hash":"audio-key","composite_hash":"composite-key","keystroke":{"avgHoldTime":98.5,"stdHoldTime":11.3,"avgFlightTime":120.2,"stdFlightTime":19.1,"typingSpeed":4.7,"sampleCount":132,"commonDigraphs":[{"digraph":"alpha->digit","avgFlightTime":116.2,"stdFlightTime":13.5,"sampleCount":41}]}}`
	ctx, recorder := newFingerprintReportTestContext(http.MethodPost, "/api/fingerprint/report", body)
	ctx.Set("id", 31)
	ctx.Set("real_ip", "1.2.3.4")

	ReportFingerprint(ctx)
	require.Equal(t, http.StatusOK, recorder.Code)

	profile := model.GetLatestKeystrokeProfile(31)
	require.NotNil(t, profile)
	require.InDelta(t, 98.5, profile.AvgHoldTime, 0.0001)
	require.InDelta(t, 120.2, profile.AvgFlightTime, 0.0001)
	require.Equal(t, 132, profile.SampleCount)
	require.Contains(t, profile.DigraphData, "alpha-\\u003edigit")
}

func TestReportFingerprint_PersistsMouseProfile(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)

	oldEnabled := common.FingerprintEnabled
	oldRedis := common.RedisEnabled
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.RedisEnabled = oldRedis
	})

	common.FingerprintEnabled = true
	common.RedisEnabled = false

	body := `{"local_device_id":"lid-mouse","canvas_hash":"canvas-mouse","webgl_hash":"webgl-mouse","audio_hash":"audio-mouse","composite_hash":"composite-mouse","mouse":{"avgSpeed":1380.5,"maxSpeed":2100.2,"speedStd":180.4,"avgAcceleration":320.6,"accStd":75.1,"directionChangeRate":0.21,"avgScrollDelta":96.5,"scrollDeltaMode":0,"clickDistribution":{"topLeft":0.25,"topRight":0.25,"bottomLeft":0.25,"bottomRight":0.25},"sampleCount":64}}`
	ctx, recorder := newFingerprintReportTestContext(http.MethodPost, "/api/fingerprint/report", body)
	ctx.Set("id", 38)
	ctx.Set("real_ip", "1.2.3.4")

	ReportFingerprint(ctx)
	require.Equal(t, http.StatusOK, recorder.Code)

	profile := model.GetLatestMouseProfile(38)
	require.NotNil(t, profile)
	require.InDelta(t, 1380.5, profile.AvgSpeed, 0.0001)
	require.InDelta(t, 0.21, profile.DirectionChangeRate, 0.0001)
	require.Equal(t, 64, profile.SampleCount)
	require.Contains(t, profile.ClickDistribution, "topLeft")
}

func TestReportBehaviorFingerprint_PersistsProfilesWithoutFingerprintRow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)

	oldEnabled := common.FingerprintEnabled
	oldBehaviorEnabled := common.FingerprintEnableBehaviorAnalysis
	oldRedis := common.RedisEnabled
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.FingerprintEnableBehaviorAnalysis = oldBehaviorEnabled
		common.RedisEnabled = oldRedis
	})

	common.FingerprintEnabled = true
	common.FingerprintEnableBehaviorAnalysis = true
	common.RedisEnabled = false

	body := `{"session_id":"behavior-session-1","keystroke":{"avgHoldTime":98.5,"stdHoldTime":11.3,"avgFlightTime":120.2,"stdFlightTime":19.1,"typingSpeed":4.7,"sampleCount":132,"commonDigraphs":[{"digraph":"alpha->digit","avgFlightTime":116.2,"stdFlightTime":13.5,"sampleCount":41}]},"mouse":{"avgSpeed":1380.5,"maxSpeed":2100.2,"speedStd":180.4,"avgAcceleration":320.6,"accStd":75.1,"directionChangeRate":0.21,"avgScrollDelta":96.5,"scrollDeltaMode":0,"clickDistribution":{"topLeft":0.25,"topRight":0.25,"bottomLeft":0.25,"bottomRight":0.25},"sampleCount":64}}`
	ctx, recorder := newFingerprintReportTestContext(http.MethodPost, "/api/fingerprint/behavior", body)
	ctx.Set("id", 41)

	ReportBehaviorFingerprint(ctx)
	grequire := require.New(t)
	grequire.Equal(http.StatusOK, recorder.Code)
	grequire.Contains(recorder.Body.String(), `"success":true`)

	keystrokeProfile := model.GetLatestKeystrokeProfile(41)
	grequire.NotNil(keystrokeProfile)
	grequire.InDelta(98.5, keystrokeProfile.AvgHoldTime, 0.0001)
	grequire.Equal(132, keystrokeProfile.SampleCount)

	mouseProfile := model.GetLatestMouseProfile(41)
	grequire.NotNil(mouseProfile)
	grequire.InDelta(1380.5, mouseProfile.AvgSpeed, 0.0001)
	grequire.Equal(64, mouseProfile.SampleCount)

	grequire.Len(model.GetLatestFingerprints(41, 1), 0)
	grequire.Len(model.GetLatestUserSessions(41, 10), 0)
}

func TestReportBehaviorFingerprint_RejectsInvalidPayload(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)

	oldEnabled := common.FingerprintEnabled
	oldBehaviorEnabled := common.FingerprintEnableBehaviorAnalysis
	oldRedis := common.RedisEnabled
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.FingerprintEnableBehaviorAnalysis = oldBehaviorEnabled
		common.RedisEnabled = oldRedis
	})

	common.FingerprintEnabled = true
	common.FingerprintEnableBehaviorAnalysis = true
	common.RedisEnabled = false

	body := `{"keystroke":{"avgHoldTime":98.5,"stdHoldTime":11.3,"avgFlightTime":120.2,"stdFlightTime":19.1,"typingSpeed":4.7,"sampleCount":132,"commonDigraphs":[{"digraph":"alpha->digit","avgFlightTime":116.2,"stdFlightTime":13.5,"sampleCount":41}]},"mouse":{"avgSpeed":"fast","maxSpeed":2100.2,"speedStd":180.4,"avgAcceleration":320.6,"accStd":75.1,"directionChangeRate":0.21,"avgScrollDelta":96.5,"scrollDeltaMode":0,"clickDistribution":{"topLeft":0.25,"topRight":0.25,"bottomLeft":0.25,"bottomRight":0.25},"sampleCount":64}}`
	ctx, recorder := newFingerprintReportTestContext(http.MethodPost, "/api/fingerprint/behavior", body)
	ctx.Set("id", 42)

	ReportBehaviorFingerprint(ctx)
	require.Equal(t, http.StatusBadRequest, recorder.Code)
	require.Nil(t, model.GetLatestKeystrokeProfile(42))
	require.Nil(t, model.GetLatestMouseProfile(42))
	require.Len(t, model.GetLatestFingerprints(42, 1), 0)
}

func TestReportFingerprint_BehaviorDisabledSkipsValidationAndPersistence(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)

	oldEnabled := common.FingerprintEnabled
	oldBehaviorEnabled := common.FingerprintEnableBehaviorAnalysis
	oldRedis := common.RedisEnabled
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.FingerprintEnableBehaviorAnalysis = oldBehaviorEnabled
		common.RedisEnabled = oldRedis
	})

	common.FingerprintEnabled = true
	common.FingerprintEnableBehaviorAnalysis = false
	common.RedisEnabled = false

	body := `{"local_device_id":"lid-behavior-off","canvas_hash":"canvas-off","webgl_hash":"webgl-off","audio_hash":"audio-off","composite_hash":"composite-off","session_id":"session-behavior-off","mouse":{"avgSpeed":1380.5,"maxSpeed":2100.2,"speedStd":180.4,"avgAcceleration":320.6,"accStd":75.1,"directionChangeRate":1.21,"avgScrollDelta":96.5,"scrollDeltaMode":0,"clickDistribution":{"topLeft":0.25,"topRight":0.25,"bottomLeft":0.25,"bottomRight":0.25},"sampleCount":64}}`
	ctx, recorder := newFingerprintReportTestContext(http.MethodPost, "/api/fingerprint/report", body)
	ctx.Set("id", 43)
	ctx.Set("real_ip", "1.2.3.4")

	ReportFingerprint(ctx)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"success":true`)
	require.Len(t, model.GetLatestFingerprints(43, 1), 1)
	require.Len(t, model.GetLatestUserSessions(43, 10), 1)
	require.Nil(t, model.GetLatestKeystrokeProfile(43))
	require.Nil(t, model.GetLatestMouseProfile(43))
}

func TestReportBehaviorFingerprint_Returns500WhenProfileUpsertFails(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)

	oldEnabled := common.FingerprintEnabled
	oldBehaviorEnabled := common.FingerprintEnableBehaviorAnalysis
	oldRedis := common.RedisEnabled
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.FingerprintEnableBehaviorAnalysis = oldBehaviorEnabled
		common.RedisEnabled = oldRedis
	})

	common.FingerprintEnabled = true
	common.FingerprintEnableBehaviorAnalysis = true
	common.RedisEnabled = false
	require.NoError(t, model.DB.Migrator().DropTable(&model.KeystrokeProfile{}))

	body := `{"session_id":"behavior-session-fail","keystroke":{"avgHoldTime":98.5,"stdHoldTime":11.3,"avgFlightTime":120.2,"stdFlightTime":19.1,"typingSpeed":4.7,"sampleCount":132,"commonDigraphs":[{"digraph":"alpha->digit","avgFlightTime":116.2,"stdFlightTime":13.5,"sampleCount":41}]}}`
	ctx, recorder := newFingerprintReportTestContext(http.MethodPost, "/api/fingerprint/behavior", body)
	ctx.Set("id", 44)

	ReportBehaviorFingerprint(ctx)
	require.Equal(t, http.StatusInternalServerError, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"success":false`)
	require.Nil(t, model.GetLatestKeystrokeProfile(44))
	require.Nil(t, model.GetLatestMouseProfile(44))
	require.Len(t, model.GetLatestFingerprints(44, 1), 0)
}

func TestReportBehaviorFingerprint_RollsBackOnPartialProfileFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)

	oldEnabled := common.FingerprintEnabled
	oldBehaviorEnabled := common.FingerprintEnableBehaviorAnalysis
	oldRedis := common.RedisEnabled
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.FingerprintEnableBehaviorAnalysis = oldBehaviorEnabled
		common.RedisEnabled = oldRedis
	})

	common.FingerprintEnabled = true
	common.FingerprintEnableBehaviorAnalysis = true
	common.RedisEnabled = false
	require.NoError(t, model.DB.Migrator().DropTable(&model.MouseProfile{}))

	body := `{"session_id":"behavior-session-partial-fail","keystroke":{"avgHoldTime":98.5,"stdHoldTime":11.3,"avgFlightTime":120.2,"stdFlightTime":19.1,"typingSpeed":4.7,"sampleCount":132,"commonDigraphs":[{"digraph":"alpha->digit","avgFlightTime":116.2,"stdFlightTime":13.5,"sampleCount":41}]},"mouse":{"avgSpeed":1380.5,"maxSpeed":2100.2,"speedStd":180.4,"avgAcceleration":320.6,"accStd":75.1,"directionChangeRate":0.21,"avgScrollDelta":96.5,"scrollDeltaMode":0,"clickDistribution":{"topLeft":0.25,"topRight":0.25,"bottomLeft":0.25,"bottomRight":0.25},"sampleCount":64}}`
	ctx, recorder := newFingerprintReportTestContext(http.MethodPost, "/api/fingerprint/behavior", body)
	ctx.Set("id", 45)

	ReportBehaviorFingerprint(ctx)
	require.Equal(t, http.StatusInternalServerError, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"success":false`)
	require.Nil(t, model.GetLatestKeystrokeProfile(45))
	require.Nil(t, model.GetLatestMouseProfile(45))
}

func TestReportFingerprint_Returns500WhenBehaviorProfileUpsertFails(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)

	oldEnabled := common.FingerprintEnabled
	oldBehaviorEnabled := common.FingerprintEnableBehaviorAnalysis
	oldRedis := common.RedisEnabled
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.FingerprintEnableBehaviorAnalysis = oldBehaviorEnabled
		common.RedisEnabled = oldRedis
	})

	common.FingerprintEnabled = true
	common.FingerprintEnableBehaviorAnalysis = true
	common.RedisEnabled = false
	require.NoError(t, model.DB.Migrator().DropTable(&model.KeystrokeProfile{}))

	body := `{"local_device_id":"lid-report-fail","canvas_hash":"canvas-report-fail","webgl_hash":"webgl-report-fail","audio_hash":"audio-report-fail","composite_hash":"composite-report-fail","mouse":{"avgSpeed":1380.5,"maxSpeed":2100.2,"speedStd":180.4,"avgAcceleration":320.6,"accStd":75.1,"directionChangeRate":0.21,"avgScrollDelta":96.5,"scrollDeltaMode":0,"clickDistribution":{"topLeft":0.25,"topRight":0.25,"bottomLeft":0.25,"bottomRight":0.25},"sampleCount":64},"keystroke":{"avgHoldTime":98.5,"stdHoldTime":11.3,"avgFlightTime":120.2,"stdFlightTime":19.1,"typingSpeed":4.7,"sampleCount":132,"commonDigraphs":[{"digraph":"alpha->digit","avgFlightTime":116.2,"stdFlightTime":13.5,"sampleCount":41}]}}`
	ctx, recorder := newFingerprintReportTestContext(http.MethodPost, "/api/fingerprint/report", body)
	ctx.Set("id", 46)
	ctx.Set("real_ip", "1.2.3.4")

	ReportFingerprint(ctx)
	require.Equal(t, http.StatusInternalServerError, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"success":false`)
	require.Empty(t, model.GetLatestFingerprints(46, 1))
	require.Empty(t, model.GetDeviceProfiles(46))
	require.Empty(t, model.GetLatestUserSessions(46, 10))
	require.Nil(t, model.GetLatestKeystrokeProfile(46))
	require.Nil(t, model.GetLatestMouseProfile(46))
}

func TestReportFingerprint_RejectsInvalidMousePayload(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)

	oldEnabled := common.FingerprintEnabled
	oldRedis := common.RedisEnabled
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.RedisEnabled = oldRedis
	})

	common.FingerprintEnabled = true
	common.RedisEnabled = false

	body := `{"local_device_id":"lid-mouse-invalid","canvas_hash":"canvas-mouse","webgl_hash":"webgl-mouse","audio_hash":"audio-mouse","composite_hash":"composite-mouse","mouse":{"avgSpeed":"fast","maxSpeed":2100.2,"speedStd":180.4,"avgAcceleration":320.6,"accStd":75.1,"directionChangeRate":0.21,"avgScrollDelta":96.5,"scrollDeltaMode":0,"clickDistribution":{"topLeft":0.25,"topRight":0.25,"bottomLeft":0.25,"bottomRight":0.25},"sampleCount":64}}`
	ctx, recorder := newFingerprintReportTestContext(http.MethodPost, "/api/fingerprint/report", body)
	ctx.Set("id", 39)
	ctx.Set("real_ip", "1.2.3.4")

	ReportFingerprint(ctx)
	require.Equal(t, http.StatusBadRequest, recorder.Code)
	require.Nil(t, model.GetLatestMouseProfile(39))
}

func TestReportFingerprint_RejectsInvalidKeystrokeDigraphShape(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)

	oldEnabled := common.FingerprintEnabled
	oldRedis := common.RedisEnabled
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.RedisEnabled = oldRedis
	})

	common.FingerprintEnabled = true
	common.RedisEnabled = false

	body := `{"local_device_id":"lid-key-invalid","canvas_hash":"canvas-key","webgl_hash":"webgl-key","audio_hash":"audio-key","composite_hash":"composite-key","keystroke":{"avgHoldTime":98.5,"stdHoldTime":11.3,"avgFlightTime":120.2,"stdFlightTime":19.1,"typingSpeed":4.7,"sampleCount":132,"commonDigraphs":[{"digraph":"alpha->digit","avgFlightTime":"116.2","stdFlightTime":13.5,"sampleCount":41}]}}`
	ctx, recorder := newFingerprintReportTestContext(http.MethodPost, "/api/fingerprint/report", body)
	ctx.Set("id", 32)
	ctx.Set("real_ip", "1.2.3.4")

	ReportFingerprint(ctx)
	require.Equal(t, http.StatusBadRequest, recorder.Code)
	require.Nil(t, model.GetLatestKeystrokeProfile(32))
}

func TestReportFingerprint_RejectsInvalidKeystrokeDigraphValue(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)

	oldEnabled := common.FingerprintEnabled
	oldRedis := common.RedisEnabled
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.RedisEnabled = oldRedis
	})

	common.FingerprintEnabled = true
	common.RedisEnabled = false

	body := `{"local_device_id":"lid-key-invalid-digraph","canvas_hash":"canvas-key","webgl_hash":"webgl-key","audio_hash":"audio-key","composite_hash":"composite-key","keystroke":{"avgHoldTime":98.5,"stdHoldTime":11.3,"avgFlightTime":120.2,"stdFlightTime":19.1,"typingSpeed":4.7,"sampleCount":132,"commonDigraphs":[{"digraph":"rawkey->digit","avgFlightTime":116.2,"stdFlightTime":13.5,"sampleCount":41}]}}`
	ctx, recorder := newFingerprintReportTestContext(http.MethodPost, "/api/fingerprint/report", body)
	ctx.Set("id", 33)
	ctx.Set("real_ip", "1.2.3.4")

	ReportFingerprint(ctx)
	require.Equal(t, http.StatusBadRequest, recorder.Code)
	require.Nil(t, model.GetLatestKeystrokeProfile(33))
}

func TestReportFingerprint_RejectsUnknownKeystrokeFields(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)

	oldEnabled := common.FingerprintEnabled
	oldRedis := common.RedisEnabled
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.RedisEnabled = oldRedis
	})

	common.FingerprintEnabled = true
	common.RedisEnabled = false

	body := `{"local_device_id":"lid-key-unknown-field","canvas_hash":"canvas-key","webgl_hash":"webgl-key","audio_hash":"audio-key","composite_hash":"composite-key","keystroke":{"avgHoldTime":98.5,"stdHoldTime":11.3,"avgFlightTime":120.2,"stdFlightTime":19.1,"typingSpeed":4.7,"sampleCount":132,"commonDigraphs":[{"digraph":"alpha->digit","avgFlightTime":116.2,"stdFlightTime":13.5,"sampleCount":41,"rawKeys":"ab"}]}}`
	ctx, recorder := newFingerprintReportTestContext(http.MethodPost, "/api/fingerprint/report", body)
	ctx.Set("id", 34)
	ctx.Set("real_ip", "1.2.3.4")

	ReportFingerprint(ctx)
	require.Equal(t, http.StatusBadRequest, recorder.Code)
	require.Nil(t, model.GetLatestKeystrokeProfile(34))
}

func TestReportFingerprint_RejectsOutOfRangeKeystrokeMetrics(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)

	oldEnabled := common.FingerprintEnabled
	oldRedis := common.RedisEnabled
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.RedisEnabled = oldRedis
	})

	common.FingerprintEnabled = true
	common.RedisEnabled = false

	body := `{"local_device_id":"lid-key-metric","canvas_hash":"canvas-key","webgl_hash":"webgl-key","audio_hash":"audio-key","composite_hash":"composite-key","keystroke":{"avgHoldTime":10001,"stdHoldTime":11.3,"avgFlightTime":120.2,"stdFlightTime":19.1,"typingSpeed":4.7,"sampleCount":132,"commonDigraphs":[{"digraph":"alpha->digit","avgFlightTime":116.2,"stdFlightTime":13.5,"sampleCount":41}]}}`
	ctx, recorder := newFingerprintReportTestContext(http.MethodPost, "/api/fingerprint/report", body)
	ctx.Set("id", 35)
	ctx.Set("real_ip", "1.2.3.4")

	ReportFingerprint(ctx)
	require.Equal(t, http.StatusBadRequest, recorder.Code)
	require.Nil(t, model.GetLatestKeystrokeProfile(35))
}

func TestReportFingerprint_ClampsFarFutureSessionTimestamp(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)

	oldEnabled := common.FingerprintEnabled
	oldRedis := common.RedisEnabled
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.RedisEnabled = oldRedis
	})

	common.FingerprintEnabled = true
	common.RedisEnabled = false

	future := time.Now().UTC().Add(72 * time.Hour).Unix()
	body := fmt.Sprintf(`{"local_device_id":"lid-future-session","canvas_hash":"canvas-dns","webgl_hash":"webgl-dns","audio_hash":"audio-dns","composite_hash":"composite-dns","session_id":"session-future","session_start_at":%d,"session_end_at":%d}`,
		future,
		future,
	)
	before := time.Now().UTC().Add(-5 * time.Second)
	ctx, recorder := newFingerprintReportTestContext(http.MethodPost, "/api/fingerprint/report", body)
	ctx.Set("id", 36)
	ctx.Set("real_ip", "1.2.3.4")
	ctx.Request.Header.Set("User-Agent", "Mozilla/5.0")

	ReportFingerprint(ctx)
	after := time.Now().UTC().Add(5 * time.Second)

	require.Equal(t, http.StatusOK, recorder.Code)
	sessions := model.GetLatestUserSessions(36, 10)
	require.Len(t, sessions, 1)
	require.True(t, sessions[0].StartedAt.After(before))
	require.True(t, sessions[0].StartedAt.Before(after))
	require.True(t, sessions[0].EndedAt.Equal(sessions[0].StartedAt))
}

func TestReportFingerprint_RejectsTooLongSessionID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)

	oldEnabled := common.FingerprintEnabled
	oldRedis := common.RedisEnabled
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.RedisEnabled = oldRedis
	})

	common.FingerprintEnabled = true
	common.RedisEnabled = false

	body := fmt.Sprintf(`{"local_device_id":"lid-long-session","canvas_hash":"canvas-dns","webgl_hash":"webgl-dns","audio_hash":"audio-dns","composite_hash":"composite-dns","session_id":"%s"}`,
		strings.Repeat("s", 65),
	)
	ctx, recorder := newFingerprintReportTestContext(http.MethodPost, "/api/fingerprint/report", body)
	ctx.Set("id", 37)
	ctx.Set("real_ip", "1.2.3.4")
	ctx.Request.Header.Set("User-Agent", "Mozilla/5.0")

	ReportFingerprint(ctx)

	require.Equal(t, http.StatusBadRequest, recorder.Code)
	require.Len(t, model.GetLatestFingerprints(37, 1), 0)
	require.Len(t, model.GetLatestUserSessions(37, 10), 0)
}

func TestReportFingerprint_TrimsStorageHeavyFields(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)

	oldEnabled := common.FingerprintEnabled
	oldRedis := common.RedisEnabled
	oldMaxUA := os.Getenv("FINGERPRINT_MAX_USER_AGENT_LENGTH")
	oldMaxFonts := os.Getenv("FINGERPRINT_MAX_FONTS_LIST_LENGTH")
	oldMaxWebRTC := os.Getenv("FINGERPRINT_MAX_WEBRTC_IPS_LENGTH")
	oldMaxPageURL := os.Getenv("FINGERPRINT_MAX_PAGE_URL_LENGTH")
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.RedisEnabled = oldRedis
		if oldMaxUA == "" {
			_ = os.Unsetenv("FINGERPRINT_MAX_USER_AGENT_LENGTH")
		} else {
			_ = os.Setenv("FINGERPRINT_MAX_USER_AGENT_LENGTH", oldMaxUA)
		}
		if oldMaxFonts == "" {
			_ = os.Unsetenv("FINGERPRINT_MAX_FONTS_LIST_LENGTH")
		} else {
			_ = os.Setenv("FINGERPRINT_MAX_FONTS_LIST_LENGTH", oldMaxFonts)
		}
		if oldMaxWebRTC == "" {
			_ = os.Unsetenv("FINGERPRINT_MAX_WEBRTC_IPS_LENGTH")
		} else {
			_ = os.Setenv("FINGERPRINT_MAX_WEBRTC_IPS_LENGTH", oldMaxWebRTC)
		}
		if oldMaxPageURL == "" {
			_ = os.Unsetenv("FINGERPRINT_MAX_PAGE_URL_LENGTH")
		} else {
			_ = os.Setenv("FINGERPRINT_MAX_PAGE_URL_LENGTH", oldMaxPageURL)
		}
	})

	common.FingerprintEnabled = true
	common.RedisEnabled = false
	_ = os.Setenv("FINGERPRINT_MAX_USER_AGENT_LENGTH", "12")
	_ = os.Setenv("FINGERPRINT_MAX_FONTS_LIST_LENGTH", "10")
	_ = os.Setenv("FINGERPRINT_MAX_WEBRTC_IPS_LENGTH", "12")
	_ = os.Setenv("FINGERPRINT_MAX_PAGE_URL_LENGTH", "18")

	longUA := strings.Repeat("U", 30)
	longFonts := strings.Repeat("F", 40)
	body := fmt.Sprintf(`{"canvas_hash":"canvas-trim","webgl_hash":"webgl-trim","audio_hash":"audio-trim","composite_hash":"comp-trim","fonts_list":"%s","webrtc_local_ips":["192.168.1.2"],"webrtc_public_ips":["8.8.8.8"],"session_id":"trim-session"}`,
		longFonts,
	)
	ctx, recorder := newFingerprintReportTestContext(http.MethodPost, "/api/fingerprint/report", body)
	ctx.Set("id", 381)
	ctx.Set("real_ip", "1.2.3.4")
	ctx.Request.Header.Set("User-Agent", longUA)
	ctx.Request.Header.Set("Referer", "https://example.com/path/that/is/very/long?token=secret")

	ReportFingerprint(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)
	fps := model.GetLatestFingerprints(381, 1)
	require.Len(t, fps, 1)
	require.Equal(t, 12, len([]rune(fps[0].UserAgent)))
	require.Equal(t, 10, len([]rune(fps[0].FontsList)))
	require.Equal(t, "[]", fps[0].WebRTCLocalIPs)
	require.Equal(t, `["8.8.8.8"]`, fps[0].WebRTCPublicIPs)
	require.Equal(t, 18, len([]rune(fps[0].PageURL)))
}

func TestFPGetUserTemporalProfile_RealtimeReturnsZeroComputedAtWhenNoSamples(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)

	oldRead := common.FingerprintEnableTemporalPrecomputeRead
	common.FingerprintEnableTemporalPrecomputeRead = false
	t.Cleanup(func() {
		common.FingerprintEnableTemporalPrecomputeRead = oldRead
	})

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Params = gin.Params{{Key: "id", Value: "999"}}
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/admin/fingerprint/user/999/temporal", nil)

	FPGetUserTemporalProfile(ctx)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"success":true`)
	require.Contains(t, recorder.Body.String(), `"sample_count":0`)
	require.Contains(t, recorder.Body.String(), `"source":"realtime"`)
	require.Contains(t, recorder.Body.String(), `"computed_at":"0001-01-01T00:00:00Z"`)
}

func TestRegister_PersistsKeystrokeProfileFromFingerprintPayload(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)
	require.NoError(t, model.DB.AutoMigrate(&model.User{}))
	model.LOG_DB = model.DB

	oldRegisterEnabled := common.RegisterEnabled
	oldPasswordRegisterEnabled := common.PasswordRegisterEnabled
	oldEmailVerificationEnabled := common.EmailVerificationEnabled
	oldFingerprintEnabled := common.FingerprintEnabled
	oldRedisEnabled := common.RedisEnabled
	oldGenerateDefaultToken := constant.GenerateDefaultToken
	t.Cleanup(func() {
		common.RegisterEnabled = oldRegisterEnabled
		common.PasswordRegisterEnabled = oldPasswordRegisterEnabled
		common.EmailVerificationEnabled = oldEmailVerificationEnabled
		common.FingerprintEnabled = oldFingerprintEnabled
		common.RedisEnabled = oldRedisEnabled
		constant.GenerateDefaultToken = oldGenerateDefaultToken
	})

	common.RegisterEnabled = true
	common.PasswordRegisterEnabled = true
	common.EmailVerificationEnabled = false
	common.FingerprintEnabled = true
	common.RedisEnabled = false
	constant.GenerateDefaultToken = false

	body := `{"username":"reg_keystroke_user","password":"12345678","fingerprint":{"local_device_id":"lid-reg","canvas_hash":"canvas-reg","webgl_hash":"webgl-reg","audio_hash":"audio-reg","composite_hash":"comp-reg","keystroke":{"avgHoldTime":88.5,"stdHoldTime":12.3,"avgFlightTime":110.2,"stdFlightTime":15.7,"typingSpeed":4.2,"sampleCount":123,"commonDigraphs":[{"digraph":"alpha->digit","avgFlightTime":108.8,"stdFlightTime":11.1,"sampleCount":51}]}}}`
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/user/register", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.Header.Set("User-Agent", "Mozilla/5.0")
	ctx.Set("real_ip", "1.2.3.4")

	Register(ctx)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"success":true`)

	var inserted model.User
	require.NoError(t, model.DB.Where("username = ?", "reg_keystroke_user").First(&inserted).Error)
	require.Eventually(t, func() bool {
		profile := model.GetLatestKeystrokeProfile(inserted.Id)
		return profile != nil && profile.SampleCount == 123
	}, 2*time.Second, 50*time.Millisecond)

	profile := model.GetLatestKeystrokeProfile(inserted.Id)
	require.NotNil(t, profile)
	require.InDelta(t, 88.5, profile.AvgHoldTime, 0.0001)
	require.InDelta(t, 110.2, profile.AvgFlightTime, 0.0001)
	require.Equal(t, 123, profile.SampleCount)
	require.Contains(t, profile.DigraphData, "alpha-\\u003edigit")
}

func TestRegister_PersistsMouseProfile(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)
	require.NoError(t, model.DB.AutoMigrate(&model.User{}))
	model.LOG_DB = model.DB

	oldRegisterEnabled := common.RegisterEnabled
	oldPasswordRegisterEnabled := common.PasswordRegisterEnabled
	oldEmailVerificationEnabled := common.EmailVerificationEnabled
	oldFingerprintEnabled := common.FingerprintEnabled
	oldRedisEnabled := common.RedisEnabled
	oldGenerateDefaultToken := constant.GenerateDefaultToken
	t.Cleanup(func() {
		common.RegisterEnabled = oldRegisterEnabled
		common.PasswordRegisterEnabled = oldPasswordRegisterEnabled
		common.EmailVerificationEnabled = oldEmailVerificationEnabled
		common.FingerprintEnabled = oldFingerprintEnabled
		common.RedisEnabled = oldRedisEnabled
		constant.GenerateDefaultToken = oldGenerateDefaultToken
	})

	common.RegisterEnabled = true
	common.PasswordRegisterEnabled = true
	common.EmailVerificationEnabled = false
	common.FingerprintEnabled = true
	common.RedisEnabled = false
	constant.GenerateDefaultToken = false

	body := `{"username":"reg_mouse_user","password":"12345678","fingerprint":{"local_device_id":"lid-reg-mouse","canvas_hash":"canvas-reg-mouse","webgl_hash":"webgl-reg-mouse","audio_hash":"audio-reg-mouse","composite_hash":"comp-reg-mouse","dns_resolver_ip":"","dns_probe_id":"probe-1","session_id":"session-1","session_start_at":1712380000,"session_end_at":1712380000,"mouse":{"avgSpeed":1380.5,"maxSpeed":2100.2,"speedStd":180.4,"avgAcceleration":320.6,"accStd":75.1,"directionChangeRate":0.21,"avgScrollDelta":96.5,"scrollDeltaMode":0,"clickDistribution":{"topLeft":0.25,"topRight":0.25,"bottomLeft":0.25,"bottomRight":0.25},"sampleCount":64}}}`
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/user/register", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.Header.Set("User-Agent", "Mozilla/5.0")
	ctx.Set("real_ip", "1.2.3.4")

	Register(ctx)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"success":true`)

	var inserted model.User
	require.NoError(t, model.DB.Where("username = ?", "reg_mouse_user").First(&inserted).Error)
	require.Eventually(t, func() bool {
		profile := model.GetLatestMouseProfile(inserted.Id)
		return profile != nil && profile.SampleCount == 64
	}, 2*time.Second, 50*time.Millisecond)

	profile := model.GetLatestMouseProfile(inserted.Id)
	require.NotNil(t, profile)
	require.InDelta(t, 1380.5, profile.AvgSpeed, 0.0001)
	require.InDelta(t, 0.21, profile.DirectionChangeRate, 0.0001)
	require.Equal(t, 64, profile.SampleCount)
	require.Contains(t, profile.ClickDistribution, "topLeft")
}

func TestRegister_InvalidMousePayloadDoesNotPersistProfile(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)
	require.NoError(t, model.DB.AutoMigrate(&model.User{}))
	model.LOG_DB = model.DB

	oldRegisterEnabled := common.RegisterEnabled
	oldPasswordRegisterEnabled := common.PasswordRegisterEnabled
	oldEmailVerificationEnabled := common.EmailVerificationEnabled
	oldFingerprintEnabled := common.FingerprintEnabled
	oldRedisEnabled := common.RedisEnabled
	oldGenerateDefaultToken := constant.GenerateDefaultToken
	t.Cleanup(func() {
		common.RegisterEnabled = oldRegisterEnabled
		common.PasswordRegisterEnabled = oldPasswordRegisterEnabled
		common.EmailVerificationEnabled = oldEmailVerificationEnabled
		common.FingerprintEnabled = oldFingerprintEnabled
		common.RedisEnabled = oldRedisEnabled
		constant.GenerateDefaultToken = oldGenerateDefaultToken
	})

	common.RegisterEnabled = true
	common.PasswordRegisterEnabled = true
	common.EmailVerificationEnabled = false
	common.FingerprintEnabled = true
	common.RedisEnabled = false
	constant.GenerateDefaultToken = false

	body := `{"username":"reg_invalid_mouse_u","password":"12345678","fingerprint":{"local_device_id":"lid-reg-mouse","canvas_hash":"canvas-reg-mouse","webgl_hash":"webgl-reg-mouse","audio_hash":"audio-reg-mouse","composite_hash":"comp-reg-mouse","mouse":{"avgSpeed":"fast","maxSpeed":2100.2,"speedStd":180.4,"avgAcceleration":320.6,"accStd":75.1,"directionChangeRate":0.21,"avgScrollDelta":96.5,"scrollDeltaMode":0,"clickDistribution":{"topLeft":0.25,"topRight":0.25,"bottomLeft":0.25,"bottomRight":0.25},"sampleCount":64}}}`
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/user/register", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.Header.Set("User-Agent", "Mozilla/5.0")
	ctx.Set("real_ip", "1.2.3.4")

	Register(ctx)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"success":false`)

	var inserted model.User
	require.Error(t, model.DB.Where("username = ?", "reg_invalid_mouse_u").First(&inserted).Error)
}

func TestRegister_DoesNotPersistKeystrokeProfileWhenFingerprintDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)
	require.NoError(t, model.DB.AutoMigrate(&model.User{}))
	model.LOG_DB = model.DB

	oldRegisterEnabled := common.RegisterEnabled
	oldPasswordRegisterEnabled := common.PasswordRegisterEnabled
	oldEmailVerificationEnabled := common.EmailVerificationEnabled
	oldFingerprintEnabled := common.FingerprintEnabled
	oldRedisEnabled := common.RedisEnabled
	oldGenerateDefaultToken := constant.GenerateDefaultToken
	t.Cleanup(func() {
		common.RegisterEnabled = oldRegisterEnabled
		common.PasswordRegisterEnabled = oldPasswordRegisterEnabled
		common.EmailVerificationEnabled = oldEmailVerificationEnabled
		common.FingerprintEnabled = oldFingerprintEnabled
		common.RedisEnabled = oldRedisEnabled
		constant.GenerateDefaultToken = oldGenerateDefaultToken
	})

	common.RegisterEnabled = true
	common.PasswordRegisterEnabled = true
	common.EmailVerificationEnabled = false
	common.FingerprintEnabled = false
	common.RedisEnabled = false
	constant.GenerateDefaultToken = false

	body := `{"username":"reg_key_disabled","password":"12345678","fingerprint":{"keystroke":{"avgHoldTime":80,"stdHoldTime":10,"avgFlightTime":100,"stdFlightTime":12,"typingSpeed":4.0,"sampleCount":111,"commonDigraphs":[{"digraph":"alpha->digit","avgFlightTime":100,"stdFlightTime":10,"sampleCount":50}]}}}`
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/user/register", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.Header.Set("User-Agent", "Mozilla/5.0")
	ctx.Set("real_ip", "1.2.3.4")

	Register(ctx)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"success":true`)

	var inserted model.User
	require.NoError(t, model.DB.Where("username = ?", "reg_key_disabled").First(&inserted).Error)
	require.Eventually(t, func() bool {
		return model.GetLatestKeystrokeProfile(inserted.Id) == nil
	}, time.Second, 20*time.Millisecond)
}

func TestRegister_InvalidKeystrokePayloadDoesNotPersistProfile(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)
	require.NoError(t, model.DB.AutoMigrate(&model.User{}))
	model.LOG_DB = model.DB

	oldRegisterEnabled := common.RegisterEnabled
	oldPasswordRegisterEnabled := common.PasswordRegisterEnabled
	oldEmailVerificationEnabled := common.EmailVerificationEnabled
	oldFingerprintEnabled := common.FingerprintEnabled
	oldRedisEnabled := common.RedisEnabled
	oldGenerateDefaultToken := constant.GenerateDefaultToken
	t.Cleanup(func() {
		common.RegisterEnabled = oldRegisterEnabled
		common.PasswordRegisterEnabled = oldPasswordRegisterEnabled
		common.EmailVerificationEnabled = oldEmailVerificationEnabled
		common.FingerprintEnabled = oldFingerprintEnabled
		common.RedisEnabled = oldRedisEnabled
		constant.GenerateDefaultToken = oldGenerateDefaultToken
	})

	common.RegisterEnabled = true
	common.PasswordRegisterEnabled = true
	common.EmailVerificationEnabled = false
	common.FingerprintEnabled = true
	common.RedisEnabled = false
	constant.GenerateDefaultToken = false

	body := `{"username":"reg_invalid_key_u","password":"12345678","fingerprint":{"local_device_id":"lid-reg","canvas_hash":"canvas-reg","webgl_hash":"webgl-reg","audio_hash":"audio-reg","composite_hash":"comp-reg","keystroke":{"avgHoldTime":88.5,"stdHoldTime":12.3,"avgFlightTime":110.2,"stdFlightTime":15.7,"typingSpeed":4.2,"sampleCount":123,"commonDigraphs":[{"digraph":"alpha->digit","avgFlightTime":"108.8","stdFlightTime":11.1,"sampleCount":51}]}}}`
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/user/register", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.Header.Set("User-Agent", "Mozilla/5.0")
	ctx.Set("real_ip", "1.2.3.4")

	Register(ctx)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"success":false`)

	var inserted model.User
	require.Error(t, model.DB.Where("username = ?", "reg_invalid_key_u").First(&inserted).Error)
}

func TestRegister_BehaviorDisabledSkipsValidationAndPersistence(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)
	require.NoError(t, model.DB.AutoMigrate(&model.User{}))
	model.LOG_DB = model.DB

	oldRegisterEnabled := common.RegisterEnabled
	oldPasswordRegisterEnabled := common.PasswordRegisterEnabled
	oldEmailVerificationEnabled := common.EmailVerificationEnabled
	oldFingerprintEnabled := common.FingerprintEnabled
	oldBehaviorEnabled := common.FingerprintEnableBehaviorAnalysis
	oldRedisEnabled := common.RedisEnabled
	oldGenerateDefaultToken := constant.GenerateDefaultToken
	t.Cleanup(func() {
		common.RegisterEnabled = oldRegisterEnabled
		common.PasswordRegisterEnabled = oldPasswordRegisterEnabled
		common.EmailVerificationEnabled = oldEmailVerificationEnabled
		common.FingerprintEnabled = oldFingerprintEnabled
		common.FingerprintEnableBehaviorAnalysis = oldBehaviorEnabled
		common.RedisEnabled = oldRedisEnabled
		constant.GenerateDefaultToken = oldGenerateDefaultToken
	})

	common.RegisterEnabled = true
	common.PasswordRegisterEnabled = true
	common.EmailVerificationEnabled = false
	common.FingerprintEnabled = true
	common.FingerprintEnableBehaviorAnalysis = false
	common.RedisEnabled = false
	constant.GenerateDefaultToken = false

	body := `{"username":"regboff","password":"12345678","fingerprint":{"local_device_id":"lid-reg","canvas_hash":"canvas-reg","webgl_hash":"webgl-reg","audio_hash":"audio-reg","composite_hash":"comp-reg","mouse":{"avgSpeed":1380.5,"maxSpeed":2100.2,"speedStd":180.4,"avgAcceleration":320.6,"accStd":75.1,"directionChangeRate":1.21,"avgScrollDelta":96.5,"scrollDeltaMode":0,"clickDistribution":{"topLeft":0.25,"topRight":0.25,"bottomLeft":0.25,"bottomRight":0.25},"sampleCount":64}}}`
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/user/register", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.Header.Set("User-Agent", "Mozilla/5.0")
	ctx.Set("real_ip", "1.2.3.4")

	Register(ctx)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"success":true`)

	var inserted model.User
	require.NoError(t, model.DB.Where("username = ?", "regboff").First(&inserted).Error)
	require.Eventually(t, func() bool {
		return model.GetLatestKeystrokeProfile(inserted.Id) == nil && model.GetLatestMouseProfile(inserted.Id) == nil
	}, time.Second, 20*time.Millisecond)
}

func TestLogin_Require2FA_DoesNotPersistKeystrokeProfile(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)
	require.NoError(t, model.DB.AutoMigrate(&model.User{}, &model.TwoFA{}))
	model.LOG_DB = model.DB
	require.NoError(t, i18n.Init())

	passwordHash, err := common.Password2Hash("12345678")
	require.NoError(t, err)
	user := &model.User{
		Username:    "login2fa_user",
		Password:    passwordHash,
		DisplayName: "login2fa_user",
		Role:        common.RoleCommonUser,
		Status:      common.UserStatusEnabled,
		Group:       "default",
	}
	require.NoError(t, model.DB.Create(user).Error)
	require.NoError(t, model.DB.Create(&model.TwoFA{UserId: user.Id, Secret: "secret", IsEnabled: true}).Error)

	oldPasswordLoginEnabled := common.PasswordLoginEnabled
	t.Cleanup(func() {
		common.PasswordLoginEnabled = oldPasswordLoginEnabled
	})
	common.PasswordLoginEnabled = true

	router := gin.New()
	router.Use(sessions.Sessions("test-session", cookie.NewStore([]byte("test-secret"))))
	router.POST("/api/user/login", Login)

	loginBody := `{"username":"login2fa_user","password":"12345678"}`
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/user/login", strings.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, req)

	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"success":true`)
	require.Contains(t, recorder.Body.String(), `"require_2fa":true`)
	require.Nil(t, model.GetLatestKeystrokeProfile(user.Id))
}
