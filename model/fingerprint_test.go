package model

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func initFingerprintModelTestDB(t *testing.T) {
	t.Helper()
	oldDB := DB
	dsn := fmt.Sprintf("file:fingerprint_model_test_%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(8)
	require.NoError(t, db.AutoMigrate(&UserDeviceProfile{}, &Fingerprint{}, &IPUAHistory{}))
	DB = db
	t.Cleanup(func() {
		DB = oldDB
		_ = sqlDB.Close()
	})
}

func TestUpsertDeviceProfile_UpdatesFingerprintFieldsForExistingRecord(t *testing.T) {
	initFingerprintModelTestDB(t)

	first := &UserDeviceProfile{
		UserID:                11,
		DeviceKey:             "lid:device-11",
		CanvasHash:            "canvas-old",
		WebGLHash:             "webgl-old",
		WebGLDeepHash:         "webgl-deep-old",
		ClientRectsHash:       "rects-old",
		MediaDevicesHash:      "media-old",
		MediaDeviceCount:      "1-0-0",
		MediaDeviceGroupHash:  "media-group-old",
		MediaDeviceTotal:      1,
		SpeechVoicesHash:      "speech-old",
		SpeechVoiceCount:      2,
		SpeechLocalVoiceCount: 1,
		AudioHash:             "audio-old",
		FontsHash:             "fonts-old",
		LocalDeviceID:         "device-11",
		CompositeHash:         "composite-old",
		HTTPHeaderHash:        "hdr-old",
		UABrowser:             "Chrome",
		UAOS:                  "Windows",
		UADeviceType:          "desktop",
		LastSeenIP:            "1.1.1.1",
	}
	require.NoError(t, UpsertDeviceProfile(first))

	second := &UserDeviceProfile{
		UserID:                11,
		DeviceKey:             "lid:device-11",
		CanvasHash:            "canvas-new",
		WebGLHash:             "webgl-new",
		WebGLDeepHash:         "webgl-deep-new",
		ClientRectsHash:       "rects-new",
		MediaDevicesHash:      "media-new",
		MediaDeviceCount:      "2-1-1",
		MediaDeviceGroupHash:  "media-group-new",
		MediaDeviceTotal:      4,
		SpeechVoicesHash:      "speech-new",
		SpeechVoiceCount:      9,
		SpeechLocalVoiceCount: 3,
		AudioHash:             "audio-new",
		FontsHash:             "fonts-new",
		LocalDeviceID:         "device-11",
		CompositeHash:         "composite-new",
		HTTPHeaderHash:        "hdr-new",
		UABrowser:             "Edge",
		UAOS:                  "Windows",
		UADeviceType:          "desktop",
		LastSeenIP:            "2.2.2.2",
	}
	require.NoError(t, UpsertDeviceProfile(second))

	profiles := GetDeviceProfiles(11)
	require.Len(t, profiles, 1)
	profile := profiles[0]

	require.Equal(t, "canvas-new", profile.CanvasHash)
	require.Equal(t, "webgl-new", profile.WebGLHash)
	require.Equal(t, "webgl-deep-new", profile.WebGLDeepHash)
	require.Equal(t, "rects-new", profile.ClientRectsHash)
	require.Equal(t, "media-new", profile.MediaDevicesHash)
	require.Equal(t, "2-1-1", profile.MediaDeviceCount)
	require.Equal(t, "media-group-new", profile.MediaDeviceGroupHash)
	require.Equal(t, 4, profile.MediaDeviceTotal)
	require.Equal(t, "speech-new", profile.SpeechVoicesHash)
	require.Equal(t, 9, profile.SpeechVoiceCount)
	require.Equal(t, 3, profile.SpeechLocalVoiceCount)
	require.Equal(t, "audio-new", profile.AudioHash)
	require.Equal(t, "fonts-new", profile.FontsHash)
	require.Equal(t, "composite-new", profile.CompositeHash)
	require.Equal(t, "hdr-new", profile.HTTPHeaderHash)
	require.Equal(t, "Edge", profile.UABrowser)
	require.Equal(t, "2.2.2.2", profile.LastSeenIP)
	require.Equal(t, 2, profile.SeenCount)
}

func TestUpsertDeviceProfile_ReturnsNilWhenProfileMissing(t *testing.T) {
	initFingerprintModelTestDB(t)
	require.NoError(t, UpsertDeviceProfile(nil))
}

func TestUpsertDeviceProfile_ConcurrentSameDeviceDoesNotFail(t *testing.T) {
	initFingerprintModelTestDB(t)

	const workers = 8
	var wg sync.WaitGroup
	errCh := make(chan error, workers)

	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errCh <- UpsertDeviceProfile(&UserDeviceProfile{
				UserID:                23,
				DeviceKey:             "lid:device-23",
				CanvasHash:            fmt.Sprintf("canvas-%d", i),
				WebGLHash:             fmt.Sprintf("webgl-%d", i),
				WebGLDeepHash:         fmt.Sprintf("webgl-deep-%d", i),
				ClientRectsHash:       fmt.Sprintf("rects-%d", i),
				MediaDevicesHash:      fmt.Sprintf("media-%d", i),
				MediaDeviceCount:      "2-1-1",
				MediaDeviceGroupHash:  fmt.Sprintf("media-group-%d", i),
				MediaDeviceTotal:      4,
				SpeechVoicesHash:      fmt.Sprintf("speech-%d", i),
				SpeechVoiceCount:      9,
				SpeechLocalVoiceCount: 3,
				AudioHash:             fmt.Sprintf("audio-%d", i),
				FontsHash:             fmt.Sprintf("fonts-%d", i),
				LocalDeviceID:         "device-23",
				CompositeHash:         fmt.Sprintf("composite-%d", i),
				HTTPHeaderHash:        fmt.Sprintf("hdr-%d", i),
				UABrowser:             "Chrome",
				UAOS:                  "Windows",
				UADeviceType:          "desktop",
				LastSeenIP:            fmt.Sprintf("10.0.0.%d", i+1),
			})
		}(i)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}

	profiles := GetDeviceProfiles(23)
	require.Len(t, profiles, 1)
	require.Equal(t, workers, profiles[0].SeenCount)
}

func TestFingerprintInsert_NormalizesStorageHeavyFields(t *testing.T) {
	initFingerprintModelTestDB(t)
	t.Setenv("FINGERPRINT_MAX_USER_AGENT_LENGTH", "5")
	t.Setenv("FINGERPRINT_MAX_FONTS_LIST_LENGTH", "4")
	t.Setenv("FINGERPRINT_MAX_WEBRTC_IPS_LENGTH", "10")
	t.Setenv("FINGERPRINT_MAX_PAGE_URL_LENGTH", "6")

	fp := &Fingerprint{
		UserID:          7,
		IPAddress:       "1.2.3.4",
		CompositeHash:   "cmp",
		UserAgent:       "  abcdef  ",
		FontsList:       "  xyzuvw  ",
		WebRTCLocalIPs:  " [\"10.0.0.1\"] ",
		WebRTCPublicIPs: " [\"8.8.8.8\"] ",
		PageURL:         "  https://example.com/path  ",
	}
	require.NoError(t, fp.Insert())

	var got Fingerprint
	require.NoError(t, DB.Where("user_id = ?", 7).First(&got).Error)
	require.Equal(t, "abcde", got.UserAgent)
	require.Equal(t, "xyzu", got.FontsList)
	require.Equal(t, "[]", got.WebRTCLocalIPs)
	require.Equal(t, "[]", got.WebRTCPublicIPs)
	require.Equal(t, "https:", got.PageURL)
}

func TestNormalizeWebRTCIPList_EmptyInputKeepsEmpty(t *testing.T) {
	require.Equal(t, "", normalizeWebRTCIPList("", 256))
	require.Equal(t, "", normalizeWebRTCIPList("   ", 256))
}

func TestFingerprintInsert_CanonicalizesWebRTCJSON(t *testing.T) {
	initFingerprintModelTestDB(t)
	t.Setenv("FINGERPRINT_MAX_WEBRTC_IPS_LENGTH", "256")

	fp := &Fingerprint{
		UserID:          8,
		IPAddress:       "2.2.2.2",
		CompositeHash:   "cmp-2",
		WebRTCLocalIPs:  " [\"192.168.1.9\"] ",
		WebRTCPublicIPs: " [\"8.8.8.8\"] ",
	}
	require.NoError(t, fp.Insert())

	var got Fingerprint
	require.NoError(t, DB.Where("user_id = ?", 8).First(&got).Error)
	require.Equal(t, `["192.168.1.9"]`, got.WebRTCLocalIPs)
	require.Equal(t, `["8.8.8.8"]`, got.WebRTCPublicIPs)
}

func TestFingerprintInsert_InvalidWebRTCBecomesEmptyArray(t *testing.T) {
	initFingerprintModelTestDB(t)
	t.Setenv("FINGERPRINT_MAX_WEBRTC_IPS_LENGTH", "256")

	fp := &Fingerprint{
		UserID:          9,
		IPAddress:       "3.3.3.3",
		CompositeHash:   "cmp-3",
		WebRTCLocalIPs:  "not-json",
		WebRTCPublicIPs: "1.1.1.1,2.2.2.2",
	}
	require.NoError(t, fp.Insert())

	var got Fingerprint
	require.NoError(t, DB.Where("user_id = ?", 9).First(&got).Error)
	require.Equal(t, "[]", got.WebRTCLocalIPs)
	require.Equal(t, "[]", got.WebRTCPublicIPs)
}

func TestFingerprintInsert_WebRTCOverLimitBecomesEmptyArray(t *testing.T) {
	initFingerprintModelTestDB(t)
	t.Setenv("FINGERPRINT_MAX_WEBRTC_IPS_LENGTH", "8")

	fp := &Fingerprint{
		UserID:          10,
		IPAddress:       "4.4.4.4",
		CompositeHash:   "cmp-4",
		WebRTCLocalIPs:  `["192.168.1.10"]`,
		WebRTCPublicIPs: `["203.0.113.99"]`,
	}
	require.NoError(t, fp.Insert())

	var got Fingerprint
	require.NoError(t, DB.Where("user_id = ?", 10).First(&got).Error)
	require.Equal(t, "[]", got.WebRTCLocalIPs)
	require.Equal(t, "[]", got.WebRTCPublicIPs)
}

func TestGetActiveUserIDsWithFingerprints_FiltersByWindowAndLimit(t *testing.T) {
	initFingerprintModelTestDB(t)

	now := time.Now().UTC()
	require.NoError(t, DB.Create(&Fingerprint{UserID: 8401, CompositeHash: "u8401", CreatedAt: now.Add(-20 * time.Minute)}).Error)
	require.NoError(t, DB.Create(&Fingerprint{UserID: 8402, CompositeHash: "u8402", CreatedAt: now.Add(-10 * time.Minute)}).Error)
	require.NoError(t, DB.Create(&Fingerprint{UserID: 8403, CompositeHash: "u8403", CreatedAt: now.Add(-30 * time.Hour)}).Error)
	require.NoError(t, DB.Create(&Fingerprint{UserID: 8404, CompositeHash: "u8404", CreatedAt: now.Add(-5 * time.Minute)}).Error)

	got := GetActiveUserIDsWithFingerprints(24, 2)
	require.Equal(t, []int{8404, 8402}, got)
}

func TestGetActiveUserIDsWithFingerprints_DefaultWindowWhenNonPositive(t *testing.T) {
	initFingerprintModelTestDB(t)

	now := time.Now().UTC()
	require.NoError(t, DB.Create(&Fingerprint{UserID: 8501, CompositeHash: "u8501", CreatedAt: now.Add(-6 * 24 * time.Hour)}).Error)
	require.NoError(t, DB.Create(&Fingerprint{UserID: 8502, CompositeHash: "u8502", CreatedAt: now.Add(-9 * 24 * time.Hour)}).Error)

	got := GetActiveUserIDsWithFingerprints(0, 10)
	require.Equal(t, []int{8501}, got)
}

func TestGetActiveUserIDsWithFingerprints_ReturnsNilWhenMaxUsersNonPositive(t *testing.T) {
	initFingerprintModelTestDB(t)
	require.Nil(t, GetActiveUserIDsWithFingerprints(24, 0))
	require.Nil(t, GetActiveUserIDsWithFingerprints(24, -1))
}

func TestCountUniqueUAs_SQLiteAndPostgresExpression(t *testing.T) {
	initFingerprintModelTestDB(t)

	require.NoError(t, DB.Create(&IPUAHistory{UserID: 9101, IPAddress: "1.1.1.1", UABrowser: "Chrome", UAOS: "Windows"}).Error)
	require.NoError(t, DB.Create(&IPUAHistory{UserID: 9101, IPAddress: "2.2.2.2", UABrowser: "Chrome", UAOS: "Windows"}).Error)
	require.NoError(t, DB.Create(&IPUAHistory{UserID: 9101, IPAddress: "3.3.3.3", UABrowser: "Safari", UAOS: "macOS"}).Error)

	oldSQLite := common.UsingSQLite
	oldMySQL := common.UsingMySQL
	oldPostgreSQL := common.UsingPostgreSQL
	t.Cleanup(func() {
		common.UsingSQLite = oldSQLite
		common.UsingMySQL = oldMySQL
		common.UsingPostgreSQL = oldPostgreSQL
	})

	common.UsingSQLite = true
	common.UsingMySQL = false
	common.UsingPostgreSQL = false
	require.Equal(t, 2, CountUniqueUAs(9101))
	require.Equal(t, "COUNT(DISTINCT (ua_browser || '|' || ua_os))", uniqueUACountExpression())

	common.UsingSQLite = false
	common.UsingMySQL = false
	common.UsingPostgreSQL = true
	require.Equal(t, 2, CountUniqueUAs(9101))
	require.Equal(t, "COUNT(DISTINCT (ua_browser || '|' || ua_os))", uniqueUACountExpression())

	common.UsingSQLite = false
	common.UsingMySQL = true
	common.UsingPostgreSQL = false
	require.Equal(t, "COUNT(DISTINCT CONCAT(ua_browser, '|', ua_os))", uniqueUACountExpression())
}
