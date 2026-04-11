package model

import (
	"fmt"
	"sync"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func initFingerprintModelTestDB(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:fingerprint_model_test?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(8)
	require.NoError(t, db.AutoMigrate(&UserDeviceProfile{}))
	DB = db
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

	for i := 0; i < workers; i++ {
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
