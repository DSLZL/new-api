package service

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFullLinkScan_RefreshesTemporalProfilesBeforeScan_WhenPrecomputeReadEnabled(t *testing.T) {
	initTestDB(t)
	require.NoError(t, model.DB.AutoMigrate(&model.UserDeviceProfile{}, &model.AccountLink{}, &model.UserRiskScore{}, &model.LinkWhitelist{}))
	require.NoError(t, model.EnsureAccountLinkUniqueIndex(model.DB))

	base := time.Date(2026, 4, 4, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 6; i++ {
		require.NoError(t, model.DB.Create(&model.Fingerprint{
			UserID:        8101,
			CompositeHash: "u8101",
			CreatedAt:     base.Add(time.Duration(i*11) * time.Minute),
		}).Error)
		require.NoError(t, model.DB.Create(&model.Fingerprint{
			UserID:        8102,
			CompositeHash: "u8102",
			CreatedAt:     base.Add(time.Duration(i*11+2) * time.Minute),
		}).Error)
	}

	assert.Nil(t, model.GetLatestTemporalProfile(8101))
	assert.Nil(t, model.GetLatestTemporalProfile(8102))

	oldEnabled := common.FingerprintEnabled
	oldTemporal := common.FingerprintEnableTemporalAnalysis
	oldPrecomputeWrite := common.FingerprintEnableTemporalPrecomputeWrite
	oldPrecomputeRead := common.FingerprintEnableTemporalPrecomputeRead
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.FingerprintEnableTemporalAnalysis = oldTemporal
		common.FingerprintEnableTemporalPrecomputeWrite = oldPrecomputeWrite
		common.FingerprintEnableTemporalPrecomputeRead = oldPrecomputeRead
	})

	common.FingerprintEnabled = true
	common.FingerprintEnableTemporalAnalysis = true
	common.FingerprintEnableTemporalPrecomputeWrite = true
	common.FingerprintEnableTemporalPrecomputeRead = true

	FullLinkScan()

	profileA := model.GetLatestTemporalProfile(8101)
	profileB := model.GetLatestTemporalProfile(8102)
	require.NotNil(t, profileA)
	require.NotNil(t, profileB)
	assert.GreaterOrEqual(t, profileA.SampleCount, 1)
	assert.GreaterOrEqual(t, profileB.SampleCount, 1)
}

func TestFullLinkScan_DoesNotRefreshTemporalProfiles_WhenPrecomputeReadDisabled(t *testing.T) {
	initTestDB(t)
	require.NoError(t, model.DB.AutoMigrate(&model.UserDeviceProfile{}, &model.AccountLink{}, &model.UserRiskScore{}, &model.LinkWhitelist{}))
	require.NoError(t, model.EnsureAccountLinkUniqueIndex(model.DB))

	base := time.Date(2026, 4, 4, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 6; i++ {
		require.NoError(t, model.DB.Create(&model.Fingerprint{
			UserID:        8301,
			CompositeHash: "u8301",
			CreatedAt:     base.Add(time.Duration(i*7) * time.Minute),
		}).Error)
	}

	assert.Nil(t, model.GetLatestTemporalProfile(8301))

	oldEnabled := common.FingerprintEnabled
	oldTemporal := common.FingerprintEnableTemporalAnalysis
	oldPrecomputeWrite := common.FingerprintEnableTemporalPrecomputeWrite
	oldPrecomputeRead := common.FingerprintEnableTemporalPrecomputeRead
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.FingerprintEnableTemporalAnalysis = oldTemporal
		common.FingerprintEnableTemporalPrecomputeWrite = oldPrecomputeWrite
		common.FingerprintEnableTemporalPrecomputeRead = oldPrecomputeRead
	})

	common.FingerprintEnabled = true
	common.FingerprintEnableTemporalAnalysis = true
	common.FingerprintEnableTemporalPrecomputeWrite = true
	common.FingerprintEnableTemporalPrecomputeRead = false

	FullLinkScan()

	assert.Nil(t, model.GetLatestTemporalProfile(8301))
}

func TestRefreshTemporalProfilesCron_SerializesConcurrentRuns(t *testing.T) {
	initTestDB(t)

	base := time.Date(2026, 4, 4, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 8; i++ {
		require.NoError(t, model.DB.Create(&model.Fingerprint{
			UserID:        8201,
			CompositeHash: "u8201",
			CreatedAt:     base.Add(time.Duration(i*9) * time.Minute),
		}).Error)
	}

	oldEnabled := common.FingerprintEnabled
	oldTemporal := common.FingerprintEnableTemporalAnalysis
	oldPrecomputeWrite := common.FingerprintEnableTemporalPrecomputeWrite
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.FingerprintEnableTemporalAnalysis = oldTemporal
		common.FingerprintEnableTemporalPrecomputeWrite = oldPrecomputeWrite
	})

	common.FingerprintEnabled = true
	common.FingerprintEnableTemporalAnalysis = true
	common.FingerprintEnableTemporalPrecomputeWrite = true

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		RefreshTemporalProfilesCron(120)
	}()
	go func() {
		defer wg.Done()
		RefreshTemporalProfilesCron(120)
	}()
	wg.Wait()

	profile := model.GetLatestTemporalProfile(8201)
	require.NotNil(t, profile)
	assert.GreaterOrEqual(t, profile.SampleCount, 1)

	var sessionCount int64
	require.NoError(t, model.DB.Model(&model.UserSession{}).Where("user_id = ?", 8201).Count(&sessionCount).Error)
	assert.Greater(t, sessionCount, int64(0))
}

func TestFullLinkScan_CleansOldFingerprintsUsingRetentionDays(t *testing.T) {
	initTestDB(t)
	require.NoError(t, model.DB.AutoMigrate(&model.UserDeviceProfile{}, &model.AccountLink{}, &model.UserRiskScore{}, &model.LinkWhitelist{}))
	require.NoError(t, model.EnsureAccountLinkUniqueIndex(model.DB))

	now := time.Now().UTC()
	stale := &model.Fingerprint{UserID: 9901, CompositeHash: "stale", CreatedAt: now.Add(-10 * 24 * time.Hour)}
	fresh := &model.Fingerprint{UserID: 9901, CompositeHash: "fresh", CreatedAt: now.Add(-2 * 24 * time.Hour)}
	require.NoError(t, model.DB.Create(stale).Error)
	require.NoError(t, model.DB.Create(fresh).Error)

	oldEnabled := common.FingerprintEnabled
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
	})
	common.FingerprintEnabled = true

	oldRetention := os.Getenv("FINGERPRINT_RETENTION_DAYS")
	t.Cleanup(func() {
		if oldRetention == "" {
			_ = os.Unsetenv("FINGERPRINT_RETENTION_DAYS")
		} else {
			_ = os.Setenv("FINGERPRINT_RETENTION_DAYS", oldRetention)
		}
	})
	_ = os.Setenv("FINGERPRINT_RETENTION_DAYS", "5")

	FullLinkScan()

	assert.Nil(t, model.GetFingerprintByID(stale.ID))
	require.NotNil(t, model.GetFingerprintByID(fresh.ID))
}

func TestCleanOldBehaviorProfiles_UsesBehaviorRetentionDays(t *testing.T) {
	initTestDB(t)
	require.NoError(t, model.DB.AutoMigrate(&model.KeystrokeProfile{}, &model.MouseProfile{}))

	now := time.Now().UTC()
	require.NoError(t, model.DB.Create(&model.KeystrokeProfile{UserID: 9101, SampleCount: 11, UpdatedAt: now.Add(-10 * 24 * time.Hour)}).Error)
	require.NoError(t, model.DB.Create(&model.KeystrokeProfile{UserID: 9102, SampleCount: 11, UpdatedAt: now.Add(-2 * 24 * time.Hour)}).Error)
	require.NoError(t, model.DB.Create(&model.MouseProfile{UserID: 9201, SampleCount: 12, UpdatedAt: now.Add(-8 * 24 * time.Hour)}).Error)
	require.NoError(t, model.DB.Create(&model.MouseProfile{UserID: 9202, SampleCount: 12, UpdatedAt: now.Add(-1 * 24 * time.Hour)}).Error)

	oldBehaviorRetention := os.Getenv("FINGERPRINT_BEHAVIOR_RETENTION_DAYS")
	oldRetention := os.Getenv("FINGERPRINT_RETENTION_DAYS")
	t.Cleanup(func() {
		if oldBehaviorRetention == "" {
			_ = os.Unsetenv("FINGERPRINT_BEHAVIOR_RETENTION_DAYS")
		} else {
			_ = os.Setenv("FINGERPRINT_BEHAVIOR_RETENTION_DAYS", oldBehaviorRetention)
		}
		if oldRetention == "" {
			_ = os.Unsetenv("FINGERPRINT_RETENTION_DAYS")
		} else {
			_ = os.Setenv("FINGERPRINT_RETENTION_DAYS", oldRetention)
		}
	})
	_ = os.Setenv("FINGERPRINT_BEHAVIOR_RETENTION_DAYS", "5")
	_ = os.Setenv("FINGERPRINT_RETENTION_DAYS", "90")

	CleanOldBehaviorProfiles()

	assert.Nil(t, model.GetLatestKeystrokeProfile(9101))
	assert.NotNil(t, model.GetLatestKeystrokeProfile(9102))
	assert.Nil(t, model.GetLatestMouseProfile(9201))
	assert.NotNil(t, model.GetLatestMouseProfile(9202))
}

func TestUpsertIPUAHistory_ThrottlesAndTrimsByUserLimit(t *testing.T) {
	initTestDB(t)

	oldSampleRate := os.Getenv("FINGERPRINT_IPUA_WRITE_SAMPLE_RATE")
	oldMinInterval := os.Getenv("FINGERPRINT_IPUA_WRITE_MIN_INTERVAL_SECONDS")
	oldLimit := os.Getenv("FINGERPRINT_IPUA_USER_HISTORY_LIMIT")
	oldBatch := os.Getenv("FINGERPRINT_IPUA_USER_HISTORY_CLEANUP_BATCH")
	t.Cleanup(func() {
		if oldSampleRate == "" {
			_ = os.Unsetenv("FINGERPRINT_IPUA_WRITE_SAMPLE_RATE")
		} else {
			_ = os.Setenv("FINGERPRINT_IPUA_WRITE_SAMPLE_RATE", oldSampleRate)
		}
		if oldMinInterval == "" {
			_ = os.Unsetenv("FINGERPRINT_IPUA_WRITE_MIN_INTERVAL_SECONDS")
		} else {
			_ = os.Setenv("FINGERPRINT_IPUA_WRITE_MIN_INTERVAL_SECONDS", oldMinInterval)
		}
		if oldLimit == "" {
			_ = os.Unsetenv("FINGERPRINT_IPUA_USER_HISTORY_LIMIT")
		} else {
			_ = os.Setenv("FINGERPRINT_IPUA_USER_HISTORY_LIMIT", oldLimit)
		}
		if oldBatch == "" {
			_ = os.Unsetenv("FINGERPRINT_IPUA_USER_HISTORY_CLEANUP_BATCH")
		} else {
			_ = os.Setenv("FINGERPRINT_IPUA_USER_HISTORY_CLEANUP_BATCH", oldBatch)
		}
	})

	_ = os.Setenv("FINGERPRINT_IPUA_WRITE_SAMPLE_RATE", "100")
	_ = os.Setenv("FINGERPRINT_IPUA_WRITE_MIN_INTERVAL_SECONDS", "3600")
	_ = os.Setenv("FINGERPRINT_IPUA_USER_HISTORY_LIMIT", "2")
	_ = os.Setenv("FINGERPRINT_IPUA_USER_HISTORY_CLEANUP_BATCH", "1")

	require.NoError(t, model.UpsertIPUAHistory(&model.IPUAHistory{
		UserID:    9301,
		IPAddress: "10.0.0.1",
		UABrowser: "Chrome",
		UAOS:      "Windows",
		UserAgent: "ua-1",
		Endpoint:  "/api/test",
	}))
	require.NoError(t, model.UpsertIPUAHistory(&model.IPUAHistory{
		UserID:    9301,
		IPAddress: "10.0.0.1",
		UABrowser: "Chrome",
		UAOS:      "Windows",
		UserAgent: "ua-1",
		Endpoint:  "/api/test",
	}))

	var throttled model.IPUAHistory
	require.NoError(t, model.DB.Where("user_id = ? AND ip_address = ?", 9301, "10.0.0.1").First(&throttled).Error)
	assert.Equal(t, 1, throttled.RequestCount)

	_ = os.Setenv("FINGERPRINT_IPUA_WRITE_MIN_INTERVAL_SECONDS", "1")
	require.NoError(t, model.UpsertIPUAHistory(&model.IPUAHistory{UserID: 9302, IPAddress: "10.0.0.1", UABrowser: "Chrome", UAOS: "Windows", UserAgent: "ua-a", Endpoint: "/api/test"}))
	require.NoError(t, model.UpsertIPUAHistory(&model.IPUAHistory{UserID: 9302, IPAddress: "10.0.0.2", UABrowser: "Chrome", UAOS: "Windows", UserAgent: "ua-b", Endpoint: "/api/test"}))
	require.NoError(t, model.UpsertIPUAHistory(&model.IPUAHistory{UserID: 9302, IPAddress: "10.0.0.3", UABrowser: "Chrome", UAOS: "Windows", UserAgent: "ua-c", Endpoint: "/api/test"}))
	require.NoError(t, model.UpsertIPUAHistory(&model.IPUAHistory{UserID: 9302, IPAddress: "10.0.0.4", UABrowser: "Chrome", UAOS: "Windows", UserAgent: "ua-d", Endpoint: "/api/test"}))

	var trimmedCount int64
	require.NoError(t, model.DB.Model(&model.IPUAHistory{}).Where("user_id = ?", 9302).Count(&trimmedCount).Error)
	assert.Equal(t, int64(2), trimmedCount)
}

func TestFullLinkScan_CleansOldIPUAHistoryUsingRetentionDays(t *testing.T) {
	initTestDB(t)
	require.NoError(t, model.DB.AutoMigrate(&model.UserDeviceProfile{}, &model.AccountLink{}, &model.UserRiskScore{}, &model.LinkWhitelist{}))
	require.NoError(t, model.EnsureAccountLinkUniqueIndex(model.DB))

	now := time.Now().UTC()
	require.NoError(t, model.DB.Create(&model.IPUAHistory{UserID: 9401, IPAddress: "1.1.1.1", UABrowser: "Chrome", UAOS: "Windows", LastSeen: now.Add(-10 * 24 * time.Hour)}).Error)
	require.NoError(t, model.DB.Create(&model.IPUAHistory{UserID: 9402, IPAddress: "2.2.2.2", UABrowser: "Chrome", UAOS: "Windows", LastSeen: now.Add(-2 * 24 * time.Hour)}).Error)
	require.NoError(t, model.DB.Create(&model.UserSession{UserID: 9411, SessionID: "sess-old", Source: "fingerprint", StartedAt: now.Add(-10 * 24 * time.Hour), EndedAt: now.Add(-10 * 24 * time.Hour)}).Error)
	require.NoError(t, model.DB.Create(&model.UserSession{UserID: 9412, SessionID: "sess-fresh", Source: "fingerprint", StartedAt: now.Add(-2 * 24 * time.Hour), EndedAt: now.Add(-2 * 24 * time.Hour)}).Error)

	oldEnabled := common.FingerprintEnabled
	oldIPUARetention := os.Getenv("FINGERPRINT_IPUA_RETENTION_DAYS")
	oldSessionRetention := os.Getenv("FINGERPRINT_SESSION_RETENTION_DAYS")
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		if oldIPUARetention == "" {
			_ = os.Unsetenv("FINGERPRINT_IPUA_RETENTION_DAYS")
		} else {
			_ = os.Setenv("FINGERPRINT_IPUA_RETENTION_DAYS", oldIPUARetention)
		}
		if oldSessionRetention == "" {
			_ = os.Unsetenv("FINGERPRINT_SESSION_RETENTION_DAYS")
		} else {
			_ = os.Setenv("FINGERPRINT_SESSION_RETENTION_DAYS", oldSessionRetention)
		}
	})
	common.FingerprintEnabled = true
	_ = os.Setenv("FINGERPRINT_IPUA_RETENTION_DAYS", "5")
	_ = os.Setenv("FINGERPRINT_SESSION_RETENTION_DAYS", "5")

	FullLinkScan()

	var staleCount int64
	var freshCount int64
	require.NoError(t, model.DB.Model(&model.IPUAHistory{}).Where("user_id = ?", 9401).Count(&staleCount).Error)
	require.NoError(t, model.DB.Model(&model.IPUAHistory{}).Where("user_id = ?", 9402).Count(&freshCount).Error)
	assert.Equal(t, int64(0), staleCount)
	assert.Equal(t, int64(1), freshCount)

	var staleSessionCount int64
	var freshSessionCount int64
	require.NoError(t, model.DB.Model(&model.UserSession{}).Where("user_id = ?", 9411).Count(&staleSessionCount).Error)
	require.NoError(t, model.DB.Model(&model.UserSession{}).Where("user_id = ?", 9412).Count(&freshSessionCount).Error)
	assert.Equal(t, int64(0), staleSessionCount)
	assert.Equal(t, int64(1), freshSessionCount)
}

func TestCheckAndUpdateASNData_NoOpAndSafe(t *testing.T) {
	oldASNEnabled := common.FingerprintEnableASNAnalysis
	oldPath := os.Getenv("FINGERPRINT_ASN_DB_PATH")
	t.Cleanup(func() {
		common.FingerprintEnableASNAnalysis = oldASNEnabled
		if oldPath == "" {
			_ = os.Unsetenv("FINGERPRINT_ASN_DB_PATH")
		} else {
			_ = os.Setenv("FINGERPRINT_ASN_DB_PATH", oldPath)
		}
	})

	common.FingerprintEnableASNAnalysis = false
	_ = os.Setenv("FINGERPRINT_ASN_DB_PATH", "")
	require.NotPanics(t, CheckAndUpdateASNData)

	common.FingerprintEnableASNAnalysis = true
	_ = os.Setenv("FINGERPRINT_ASN_DB_PATH", "")
	require.NotPanics(t, CheckAndUpdateASNData)

	_ = os.Setenv("FINGERPRINT_ASN_DB_PATH", "C:/this/path/does/not/exist.mmdb")
	require.NotPanics(t, CheckAndUpdateASNData)
}

func TestFullLinkScan_RecalculatesExistingLinkConfidenceDownward(t *testing.T) {
	initTestDB(t)
	require.NoError(t, model.DB.AutoMigrate(&model.UserDeviceProfile{}, &model.AccountLink{}, &model.UserRiskScore{}, &model.LinkWhitelist{}))
	require.NoError(t, model.EnsureAccountLinkUniqueIndex(model.DB))

	reviewedAt := time.Date(2026, 4, 8, 10, 0, 0, 0, time.UTC)
	require.NoError(t, model.DB.Create(&model.AccountLink{
		UserIDA:         1001,
		UserIDB:         1002,
		Confidence:      0.99,
		MatchDimensions: 8,
		TotalDimensions: 8,
		MatchDetails:    `[{"dimension":"legacy_high","score":0.99}]`,
		Status:          model.AccountLinkStatusConfirmed,
		ReviewedBy:      77,
		ReviewedAt:      &reviewedAt,
		ReviewNote:      "manual confirmed",
	}).Error)

	fpA := &model.Fingerprint{
		UserID:        1001,
		CanvasHash:    "full-scan-a",
		WebGLHash:     "full-webgl-a",
		CompositeHash: "full-comp-a",
		IPAddress:     "9.8.7.6",
		UABrowser:     "Chrome",
		UABrowserVer:  "120",
		UAOS:          "Windows",
		UAOSVer:       "11",
		UADeviceType:  "desktop",
	}
	fpB := &model.Fingerprint{
		UserID:        1002,
		CanvasHash:    "full-scan-b",
		WebGLHash:     "full-webgl-b",
		CompositeHash: "full-comp-b",
		IPAddress:     "9.8.7.6",
		UABrowser:     "Chrome",
		UABrowserVer:  "120",
		UAOS:          "Windows",
		UAOSVer:       "11",
		UADeviceType:  "desktop",
	}
	require.NoError(t, model.DB.Create(fpA).Error)
	require.NoError(t, model.DB.Create(fpB).Error)

	expectedConf, _, expectedMatch, expectedTotal := CompareFingerprints(fpA, fpB, 1001, 1002)
	require.Less(t, expectedConf, 0.99)

	oldEnabled := common.FingerprintEnabled
	oldTemporalRead := common.FingerprintEnableTemporalPrecomputeRead
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.FingerprintEnableTemporalPrecomputeRead = oldTemporalRead
	})
	common.FingerprintEnabled = true
	common.FingerprintEnableTemporalPrecomputeRead = false

	FullLinkScan()

	link := model.FindExistingLink(1001, 1002)
	require.NotNil(t, link)
	assert.InDelta(t, expectedConf, link.Confidence, 0.0001)
	assert.Equal(t, expectedMatch, link.MatchDimensions)
	assert.Equal(t, expectedTotal, link.TotalDimensions)
	assert.Equal(t, model.AccountLinkStatusConfirmed, link.Status)
	assert.Equal(t, 77, link.ReviewedBy)
	require.NotNil(t, link.ReviewedAt)
	assert.Equal(t, "manual confirmed", link.ReviewNote)
}

func TestIncrementalLinkScan_RecalculatesUserPairsAndKeepsUnrelatedPairs(t *testing.T) {
	initTestDB(t)
	require.NoError(t, model.DB.AutoMigrate(&model.UserDeviceProfile{}, &model.AccountLink{}, &model.UserRiskScore{}, &model.LinkWhitelist{}))
	require.NoError(t, model.EnsureAccountLinkUniqueIndex(model.DB))

	reviewedAt := time.Date(2026, 4, 8, 11, 0, 0, 0, time.UTC)
	require.NoError(t, model.DB.Create(&model.AccountLink{
		UserIDA:         2101,
		UserIDB:         2102,
		Confidence:      0.99,
		MatchDimensions: 9,
		TotalDimensions: 9,
		MatchDetails:    `[{"dimension":"legacy_high","score":0.99}]`,
		Status:          model.AccountLinkStatusConfirmed,
		ReviewedBy:      88,
		ReviewedAt:      &reviewedAt,
		ReviewNote:      "keep review fields",
	}).Error)
	require.NoError(t, model.DB.Create(&model.AccountLink{
		UserIDA:         2101,
		UserIDB:         2103,
		Confidence:      0.93,
		MatchDimensions: 7,
		TotalDimensions: 7,
		MatchDetails:    `[{"dimension":"legacy_high","score":0.93}]`,
		Status:          model.AccountLinkStatusConfirmed,
		ReviewedBy:      66,
		ReviewedAt:      &reviewedAt,
		ReviewNote:      "stale pair",
	}).Error)
	require.NoError(t, model.DB.Create(&model.AccountLink{
		UserIDA:         2201,
		UserIDB:         2202,
		Confidence:      0.88,
		MatchDimensions: 6,
		TotalDimensions: 6,
		MatchDetails:    `[{"dimension":"legacy_high","score":0.88}]`,
		Status:          model.AccountLinkStatusConfirmed,
		ReviewedBy:      55,
		ReviewedAt:      &reviewedAt,
		ReviewNote:      "unrelated",
	}).Error)

	latestFP := &model.Fingerprint{
		UserID:        2101,
		CanvasHash:    "inc-canvas-shared",
		WebGLHash:     "inc-webgl-a",
		CompositeHash: "inc-comp-a",
		IPAddress:     "2.2.2.2",
		UABrowser:     "Chrome",
		UABrowserVer:  "120",
		UAOS:          "Windows",
		UAOSVer:       "11",
		UADeviceType:  "desktop",
	}
	candidateFP := &model.Fingerprint{
		UserID:        2102,
		CanvasHash:    "inc-canvas-shared",
		WebGLHash:     "inc-webgl-b",
		CompositeHash: "inc-comp-b",
		IPAddress:     "2.2.2.2",
		UABrowser:     "Chrome",
		UABrowserVer:  "120",
		UAOS:          "Windows",
		UAOSVer:       "11",
		UADeviceType:  "desktop",
	}
	require.NoError(t, model.DB.Create(candidateFP).Error)

	expectedConf, _, expectedMatch, expectedTotal := CompareFingerprints(latestFP, candidateFP, 2101, 2102)
	require.Less(t, expectedConf, 0.99)

	unrelatedBefore := model.FindExistingLink(2201, 2202)
	require.NotNil(t, unrelatedBefore)
	unrelatedBeforeUpdatedAt := unrelatedBefore.UpdatedAt
	unrelatedBeforeConfidence := unrelatedBefore.Confidence

	oldEnabled := common.FingerprintEnabled
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
	})
	common.FingerprintEnabled = true

	IncrementalLinkScan(2101, latestFP)

	target := model.FindExistingLink(2101, 2102)
	require.NotNil(t, target)
	assert.InDelta(t, expectedConf, target.Confidence, 0.0001)
	assert.Equal(t, expectedMatch, target.MatchDimensions)
	assert.Equal(t, expectedTotal, target.TotalDimensions)
	assert.Equal(t, model.AccountLinkStatusConfirmed, target.Status)
	assert.Equal(t, 88, target.ReviewedBy)
	assert.Equal(t, "keep review fields", target.ReviewNote)

	stale := model.FindExistingLink(2101, 2103)
	require.NotNil(t, stale)
	assert.InDelta(t, 0.0, stale.Confidence, 0.0001)
	assert.Equal(t, model.AccountLinkStatusConfirmed, stale.Status)
	assert.Equal(t, 66, stale.ReviewedBy)
	assert.Equal(t, "stale pair", stale.ReviewNote)

	unrelatedAfter := model.FindExistingLink(2201, 2202)
	require.NotNil(t, unrelatedAfter)
	assert.InDelta(t, unrelatedBeforeConfidence, unrelatedAfter.Confidence, 0.0001)
	assert.Equal(t, unrelatedBeforeUpdatedAt.UnixNano(), unrelatedAfter.UpdatedAt.UnixNano())
}

func TestFullLinkScan_CreatesLinkForAllUserPairsWithoutGroupHit(t *testing.T) {
	initTestDB(t)
	require.NoError(t, model.DB.AutoMigrate(&model.UserDeviceProfile{}, &model.AccountLink{}, &model.UserRiskScore{}, &model.LinkWhitelist{}))
	require.NoError(t, model.EnsureAccountLinkUniqueIndex(model.DB))

	fpA := &model.Fingerprint{
		UserID:       3101,
		CanvasHash:   "allpair-canvas-a",
		IPAddress:    "33.44.55.66",
		UABrowser:    "Firefox",
		UABrowserVer: "122",
		UAOS:         "Linux",
		UAOSVer:      "6",
		UADeviceType: "desktop",
	}
	fpB := &model.Fingerprint{
		UserID:       3102,
		CanvasHash:   "allpair-canvas-b",
		IPAddress:    "33.44.55.66",
		UABrowser:    "Firefox",
		UABrowserVer: "122",
		UAOS:         "Linux",
		UAOSVer:      "6",
		UADeviceType: "desktop",
	}
	require.NoError(t, model.DB.Create(fpA).Error)
	require.NoError(t, model.DB.Create(fpB).Error)
	require.Nil(t, model.FindExistingLink(3101, 3102))

	expectedConf, _, expectedMatch, expectedTotal := CompareFingerprints(fpA, fpB, 3101, 3102)
	require.GreaterOrEqual(t, expectedConf, 0.30)

	oldEnabled := common.FingerprintEnabled
	oldTemporalRead := common.FingerprintEnableTemporalPrecomputeRead
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.FingerprintEnableTemporalPrecomputeRead = oldTemporalRead
	})
	common.FingerprintEnabled = true
	common.FingerprintEnableTemporalPrecomputeRead = false

	FullLinkScan()

	link := model.FindExistingLink(3101, 3102)
	require.NotNil(t, link)
	assert.InDelta(t, expectedConf, link.Confidence, 0.0001)
	assert.Equal(t, expectedMatch, link.MatchDimensions)
	assert.Equal(t, expectedTotal, link.TotalDimensions)
}

func TestIncrementalLinkScan_MergesLatestFingerprintAndDeviceProfileSources(t *testing.T) {
	initTestDB(t)
	require.NoError(t, model.DB.AutoMigrate(&model.UserDeviceProfile{}, &model.AccountLink{}, &model.UserRiskScore{}, &model.LinkWhitelist{}))
	require.NoError(t, model.EnsureAccountLinkUniqueIndex(model.DB))

	latestFP := &model.Fingerprint{
		UserID: 3201,
		ETagID: "etag-merge-320x",
	}
	require.NoError(t, model.DB.Create(latestFP).Error)
	counterpartFP := &model.Fingerprint{
		UserID: 3202,
		ETagID: "etag-merge-320x",
	}
	require.NoError(t, model.DB.Create(counterpartFP).Error)
	require.NoError(t, model.UpsertDeviceProfile(&model.UserDeviceProfile{
		UserID:        3201,
		DeviceKey:     "lid:merge-src-a",
		LocalDeviceID: "merge-src-a",
		CompositeHash: "merge-src-comp-a",
		LastSeenIP:    "100.10.10.1",
	}))
	require.NoError(t, model.UpsertDeviceProfile(&model.UserDeviceProfile{
		UserID:        3202,
		DeviceKey:     "lid:merge-src-b",
		LocalDeviceID: "merge-src-b",
		CompositeHash: "merge-src-comp-b",
		LastSeenIP:    "100.10.10.2",
	}))

	expectedConf, _, expectedMatch, expectedTotal := CompareFingerprints(latestFP, counterpartFP, 3201, 3202)
	require.GreaterOrEqual(t, expectedConf, 0.90)

	oldEnabled := common.FingerprintEnabled
	oldETag := common.FingerprintEnableETag
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.FingerprintEnableETag = oldETag
	})
	common.FingerprintEnabled = true
	common.FingerprintEnableETag = true

	IncrementalLinkScan(3201, latestFP)

	link := model.FindExistingLink(3201, 3202)
	require.NotNil(t, link)
	assert.InDelta(t, expectedConf, link.Confidence, 0.0001)
	assert.Equal(t, expectedMatch, link.MatchDimensions)
	assert.Equal(t, expectedTotal, link.TotalDimensions)
}

func TestIncrementalLinkScan_DoesNotFanOutToUnrelatedUsers(t *testing.T) {
	initTestDB(t)
	require.NoError(t, model.DB.AutoMigrate(&model.UserDeviceProfile{}, &model.AccountLink{}, &model.UserRiskScore{}, &model.LinkWhitelist{}))
	require.NoError(t, model.EnsureAccountLinkUniqueIndex(model.DB))

	latestFP := &model.Fingerprint{
		UserID:       3301,
		CanvasHash:   "fanout-canvas-shared",
		UABrowser:    "Chrome",
		UABrowserVer: "124",
		UAOS:         "Windows",
		UAOSVer:      "11",
		UADeviceType: "desktop",
	}
	candidateFP := &model.Fingerprint{
		UserID:       3302,
		CanvasHash:   "fanout-canvas-shared",
		UABrowser:    "Firefox",
		UABrowserVer: "123",
		UAOS:         "Linux",
		UAOSVer:      "6",
		UADeviceType: "desktop",
	}
	nonCandidateFP := &model.Fingerprint{
		UserID:       3303,
		CanvasHash:   "",
		UABrowser:    "Chrome",
		UABrowserVer: "124",
		UAOS:         "Windows",
		UAOSVer:      "11",
		UADeviceType: "desktop",
	}
	require.NoError(t, model.DB.Create(candidateFP).Error)
	require.NoError(t, model.DB.Create(nonCandidateFP).Error)

	nonCandidateConf, _, _, _ := CompareFingerprints(latestFP, nonCandidateFP, 3301, 3303)
	require.GreaterOrEqual(t, nonCandidateConf, 0.30)

	oldEnabled := common.FingerprintEnabled
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
	})
	common.FingerprintEnabled = true

	IncrementalLinkScan(3301, latestFP)

	require.NotNil(t, model.FindExistingLink(3301, 3302))
	assert.Nil(t, model.FindExistingLink(3301, 3303))
}

func TestFullLinkScan_SkipsWhitelistedPairs(t *testing.T) {
	initTestDB(t)
	require.NoError(t, model.DB.AutoMigrate(&model.UserDeviceProfile{}, &model.AccountLink{}, &model.UserRiskScore{}, &model.LinkWhitelist{}))
	require.NoError(t, model.EnsureAccountLinkUniqueIndex(model.DB))

	reviewedAt := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)
	require.NoError(t, model.DB.Create(&model.AccountLink{
		UserIDA:         3401,
		UserIDB:         3402,
		Confidence:      0.91,
		MatchDimensions: 4,
		TotalDimensions: 6,
		MatchDetails:    `[{"dimension":"legacy","score":0.91}]`,
		Status:          model.AccountLinkStatusConfirmed,
		ReviewedBy:      9,
		ReviewedAt:      &reviewedAt,
		ReviewNote:      "keep whitelisted pair untouched",
	}).Error)
	require.NoError(t, model.AddToWhitelist(3401, 3402, 1, "trusted pair"))
	require.NoError(t, model.DB.Create(&model.Fingerprint{UserID: 3401, CanvasHash: "wl-a", IPAddress: "11.22.33.44", UABrowser: "Chrome", UABrowserVer: "124", UAOS: "Windows", UAOSVer: "11", UADeviceType: "desktop"}).Error)
	require.NoError(t, model.DB.Create(&model.Fingerprint{UserID: 3402, CanvasHash: "wl-b", IPAddress: "11.22.33.44", UABrowser: "Chrome", UABrowserVer: "124", UAOS: "Windows", UAOSVer: "11", UADeviceType: "desktop"}).Error)

	before := model.FindExistingLink(3401, 3402)
	require.NotNil(t, before)
	beforeUpdatedAt := before.UpdatedAt

	oldEnabled := common.FingerprintEnabled
	oldTemporalRead := common.FingerprintEnableTemporalPrecomputeRead
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		common.FingerprintEnableTemporalPrecomputeRead = oldTemporalRead
	})
	common.FingerprintEnabled = true
	common.FingerprintEnableTemporalPrecomputeRead = false

	FullLinkScan()

	after := model.FindExistingLink(3401, 3402)
	require.NotNil(t, after)
	assert.InDelta(t, before.Confidence, after.Confidence, 0.0001)
	assert.Equal(t, before.MatchDimensions, after.MatchDimensions)
	assert.Equal(t, before.TotalDimensions, after.TotalDimensions)
	assert.Equal(t, before.ReviewedBy, after.ReviewedBy)
	assert.Equal(t, before.ReviewNote, after.ReviewNote)
	assert.Equal(t, beforeUpdatedAt.UnixNano(), after.UpdatedAt.UnixNano())
}

func TestIncrementalLinkScan_AutoConfirmUsesCompareAndSwap(t *testing.T) {
	initTestDB(t)
	require.NoError(t, model.DB.AutoMigrate(&model.UserDeviceProfile{}, &model.AccountLink{}, &model.UserRiskScore{}, &model.LinkWhitelist{}))
	require.NoError(t, model.EnsureAccountLinkUniqueIndex(model.DB))

	require.NoError(t, model.DB.Create(&model.AccountLink{
		UserIDA:    3501,
		UserIDB:    3502,
		Confidence: 0.82,
		Status:     model.AccountLinkStatusPending,
	}).Error)
	require.NoError(t, model.UpsertIPUAHistory(&model.IPUAHistory{
		UserID:       3501,
		IPAddress:    "10.20.30.40",
		UABrowser:    "Chrome",
		UAOS:         "Windows",
		UserAgent:    "test-agent",
		Endpoint:     "/api/test",
		RequestCount: 1,
	}))
	require.NoError(t, model.UpsertIPUAHistory(&model.IPUAHistory{
		UserID:       3502,
		IPAddress:    "10.20.30.40",
		UABrowser:    "Chrome",
		UAOS:         "Windows",
		UserAgent:    "test-agent",
		Endpoint:     "/api/test",
		RequestCount: 1,
	}))
	require.NoError(t, model.UpsertDeviceProfile(&model.UserDeviceProfile{
		UserID:        3502,
		DeviceKey:     "lid:cron-auto-confirm-candidate",
		LocalDeviceID: "shared-cron-auto-confirm-device",
		UABrowser:     "Chrome",
		UAOS:          "Windows",
		LastSeenIP:    "10.20.30.40",
	}))

	target := &model.Fingerprint{
		UserID:        3501,
		IPAddress:     "10.20.30.40",
		LocalDeviceID: "shared-cron-auto-confirm-device",
		UABrowser:     "Chrome",
		UAOS:          "Windows",
	}

	oldEnabled := common.FingerprintEnabled
	oldAuto := os.Getenv("FINGERPRINT_AUTO_CONFIRM_THRESHOLD")
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		if oldAuto == "" {
			_ = os.Unsetenv("FINGERPRINT_AUTO_CONFIRM_THRESHOLD")
		} else {
			_ = os.Setenv("FINGERPRINT_AUTO_CONFIRM_THRESHOLD", oldAuto)
		}
	})
	common.FingerprintEnabled = true
	_ = os.Setenv("FINGERPRINT_AUTO_CONFIRM_THRESHOLD", "0.8")

	IncrementalLinkScan(3501, target)

	link := model.FindExistingLink(3501, 3502)
	require.NotNil(t, link)
	require.Equal(t, model.AccountLinkStatusAutoConfirmed, link.Status)

	require.NoError(t, model.UpdateLinkStatus(link.ID, model.AccountLinkStatusConfirmed, 99, "manual review"))
	IncrementalLinkScan(3501, target)

	link = model.FindExistingLink(3501, 3502)
	require.NotNil(t, link)
	require.Equal(t, model.AccountLinkStatusConfirmed, link.Status)
	require.Equal(t, 99, link.ReviewedBy)
	require.Equal(t, "manual review", link.ReviewNote)
}
