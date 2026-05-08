package model

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func initTemporalModelRawTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&UserTemporalProfile{}, &UserSession{}))
	DB = db
	return db
}

func initTemporalModelTestDB(t *testing.T) {
	t.Helper()
	db := initTemporalModelRawTestDB(t)
	require.NoError(t, EnsureUserSessionUniqueIndex(db))
}

func TestUserTemporalProfile_TableName(t *testing.T) {
	require.Equal(t, "user_temporal_profiles", UserTemporalProfile{}.TableName())
}

func TestUserSession_TableName(t *testing.T) {
	require.Equal(t, "user_sessions", UserSession{}.TableName())
}

func TestUserTemporalProfile_CRUD(t *testing.T) {
	initTemporalModelTestDB(t)

	now := time.Now().UTC().Truncate(time.Second)
	rec := &UserTemporalProfile{
		UserID:         9001,
		ProfileDate:    "2026-04-03",
		Timezone:       "Asia/Shanghai",
		ActivityBins:   `[0.1,0.2,0.3]`,
		PeakBin:        17,
		SampleCount:    12,
		LastActivityAt: now,
	}
	require.NoError(t, DB.Create(rec).Error)

	var got UserTemporalProfile
	require.NoError(t, DB.Where("user_id = ? AND profile_date = ?", 9001, "2026-04-03").First(&got).Error)
	require.Equal(t, rec.Timezone, got.Timezone)
	require.Equal(t, rec.ActivityBins, got.ActivityBins)
	require.Equal(t, rec.PeakBin, got.PeakBin)
	require.Equal(t, rec.SampleCount, got.SampleCount)
}

func TestUserSession_CRUD(t *testing.T) {
	initTemporalModelTestDB(t)

	start := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Second)
	end := start.Add(7 * time.Minute)
	rec := &UserSession{
		UserID:          9002,
		SessionID:       "sid-9002",
		DeviceKey:       "lid:device-9002",
		IPAddress:       "10.0.0.2",
		StartedAt:       start,
		EndedAt:         end,
		DurationSeconds: int(end.Sub(start).Seconds()),
		EventCount:      5,
		IsBurst:         true,
		Source:          "fingerprint",
	}
	require.NoError(t, DB.Create(rec).Error)

	var got UserSession
	require.NoError(t, DB.Where("user_id = ? AND session_id = ?", 9002, "sid-9002").First(&got).Error)
	require.Equal(t, rec.DeviceKey, got.DeviceKey)
	require.Equal(t, rec.IPAddress, got.IPAddress)
	require.Equal(t, rec.DurationSeconds, got.DurationSeconds)
	require.Equal(t, rec.EventCount, got.EventCount)
	require.Equal(t, rec.IsBurst, got.IsBurst)
	require.Equal(t, rec.Source, got.Source)
}

func TestUpsertTemporalProfile_InsertAndUpdate(t *testing.T) {
	initTemporalModelTestDB(t)

	first := &UserTemporalProfile{
		UserID:         9101,
		ProfileDate:    "2026-04-03",
		Timezone:       "Asia/Shanghai",
		ActivityBins:   `[0.2,0.3,0.5]`,
		PeakBin:        20,
		SampleCount:    10,
		LastActivityAt: time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second),
	}
	require.NoError(t, UpsertTemporalProfile(first))

	updatedAtAfterInsert := time.Time{}
	{
		var got UserTemporalProfile
		require.NoError(t, DB.Where("user_id = ? AND profile_date = ?", 9101, "2026-04-03").First(&got).Error)
		require.Equal(t, "Asia/Shanghai", got.Timezone)
		require.Equal(t, `[0.2,0.3,0.5]`, got.ActivityBins)
		require.Equal(t, 20, got.PeakBin)
		require.Equal(t, 10, got.SampleCount)
		updatedAtAfterInsert = got.UpdatedAt
	}

	second := &UserTemporalProfile{
		UserID:         9101,
		ProfileDate:    "2026-04-03",
		Timezone:       "UTC",
		ActivityBins:   `[0.1,0.4,0.5]`,
		PeakBin:        21,
		SampleCount:    15,
		LastActivityAt: time.Now().UTC().Truncate(time.Second),
	}
	require.NoError(t, UpsertTemporalProfile(second))

	var got UserTemporalProfile
	require.NoError(t, DB.Where("user_id = ? AND profile_date = ?", 9101, "2026-04-03").First(&got).Error)
	require.Equal(t, "UTC", got.Timezone)
	require.Equal(t, `[0.1,0.4,0.5]`, got.ActivityBins)
	require.Equal(t, 21, got.PeakBin)
	require.Equal(t, 15, got.SampleCount)
	require.False(t, got.UpdatedAt.Before(updatedAtAfterInsert))
}

func TestUpsertTemporalProfile_IgnoresInvalidInput(t *testing.T) {
	initTemporalModelTestDB(t)

	require.NoError(t, UpsertTemporalProfile(nil))
	require.NoError(t, UpsertTemporalProfile(&UserTemporalProfile{UserID: 0, ProfileDate: "2026-04-03"}))
	require.NoError(t, UpsertTemporalProfile(&UserTemporalProfile{UserID: 1, ProfileDate: ""}))

	var count int64
	require.NoError(t, DB.Model(&UserTemporalProfile{}).Count(&count).Error)
	require.Equal(t, int64(0), count)
}

func TestGetLatestTemporalProfile_ReturnsLatestByDateAndActivity(t *testing.T) {
	initTemporalModelTestDB(t)

	base := time.Date(2026, 4, 1, 8, 0, 0, 0, time.UTC)
	require.NoError(t, DB.Create(&UserTemporalProfile{
		UserID:         9201,
		ProfileDate:    "2026-04-01",
		ActivityBins:   `[1]`,
		PeakBin:        10,
		SampleCount:    2,
		LastActivityAt: base,
	}).Error)
	require.NoError(t, DB.Create(&UserTemporalProfile{
		UserID:         9201,
		ProfileDate:    "2026-04-02",
		ActivityBins:   `[2]`,
		PeakBin:        12,
		SampleCount:    3,
		LastActivityAt: base.Add(1 * time.Hour),
	}).Error)

	latest := GetLatestTemporalProfile(9201)
	require.NotNil(t, latest)
	require.Equal(t, "2026-04-02", latest.ProfileDate)
	require.Equal(t, `[2]`, latest.ActivityBins)

	require.Nil(t, GetLatestTemporalProfile(0))
	require.Nil(t, GetLatestTemporalProfile(9999))
}

func TestReplaceUserSessions_ReplacesAllSessionsForUser(t *testing.T) {
	initTemporalModelTestDB(t)

	uid := 9301
	require.NoError(t, DB.Create(&UserSession{
		UserID:     uid,
		SessionID:  "old-1",
		StartedAt:  time.Now().UTC().Add(-3 * time.Hour),
		EndedAt:    time.Now().UTC().Add(-2 * time.Hour),
		Source:     "fingerprint",
		EventCount: 2,
	}).Error)
	require.NoError(t, DB.Create(&UserSession{
		UserID:     uid,
		SessionID:  "old-2",
		StartedAt:  time.Now().UTC().Add(-2 * time.Hour),
		EndedAt:    time.Now().UTC().Add(-1 * time.Hour),
		Source:     "fingerprint",
		EventCount: 3,
	}).Error)

	require.NoError(t, ReplaceUserSessions(uid, []UserSession{
		{
			UserID:          uid,
			SessionID:       "new-1",
			DeviceKey:       "lid:replace-1",
			IPAddress:       "10.0.0.10",
			StartedAt:       time.Now().UTC().Add(-30 * time.Minute),
			EndedAt:         time.Now().UTC().Add(-20 * time.Minute),
			DurationSeconds: 600,
			EventCount:      4,
			Source:          "fingerprint",
		},
		{
			UserID:          uid,
			SessionID:       "new-2",
			DeviceKey:       "lid:replace-2",
			IPAddress:       "10.0.0.11",
			StartedAt:       time.Now().UTC().Add(-10 * time.Minute),
			EndedAt:         time.Now().UTC().Add(-5 * time.Minute),
			DurationSeconds: 300,
			EventCount:      5,
			Source:          "fingerprint",
		},
	}))

	var sessions []UserSession
	require.NoError(t, DB.Where("user_id = ?", uid).Order("started_at ASC").Find(&sessions).Error)
	require.Len(t, sessions, 2)
	require.Equal(t, "new-1", sessions[0].SessionID)
	require.Equal(t, "new-2", sessions[1].SessionID)
}

func TestReplaceUserSessions_HandlesEmptyAndInvalidUser(t *testing.T) {
	initTemporalModelTestDB(t)

	require.NoError(t, ReplaceUserSessions(0, []UserSession{{UserID: 0, SessionID: "ignored", StartedAt: time.Now().UTC()}}))
	require.NoError(t, ReplaceUserSessions(9401, nil))

	var count int64
	require.NoError(t, DB.Model(&UserSession{}).Count(&count).Error)
	require.Equal(t, int64(0), count)
}

func TestGetLatestUserSessions_ReturnsSortedAndLimited(t *testing.T) {
	initTemporalModelTestDB(t)

	uid := 9501
	now := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 3; i++ {
		require.NoError(t, DB.Create(&UserSession{
			UserID:          uid,
			SessionID:       "sid-9501-" + string(rune('A'+i)),
			StartedAt:       now.Add(time.Duration(i) * time.Minute),
			EndedAt:         now.Add(time.Duration(i+1) * time.Minute),
			DurationSeconds: 60,
			EventCount:      i + 1,
			Source:          "fingerprint",
		}).Error)
	}

	limited := GetLatestUserSessions(uid, 2)
	require.Len(t, limited, 2)
	require.True(t, !limited[0].StartedAt.Before(limited[1].StartedAt))

	all := GetLatestUserSessions(uid, 0)
	require.Len(t, all, 3)

	require.Nil(t, GetLatestUserSessions(0, 10))
}

func TestUpsertUserSession_InsertAndUpdate(t *testing.T) {
	initTemporalModelTestDB(t)

	start := time.Now().UTC().Add(-15 * time.Minute).Truncate(time.Second)
	end := start.Add(5 * time.Minute)
	require.NoError(t, UpsertUserSession(&UserSession{
		UserID:          9601,
		SessionID:       "sid-9601",
		DeviceKey:       "lid:device-a",
		IPAddress:       "1.1.1.1",
		StartedAt:       start,
		EndedAt:         end,
		DurationSeconds: int(end.Sub(start).Seconds()),
		EventCount:      1,
		Source:          "fingerprint",
	}))

	updatedEnd := end.Add(3 * time.Minute)
	require.NoError(t, UpsertUserSession(&UserSession{
		UserID:          9601,
		SessionID:       "sid-9601",
		DeviceKey:       "lid:device-b",
		IPAddress:       "2.2.2.2",
		StartedAt:       start,
		EndedAt:         updatedEnd,
		DurationSeconds: int(updatedEnd.Sub(start).Seconds()),
		EventCount:      3,
		Source:          "fingerprint",
	}))

	var sessions []UserSession
	require.NoError(t, DB.Where("user_id = ?", 9601).Find(&sessions).Error)
	require.Len(t, sessions, 1)
	require.Equal(t, "lid:device-b", sessions[0].DeviceKey)
	require.Equal(t, "2.2.2.2", sessions[0].IPAddress)
	require.Equal(t, 3, sessions[0].EventCount)
	require.Equal(t, int(updatedEnd.Sub(start).Seconds()), sessions[0].DurationSeconds)
}

func TestUpsertUserSession_ConcurrentSameSessionKeepsSingleRow(t *testing.T) {
	initTemporalModelTestDB(t)

	callbackName := "test_delay_user_session_lookup"
	require.NoError(t, DB.Callback().Query().Before("gorm:query").Register(callbackName, func(tx *gorm.DB) {
		if tx.Statement == nil || tx.Statement.Schema == nil || tx.Statement.Schema.Table != (UserSession{}).TableName() {
			return
		}
		if tx.Statement.SQL.Len() == 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}))
	defer func() {
		_ = DB.Callback().Query().Remove(callbackName)
	}()

	start := time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC)
	end := start.Add(5 * time.Minute)
	started := make(chan struct{})
	errCh := make(chan error, 2)

	run := func(deviceKey, ip string, eventCount int) {
		<-started
		errCh <- UpsertUserSession(&UserSession{
			UserID:          9801,
			SessionID:       "sid-concurrent-9801",
			DeviceKey:       deviceKey,
			IPAddress:       ip,
			StartedAt:       start,
			EndedAt:         end,
			DurationSeconds: int(end.Sub(start).Seconds()),
			EventCount:      eventCount,
			Source:          "fingerprint",
		})
	}

	go run("lid:device-a", "1.1.1.1", 1)
	go run("lid:device-b", "2.2.2.2", 2)
	close(started)

	require.NoError(t, <-errCh)
	require.NoError(t, <-errCh)

	var sessions []UserSession
	require.NoError(t, DB.Where("user_id = ?", 9801).Order("id ASC").Find(&sessions).Error)
	require.Len(t, sessions, 1)
	require.Equal(t, "sid-concurrent-9801", sessions[0].SessionID)
}

func TestUpsertUserSession_AllowsSameSessionIDAcrossUsers(t *testing.T) {
	initTemporalModelTestDB(t)

	start := time.Date(2026, 4, 5, 13, 0, 0, 0, time.UTC)
	for _, userID := range []int{9811, 9812} {
		require.NoError(t, UpsertUserSession(&UserSession{
			UserID:          userID,
			SessionID:       "shared-session-id",
			DeviceKey:       fmt.Sprintf("lid:user-%d", userID),
			IPAddress:       fmt.Sprintf("10.0.0.%d", userID-9800),
			StartedAt:       start,
			EndedAt:         start.Add(time.Minute),
			DurationSeconds: 60,
			EventCount:      1,
			Source:          "fingerprint",
		}))
	}

	var sessions []UserSession
	require.NoError(t, DB.Where("session_id = ?", "shared-session-id").Order("user_id ASC").Find(&sessions).Error)
	require.Len(t, sessions, 2)
	require.Equal(t, 9811, sessions[0].UserID)
	require.Equal(t, 9812, sessions[1].UserID)
}

func TestUpsertUserSession_EmptySessionIDCreatesDistinctRows(t *testing.T) {
	initTemporalModelTestDB(t)

	start := time.Date(2026, 4, 5, 13, 30, 0, 0, time.UTC)
	for i := 0; i < 2; i++ {
		require.NoError(t, UpsertUserSession(&UserSession{
			UserID:          9821,
			SessionID:       "",
			DeviceKey:       fmt.Sprintf("lid:anon-%d", i),
			IPAddress:       fmt.Sprintf("10.0.1.%d", i+1),
			StartedAt:       start.Add(time.Duration(i) * time.Minute),
			EndedAt:         start.Add(time.Duration(i+1) * time.Minute),
			DurationSeconds: 60,
			EventCount:      1,
			Source:          "fingerprint",
		}))
	}

	var sessions []UserSession
	require.NoError(t, DB.Where("user_id = ?", 9821).Order("id ASC").Find(&sessions).Error)
	require.Len(t, sessions, 2)
	require.NotEmpty(t, sessions[0].SessionID)
	require.NotEmpty(t, sessions[1].SessionID)
	require.NotEqual(t, sessions[0].SessionID, sessions[1].SessionID)
}

func TestEnsureUserSessionUniqueIndex_NormalizesLegacyRows(t *testing.T) {
	db := initTemporalModelRawTestDB(t)
	now := time.Date(2026, 4, 5, 14, 0, 0, 0, time.UTC)

	require.NoError(t, db.Create(&UserSession{
		UserID:          9901,
		SessionID:       "",
		StartedAt:       now,
		EndedAt:         now.Add(time.Minute),
		DurationSeconds: 60,
		EventCount:      1,
		Source:          "fingerprint",
	}).Error)
	require.NoError(t, db.Create(&UserSession{
		UserID:          9901,
		SessionID:       "",
		StartedAt:       now.Add(2 * time.Minute),
		EndedAt:         now.Add(3 * time.Minute),
		DurationSeconds: 60,
		EventCount:      1,
		Source:          "fingerprint",
	}).Error)
	require.NoError(t, db.Create(&UserSession{
		UserID:          9902,
		SessionID:       "dup-9902",
		StartedAt:       now,
		EndedAt:         now.Add(time.Minute),
		DurationSeconds: 60,
		EventCount:      1,
		Source:          "fingerprint",
	}).Error)
	require.NoError(t, db.Create(&UserSession{
		UserID:          9902,
		SessionID:       "dup-9902",
		StartedAt:       now.Add(2 * time.Minute),
		EndedAt:         now.Add(3 * time.Minute),
		DurationSeconds: 60,
		EventCount:      2,
		Source:          "fingerprint",
	}).Error)

	require.NoError(t, EnsureUserSessionUniqueIndex(db))
	require.True(t, db.Migrator().HasIndex(&UserSession{}, "uk_us_user_session"))

	var sessions []UserSession
	require.NoError(t, db.Order("id ASC").Find(&sessions).Error)
	require.Len(t, sessions, 4)

	seen := make(map[string]struct{}, len(sessions))
	for _, session := range sessions {
		require.NotEmpty(t, session.SessionID)
		key := fmt.Sprintf("%d:%s", session.UserID, session.SessionID)
		if _, ok := seen[key]; ok {
			t.Fatalf("duplicate session pair remained: %s", key)
		}
		seen[key] = struct{}{}
	}
}

func TestReplaceUserSessionsBySource_PreservesOtherSources(t *testing.T) {
	initTemporalModelTestDB(t)

	uid := 9701
	now := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, DB.Create(&UserSession{
		UserID:          uid,
		SessionID:       "fingerprint-1",
		StartedAt:       now.Add(-20 * time.Minute),
		EndedAt:         now.Add(-10 * time.Minute),
		DurationSeconds: 600,
		EventCount:      2,
		Source:          "fingerprint",
	}).Error)
	require.NoError(t, DB.Create(&UserSession{
		UserID:          uid,
		SessionID:       "precompute-old",
		StartedAt:       now.Add(-8 * time.Minute),
		EndedAt:         now.Add(-6 * time.Minute),
		DurationSeconds: 120,
		EventCount:      1,
		Source:          "precompute",
	}).Error)

	require.NoError(t, ReplaceUserSessionsBySource(uid, "precompute", []UserSession{{
		UserID:          uid,
		SessionID:       "precompute-new",
		StartedAt:       now.Add(-4 * time.Minute),
		EndedAt:         now.Add(-2 * time.Minute),
		DurationSeconds: 120,
		EventCount:      4,
		Source:          "precompute",
	}}))

	var sessions []UserSession
	require.NoError(t, DB.Where("user_id = ?", uid).Order("source ASC, started_at ASC").Find(&sessions).Error)
	require.Len(t, sessions, 2)
	require.Equal(t, "fingerprint", sessions[0].Source)
	require.Equal(t, "fingerprint-1", sessions[0].SessionID)
	require.Equal(t, "precompute", sessions[1].Source)
	require.Equal(t, "precompute-new", sessions[1].SessionID)
}

func TestUpsertUserSession_DoesNotAllowFingerprintToUseReservedPrecomputePrefix(t *testing.T) {
	initTemporalModelTestDB(t)

	start := time.Now().UTC().Add(-2 * time.Minute).Truncate(time.Second)
	end := start.Add(30 * time.Second)
	require.NoError(t, UpsertUserSession(&UserSession{
		UserID:          9711,
		SessionID:       UserSessionReservedPrefixPrecompute + "9711:1:2",
		StartedAt:       start,
		EndedAt:         end,
		DurationSeconds: int(end.Sub(start).Seconds()),
		EventCount:      1,
		Source:          "fingerprint",
	}))

	var sessions []UserSession
	require.NoError(t, DB.Where("user_id = ?", 9711).Find(&sessions).Error)
	require.Len(t, sessions, 1)
	require.NotEqual(t, UserSessionReservedPrefixPrecompute+"9711:1:2", sessions[0].SessionID)
	require.False(t, strings.HasPrefix(sessions[0].SessionID, UserSessionReservedPrefixPrecompute))
	require.Equal(t, "fingerprint", sessions[0].Source)
}

func TestUpsertUserSession_DoesNotOverwriteExistingSourceOnConflict(t *testing.T) {
	initTemporalModelTestDB(t)

	start := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Second)
	end := start.Add(5 * time.Minute)
	reservedID := UserSessionReservedPrefixPrecompute + "9712:1:2"
	require.NoError(t, UpsertUserSession(&UserSession{
		UserID:          9712,
		SessionID:       reservedID,
		StartedAt:       start,
		EndedAt:         end,
		DurationSeconds: int(end.Sub(start).Seconds()),
		EventCount:      3,
		Source:          "precompute",
	}))
	require.NoError(t, UpsertUserSession(&UserSession{
		UserID:          9712,
		SessionID:       reservedID,
		DeviceKey:       "lid:override-attempt",
		IPAddress:       "1.2.3.4",
		StartedAt:       start.Add(time.Minute),
		EndedAt:         end.Add(time.Minute),
		DurationSeconds: int(end.Sub(start).Seconds()),
		EventCount:      4,
		Source:          "fingerprint",
	}))

	var got UserSession
	require.NoError(t, DB.Where("user_id = ? AND session_id = ?", 9712, reservedID).First(&got).Error)
	require.Equal(t, "precompute", got.Source)
	require.Equal(t, "", got.DeviceKey)
	require.Equal(t, "", got.IPAddress)
}

func TestDeleteOldUserSessions_RemovesStaleOnly(t *testing.T) {
	initTemporalModelTestDB(t)

	now := time.Now().UTC()
	require.NoError(t, DB.Create(&UserSession{
		UserID:          9801,
		SessionID:       "stale-session",
		StartedAt:       now.Add(-10 * 24 * time.Hour),
		EndedAt:         now.Add(-10 * 24 * time.Hour),
		DurationSeconds: 60,
		EventCount:      1,
		Source:          "fingerprint",
	}).Error)
	require.NoError(t, DB.Create(&UserSession{
		UserID:          9802,
		SessionID:       "fresh-session",
		StartedAt:       now.Add(-2 * 24 * time.Hour),
		EndedAt:         now.Add(-2 * 24 * time.Hour),
		DurationSeconds: 60,
		EventCount:      1,
		Source:          "fingerprint",
	}).Error)

	deleted, err := DeleteOldUserSessions(now.Add(-5 * 24 * time.Hour))
	require.NoError(t, err)
	require.Equal(t, int64(1), deleted)

	var staleCount int64
	var freshCount int64
	require.NoError(t, DB.Model(&UserSession{}).Where("user_id = ?", 9801).Count(&staleCount).Error)
	require.NoError(t, DB.Model(&UserSession{}).Where("user_id = ?", 9802).Count(&freshCount).Error)
	require.Equal(t, int64(0), staleCount)
	require.Equal(t, int64(1), freshCount)
}
