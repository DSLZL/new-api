package model

import (
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func initBehaviorProfileTestDB(t *testing.T) {
	t.Helper()
	oldDB := DB
	dsn := "file:" + t.Name() + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&KeystrokeProfile{}, &MouseProfile{}))
	DB = db
	t.Cleanup(func() {
		DB = oldDB
		_ = sqlDB.Close()
	})
}

func TestUpsertKeystrokeProfile_CreateAndUpdate(t *testing.T) {
	initBehaviorProfileTestDB(t)

	first := &KeystrokeProfile{
		UserID:        501,
		AvgHoldTime:   95,
		StdHoldTime:   18,
		AvgFlightTime: 125,
		StdFlightTime: 24,
		TypingSpeed:   4.7,
		DigraphData:   `[{"digraph":"alpha->alpha","avgFlightTime":120}]`,
		SampleCount:   120,
	}
	require.NoError(t, UpsertKeystrokeProfile(first))

	latest := GetLatestKeystrokeProfile(501)
	require.NotNil(t, latest)
	require.Equal(t, 95.0, latest.AvgHoldTime)
	require.Equal(t, 120, latest.SampleCount)

	second := &KeystrokeProfile{
		UserID:        501,
		AvgHoldTime:   102,
		StdHoldTime:   20,
		AvgFlightTime: 133,
		StdFlightTime: 26,
		TypingSpeed:   5.1,
		DigraphData:   `[{"digraph":"digit->alpha","avgFlightTime":128}]`,
		SampleCount:   180,
		UpdatedAt:     time.Now().UTC().Add(2 * time.Minute),
	}
	require.NoError(t, UpsertKeystrokeProfile(second))

	updated := GetLatestKeystrokeProfile(501)
	require.NotNil(t, updated)
	require.Equal(t, 102.0, updated.AvgHoldTime)
	require.Equal(t, 180, updated.SampleCount)
	require.Equal(t, second.DigraphData, updated.DigraphData)
}

func TestUpsertKeystrokeProfile_IgnoresInvalidInput(t *testing.T) {
	initBehaviorProfileTestDB(t)

	require.NoError(t, UpsertKeystrokeProfile(nil))
	require.NoError(t, UpsertKeystrokeProfile(&KeystrokeProfile{UserID: 0}))
	require.Nil(t, GetLatestKeystrokeProfile(0))
}

func TestGetLatestKeystrokeProfile_ReturnsNilWhenMissing(t *testing.T) {
	initBehaviorProfileTestDB(t)
	require.Nil(t, GetLatestKeystrokeProfile(9999))
}

func TestUpsertKeystrokeProfile_UsesUniqueUserConstraintAndKeepsSingleRow(t *testing.T) {
	initBehaviorProfileTestDB(t)

	require.True(t, DB.Migrator().HasIndex(&KeystrokeProfile{}, "uk_keystroke_user"))

	require.NoError(t, UpsertKeystrokeProfile(&KeystrokeProfile{
		UserID:        777,
		AvgHoldTime:   80,
		StdHoldTime:   12,
		AvgFlightTime: 140,
		StdFlightTime: 20,
		TypingSpeed:   5.5,
		DigraphData:   `[{"digraph":"alpha->alpha","avgFlightTime":138}]`,
		SampleCount:   101,
	}))
	require.NoError(t, UpsertKeystrokeProfile(&KeystrokeProfile{
		UserID:        777,
		AvgHoldTime:   88,
		StdHoldTime:   13,
		AvgFlightTime: 144,
		StdFlightTime: 22,
		TypingSpeed:   5.9,
		DigraphData:   `[{"digraph":"alpha->digit","avgFlightTime":142}]`,
		SampleCount:   160,
	}))

	var count int64
	require.NoError(t, DB.Model(&KeystrokeProfile{}).Where("user_id = ?", 777).Count(&count).Error)
	require.Equal(t, int64(1), count)

	latest := GetLatestKeystrokeProfile(777)
	require.NotNil(t, latest)
	require.Equal(t, 160, latest.SampleCount)
	require.Equal(t, 88.0, latest.AvgHoldTime)
}

func TestUpsertMouseProfile_CreateAndUpdate(t *testing.T) {
	initBehaviorProfileTestDB(t)

	first := &MouseProfile{
		UserID:              601,
		AvgSpeed:            1380,
		MaxSpeed:            2100,
		SpeedStd:            180,
		AvgAcceleration:     320,
		AccStd:              75,
		DirectionChangeRate: 0.21,
		AvgScrollDelta:      96,
		ScrollDeltaMode:     0,
		ClickDistribution:   `{"topLeft":0.25,"topRight":0.25,"bottomLeft":0.25,"bottomRight":0.25}`,
		SampleCount:         64,
	}
	require.NoError(t, UpsertMouseProfile(first))

	latest := GetLatestMouseProfile(601)
	require.NotNil(t, latest)
	require.Equal(t, 1380.0, latest.AvgSpeed)
	require.Equal(t, 64, latest.SampleCount)

	second := &MouseProfile{
		UserID:              601,
		AvgSpeed:            1425,
		MaxSpeed:            2200,
		SpeedStd:            165,
		AvgAcceleration:     335,
		AccStd:              70,
		DirectionChangeRate: 0.18,
		AvgScrollDelta:      110,
		ScrollDeltaMode:     1,
		ClickDistribution:   `{"topLeft":0.10,"topRight":0.40,"bottomLeft":0.20,"bottomRight":0.30}`,
		SampleCount:         88,
		UpdatedAt:           time.Now().UTC().Add(2 * time.Minute),
	}
	require.NoError(t, UpsertMouseProfile(second))

	updated := GetLatestMouseProfile(601)
	require.NotNil(t, updated)
	require.Equal(t, 1425.0, updated.AvgSpeed)
	require.Equal(t, 88, updated.SampleCount)
	require.Equal(t, second.ClickDistribution, updated.ClickDistribution)
}

func TestUpsertMouseProfile_UsesUniqueUserConstraintAndKeepsSingleRow(t *testing.T) {
	initBehaviorProfileTestDB(t)

	require.True(t, DB.Migrator().HasIndex(&MouseProfile{}, "uk_mouse_user"))

	require.NoError(t, UpsertMouseProfile(&MouseProfile{
		UserID:              888,
		AvgSpeed:            1380,
		MaxSpeed:            2100,
		SpeedStd:            180,
		AvgAcceleration:     320,
		AccStd:              75,
		DirectionChangeRate: 0.21,
		AvgScrollDelta:      96,
		ScrollDeltaMode:     0,
		ClickDistribution:   `{"topLeft":0.25,"topRight":0.25,"bottomLeft":0.25,"bottomRight":0.25}`,
		SampleCount:         64,
	}))
	require.NoError(t, UpsertMouseProfile(&MouseProfile{
		UserID:              888,
		AvgSpeed:            1425,
		MaxSpeed:            2200,
		SpeedStd:            165,
		AvgAcceleration:     335,
		AccStd:              70,
		DirectionChangeRate: 0.18,
		AvgScrollDelta:      110,
		ScrollDeltaMode:     1,
		ClickDistribution:   `{"topLeft":0.10,"topRight":0.40,"bottomLeft":0.20,"bottomRight":0.30}`,
		SampleCount:         88,
	}))

	var count int64
	require.NoError(t, DB.Model(&MouseProfile{}).Where("user_id = ?", 888).Count(&count).Error)
	require.Equal(t, int64(1), count)

	latest := GetLatestMouseProfile(888)
	require.NotNil(t, latest)
	require.Equal(t, 88, latest.SampleCount)
	require.Equal(t, 1425.0, latest.AvgSpeed)
}

func TestUpsertMouseProfile_IgnoresInvalidInput(t *testing.T) {
	initBehaviorProfileTestDB(t)

	require.NoError(t, UpsertMouseProfile(nil))
	require.NoError(t, UpsertMouseProfile(&MouseProfile{UserID: 0}))
	require.Nil(t, GetLatestMouseProfile(0))
}

func TestGetLatestMouseProfile_ReturnsNilWhenMissing(t *testing.T) {
	initBehaviorProfileTestDB(t)
	require.Nil(t, GetLatestMouseProfile(9999))
}

func TestDeleteOldBehaviorProfiles_ByUpdatedAt(t *testing.T) {
	initBehaviorProfileTestDB(t)

	now := time.Now().UTC()
	require.NoError(t, DB.Create(&KeystrokeProfile{UserID: 901, SampleCount: 10, UpdatedAt: now.Add(-48 * time.Hour)}).Error)
	require.NoError(t, DB.Create(&KeystrokeProfile{UserID: 902, SampleCount: 10, UpdatedAt: now.Add(-6 * time.Hour)}).Error)
	require.NoError(t, DB.Create(&MouseProfile{UserID: 901, SampleCount: 12, UpdatedAt: now.Add(-72 * time.Hour)}).Error)
	require.NoError(t, DB.Create(&MouseProfile{UserID: 902, SampleCount: 12, UpdatedAt: now.Add(-3 * time.Hour)}).Error)

	cutoff := now.Add(-24 * time.Hour)
	deletedKey, err := DeleteOldKeystrokeProfiles(cutoff)
	require.NoError(t, err)
	require.Equal(t, int64(1), deletedKey)
	deletedMouse, err := DeleteOldMouseProfiles(cutoff)
	require.NoError(t, err)
	require.Equal(t, int64(1), deletedMouse)

	var keyCount int64
	require.NoError(t, DB.Model(&KeystrokeProfile{}).Count(&keyCount).Error)
	require.Equal(t, int64(1), keyCount)

	var mouseCount int64
	require.NoError(t, DB.Model(&MouseProfile{}).Count(&mouseCount).Error)
	require.Equal(t, int64(1), mouseCount)

	remainingKey := GetLatestKeystrokeProfile(902)
	require.NotNil(t, remainingKey)
	require.Equal(t, 902, remainingKey.UserID)

	remainingMouse := GetLatestMouseProfile(902)
	require.NotNil(t, remainingMouse)
	require.Equal(t, 902, remainingMouse.UserID)
}

func TestDeleteOldBehaviorProfiles_ReturnsDBError(t *testing.T) {
	initBehaviorProfileTestDB(t)

	brokenDB := DB.Session(&gorm.Session{NewDB: true})
	oldDB := DB
	DB = brokenDB
	t.Cleanup(func() {
		DB = oldDB
	})

	sqlDB, err := brokenDB.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	_, err = DeleteOldKeystrokeProfiles(time.Now().UTC())
	require.Error(t, err)

	_, err = DeleteOldMouseProfiles(time.Now().UTC())
	require.Error(t, err)
}
