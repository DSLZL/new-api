package model

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func initAccountLinkTestDB(t *testing.T) {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(8)
	require.NoError(t, db.AutoMigrate(&AccountLink{}))
	require.NoError(t, EnsureAccountLinkUniqueIndex(db))
	DB = db
}

func TestUpsertLink_NormalizesPairAndUpdatesExistingRecord(t *testing.T) {
	initAccountLinkTestDB(t)

	require.NoError(t, UpsertLink(8, 3, 0.61, 2, 6, `[{"dimension":"canvas","score":0.61}]`))
	require.NoError(t, UpsertLink(3, 8, 0.88, 4, 6, `[{"dimension":"device_key","score":0.95}]`))

	link := FindExistingLink(3, 8)
	require.NotNil(t, link)
	require.Equal(t, 3, link.UserIDA)
	require.Equal(t, 8, link.UserIDB)
	require.InDelta(t, 0.88, link.Confidence, 0.0001)
	require.Equal(t, 4, link.MatchDimensions)
	require.Equal(t, 6, link.TotalDimensions)
	require.Equal(t, `[{"dimension":"device_key","score":0.95}]`, link.MatchDetails)
	require.Equal(t, "pending", link.Status)

	var count int64
	require.NoError(t, DB.Model(&AccountLink{}).Count(&count).Error)
	require.Equal(t, int64(1), count)
}

func TestUpsertLink_ConcurrentSamePairDoesNotDuplicate(t *testing.T) {
	initAccountLinkTestDB(t)

	const workers = 8
	var wg sync.WaitGroup
	errCh := make(chan error, workers)

	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errCh <- UpsertLink(42, 99, 0.40+float64(i)*0.01, i+1, 8, fmt.Sprintf(`[{"dimension":"device_key","score":%.2f}]`, 0.40+float64(i)*0.01))
		}(i)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}

	var count int64
	require.NoError(t, DB.Model(&AccountLink{}).Count(&count).Error)
	require.Equal(t, int64(1), count)

	link := FindExistingLink(42, 99)
	require.NotNil(t, link)
	require.Equal(t, 42, link.UserIDA)
	require.Equal(t, 99, link.UserIDB)
	require.Equal(t, 8, link.TotalDimensions)
	require.NotEmpty(t, link.MatchDetails)
	require.GreaterOrEqual(t, link.Confidence, 0.40)
	require.InDelta(t, 0.47, link.Confidence, 1e-9)
	require.GreaterOrEqual(t, link.MatchDimensions, 1)
	require.LessOrEqual(t, link.MatchDimensions, 8)
}

func TestUpsertLink_KeepsHigherConfidenceWhenWeakerEvidenceArrives(t *testing.T) {
	initAccountLinkTestDB(t)

	require.NoError(t, UpsertLink(9, 4, 0.91, 4, 6, `[{"dimension":"canvas","score":0.91}]`))
	require.NoError(t, UpsertLink(4, 9, 0.52, 2, 6, `[{"dimension":"ip_exact","score":0.52}]`))

	link := FindExistingLink(4, 9)
	require.NotNil(t, link)
	require.InDelta(t, 0.91, link.Confidence, 0.0001)
	require.Equal(t, 4, link.MatchDimensions)
	require.Equal(t, 6, link.TotalDimensions)
	require.Equal(t, `[{"dimension":"canvas","score":0.91}]`, link.MatchDetails)
}

func TestEnsureAccountLinkUniqueIndex_NormalizesLegacyRows(t *testing.T) {
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&AccountLink{}))
	DB = db

	now := time.Date(2026, 4, 7, 12, 0, 0, 0, time.UTC)
	reviewedAt := now.Add(10 * time.Minute)
	require.NoError(t, db.Create(&AccountLink{
		UserIDA:         8,
		UserIDB:         3,
		Confidence:      0.45,
		MatchDimensions: 2,
		TotalDimensions: 6,
		MatchDetails:    `[{"dimension":"ip_exact","score":0.45}]`,
		Status:          AccountLinkStatusPending,
		CreatedAt:       now,
		UpdatedAt:       now,
	}).Error)
	require.NoError(t, db.Create(&AccountLink{
		UserIDA:         3,
		UserIDB:         8,
		Confidence:      0.88,
		MatchDimensions: 5,
		TotalDimensions: 6,
		MatchDetails:    `[{"dimension":"device_key","score":0.95}]`,
		Status:          AccountLinkStatusConfirmed,
		ReviewedBy:      7,
		ReviewedAt:      &reviewedAt,
		ReviewNote:      "confirmed by admin",
		CreatedAt:       now.Add(time.Minute),
		UpdatedAt:       reviewedAt,
	}).Error)

	require.NoError(t, EnsureAccountLinkUniqueIndex(db))
	require.True(t, db.Migrator().HasIndex(&AccountLink{}, "uk_link_pair"))

	var links []AccountLink
	require.NoError(t, db.Order("id ASC").Find(&links).Error)
	require.Len(t, links, 1)
	require.Equal(t, 3, links[0].UserIDA)
	require.Equal(t, 8, links[0].UserIDB)
	require.InDelta(t, 0.88, links[0].Confidence, 0.0001)
	require.Equal(t, 5, links[0].MatchDimensions)
	require.Equal(t, AccountLinkStatusConfirmed, links[0].Status)
	require.Equal(t, 7, links[0].ReviewedBy)
	require.NotNil(t, links[0].ReviewedAt)
	require.Equal(t, "confirmed by admin", links[0].ReviewNote)
}

func TestEnsureAccountLinkUniqueIndex_PreservesUnknownLegacyStatus(t *testing.T) {
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&AccountLink{}))
	DB = db

	require.NoError(t, db.Create(&AccountLink{
		UserIDA:      11,
		UserIDB:      12,
		Confidence:   0.66,
		Status:       "legacy_blocked",
		ReviewNote:   "keep custom status",
		MatchDetails: `[{"dimension":"legacy","score":0.66}]`,
	}).Error)

	require.NoError(t, EnsureAccountLinkUniqueIndex(db))

	link := FindExistingLink(11, 12)
	require.NotNil(t, link)
	require.Equal(t, "legacy_blocked", link.Status)
	require.Equal(t, "keep custom status", link.ReviewNote)
}
