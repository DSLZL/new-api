package model

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/glebarez/sqlite"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm/logger"
	"gorm.io/gorm"
)

func initAccountLinkTestDB(t *testing.T) {
	t.Helper()
	dsn := fmt.Sprintf("file:%s_%d?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"), time.Now().UnixNano())
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

func TestUpsertLinkSnapshot_ReturnsErrorWhenUniqueIndexNotReady(t *testing.T) {
	dsn := fmt.Sprintf("file:%s_%d?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"), time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&AccountLink{}))
	DB = db
	setAccountLinkWritesReady(false)

	err = UpsertLinkSnapshot(1, 2, 0.9, 2, 3, `[]`)
	require.ErrorIs(t, err, ErrAccountLinkUniqueIndexNotReady)
}

func TestUpsertLink_ReturnsErrorWhenUniqueIndexNotReady(t *testing.T) {
	dsn := fmt.Sprintf("file:%s_%d?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"), time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&AccountLink{}))
	DB = db
	setAccountLinkWritesReady(false)

	err = UpsertLink(1, 2, 0.9, 2, 3, `[]`)
	require.ErrorIs(t, err, ErrAccountLinkUniqueIndexNotReady)
}

func TestRepairAccountLinkUniqueIndex_NormalizesLegacyRows(t *testing.T) {
	dsn := fmt.Sprintf("file:%s_%d?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"), time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&AccountLink{}, &Option{}))
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

	require.NoError(t, RepairAccountLinkUniqueIndex(db))
	require.True(t, db.Migrator().HasIndex(&AccountLink{}, "uk_link_pair"))

	var option Option
	require.NoError(t, db.Where("key = ?", accountLinkUniqueIndexNormalizedOptionKey).First(&option).Error)
	require.Equal(t, accountLinkUniqueIndexNormalizedOptionVal, option.Value)

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
	dsn := fmt.Sprintf("file:%s_%d?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"), time.Now().UnixNano())
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

func TestRepairAccountLinkUniqueIndex_MarkerDoesNotSkipNormalizationWithoutIndex(t *testing.T) {
	dsn := fmt.Sprintf("file:%s_%d?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"), time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&AccountLink{}, &Option{}))
	DB = db

	require.NoError(t, db.Create(&AccountLink{
		UserIDA:      8,
		UserIDB:      3,
		Confidence:   0.66,
		Status:       AccountLinkStatusPending,
		MatchDetails: `[{"dimension":"ip_exact","score":0.66}]`,
	}).Error)
	require.NoError(t, db.Create(&Option{
		Key:   accountLinkUniqueIndexNormalizedOptionKey,
		Value: accountLinkUniqueIndexNormalizedOptionVal,
	}).Error)

	require.NoError(t, RepairAccountLinkUniqueIndex(db))
	require.True(t, db.Migrator().HasIndex(&AccountLink{}, accountLinkUniqueIndexName))

	var links []AccountLink
	require.NoError(t, db.Order("id ASC").Find(&links).Error)
	require.Len(t, links, 1)
	require.Equal(t, 3, links[0].UserIDA)
	require.Equal(t, 8, links[0].UserIDB)
}

func TestEnsureAccountLinkUniqueIndex_SkipsHeavyRepairOnStartupWhenLegacyDataExists(t *testing.T) {
	dsn := fmt.Sprintf("file:%s_%d?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"), time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&AccountLink{}, &Option{}))
	DB = db

	require.NoError(t, db.Create(&AccountLink{UserIDA: 9, UserIDB: 4, Confidence: 0.4, Status: AccountLinkStatusPending, MatchDetails: `[]`}).Error)
	require.NoError(t, db.Create(&AccountLink{UserIDA: 4, UserIDB: 9, Confidence: 0.8, Status: AccountLinkStatusConfirmed, MatchDetails: `[]`}).Error)

	require.NoError(t, EnsureAccountLinkUniqueIndex(db))
	require.False(t, db.Migrator().HasIndex(&AccountLink{}, accountLinkUniqueIndexName))

	var links []AccountLink
	require.NoError(t, db.Order("id ASC").Find(&links).Error)
	require.Len(t, links, 2)
}

func TestEnsureAccountLinkUniqueIndex_ReturnsImmediatelyWhenIndexExists(t *testing.T) {
	dsn := fmt.Sprintf("file:%s_%d?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"), time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&AccountLink{}, &Option{}))
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX uk_link_pair ON account_links(user_id_a, user_id_b)").Error)
	DB = db

	require.NoError(t, db.Create(&AccountLink{
		UserIDA:      8,
		UserIDB:      3,
		Confidence:   0.66,
		Status:       AccountLinkStatusPending,
		MatchDetails: `[{"dimension":"ip_exact","score":0.66}]`,
	}).Error)

	require.NoError(t, EnsureAccountLinkUniqueIndex(db))

	var links []AccountLink
	require.NoError(t, db.Order("id ASC").Find(&links).Error)
	require.Len(t, links, 1)
	require.Equal(t, 8, links[0].UserIDA)
	require.Equal(t, 3, links[0].UserIDB)

	var count int64
	require.NoError(t, db.Model(&Option{}).Where("key = ?", accountLinkUniqueIndexNormalizedOptionKey).Count(&count).Error)
	require.Equal(t, int64(0), count)
}

func TestEnsureAccountLinkUniqueIndex_StartupCheckLogAndNoFullTableSelectWhenIndexExists(t *testing.T) {
	dsn := fmt.Sprintf("file:%s_%d?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"), time.Now().UnixNano())
	var sqlBuf bytes.Buffer
	gormLogger := logger.New(log.New(&sqlBuf, "", 0), logger.Config{
		SlowThreshold:             time.Second,
		LogLevel:                  logger.Info,
		IgnoreRecordNotFoundError: true,
		Colorful:                  false,
	})
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: gormLogger})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&AccountLink{}, &Option{}))
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX uk_link_pair ON account_links(user_id_a, user_id_b)").Error)
	DB = db

	var logBuf bytes.Buffer
	origWriter := gin.DefaultWriter
	common.LogWriterMu.Lock()
	gin.DefaultWriter = io.MultiWriter(origWriter, &logBuf)
	common.LogWriterMu.Unlock()
	t.Cleanup(func() {
		common.LogWriterMu.Lock()
		gin.DefaultWriter = origWriter
		common.LogWriterMu.Unlock()
	})

	require.NoError(t, EnsureAccountLinkUniqueIndex(db))

	logText := logBuf.String()
	require.Contains(t, logText, "account_links unique index check: index exists, skip startup repair")

	sqlText := strings.ToLower(sqlBuf.String())
	require.NotContains(t, sqlText, "select * from `account_links`")
	require.NotContains(t, sqlText, "select * from \"account_links\"")
}

func TestRepairAccountLinkUniqueIndex_EmitsRepairLogs(t *testing.T) {
	dsn := fmt.Sprintf("file:%s_%d?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"), time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&AccountLink{}, &Option{}))
	DB = db

	require.NoError(t, db.Create(&AccountLink{UserIDA: 9, UserIDB: 4, Confidence: 0.4, Status: AccountLinkStatusPending, MatchDetails: `[]`}).Error)
	require.NoError(t, db.Create(&AccountLink{UserIDA: 4, UserIDB: 9, Confidence: 0.8, Status: AccountLinkStatusConfirmed, MatchDetails: `[]`}).Error)

	var logBuf bytes.Buffer
	origWriter := gin.DefaultWriter
	common.LogWriterMu.Lock()
	gin.DefaultWriter = io.MultiWriter(origWriter, &logBuf)
	common.LogWriterMu.Unlock()
	t.Cleanup(func() {
		common.LogWriterMu.Lock()
		gin.DefaultWriter = origWriter
		common.LogWriterMu.Unlock()
	})

	require.NoError(t, RepairAccountLinkUniqueIndex(db))

	logText := logBuf.String()
	require.Contains(t, logText, "account_links unique index repair: legacy anomalies detected, starting normalization")
	require.Contains(t, logText, "account_links unique index repair: normalization completed")
}

func TestEnsureAccountLinkUniqueIndex_DoesNotRepeatRepairAfterManualRepair(t *testing.T) {
	dsn := fmt.Sprintf("file:%s_%d?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"), time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&AccountLink{}, &Option{}))
	DB = db

	require.NoError(t, db.Create(&AccountLink{UserIDA: 9, UserIDB: 4, Confidence: 0.4, Status: AccountLinkStatusPending, MatchDetails: `[]`}).Error)
	require.NoError(t, db.Create(&AccountLink{UserIDA: 4, UserIDB: 9, Confidence: 0.8, Status: AccountLinkStatusConfirmed, MatchDetails: `[]`}).Error)

	require.NoError(t, RepairAccountLinkUniqueIndex(db))
	require.True(t, db.Migrator().HasIndex(&AccountLink{}, accountLinkUniqueIndexName))

	var logBuf bytes.Buffer
	origWriter := gin.DefaultWriter
	common.LogWriterMu.Lock()
	gin.DefaultWriter = io.MultiWriter(origWriter, &logBuf)
	common.LogWriterMu.Unlock()
	t.Cleanup(func() {
		common.LogWriterMu.Lock()
		gin.DefaultWriter = origWriter
		common.LogWriterMu.Unlock()
	})

	require.NoError(t, EnsureAccountLinkUniqueIndex(db))
	require.Contains(t, logBuf.String(), "account_links unique index check: index exists, skip startup repair")

	var links []AccountLink
	require.NoError(t, db.Order("id ASC").Find(&links).Error)
	require.Len(t, links, 1)
}

func TestAccountLinksNeedUniqueIndexNormalization_DetectsReverseAndDuplicatePairs(t *testing.T) {
	dsn := fmt.Sprintf("file:%s_%d?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"), time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&AccountLink{}))

	require.NoError(t, db.Create(&AccountLink{UserIDA: 9, UserIDB: 4, Confidence: 0.4, Status: AccountLinkStatusPending, MatchDetails: `[]`}).Error)
	require.True(t, accountLinksNeedUniqueIndexNormalization(db))

	require.NoError(t, db.Exec("DELETE FROM account_links").Error)
	require.NoError(t, db.Create(&AccountLink{UserIDA: 4, UserIDB: 9, Confidence: 0.4, Status: AccountLinkStatusPending, MatchDetails: `[]`}).Error)
	require.NoError(t, db.Create(&AccountLink{UserIDA: 4, UserIDB: 9, Confidence: 0.5, Status: AccountLinkStatusConfirmed, MatchDetails: `[]`}).Error)
	require.True(t, accountLinksNeedUniqueIndexNormalization(db))
}

func TestCreateAccountLinkUniqueIndex_SQLIsCrossDBCompatible(t *testing.T) {
	origPg := common.UsingPostgreSQL
	origMy := common.UsingMySQL
	origSq := common.UsingSQLite
	defer func() {
		common.UsingPostgreSQL = origPg
		common.UsingMySQL = origMy
		common.UsingSQLite = origSq
	}()

	type probe struct {
		usePg bool
		useMy bool
		useSq bool
	}
	cases := []probe{
		{usePg: true},
		{useMy: true},
		{useSq: true},
	}
	for _, tc := range cases {
		common.UsingPostgreSQL = tc.usePg
		common.UsingMySQL = tc.useMy
		common.UsingSQLite = tc.useSq

		db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s_%d?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"), time.Now().UnixNano())), &gorm.Config{})
		require.NoError(t, err)
		require.NoError(t, db.AutoMigrate(&AccountLink{}))
		require.NoError(t, createAccountLinkUniqueIndex(db))
		require.True(t, db.Migrator().HasIndex(&AccountLink{}, accountLinkUniqueIndexName))
	}
}

func TestCollectAccountLinkNormalizationGroups_BatchesRows(t *testing.T) {
	dsn := fmt.Sprintf("file:%s_%d?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"), time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&AccountLink{}))

	for i := range accountLinkNormalizeBatchSize + 5 {
		userA, userB := NormalizePair(100+i%3, 200+i%3)
		if i%2 == 0 {
			userA, userB = userB, userA
		}
		require.NoError(t, db.Create(&AccountLink{
			UserIDA:         userA,
			UserIDB:         userB,
			Confidence:      0.4 + float64(i)/1000,
			MatchDimensions: 1 + i%5,
			TotalDimensions: 6,
			Status:          AccountLinkStatusPending,
			MatchDetails:    `[]`,
		}).Error)
	}

	groups, scannedRows, err := collectAccountLinkNormalizationGroups(db, 64)
	require.NoError(t, err)
	require.Greater(t, scannedRows, 0)
	require.Len(t, groups, 3)
	for _, group := range groups {
		require.Greater(t, len(group.ids), 0)
		require.True(t, group.merged.UserIDA < group.merged.UserIDB)
	}
}

func TestGetLinksByUserAndCandidates_BatchesAndMapsByPeer(t *testing.T) {
	initAccountLinkTestDB(t)

	require.NoError(t, DB.Create(&AccountLink{
		UserIDA:      50,
		UserIDB:      60,
		Confidence:   0.91,
		Status:       AccountLinkStatusConfirmed,
		MatchDetails: `[{"dimension":"device_key","score":0.91}]`,
	}).Error)
	require.NoError(t, DB.Create(&AccountLink{
		UserIDA:      60,
		UserIDB:      50,
		Confidence:   0.33,
		Status:       AccountLinkStatusPending,
		MatchDetails: `[{"dimension":"ip_exact","score":0.33}]`,
	}).Error)
	require.NoError(t, DB.Create(&AccountLink{
		UserIDA:      70,
		UserIDB:      50,
		Confidence:   0.72,
		Status:       AccountLinkStatusAutoConfirmed,
		MatchDetails: `[{"dimension":"canvas","score":0.72}]`,
	}).Error)
	require.NoError(t, DB.Create(&AccountLink{
		UserIDA:      91,
		UserIDB:      92,
		Confidence:   0.88,
		Status:       AccountLinkStatusConfirmed,
		MatchDetails: `[{"dimension":"noise","score":0.88}]`,
	}).Error)

	links := GetLinksByUserAndCandidates(50, []int{-1, 0, 50, 60, 60, 70, 80})
	require.Len(t, links, 2)
	require.Contains(t, links, 60)
	require.Contains(t, links, 70)
	require.NotContains(t, links, 80)

	require.Equal(t, AccountLinkStatusConfirmed, links[60].Status)
	require.InDelta(t, 0.91, links[60].Confidence, 0.0001)
	require.Equal(t, AccountLinkStatusAutoConfirmed, links[70].Status)
	require.InDelta(t, 0.72, links[70].Confidence, 0.0001)
}

func BenchmarkEnsureAccountLinkUniqueIndex_StartupPaths(b *testing.B) {
	origWriter := gin.DefaultWriter
	common.LogWriterMu.Lock()
	gin.DefaultWriter = io.Discard
	common.LogWriterMu.Unlock()
	b.Cleanup(func() {
		common.LogWriterMu.Lock()
		gin.DefaultWriter = origWriter
		common.LogWriterMu.Unlock()
	})

	makeDB := func(name string, withIndex bool, withLegacy bool) *gorm.DB {
		dsn := fmt.Sprintf("file:%s_%d?mode=memory&cache=shared", name, time.Now().UnixNano())
		db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
		if err != nil {
			b.Fatalf("open db failed: %v", err)
		}
		if err := db.AutoMigrate(&AccountLink{}, &Option{}); err != nil {
			b.Fatalf("migrate failed: %v", err)
		}
		if withIndex {
			if err := db.Exec("CREATE UNIQUE INDEX uk_link_pair ON account_links(user_id_a, user_id_b)").Error; err != nil {
				b.Fatalf("create index failed: %v", err)
			}
		}
		if withLegacy {
			if err := db.Create(&AccountLink{UserIDA: 9, UserIDB: 4, Confidence: 0.4, Status: AccountLinkStatusPending, MatchDetails: `[]`}).Error; err != nil {
				b.Fatalf("seed row1 failed: %v", err)
			}
			if err := db.Create(&AccountLink{UserIDA: 4, UserIDB: 9, Confidence: 0.8, Status: AccountLinkStatusConfirmed, MatchDetails: `[]`}).Error; err != nil {
				b.Fatalf("seed row2 failed: %v", err)
			}
		}
		return db
	}

	b.Run("index_exists_fast_return", func(b *testing.B) {
		db := makeDB("bench_index_exists", true, false)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := EnsureAccountLinkUniqueIndex(db); err != nil {
				b.Fatalf("EnsureAccountLinkUniqueIndex failed: %v", err)
			}
		}
	})

	b.Run("legacy_detected_skip_heavy", func(b *testing.B) {
		db := makeDB("bench_legacy_detect", false, true)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := EnsureAccountLinkUniqueIndex(db); err != nil {
				b.Fatalf("EnsureAccountLinkUniqueIndex failed: %v", err)
			}
		}
	})
}
