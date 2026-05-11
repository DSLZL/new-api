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

func initUserRankingProgressTestDB(t *testing.T) {
	t.Helper()
	dsn := fmt.Sprintf("file:%s_%d?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"), time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&UserRankingProgress{}))
	DB = db
}

func loadUserRankingProgressForTest(t *testing.T, rankingDate, metric, period string, userID int) UserRankingProgress {
	t.Helper()
	var progress UserRankingProgress
	err := DB.Where("ranking_date = ? AND metric = ? AND period = ? AND user_id = ?", rankingDate, metric, period, userID).
		First(&progress).Error
	require.NoError(t, err)
	return progress
}

func TestRankingProgressUpsert_UpdatesReachedAtWhenRankImproves(t *testing.T) {
	initUserRankingProgressTestDB(t)

	const (
		rankingDate = "2026-05-11"
		metric      = "balance"
		period      = "daily"
		userID      = 101
		tick1       = int64(1715385600)
		tick2       = int64(1715385660)
	)

	require.NoError(t, UpsertUserRankingProgress(rankingDate, metric, period, userID, 1000, 3, tick1))
	first := loadUserRankingProgressForTest(t, rankingDate, metric, period, userID)
	require.Equal(t, 3, first.BestRank)
	require.Equal(t, tick1, first.ReachedAt)

	require.NoError(t, UpsertUserRankingProgress(rankingDate, metric, period, userID, 1200, 2, tick2))
	second := loadUserRankingProgressForTest(t, rankingDate, metric, period, userID)
	require.Equal(t, 2, second.BestRank)
	require.Equal(t, tick2, second.ReachedAt)
}

func TestRankingProgressUpsert_DoesNotOverwriteReachedAtForSameOrWorseRank(t *testing.T) {
	initUserRankingProgressTestDB(t)

	const (
		rankingDate = "2026-05-11"
		metric      = "invites"
		period      = "total"
		userID      = 202
		tick1       = int64(1715385600)
		tick2       = int64(1715385660)
		tick3       = int64(1715385720)
	)

	require.NoError(t, UpsertUserRankingProgress(rankingDate, metric, period, userID, 80, 2, tick1))
	initial := loadUserRankingProgressForTest(t, rankingDate, metric, period, userID)
	require.Equal(t, 2, initial.BestRank)
	require.Equal(t, tick1, initial.ReachedAt)

	require.NoError(t, UpsertUserRankingProgress(rankingDate, metric, period, userID, 81, 2, tick2))
	sameRank := loadUserRankingProgressForTest(t, rankingDate, metric, period, userID)
	require.Equal(t, 2, sameRank.BestRank)
	require.Equal(t, tick1, sameRank.ReachedAt)

	require.NoError(t, UpsertUserRankingProgress(rankingDate, metric, period, userID, 79, 3, tick3))
	worseRank := loadUserRankingProgressForTest(t, rankingDate, metric, period, userID)
	require.Equal(t, 2, worseRank.BestRank)
	require.Equal(t, tick1, worseRank.ReachedAt)
}

func TestRankingProgressUpsert_UpdatesFromUninitializedBestRank(t *testing.T) {
	initUserRankingProgressTestDB(t)

	const (
		rankingDate = "2026-05-11"
		metric      = "consumption"
		period      = "daily"
		userID      = 404
		tick1       = int64(1715385600)
		tick2       = int64(1715385660)
	)

	// Seed an uninitialized row as potential migration/backfill edge case.
	require.NoError(t, DB.Create(&UserRankingProgress{
		RankingDate: rankingDate,
		Metric:      metric,
		Period:      period,
		UserID:      userID,
		Value:       0,
		BestRank:    0,
		ReachedAt:   0,
	}).Error)

	require.NoError(t, UpsertUserRankingProgress(rankingDate, metric, period, userID, 777, 5, tick1))
	first := loadUserRankingProgressForTest(t, rankingDate, metric, period, userID)
	require.Equal(t, 5, first.BestRank)
	require.Equal(t, tick1, first.ReachedAt)

	require.NoError(t, UpsertUserRankingProgress(rankingDate, metric, period, userID, 888, 3, tick2))
	second := loadUserRankingProgressForTest(t, rankingDate, metric, period, userID)
	require.Equal(t, 3, second.BestRank)
	require.Equal(t, tick2, second.ReachedAt)
}
