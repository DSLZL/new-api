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

func initUserRankingRewardGrantTestDB(t *testing.T) {
	t.Helper()
	dsn := fmt.Sprintf("file:%s_%d?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"), time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&UserRankingRewardGrant{}))
	DB = db
}

func TestRankingRewardGrantInsert_IdempotentByUniqueKey(t *testing.T) {
	initUserRankingRewardGrantTestDB(t)

	first := UserRankingRewardGrant{
		SettleDate:  "2026-05-12",
		RankingDate: "2026-05-11",
		Metric:      "consumption",
		Period:      "daily",
		UserID:      303,
		Rank:        1,
		Quota:       1800,
		Status:      RankingRewardGrantStatusSuccess,
		GrantedAt:   1715472000,
	}
	require.NoError(t, InsertUserRankingRewardGrantIfNotExists(&first))

	dup := UserRankingRewardGrant{
		SettleDate:  "2026-05-12",
		RankingDate: "2026-05-11",
		Metric:      "consumption",
		Period:      "daily",
		UserID:      303,
		Rank:        2,
		Quota:       9999,
		Status:      RankingRewardGrantStatusFailed,
		GrantedAt:   1715472600,
	}
	require.NoError(t, InsertUserRankingRewardGrantIfNotExists(&dup))

	var count int64
	require.NoError(t, DB.Model(&UserRankingRewardGrant{}).
		Where("ranking_date = ? AND metric = ? AND period = ? AND user_id = ?", "2026-05-11", "consumption", "daily", 303).
		Count(&count).Error)
	require.Equal(t, int64(1), count)

	stored, err := GetUserRankingRewardGrantByUniqueKey("2026-05-11", "consumption", "daily", 303)
	require.NoError(t, err)
	require.NotNil(t, stored)
	require.Equal(t, 1, stored.Rank)
	require.Equal(t, 1800, stored.Quota)
	require.Equal(t, RankingRewardGrantStatusSuccess, stored.Status)
}
