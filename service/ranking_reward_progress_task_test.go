package service

import (
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/model"
	"github.com/stretchr/testify/require"
)

func TestRankingRewardProgressTargets_IncludeAllLeaderboards(t *testing.T) {
	targets := rankingRewardProgressTargets()
	require.Len(t, targets, 6)

	got := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		got[target.leaderboard] = struct{}{}
	}

	expected := map[string]struct{}{
		constant.RankingRewardLeaderboardBalanceDaily:     {},
		constant.RankingRewardLeaderboardBalanceTotal:     {},
		constant.RankingRewardLeaderboardInvitesDaily:     {},
		constant.RankingRewardLeaderboardInvitesTotal:     {},
		constant.RankingRewardLeaderboardConsumptionDaily: {},
		constant.RankingRewardLeaderboardConsumptionTotal: {},
	}
	require.Equal(t, expected, got)
}

func TestRankingRewardProgress_ReachedAtUpdateAndNoOverwriteAcrossMetricPaths(t *testing.T) {
	type caseData struct {
		name    string
		metric  UserRankingMetric
		period  UserRankingPeriod
		seedA   func(t *testing.T, dbID int)
		seedB   func(t *testing.T, dbID int)
		improve func(t *testing.T, dbID int)
		stable  func(t *testing.T, dbID int)
	}

	cases := []caseData{
		{
			name:   "balance_daily_absolute_ranking",
			metric: UserRankingMetricBalance,
			period: UserRankingPeriodDaily,
			seedA: func(t *testing.T, userID int) {
				t.Helper()
				require.NoError(t, model.DB.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]any{
					"quota": int64(100),
				}).Error)
			},
			seedB: func(t *testing.T, userID int) {
				t.Helper()
				require.NoError(t, model.DB.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]any{
					"quota": int64(300),
				}).Error)
			},
			improve: func(t *testing.T, userID int) {
				t.Helper()
				require.NoError(t, model.DB.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]any{
					"quota": int64(500),
				}).Error)
			},
			stable: func(t *testing.T, userID int) {
				t.Helper()
				require.NoError(t, model.DB.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]any{
					"quota": int64(520),
				}).Error)
			},
		},
		{
			name:   "invites_total",
			metric: UserRankingMetricInvites,
			period: UserRankingPeriodTotal,
			seedA: func(t *testing.T, userID int) {
				t.Helper()
				require.NoError(t, model.DB.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]any{
					"aff_count": int64(2),
				}).Error)
			},
			seedB: func(t *testing.T, userID int) {
				t.Helper()
				require.NoError(t, model.DB.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]any{
					"aff_count": int64(3),
				}).Error)
			},
			improve: func(t *testing.T, userID int) {
				t.Helper()
				require.NoError(t, model.DB.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]any{
					"aff_count": int64(4),
				}).Error)
			},
			stable: func(t *testing.T, userID int) {
				t.Helper()
				require.NoError(t, model.DB.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]any{
					"aff_count": int64(5),
				}).Error)
			},
		},
		{
			name:   "consumption_total",
			metric: UserRankingMetricConsumption,
			period: UserRankingPeriodTotal,
			seedA: func(t *testing.T, userID int) {
				t.Helper()
				require.NoError(t, model.DB.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]any{
					"used_quota": int64(120),
				}).Error)
			},
			seedB: func(t *testing.T, userID int) {
				t.Helper()
				require.NoError(t, model.DB.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]any{
					"used_quota": int64(300),
				}).Error)
			},
			improve: func(t *testing.T, userID int) {
				t.Helper()
				require.NoError(t, model.DB.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]any{
					"used_quota": int64(450),
				}).Error)
			},
			stable: func(t *testing.T, userID int) {
				t.Helper()
				require.NoError(t, model.DB.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]any{
					"used_quota": int64(480),
				}).Error)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := setupUserRankingServiceTestDB(t)
			setUserRankingVisibility(t, UserRankingVisibilityPublic)
			InvalidateUserRankingCache()
			require.NoError(t, db.AutoMigrate(&model.UserRankingProgress{}))

			a := mustCreateUser(t, db, model.User{
				Username:    "progress_a_" + tc.name,
				DisplayName: "Progress A",
				AffCode:     "progress-a-" + tc.name,
				Status:      common.UserStatusEnabled,
				Role:        common.RoleCommonUser,
			})
			b := mustCreateUser(t, db, model.User{
				Username:    "progress_b_" + tc.name,
				DisplayName: "Progress B",
				AffCode:     "progress-b-" + tc.name,
				Status:      common.UserStatusEnabled,
				Role:        common.RoleCommonUser,
			})

			tc.seedA(t, a.Id)
			tc.seedB(t, b.Id)

			tick1 := time.Date(2026, 5, 11, 9, 0, 0, 0, beijingLocation())
			ctx1 := resolveUserRankingProgressContext(tick1)
			require.NoError(t, trackUserRankingRewardProgress(ctx1))

			first, err := model.GetUserRankingProgress(ctx1.snapshotDate, string(tc.metric), string(tc.period), a.Id)
			require.NoError(t, err)
			require.NotNil(t, first)
			require.Equal(t, 2, first.BestRank)
			require.Equal(t, ctx1.snapshotAt.Unix(), first.ReachedAt)

			tc.improve(t, a.Id)

			tick2 := tick1.Add(1 * time.Minute)
			ctx2 := resolveUserRankingProgressContext(tick2)
			require.NoError(t, trackUserRankingRewardProgress(ctx2))

			second, err := model.GetUserRankingProgress(ctx2.snapshotDate, string(tc.metric), string(tc.period), a.Id)
			require.NoError(t, err)
			require.NotNil(t, second)
			require.Equal(t, 1, second.BestRank)
			require.Equal(t, ctx2.snapshotAt.Unix(), second.ReachedAt)

			tc.stable(t, a.Id)

			tick3 := tick2.Add(1 * time.Minute)
			ctx3 := resolveUserRankingProgressContext(tick3)
			require.NoError(t, trackUserRankingRewardProgress(ctx3))

			third, err := model.GetUserRankingProgress(ctx3.snapshotDate, string(tc.metric), string(tc.period), a.Id)
			require.NoError(t, err)
			require.NotNil(t, third)
			require.Equal(t, 1, third.BestRank)
			require.Equal(t, ctx2.snapshotAt.Unix(), third.ReachedAt)
		})
	}
}

func TestRankingRewardProgress_UsesCurrentBeijingDayKey(t *testing.T) {
	db := setupUserRankingServiceTestDB(t)
	setUserRankingVisibility(t, UserRankingVisibilityPublic)
	InvalidateUserRankingCache()
	require.NoError(t, db.AutoMigrate(&model.UserRankingProgress{}))

	u1 := mustCreateUser(t, db, model.User{
		Username:    "progress_day_u1",
		DisplayName: "Progress Day U1",
		AffCode:     "progress-day-u1",
		Quota:       500,
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
	})
	_ = mustCreateUser(t, db, model.User{
		Username:    "progress_day_u2",
		DisplayName: "Progress Day U2",
		AffCode:     "progress-day-u2",
		Quota:       300,
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
	})

	// Beijing 2026-05-11 00:05:00: snapshot context date is yesterday, progress context date must be today.
	tickNow := time.Date(2026, 5, 11, 0, 5, 0, 0, beijingLocation())
	snapshotCtx := resolveUserRankingSnapshotContext(tickNow)
	progressCtx := resolveUserRankingProgressContext(tickNow)
	require.NotEqual(t, snapshotCtx.snapshotDate, progressCtx.snapshotDate)
	require.Equal(t, "2026-05-10", snapshotCtx.snapshotDate)
	require.Equal(t, "2026-05-11", progressCtx.snapshotDate)

	require.NoError(t, trackUserRankingRewardProgress(progressCtx))

	progressToday, err := model.GetUserRankingProgress(progressCtx.snapshotDate, string(UserRankingMetricBalance), string(UserRankingPeriodDaily), u1.Id)
	require.NoError(t, err)
	require.NotNil(t, progressToday)

	progressYesterday, err := model.GetUserRankingProgress(snapshotCtx.snapshotDate, string(UserRankingMetricBalance), string(UserRankingPeriodDaily), u1.Id)
	require.NoError(t, err)
	require.Nil(t, progressYesterday)
}
