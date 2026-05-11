package service

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	operation_setting "github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestRankingRewardSettlement_SettlesYesterdayOnly(t *testing.T) {
	db := setupRankingRewardSettlementTestDB(t)
	ctx := settlementSnapshotContextForNow(time.Date(2026, 5, 11, 9, 0, 0, 0, beijingLocation()))
	yesterday := ctx.snapshotDate
	today := formatUserRankingDate(ctx.snapshotAt)
	require.Equal(t, "2026-05-10", yesterday)
	require.Equal(t, "2026-05-11", today)

	yUser := mustCreateUser(t, db, model.User{
		Username:    "settle_yesterday_user",
		DisplayName: "Settle Yesterday User",
		AffCode:     "settle-yesterday-user",
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
		Quota:       10,
	})
	tUser := mustCreateUser(t, db, model.User{
		Username:    "settle_today_user",
		DisplayName: "Settle Today User",
		AffCode:     "settle-today-user",
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
		Quota:       20,
	})

	setRankingRewardSettingForTest(t, true, operation_setting.RankingRewardRulesMap{
		RankingRewardLeaderboardInvitesTotal: {
			{Rank: 1, Quota: 100},
		},
	})

	seedRankingSnapshotWithProgress(
		t,
		yesterday,
		UserRankingMetricInvites,
		UserRankingPeriodTotal,
		[]model.UserRankingValueRow{
			{UserId: yUser.Id, Username: yUser.Username, DisplayName: yUser.DisplayName, Value: 9},
		},
		map[int]int64{yUser.Id: ctx.snapshotAt.Unix() - 120},
	)
	seedRankingSnapshotWithProgress(
		t,
		today,
		UserRankingMetricInvites,
		UserRankingPeriodTotal,
		[]model.UserRankingValueRow{
			{UserId: tUser.Id, Username: tUser.Username, DisplayName: tUser.DisplayName, Value: 99},
		},
		map[int]int64{tUser.Id: ctx.snapshotAt.Unix() - 60},
	)

	require.NoError(t, settleUserRankingRewardsForSnapshot(ctx))

	yGrant, err := model.GetUserRankingRewardGrantByUniqueKey(yesterday, string(UserRankingMetricInvites), string(UserRankingPeriodTotal), yUser.Id)
	require.NoError(t, err)
	require.NotNil(t, yGrant)

	tGrant, err := model.GetUserRankingRewardGrantByUniqueKey(today, string(UserRankingMetricInvites), string(UserRankingPeriodTotal), tUser.Id)
	require.NoError(t, err)
	require.Nil(t, tGrant)

	require.Equal(t, 110, loadUserQuotaForTest(t, yUser.Id))
	require.Equal(t, 20, loadUserQuotaForTest(t, tUser.Id))
}

func TestRankingRewardSettlement_TieBreakByReachedAtThenUserID(t *testing.T) {
	db := setupRankingRewardSettlementTestDB(t)
	ctx := settlementSnapshotContextForNow(time.Date(2026, 5, 11, 9, 10, 0, 0, beijingLocation()))
	rankingDate := ctx.snapshotDate

	u1 := mustCreateUser(t, db, model.User{
		Username:    "tie_user_1",
		DisplayName: "Tie User 1",
		AffCode:     "tie-user-1",
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
		Quota:       0,
	})
	u2 := mustCreateUser(t, db, model.User{
		Username:    "tie_user_2",
		DisplayName: "Tie User 2",
		AffCode:     "tie-user-2",
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
		Quota:       0,
	})
	u3 := mustCreateUser(t, db, model.User{
		Username:    "tie_user_3",
		DisplayName: "Tie User 3",
		AffCode:     "tie-user-3",
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
		Quota:       0,
	})

	setRankingRewardSettingForTest(t, true, operation_setting.RankingRewardRulesMap{
		RankingRewardLeaderboardInvitesTotal: {
			{Rank: 1, Quota: 100},
			{Rank: 2, Quota: 50},
		},
	})

	seedRankingSnapshotWithProgress(
		t,
		rankingDate,
		UserRankingMetricInvites,
		UserRankingPeriodTotal,
		[]model.UserRankingValueRow{
			{UserId: u2.Id, Username: u2.Username, DisplayName: u2.DisplayName, Value: 100},
			{UserId: u1.Id, Username: u1.Username, DisplayName: u1.DisplayName, Value: 100},
			{UserId: u3.Id, Username: u3.Username, DisplayName: u3.DisplayName, Value: 90},
		},
		map[int]int64{
			u1.Id: ctx.snapshotAt.Unix() - 120,
			u2.Id: ctx.snapshotAt.Unix() - 60,
			u3.Id: ctx.snapshotAt.Unix() - 30,
		},
	)

	require.NoError(t, settleUserRankingRewardsForSnapshot(ctx))

	g1 := mustLoadGrantForTest(t, rankingDate, string(UserRankingMetricInvites), string(UserRankingPeriodTotal), u1.Id)
	g2 := mustLoadGrantForTest(t, rankingDate, string(UserRankingMetricInvites), string(UserRankingPeriodTotal), u2.Id)
	require.Equal(t, 1, g1.Rank)
	require.Equal(t, 100, g1.Quota)
	require.Equal(t, model.RankingRewardGrantStatusSuccess, g1.Status)
	require.Equal(t, 2, g2.Rank)
	require.Equal(t, 50, g2.Quota)
	require.Equal(t, model.RankingRewardGrantStatusSuccess, g2.Status)

	require.Equal(t, 100, loadUserQuotaForTest(t, u1.Id))
	require.Equal(t, 50, loadUserQuotaForTest(t, u2.Id))
	require.Equal(t, 0, loadUserQuotaForTest(t, u3.Id))
}

func TestRankingRewardSettlement_AllowsStackedRewardsAcrossLeaderboards(t *testing.T) {
	db := setupRankingRewardSettlementTestDB(t)
	ctx := settlementSnapshotContextForNow(time.Date(2026, 5, 11, 9, 20, 0, 0, beijingLocation()))
	rankingDate := ctx.snapshotDate

	u := mustCreateUser(t, db, model.User{
		Username:    "stacked_user",
		DisplayName: "Stacked User",
		AffCode:     "stacked-user",
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
		Quota:       1,
	})

	setRankingRewardSettingForTest(t, true, operation_setting.RankingRewardRulesMap{
		RankingRewardLeaderboardInvitesTotal: {
			{Rank: 1, Quota: 120},
		},
		RankingRewardLeaderboardConsumptionTotal: {
			{Rank: 1, Quota: 230},
		},
	})

	seedRankingSnapshotWithProgress(
		t,
		rankingDate,
		UserRankingMetricInvites,
		UserRankingPeriodTotal,
		[]model.UserRankingValueRow{
			{UserId: u.Id, Username: u.Username, DisplayName: u.DisplayName, Value: 50},
		},
		map[int]int64{u.Id: ctx.snapshotAt.Unix() - 120},
	)
	seedRankingSnapshotWithProgress(
		t,
		rankingDate,
		UserRankingMetricConsumption,
		UserRankingPeriodTotal,
		[]model.UserRankingValueRow{
			{UserId: u.Id, Username: u.Username, DisplayName: u.DisplayName, Value: 5000},
		},
		map[int]int64{u.Id: ctx.snapshotAt.Unix() - 60},
	)

	require.NoError(t, settleUserRankingRewardsForSnapshot(ctx))

	inviteGrant := mustLoadGrantForTest(t, rankingDate, string(UserRankingMetricInvites), string(UserRankingPeriodTotal), u.Id)
	consumptionGrant := mustLoadGrantForTest(t, rankingDate, string(UserRankingMetricConsumption), string(UserRankingPeriodTotal), u.Id)
	require.Equal(t, model.RankingRewardGrantStatusSuccess, inviteGrant.Status)
	require.Equal(t, 120, inviteGrant.Quota)
	require.Equal(t, model.RankingRewardGrantStatusSuccess, consumptionGrant.Status)
	require.Equal(t, 230, consumptionGrant.Quota)
	require.Equal(t, 351, loadUserQuotaForTest(t, u.Id))
}

func TestRankingRewardSettlement_RerunIsIdempotentNoDuplicateGrant(t *testing.T) {
	db := setupRankingRewardSettlementTestDB(t)
	ctx := settlementSnapshotContextForNow(time.Date(2026, 5, 11, 9, 30, 0, 0, beijingLocation()))
	rankingDate := ctx.snapshotDate

	u := mustCreateUser(t, db, model.User{
		Username:    "rerun_user",
		DisplayName: "Rerun User",
		AffCode:     "rerun-user",
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
		Quota:       5,
	})

	setRankingRewardSettingForTest(t, true, operation_setting.RankingRewardRulesMap{
		RankingRewardLeaderboardConsumptionTotal: {
			{Rank: 1, Quota: 88},
		},
	})

	seedRankingSnapshotWithProgress(
		t,
		rankingDate,
		UserRankingMetricConsumption,
		UserRankingPeriodTotal,
		[]model.UserRankingValueRow{
			{UserId: u.Id, Username: u.Username, DisplayName: u.DisplayName, Value: 900},
		},
		map[int]int64{u.Id: ctx.snapshotAt.Unix() - 10},
	)

	require.NoError(t, settleUserRankingRewardsForSnapshot(ctx))
	require.NoError(t, settleUserRankingRewardsForSnapshot(ctx))

	require.Equal(t, 93, loadUserQuotaForTest(t, u.Id))

	var count int64
	require.NoError(t, model.DB.Model(&model.UserRankingRewardGrant{}).
		Where("ranking_date = ? AND metric = ? AND period = ? AND user_id = ?", rankingDate, string(UserRankingMetricConsumption), string(UserRankingPeriodTotal), u.Id).
		Count(&count).Error)
	require.Equal(t, int64(1), count)
}

func TestRankingRewardSettlement_GrantFailureDoesNotAbortWholeRun(t *testing.T) {
	db := setupRankingRewardSettlementTestDB(t)
	ctx := settlementSnapshotContextForNow(time.Date(2026, 5, 11, 9, 40, 0, 0, beijingLocation()))
	rankingDate := ctx.snapshotDate

	u1 := mustCreateUser(t, db, model.User{
		Username:    "partial_fail_user_1",
		DisplayName: "Partial Fail User 1",
		AffCode:     "partial-fail-user-1",
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
		Quota:       0,
	})
	u2 := mustCreateUser(t, db, model.User{
		Username:    "partial_fail_user_2",
		DisplayName: "Partial Fail User 2",
		AffCode:     "partial-fail-user-2",
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
		Quota:       0,
	})

	setRankingRewardSettingForTest(t, true, operation_setting.RankingRewardRulesMap{
		RankingRewardLeaderboardInvitesTotal: {
			{Rank: 1, Quota: 100},
			{Rank: 2, Quota: 40},
		},
	})

	seedRankingSnapshotWithProgress(
		t,
		rankingDate,
		UserRankingMetricInvites,
		UserRankingPeriodTotal,
		[]model.UserRankingValueRow{
			{UserId: u1.Id, Username: u1.Username, DisplayName: u1.DisplayName, Value: 99},
			{UserId: u2.Id, Username: u2.Username, DisplayName: u2.DisplayName, Value: 88},
		},
		map[int]int64{
			u1.Id: ctx.snapshotAt.Unix() - 100,
			u2.Id: ctx.snapshotAt.Unix() - 90,
		},
	)

	setRankingRewardGrantFuncForTest(t, func(userID int, quota int) error {
		if userID == u1.Id {
			return errors.New("forced grant failure")
		}
		return grantRankingRewardQuota(userID, quota)
	})

	require.NoError(t, settleUserRankingRewardsForSnapshot(ctx))

	g1 := mustLoadGrantForTest(t, rankingDate, string(UserRankingMetricInvites), string(UserRankingPeriodTotal), u1.Id)
	g2 := mustLoadGrantForTest(t, rankingDate, string(UserRankingMetricInvites), string(UserRankingPeriodTotal), u2.Id)
	require.Equal(t, model.RankingRewardGrantStatusFailed, g1.Status)
	require.True(t, strings.Contains(strings.ToLower(g1.ErrorMessage), "forced grant failure"))
	require.Equal(t, model.RankingRewardGrantStatusSuccess, g2.Status)

	require.Equal(t, 0, loadUserQuotaForTest(t, u1.Id))
	require.Equal(t, 40, loadUserQuotaForTest(t, u2.Id))
}

func TestRankingRewardSettlement_BalanceDailyPayoutPath(t *testing.T) {
	db := setupRankingRewardSettlementTestDB(t)
	ctx := settlementSnapshotContextForNow(time.Date(2026, 5, 11, 9, 50, 0, 0, beijingLocation()))
	rankingDate := ctx.snapshotDate

	u := mustCreateUser(t, db, model.User{
		Username:    "balance_daily_user",
		DisplayName: "Balance Daily User",
		AffCode:     "balance-daily-user",
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
		Quota:       10,
	})

	setRankingRewardSettingForTest(t, true, operation_setting.RankingRewardRulesMap{
		RankingRewardLeaderboardBalanceDaily: {
			{Rank: 1, Quota: 66},
		},
	})

	seedRankingSnapshotWithProgress(
		t,
		rankingDate,
		UserRankingMetricBalance,
		UserRankingPeriodDaily,
		[]model.UserRankingValueRow{
			{UserId: u.Id, Username: u.Username, DisplayName: u.DisplayName, Value: 1000},
		},
		map[int]int64{u.Id: ctx.snapshotAt.Unix() - 10},
	)

	require.NoError(t, settleUserRankingRewardsForSnapshot(ctx))

	grant := mustLoadGrantForTest(t, rankingDate, string(UserRankingMetricBalance), string(UserRankingPeriodDaily), u.Id)
	require.Equal(t, model.RankingRewardGrantStatusSuccess, grant.Status)
	require.Equal(t, 66, grant.Quota)
	require.Equal(t, 76, loadUserQuotaForTest(t, u.Id))
}

func setupRankingRewardSettlementTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := setupUserRankingServiceTestDB(t)
	setUserRankingVisibility(t, UserRankingVisibilityPublic)
	InvalidateUserRankingCache()
	require.NoError(t, db.AutoMigrate(&model.UserRankingProgress{}, &model.UserRankingRewardGrant{}))
	return db
}

func setRankingRewardSettingForTest(t *testing.T, enabled bool, rules operation_setting.RankingRewardRulesMap) {
	t.Helper()
	old := rankingRewardSettingGetter
	copied := make(operation_setting.RankingRewardRulesMap, len(rules))
	for key, rowRules := range rules {
		rows := make([]operation_setting.RankingRewardRule, len(rowRules))
		copy(rows, rowRules)
		copied[key] = rows
	}
	rankingRewardSettingGetter = func() *operation_setting.RankingRewardSetting {
		return &operation_setting.RankingRewardSetting{
			Enabled: enabled,
			Rules:   copied,
		}
	}
	t.Cleanup(func() {
		rankingRewardSettingGetter = old
	})
}

func setRankingRewardGrantFuncForTest(t *testing.T, fn func(userID int, quota int) error) {
	t.Helper()
	old := rankingRewardGrantQuotaFn
	rankingRewardGrantQuotaFn = fn
	t.Cleanup(func() {
		rankingRewardGrantQuotaFn = old
	})
}

func settlementSnapshotContextForNow(now time.Time) userRankingSnapshotContext {
	return resolveUserRankingSnapshotContext(now)
}

func seedRankingSnapshotWithProgress(
	t *testing.T,
	rankingDate string,
	metric UserRankingMetric,
	period UserRankingPeriod,
	rows []model.UserRankingValueRow,
	reachedAtByUser map[int]int64,
) {
	t.Helper()
	snapshotAt := time.Date(2026, 5, 11, 9, 0, 0, 0, beijingLocation()).Unix()
	require.NoError(t, model.SaveUserRankingSnapshot(rankingDate, string(metric), string(period), rows, snapshotAt))
	for idx, row := range rows {
		reachedAt := reachedAtByUser[row.UserId]
		if reachedAt <= 0 {
			reachedAt = snapshotAt + int64(idx)
		}
		require.NoError(t, model.UpsertUserRankingProgress(
			rankingDate,
			string(metric),
			string(period),
			row.UserId,
			row.Value,
			idx+1,
			reachedAt,
		))
	}
}

func mustLoadGrantForTest(t *testing.T, rankingDate, metric, period string, userID int) *model.UserRankingRewardGrant {
	t.Helper()
	grant, err := model.GetUserRankingRewardGrantByUniqueKey(rankingDate, metric, period, userID)
	require.NoError(t, err)
	require.NotNil(t, grant, fmt.Sprintf("expected grant for user=%d %s.%s", userID, metric, period))
	return grant
}

func loadUserQuotaForTest(t *testing.T, userID int) int {
	t.Helper()
	var quota int
	require.NoError(t, model.DB.Model(&model.User{}).Where("id = ?", userID).Select("quota").Scan(&quota).Error)
	return quota
}
