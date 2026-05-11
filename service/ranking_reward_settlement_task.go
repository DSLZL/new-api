package service

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/logger"
	"github.com/QuantumNous/new-api/model"
	operation_setting "github.com/QuantumNous/new-api/setting/operation_setting"
)

var (
	rankingRewardSettingGetter = operation_setting.GetRankingRewardSetting
	rankingRewardGrantQuotaFn  = grantRankingRewardQuota
)

type rankingRewardSettlementTarget struct {
	leaderboard string
	metric      UserRankingMetric
	period      UserRankingPeriod
}

func rankingRewardSettlementTargets() []rankingRewardSettlementTarget {
	return []rankingRewardSettlementTarget{
		{
			leaderboard: constant.RankingRewardLeaderboardBalanceDaily,
			metric:      UserRankingMetricBalance,
			period:      UserRankingPeriodDaily,
		},
		{
			leaderboard: constant.RankingRewardLeaderboardBalanceTotal,
			metric:      UserRankingMetricBalance,
			period:      UserRankingPeriodTotal,
		},
		{
			leaderboard: constant.RankingRewardLeaderboardInvitesDaily,
			metric:      UserRankingMetricInvites,
			period:      UserRankingPeriodDaily,
		},
		{
			leaderboard: constant.RankingRewardLeaderboardInvitesTotal,
			metric:      UserRankingMetricInvites,
			period:      UserRankingPeriodTotal,
		},
		{
			leaderboard: constant.RankingRewardLeaderboardConsumptionDaily,
			metric:      UserRankingMetricConsumption,
			period:      UserRankingPeriodDaily,
		},
		{
			leaderboard: constant.RankingRewardLeaderboardConsumptionTotal,
			metric:      UserRankingMetricConsumption,
			period:      UserRankingPeriodTotal,
		},
	}
}

func settleUserRankingRewardsForSnapshot(snapshotCtx userRankingSnapshotContext) error {
	setting := rankingRewardSettingGetter()
	if setting == nil || !setting.Enabled || len(setting.Rules) == 0 {
		return nil
	}

	rankingDate := strings.TrimSpace(snapshotCtx.snapshotDate)
	if rankingDate == "" {
		return nil
	}
	settleDate := formatUserRankingDate(snapshotCtx.snapshotAt)
	grantedAt := snapshotCtx.snapshotAt.Unix()

	for _, target := range rankingRewardSettlementTargets() {
		rules := setting.Rules[target.leaderboard]
		if len(rules) == 0 {
			continue
		}
		if err := settleUserRankingRewardTarget(settleDate, rankingDate, target, rules, grantedAt); err != nil {
			return err
		}
	}
	return nil
}

func settleUserRankingRewardTarget(
	settleDate string,
	rankingDate string,
	target rankingRewardSettlementTarget,
	rules []operation_setting.RankingRewardRule,
	grantedAt int64,
) error {
	rows, _, err := model.GetUserRankingSnapshot(rankingDate, string(target.metric), string(target.period), rankingLeaderboardLimit)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}

	progressRows, err := model.ListUserRankingProgressByTarget(rankingDate, string(target.metric), string(target.period))
	if err != nil {
		return err
	}
	reachedAtByUser := make(map[int]int64, len(progressRows))
	for _, row := range progressRows {
		reachedAtByUser[row.UserID] = row.ReachedAt
	}

	resolvedRows := append([]model.UserRankingValueRow(nil), rows...)
	sort.SliceStable(resolvedRows, func(i, j int) bool {
		if resolvedRows[i].Value != resolvedRows[j].Value {
			return resolvedRows[i].Value > resolvedRows[j].Value
		}
		leftReachedAt := reachedAtForTieBreak(resolvedRows[i].UserId, reachedAtByUser)
		rightReachedAt := reachedAtForTieBreak(resolvedRows[j].UserId, reachedAtByUser)
		if leftReachedAt != rightReachedAt {
			return leftReachedAt < rightReachedAt
		}
		return resolvedRows[i].UserId < resolvedRows[j].UserId
	})

	sortedRules := append([]operation_setting.RankingRewardRule(nil), rules...)
	sort.Slice(sortedRules, func(i, j int) bool {
		return sortedRules[i].Rank < sortedRules[j].Rank
	})

	for _, rule := range sortedRules {
		if rule.Rank <= 0 || rule.Rank > len(resolvedRows) {
			continue
		}
		winner := resolvedRows[rule.Rank-1]
		if winner.UserId <= 0 {
			continue
		}
		existing, err := model.GetUserRankingRewardGrantByUniqueKey(rankingDate, string(target.metric), string(target.period), winner.UserId)
		if err != nil {
			return err
		}
		if existing != nil {
			continue
		}

		grant := &model.UserRankingRewardGrant{
			SettleDate:  settleDate,
			RankingDate: rankingDate,
			Metric:      string(target.metric),
			Period:      string(target.period),
			UserID:      winner.UserId,
			Rank:        rule.Rank,
			Quota:       rule.Quota,
			GrantedAt:   grantedAt,
			Status:      model.RankingRewardGrantStatusSuccess,
		}

		grantErr := rankingRewardGrantQuotaFn(winner.UserId, rule.Quota)
		if grantErr != nil {
			grant.Status = model.RankingRewardGrantStatusFailed
			grant.ErrorMessage = grantErr.Error()
			if err = model.InsertUserRankingRewardGrantIfNotExists(grant); err != nil {
				return err
			}
			logger.LogWarn(context.Background(), fmt.Sprintf("ranking reward grant failed: date=%s metric=%s period=%s user_id=%d rank=%d quota=%d err=%v", rankingDate, target.metric, target.period, winner.UserId, rule.Rank, rule.Quota, grantErr))
			continue
		}

		if err = model.InsertUserRankingRewardGrantIfNotExists(grant); err != nil {
			return err
		}
		model.RecordLog(winner.UserId, model.LogTypeSystem, fmt.Sprintf("排行榜奖励发放：%s.%s 名次 #%d 奖励 %s", target.metric, target.period, rule.Rank, logger.LogQuota(rule.Quota)))
	}
	return nil
}

func reachedAtForTieBreak(userID int, reachedAtByUser map[int]int64) int64 {
	if reachedAt, ok := reachedAtByUser[userID]; ok && reachedAt > 0 {
		return reachedAt
	}
	return math.MaxInt64
}

func grantRankingRewardQuota(userID int, quota int) error {
	if userID <= 0 {
		return fmt.Errorf("invalid user id: %d", userID)
	}
	if quota < 0 {
		return fmt.Errorf("invalid reward quota: %d", quota)
	}
	if quota == 0 {
		return nil
	}
	return model.IncreaseUserQuota(userID, quota, false)
}
