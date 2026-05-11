package service

import (
	"time"

	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/model"
)

type rankingRewardProgressTarget struct {
	leaderboard string
	metric      UserRankingMetric
	period      UserRankingPeriod
}

func rankingRewardProgressTargets() []rankingRewardProgressTarget {
	return []rankingRewardProgressTarget{
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

func trackUserRankingRewardProgress(snapshotCtx userRankingSnapshotContext) error {
	reachedAt := snapshotCtx.snapshotAt.Unix()
	for _, target := range rankingRewardProgressTargets() {
		refTime := snapshotCtx.snapshotAt
		if target.period == UserRankingPeriodDaily {
			// Daily ranks use the target-day fixed-time reference from snapshot task.
			refTime = snapshotCtx.snapshotDayRef
		}

		rows, err := buildUserRankingRows(target.metric, target.period, refTime)
		if err != nil {
			return err
		}

		if err = upsertRankingRewardProgressRows(
			snapshotCtx.snapshotDate,
			string(target.metric),
			string(target.period),
			rows,
			reachedAt,
		); err != nil {
			return err
		}
	}
	return nil
}

func upsertRankingRewardProgressRows(rankingDate, metric, period string, rows []model.UserRankingValueRow, reachedAt int64) error {
	if reachedAt <= 0 {
		reachedAt = time.Now().Unix()
	}
	for idx, row := range rows {
		if row.UserId <= 0 {
			continue
		}
		if err := model.UpsertUserRankingProgress(
			rankingDate,
			metric,
			period,
			row.UserId,
			row.Value,
			idx+1,
			reachedAt,
		); err != nil {
			return err
		}
	}
	return nil
}
