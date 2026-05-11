package operation_setting

import (
	"github.com/QuantumNous/new-api/setting/config"
	"github.com/QuantumNous/new-api/constant"
)

const (
	RankingRewardLeaderboardBalanceDaily     = constant.RankingRewardLeaderboardBalanceDaily
	RankingRewardLeaderboardBalanceTotal     = constant.RankingRewardLeaderboardBalanceTotal
	RankingRewardLeaderboardInvitesDaily     = constant.RankingRewardLeaderboardInvitesDaily
	RankingRewardLeaderboardInvitesTotal     = constant.RankingRewardLeaderboardInvitesTotal
	RankingRewardLeaderboardConsumptionDaily = constant.RankingRewardLeaderboardConsumptionDaily
	RankingRewardLeaderboardConsumptionTotal = constant.RankingRewardLeaderboardConsumptionTotal
)

var rankingRewardAllowedLeaderboardKeys = constant.RankingRewardAllowedLeaderboardKeys

type RankingRewardRule struct {
	Rank  int `json:"rank"`
	Quota int `json:"quota"`
}

type RankingRewardRulesMap map[string][]RankingRewardRule

type RankingRewardSetting struct {
	Enabled bool                  `json:"enabled"`
	Rules   RankingRewardRulesMap `json:"rules"`
}

var rankingRewardSetting = RankingRewardSetting{
	Enabled: false,
	Rules:   RankingRewardRulesMap{},
}

func init() {
	config.GlobalConfig.Register("ranking_reward_setting", &rankingRewardSetting)
}

func GetRankingRewardSetting() *RankingRewardSetting {
	clone := &RankingRewardSetting{
		Enabled: rankingRewardSetting.Enabled,
		Rules:   make(RankingRewardRulesMap, len(rankingRewardSetting.Rules)),
	}

	for key, rules := range rankingRewardSetting.Rules {
		copied := make([]RankingRewardRule, len(rules))
		copy(copied, rules)
		clone.Rules[key] = copied
	}

	if !validateRankingRewardRules(clone.Rules) {
		clone.Rules = RankingRewardRulesMap{}
	}
	if clone.Rules == nil {
		clone.Rules = RankingRewardRulesMap{}
	}

	return clone
}

func validateRankingRewardRules(rules RankingRewardRulesMap) bool {
	for leaderboardKey, rowRules := range rules {
		if _, ok := rankingRewardAllowedLeaderboardKeys[leaderboardKey]; !ok {
			return false
		}
		seenRanks := make(map[int]struct{}, len(rowRules))
		for _, rule := range rowRules {
			if rule.Rank <= 0 || rule.Quota < 0 {
				return false
			}
			if _, exists := seenRanks[rule.Rank]; exists {
				return false
			}
			seenRanks[rule.Rank] = struct{}{}
		}
	}
	return true
}
