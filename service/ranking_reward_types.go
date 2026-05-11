package service

import (
	"fmt"
	"sort"
	"strings"

	"github.com/QuantumNous/new-api/common"
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

func ParseRankingRewardRules(raw string) (RankingRewardRulesMap, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return RankingRewardRulesMap{}, nil
	}

	var rules RankingRewardRulesMap
	if err := common.Unmarshal([]byte(trimmed), &rules); err != nil {
		return nil, err
	}
	if rules == nil {
		return RankingRewardRulesMap{}, nil
	}
	if err := ValidateRankingRewardRules(rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func ValidateRankingRewardRules(rules RankingRewardRulesMap) error {
	for leaderboardKey, rowRules := range rules {
		if _, ok := rankingRewardAllowedLeaderboardKeys[leaderboardKey]; !ok {
			return fmt.Errorf("invalid leaderboard key: %s", leaderboardKey)
		}

		seenRanks := make(map[int]struct{}, len(rowRules))
		for _, rule := range rowRules {
			if rule.Rank <= 0 {
				return fmt.Errorf("rank must be positive for %s", leaderboardKey)
			}
			if rule.Quota < 0 {
				return fmt.Errorf("quota must be non-negative for %s", leaderboardKey)
			}
			if _, exists := seenRanks[rule.Rank]; exists {
				return fmt.Errorf("duplicate rank %d in leaderboard %s", rule.Rank, leaderboardKey)
			}
			seenRanks[rule.Rank] = struct{}{}
		}
	}

	return nil
}

func RankingRewardAllowedLeaderboardKeys() []string {
	keys := make([]string, 0, len(rankingRewardAllowedLeaderboardKeys))
	for key := range rankingRewardAllowedLeaderboardKeys {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
