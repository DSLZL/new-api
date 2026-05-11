package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRankingRewardRulesParseValidSixKeys(t *testing.T) {
	t.Parallel()

	raw := `{
		"balance.daily": [{"rank": 1, "quota": 1000}, {"rank": 2, "quota": 500}],
		"balance.total": [{"rank": 1, "quota": 2000}],
		"invites.daily": [{"rank": 1, "quota": 1500}],
		"invites.total": [{"rank": 1, "quota": 2500}],
		"consumption.daily": [{"rank": 1, "quota": 1800}],
		"consumption.total": [{"rank": 1, "quota": 3000}]
	}`

	rules, err := ParseRankingRewardRules(raw)
	require.NoError(t, err)
	require.Len(t, rules, 6)
	require.Equal(t, 1000, rules["balance.daily"][0].Quota)
	require.Equal(t, 2, rules["balance.daily"][1].Rank)
}

func TestRankingRewardRulesRejectInvalidLeaderboardKey(t *testing.T) {
	t.Parallel()

	_, err := ParseRankingRewardRules(`{
		"balance.daily": [{"rank": 1, "quota": 1000}],
		"invalid.total": [{"rank": 1, "quota": 999}]
	}`)
	require.Error(t, err)
	require.ErrorContains(t, err, "invalid leaderboard key")
}

func TestRankingRewardRulesRejectDuplicateRankInLeaderboard(t *testing.T) {
	t.Parallel()

	_, err := ParseRankingRewardRules(`{
		"balance.total": [{"rank": 1, "quota": 1000}, {"rank": 1, "quota": 500}]
	}`)
	require.Error(t, err)
	require.ErrorContains(t, err, "duplicate rank")
}

func TestRankingRewardRulesRejectNegativeQuota(t *testing.T) {
	t.Parallel()

	_, err := ParseRankingRewardRules(`{
		"invites.total": [{"rank": 1, "quota": -1}]
	}`)
	require.Error(t, err)
	require.ErrorContains(t, err, "quota")
}

func TestRankingRewardRulesRejectNonIntegerRankOrQuota(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		raw  string
	}{
		{
			name: "non integer rank",
			raw: `{
				"consumption.daily": [{"rank": 1.5, "quota": 1000}]
			}`,
		},
		{
			name: "non integer quota",
			raw: `{
				"consumption.total": [{"rank": 1, "quota": 99.9}]
			}`,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseRankingRewardRules(tc.raw)
			require.Error(t, err)
			require.ErrorContains(t, err, "cannot unmarshal")
		})
	}
}
