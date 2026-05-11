package constant

const (
	RankingRewardLeaderboardBalanceDaily     = "balance.daily"
	RankingRewardLeaderboardBalanceTotal     = "balance.total"
	RankingRewardLeaderboardInvitesDaily     = "invites.daily"
	RankingRewardLeaderboardInvitesTotal     = "invites.total"
	RankingRewardLeaderboardConsumptionDaily = "consumption.daily"
	RankingRewardLeaderboardConsumptionTotal = "consumption.total"
)

var RankingRewardAllowedLeaderboardKeys = map[string]struct{}{
	RankingRewardLeaderboardBalanceDaily:     {},
	RankingRewardLeaderboardBalanceTotal:     {},
	RankingRewardLeaderboardInvitesDaily:     {},
	RankingRewardLeaderboardInvitesTotal:     {},
	RankingRewardLeaderboardConsumptionDaily: {},
	RankingRewardLeaderboardConsumptionTotal: {},
}
