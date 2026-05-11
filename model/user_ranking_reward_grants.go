package model

import (
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	RankingRewardGrantStatusSuccess = "success"
	RankingRewardGrantStatusFailed  = "failed"
)

type UserRankingRewardGrant struct {
	Id           int    `json:"id"`
	SettleDate   string `json:"settle_date" gorm:"type:varchar(10);not null;index:idx_user_ranking_reward_grants_settle,priority:1"`
	RankingDate  string `json:"ranking_date" gorm:"type:varchar(10);not null;index:idx_user_ranking_reward_grants_query,priority:1;uniqueIndex:idx_user_ranking_reward_grants_unique,priority:1"`
	Metric       string `json:"metric" gorm:"type:varchar(16);not null;index:idx_user_ranking_reward_grants_query,priority:2;uniqueIndex:idx_user_ranking_reward_grants_unique,priority:2"`
	Period       string `json:"period" gorm:"type:varchar(16);not null;index:idx_user_ranking_reward_grants_query,priority:3;uniqueIndex:idx_user_ranking_reward_grants_unique,priority:3"`
	UserID       int    `json:"user_id" gorm:"not null;index:idx_user_ranking_reward_grants_query,priority:4;uniqueIndex:idx_user_ranking_reward_grants_unique,priority:4"`
	Rank         int    `json:"rank" gorm:"not null;default:0"`
	Quota        int    `json:"quota" gorm:"not null;default:0"`
	Status       string `json:"status" gorm:"type:varchar(16);not null;default:'success'"`
	ErrorMessage string `json:"error_message" gorm:"type:text;default:''"`
	GrantedAt    int64  `json:"granted_at" gorm:"not null;default:0"`
	CreatedAt    int64  `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt    int64  `json:"updated_at" gorm:"autoUpdateTime"`
}

func (UserRankingRewardGrant) TableName() string {
	return "user_ranking_reward_grants"
}

func normalizeUserRankingRewardGrantKey(input string) string {
	return strings.ToLower(strings.TrimSpace(input))
}

func InsertUserRankingRewardGrantIfNotExists(grant *UserRankingRewardGrant) error {
	if grant == nil {
		return gorm.ErrInvalidData
	}

	grant.SettleDate = strings.TrimSpace(grant.SettleDate)
	grant.RankingDate = strings.TrimSpace(grant.RankingDate)
	grant.Metric = normalizeUserRankingRewardGrantKey(grant.Metric)
	grant.Period = normalizeUserRankingRewardGrantKey(grant.Period)
	grant.Status = normalizeUserRankingRewardGrantKey(grant.Status)
	grant.ErrorMessage = strings.TrimSpace(grant.ErrorMessage)

	if grant.SettleDate == "" || grant.RankingDate == "" || grant.Metric == "" || grant.Period == "" || grant.UserID <= 0 {
		return gorm.ErrInvalidData
	}
	if grant.GrantedAt <= 0 {
		grant.GrantedAt = time.Now().Unix()
	}
	if grant.Status == "" {
		grant.Status = RankingRewardGrantStatusSuccess
	}

	return DB.Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "ranking_date"},
			{Name: "metric"},
			{Name: "period"},
			{Name: "user_id"},
		},
		DoNothing: true,
	}).Create(grant).Error
}

func GetUserRankingRewardGrantByUniqueKey(rankingDate, metric, period string, userID int) (*UserRankingRewardGrant, error) {
	rankingDate = strings.TrimSpace(rankingDate)
	metric = normalizeUserRankingRewardGrantKey(metric)
	period = normalizeUserRankingRewardGrantKey(period)
	if rankingDate == "" || metric == "" || period == "" || userID <= 0 {
		return nil, gorm.ErrInvalidData
	}

	var grant UserRankingRewardGrant
	err := DB.Where("ranking_date = ? AND metric = ? AND period = ? AND user_id = ?", rankingDate, metric, period, userID).
		First(&grant).Error
	if err == nil {
		return &grant, nil
	}
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return nil, err
}

func ListUserRankingRewardGrantsBySettleDate(settleDate string) ([]UserRankingRewardGrant, error) {
	settleDate = strings.TrimSpace(settleDate)
	if settleDate == "" {
		return []UserRankingRewardGrant{}, gorm.ErrInvalidData
	}

	records := make([]UserRankingRewardGrant, 0)
	err := DB.Where("settle_date = ?", settleDate).
		Order("id ASC").
		Find(&records).Error
	return records, err
}
