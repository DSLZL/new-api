package model

import (
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type UserRankingProgress struct {
	Id          int    `json:"id"`
	RankingDate string `json:"ranking_date" gorm:"type:varchar(10);not null;index:idx_user_ranking_progress_query,priority:1;uniqueIndex:idx_user_ranking_progress_unique,priority:1"`
	Metric      string `json:"metric" gorm:"type:varchar(16);not null;index:idx_user_ranking_progress_query,priority:2;uniqueIndex:idx_user_ranking_progress_unique,priority:2"`
	Period      string `json:"period" gorm:"type:varchar(16);not null;index:idx_user_ranking_progress_query,priority:3;uniqueIndex:idx_user_ranking_progress_unique,priority:3"`
	UserID      int    `json:"user_id" gorm:"not null;index:idx_user_ranking_progress_query,priority:4;uniqueIndex:idx_user_ranking_progress_unique,priority:4"`
	Value       int64  `json:"value" gorm:"not null;default:0"`
	BestRank    int    `json:"best_rank" gorm:"not null;default:0;index:idx_user_ranking_progress_query,priority:5"`
	ReachedAt   int64  `json:"reached_at" gorm:"not null;default:0"`
	CreatedAt   int64  `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt   int64  `json:"updated_at" gorm:"autoUpdateTime"`
}

func (UserRankingProgress) TableName() string {
	return "user_ranking_progress"
}

func normalizeUserRankingProgressKey(input string) string {
	return strings.ToLower(strings.TrimSpace(input))
}

func UpsertUserRankingProgress(rankingDate, metric, period string, userID int, value int64, rank int, reachedAt int64) error {
	rankingDate = strings.TrimSpace(rankingDate)
	metric = normalizeUserRankingProgressKey(metric)
	period = normalizeUserRankingProgressKey(period)
	if rankingDate == "" || metric == "" || period == "" || userID <= 0 || rank <= 0 {
		return gorm.ErrInvalidData
	}
	if reachedAt <= 0 {
		reachedAt = time.Now().Unix()
	}

	progress := UserRankingProgress{
		RankingDate: rankingDate,
		Metric:      metric,
		Period:      period,
		UserID:      userID,
		Value:       value,
		BestRank:    rank,
		ReachedAt:   reachedAt,
	}

	return DB.Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "ranking_date"},
			{Name: "metric"},
			{Name: "period"},
			{Name: "user_id"},
		},
		DoUpdates: clause.Assignments(map[string]any{
			"value": value,
			"best_rank": gorm.Expr(
				"CASE WHEN best_rank <= 0 OR best_rank > ? THEN ? ELSE best_rank END",
				rank, rank,
			),
			"reached_at": gorm.Expr(
				"CASE WHEN best_rank <= 0 OR best_rank > ? THEN ? ELSE reached_at END",
				rank, reachedAt,
			),
			"updated_at": time.Now().Unix(),
		}),
	}).Create(&progress).Error
}

func GetUserRankingProgress(rankingDate, metric, period string, userID int) (*UserRankingProgress, error) {
	rankingDate = strings.TrimSpace(rankingDate)
	metric = normalizeUserRankingProgressKey(metric)
	period = normalizeUserRankingProgressKey(period)
	if rankingDate == "" || metric == "" || period == "" || userID <= 0 {
		return nil, gorm.ErrInvalidData
	}

	var progress UserRankingProgress
	err := DB.Where("ranking_date = ? AND metric = ? AND period = ? AND user_id = ?", rankingDate, metric, period, userID).
		First(&progress).Error
	if err == nil {
		return &progress, nil
	}
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return nil, err
}

func ListUserRankingProgressByTarget(rankingDate, metric, period string) ([]UserRankingProgress, error) {
	rankingDate = strings.TrimSpace(rankingDate)
	metric = normalizeUserRankingProgressKey(metric)
	period = normalizeUserRankingProgressKey(period)
	if rankingDate == "" || metric == "" || period == "" {
		return []UserRankingProgress{}, gorm.ErrInvalidData
	}

	records := make([]UserRankingProgress, 0)
	err := DB.Where("ranking_date = ? AND metric = ? AND period = ?", rankingDate, metric, period).
		Order("best_rank ASC, reached_at ASC, user_id ASC").
		Find(&records).Error
	return records, err
}
