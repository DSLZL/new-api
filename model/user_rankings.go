package model

import (
	"strings"
	"time"

	"gorm.io/gorm"
)

const defaultUserRankingLimit = 20

type UserRankingValueRow struct {
	UserId      int    `json:"user_id" gorm:"column:user_id"`
	Username    string `json:"username" gorm:"column:username"`
	DisplayName string `json:"display_name" gorm:"column:display_name"`
	Value       int64  `json:"value" gorm:"column:value"`
}

type userRankingAggregateRow struct {
	UserId int   `gorm:"column:user_id"`
	Value  int64 `gorm:"column:value"`
}

type UserRankingSnapshot struct {
	Id           int    `json:"id"`
	SnapshotDate string `json:"snapshot_date" gorm:"type:varchar(10);not null;index:idx_user_ranking_snapshot_query,priority:1;uniqueIndex:idx_user_ranking_snapshot_unique,priority:1"`
	Metric       string `json:"metric" gorm:"type:varchar(16);not null;index:idx_user_ranking_snapshot_query,priority:2;uniqueIndex:idx_user_ranking_snapshot_unique,priority:2"`
	Period       string `json:"period" gorm:"type:varchar(16);not null;index:idx_user_ranking_snapshot_query,priority:3;uniqueIndex:idx_user_ranking_snapshot_unique,priority:3"`
	Rank         int    `json:"rank" gorm:"not null;index:idx_user_ranking_snapshot_query,priority:4;uniqueIndex:idx_user_ranking_snapshot_unique,priority:4"`
	UserId       int    `json:"user_id" gorm:"not null;index:idx_user_ranking_snapshot_user,priority:1"`
	Username     string `json:"username" gorm:"type:varchar(64);default:''"`
	DisplayName  string `json:"display_name" gorm:"type:varchar(64);default:''"`
	Value        int64  `json:"value" gorm:"not null;default:0"`
	SnapshotAt   int64  `json:"snapshot_at" gorm:"not null;index:idx_user_ranking_snapshot_query,priority:5"`
	CreatedAt    int64  `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt    int64  `json:"updated_at" gorm:"autoUpdateTime"`
}

func normalizeUserRankingSnapshotKey(input string) string {
	return strings.ToLower(strings.TrimSpace(input))
}

func sanitizeUserRankingLimit(limit int) int {
	if limit <= 0 {
		return defaultUserRankingLimit
	}
	return limit
}

func SaveUserRankingSnapshot(snapshotDate string, metric string, period string, rows []UserRankingValueRow, snapshotAt int64) error {
	snapshotDate = strings.TrimSpace(snapshotDate)
	metric = normalizeUserRankingSnapshotKey(metric)
	period = normalizeUserRankingSnapshotKey(period)
	if snapshotDate == "" || metric == "" || period == "" {
		return gorm.ErrInvalidData
	}
	if snapshotAt <= 0 {
		snapshotAt = time.Now().Unix()
	}

	tx := DB.Begin()
	if err := tx.Error; err != nil {
		return err
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	if err := tx.Where("snapshot_date = ? AND metric = ? AND period = ?", snapshotDate, metric, period).
		Delete(&UserRankingSnapshot{}).Error; err != nil {
		tx.Rollback()
		return err
	}

	if len(rows) == 0 {
		return tx.Commit().Error
	}

	records := make([]UserRankingSnapshot, 0, len(rows))
	for idx, row := range rows {
		records = append(records, UserRankingSnapshot{
			SnapshotDate: snapshotDate,
			Metric:       metric,
			Period:       period,
			Rank:         idx + 1,
			UserId:       row.UserId,
			Username:     row.Username,
			DisplayName:  row.DisplayName,
			Value:        row.Value,
			SnapshotAt:   snapshotAt,
		})
	}

	if err := tx.Create(&records).Error; err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

func GetUserRankingSnapshot(snapshotDate string, metric string, period string, limit int) ([]UserRankingValueRow, int64, error) {
	snapshotDate = strings.TrimSpace(snapshotDate)
	metric = normalizeUserRankingSnapshotKey(metric)
	period = normalizeUserRankingSnapshotKey(period)
	if snapshotDate == "" || metric == "" || period == "" {
		return []UserRankingValueRow{}, 0, gorm.ErrInvalidData
	}

	limit = sanitizeUserRankingLimit(limit)
	records := make([]UserRankingSnapshot, 0, limit)
	query := DB.Model(&UserRankingSnapshot{}).
		Where("snapshot_date = ? AND metric = ? AND period = ?", snapshotDate, metric, period).
		Order("rank ASC").
		Limit(limit)
	if err := query.Find(&records).Error; err != nil {
		return nil, 0, err
	}

	if len(records) == 0 {
		return []UserRankingValueRow{}, 0, nil
	}

	rows := make([]UserRankingValueRow, 0, len(records))
	for _, record := range records {
		rows = append(rows, UserRankingValueRow{
			UserId:      record.UserId,
			Username:    record.Username,
			DisplayName: record.DisplayName,
			Value:       record.Value,
		})
	}
	return rows, records[0].SnapshotAt, nil
}

func GetUserBalanceRanking(limit int) ([]UserRankingValueRow, error) {
	limit = sanitizeUserRankingLimit(limit)

	rows := make([]UserRankingValueRow, 0, limit)
	err := DB.Model(&User{}).
		Select("id as user_id, username, display_name, quota as value").
		Where("quota > 0").
		Order("quota DESC, id ASC").
		Limit(limit).
		Scan(&rows).Error
	return rows, err
}

func GetUserInviteTotalRanking(limit int) ([]UserRankingValueRow, error) {
	limit = sanitizeUserRankingLimit(limit)

	rows := make([]UserRankingValueRow, 0, limit)
	err := DB.Model(&User{}).
		Select("id as user_id, username, display_name, aff_count as value").
		Where("aff_count > 0").
		Order("aff_count DESC, id ASC").
		Limit(limit).
		Scan(&rows).Error
	return rows, err
}

func GetUserInviteDailyRanking(startTime int64, endTime int64, limit int) ([]UserRankingValueRow, error) {
	limit = sanitizeUserRankingLimit(limit)

	var aggregates []userRankingAggregateRow
	query := DB.Model(&User{}).
		Select("inviter_id as user_id, COUNT(1) as value").
		Where("inviter_id > 0").
		Group("inviter_id").
		Having("COUNT(1) > 0").
		Order("value DESC, inviter_id ASC").
		Limit(limit)
	query = applyUserRankingTimeRange(query, startTime, endTime)
	if err := query.Scan(&aggregates).Error; err != nil {
		return nil, err
	}

	return fillUserRankingRows(aggregates)
}

func GetUserConsumptionTotalRanking(limit int) ([]UserRankingValueRow, error) {
	limit = sanitizeUserRankingLimit(limit)

	rows := make([]UserRankingValueRow, 0, limit)
	err := DB.Model(&User{}).
		Select("id as user_id, username, display_name, used_quota as value").
		Where("used_quota > 0").
		Order("used_quota DESC, id ASC").
		Limit(limit).
		Scan(&rows).Error
	return rows, err
}

func GetUserConsumptionDailyRanking(startTime int64, endTime int64, limit int) ([]UserRankingValueRow, error) {
	limit = sanitizeUserRankingLimit(limit)

	var aggregates []userRankingAggregateRow
	query := LOG_DB.Table("logs").
		Select("user_id as user_id, SUM(quota) as value").
		Where("type = ?", LogTypeConsume).
		Group("user_id").
		Having("SUM(quota) > 0").
		Order("value DESC, user_id ASC").
		Limit(limit)
	query = applyUserRankingTimeRange(query, startTime, endTime)
	if err := query.Scan(&aggregates).Error; err != nil {
		return nil, err
	}

	return fillUserRankingRows(aggregates)
}

func fillUserRankingRows(aggregates []userRankingAggregateRow) ([]UserRankingValueRow, error) {
	if len(aggregates) == 0 {
		return []UserRankingValueRow{}, nil
	}

	userIDs := make([]int, 0, len(aggregates))
	for _, item := range aggregates {
		if item.UserId <= 0 {
			continue
		}
		userIDs = append(userIDs, item.UserId)
	}
	if len(userIDs) == 0 {
		return []UserRankingValueRow{}, nil
	}

	var users []User
	if err := DB.Model(&User{}).
		Select("id, username, display_name").
		Where("id IN ?", userIDs).
		Find(&users).Error; err != nil {
		return nil, err
	}

	userByID := make(map[int]User, len(users))
	for _, user := range users {
		userByID[user.Id] = user
	}

	rows := make([]UserRankingValueRow, 0, len(aggregates))
	for _, item := range aggregates {
		user, ok := userByID[item.UserId]
		if !ok || item.Value <= 0 {
			continue
		}
		rows = append(rows, UserRankingValueRow{
			UserId:      user.Id,
			Username:    user.Username,
			DisplayName: user.DisplayName,
			Value:       item.Value,
		})
	}

	return rows, nil
}

func applyUserRankingTimeRange(query *gorm.DB, startTime int64, endTime int64) *gorm.DB {
	if startTime > 0 {
		query = query.Where("created_at >= ?", startTime)
	}
	if endTime > 0 {
		query = query.Where("created_at < ?", endTime)
	}
	return query
}
