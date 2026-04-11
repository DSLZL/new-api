package model

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	AccountLinkStatusPending       = "pending"
	AccountLinkStatusConfirmed     = "confirmed"
	AccountLinkStatusRejected      = "rejected"
	AccountLinkStatusAutoConfirmed = "auto_confirmed"
	AccountLinkStatusWhitelisted   = "whitelisted"
)

var allowedAccountLinkStatuses = map[string]struct{}{
	AccountLinkStatusPending:       {},
	AccountLinkStatusConfirmed:     {},
	AccountLinkStatusRejected:      {},
	AccountLinkStatusAutoConfirmed: {},
	AccountLinkStatusWhitelisted:   {},
}

// AccountLink 账号关联结果
type AccountLink struct {
	ID int64 `json:"id" gorm:"primaryKey;autoIncrement"`

	UserIDA int `json:"user_id_a" gorm:"not null;index"`
	UserIDB int `json:"user_id_b" gorm:"not null;index"`

	Confidence      float64 `json:"confidence" gorm:"index;not null;default:0"`
	MatchDimensions int     `json:"match_dimensions" gorm:"default:0"`
	TotalDimensions int     `json:"total_dimensions" gorm:"default:0"`

	// PostgreSQL: JSONB; MySQL/SQLite: TEXT (存JSON字符串)
	MatchDetails string `json:"match_details" gorm:"type:text;default:'{}'"`

	Status      string `json:"status" gorm:"type:varchar(20);index;default:'pending'"` // pending/confirmed/rejected/auto_confirmed/whitelisted
	ActionTaken string `json:"action_taken" gorm:"type:varchar(50);default:''"`

	ReviewedBy int        `json:"reviewed_by" gorm:"default:0"`
	ReviewedAt *time.Time `json:"reviewed_at"`
	ReviewNote string     `json:"review_note" gorm:"type:text;default:''"`

	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time `json:"updated_at" gorm:"autoUpdateTime"`
}

func (AccountLink) TableName() string {
	return "account_links"
}

// NormalizePair 确保 user_id_a < user_id_b
func NormalizePair(a, b int) (int, int) {
	if a > b {
		return b, a
	}
	return a, b
}

func GetLinkByUsers(userA, userB int) *AccountLink {
	return FindExistingLink(userA, userB)
}

func FindExistingLink(userA, userB int) *AccountLink {
	a, b := NormalizePair(userA, userB)
	var link AccountLink
	result := DB.Where("user_id_a = ? AND user_id_b = ?", a, b).First(&link)
	if result.Error != nil {
		return nil
	}
	return &link
}

func UpsertLink(userA, userB int, confidence float64, matchDims, totalDims int, detailsJSON string) error {
	a, b := NormalizePair(userA, userB)
	now := time.Now()
	link := AccountLink{
		UserIDA:         a,
		UserIDB:         b,
		Confidence:      confidence,
		MatchDimensions: matchDims,
		TotalDimensions: totalDims,
		MatchDetails:    detailsJSON,
		Status:          AccountLinkStatusPending,
		UpdatedAt:       now,
	}
	return DB.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "user_id_a"}, {Name: "user_id_b"}},
		DoUpdates: clause.Assignments(map[string]any{
			"confidence":       gorm.Expr("CASE WHEN confidence > ? THEN confidence ELSE ? END", confidence, confidence),
			"match_dimensions": gorm.Expr("CASE WHEN confidence > ? THEN match_dimensions ELSE ? END", confidence, matchDims),
			"total_dimensions": gorm.Expr("CASE WHEN confidence > ? THEN total_dimensions ELSE ? END", confidence, totalDims),
			"match_details":    gorm.Expr("CASE WHEN confidence > ? THEN match_details ELSE ? END", confidence, detailsJSON),
			"updated_at":       now,
		}),
	}).Create(&link).Error
}

// UpsertLinkSnapshot 使用当前快照覆盖分数与详情。
// 注意：仅覆盖评分相关字段，不修改 status/reviewed_* / review_note / action_taken 语义。
func UpsertLinkSnapshot(userA, userB int, confidence float64, matchDims, totalDims int, detailsJSON string) error {
	a, b := NormalizePair(userA, userB)
	now := time.Now()
	link := AccountLink{
		UserIDA:         a,
		UserIDB:         b,
		Confidence:      confidence,
		MatchDimensions: matchDims,
		TotalDimensions: totalDims,
		MatchDetails:    detailsJSON,
		Status:          AccountLinkStatusPending,
		UpdatedAt:       now,
	}
	return DB.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "user_id_a"}, {Name: "user_id_b"}},
		DoUpdates: clause.Assignments(map[string]any{
			"confidence":       confidence,
			"match_dimensions": matchDims,
			"total_dimensions": totalDims,
			"match_details":    detailsJSON,
			"updated_at":       now,
		}),
	}).Create(&link).Error
}

type AccountLinkPair struct {
	UserIDA int `gorm:"column:user_id_a"`
	UserIDB int `gorm:"column:user_id_b"`
}

func GetAllAccountLinkPairs() []AccountLinkPair {
	var pairs []AccountLinkPair
	DB.Model(&AccountLink{}).Select("user_id_a, user_id_b").Find(&pairs)
	return pairs
}

func GetLinkedPeerUserIDs(userID int) []int {
	type linkRow struct {
		UserIDA int `gorm:"column:user_id_a"`
		UserIDB int `gorm:"column:user_id_b"`
	}
	var rows []linkRow
	DB.Model(&AccountLink{}).
		Select("user_id_a, user_id_b").
		Where("user_id_a = ? OR user_id_b = ?", userID, userID).
		Find(&rows)
	peerSet := make(map[int]struct{}, len(rows))
	for _, row := range rows {
		if row.UserIDA == userID && row.UserIDB != userID {
			peerSet[row.UserIDB] = struct{}{}
			continue
		}
		if row.UserIDB == userID && row.UserIDA != userID {
			peerSet[row.UserIDA] = struct{}{}
		}
	}
	peers := make([]int, 0, len(peerSet))
	for id := range peerSet {
		peers = append(peers, id)
	}
	return peers
}

// GetUserLinks 获取某个用户的所有关联
func GetUserLinks(userID int, minConf float64) []*AccountLink {
	var links []*AccountLink
	DB.Where(
		"(user_id_a = ? OR user_id_b = ?) AND confidence >= ?",
		userID, userID, minConf,
	).Order("confidence DESC").Find(&links)
	return links
}

func CountLinkedAccounts(userID int, minConf float64) int {
	var count int64
	DB.Model(&AccountLink{}).
		Where("(user_id_a = ? OR user_id_b = ?) AND status != ? AND status != ? AND (confidence >= ? OR status = ? OR status = ?)",
			userID, userID, AccountLinkStatusRejected, AccountLinkStatusWhitelisted, minConf, AccountLinkStatusConfirmed, AccountLinkStatusAutoConfirmed).
		Count(&count)
	return int(count)
}

func GetAccountLinks(status string, minConf float64, page, pageSize int) ([]*AccountLink, int64) {
	var links []*AccountLink
	var total int64

	query := DB.Model(&AccountLink{})
	if status != "" && status != "all" {
		query = query.Where("status = ?", status)
	}
	if minConf > 0 {
		query = query.Where("confidence >= ?", minConf)
	}

	query.Count(&total)
	query.Order("confidence DESC, created_at DESC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&links)

	return links, total
}

func CountLinks(status string) int64 {
	var count int64
	query := DB.Model(&AccountLink{})
	if status != "" && status != "all" {
		query = query.Where("status = ?", status)
	}
	query.Count(&count)
	return count
}

func GetRecentLinks(limit int) []*AccountLink {
	var links []*AccountLink
	DB.Order("created_at DESC").Limit(limit).Find(&links)
	return links
}

func IsValidAccountLinkStatus(status string) bool {
	_, ok := allowedAccountLinkStatuses[strings.TrimSpace(status)]
	return ok
}

func UpdateLinkStatus(linkID int64, status string, reviewedBy int, note string) error {
	status = strings.TrimSpace(status)
	if !IsValidAccountLinkStatus(status) {
		return fmt.Errorf("invalid account link status: %s", status)
	}
	now := time.Now()
	return DB.Model(&AccountLink{}).Where("id = ?", linkID).Updates(map[string]any{
		"status":      status,
		"reviewed_by": reviewedBy,
		"reviewed_at": &now,
		"review_note": note,
	}).Error
}

func UpdateLinkStatusIfCurrent(linkID int64, currentStatus, nextStatus string, reviewedBy int, note string) (bool, error) {
	currentStatus = strings.TrimSpace(currentStatus)
	nextStatus = strings.TrimSpace(nextStatus)
	if !IsValidAccountLinkStatus(currentStatus) {
		return false, fmt.Errorf("invalid current account link status: %s", currentStatus)
	}
	if !IsValidAccountLinkStatus(nextStatus) {
		return false, fmt.Errorf("invalid next account link status: %s", nextStatus)
	}
	now := time.Now()
	result := DB.Model(&AccountLink{}).
		Where("id = ? AND status = ?", linkID, currentStatus).
		Updates(map[string]any{
			"status":      nextStatus,
			"reviewed_by": reviewedBy,
			"reviewed_at": &now,
			"review_note": note,
		})
	if result.Error != nil {
		return false, result.Error
	}
	return result.RowsAffected > 0, nil
}

func UpdateLinkAction(linkID int64, action string) error {
	return DB.Model(&AccountLink{}).Where("id = ?", linkID).Update("action_taken", action).Error
}

func EnsureAccountLinkUniqueIndex(db *gorm.DB) error {
	if db == nil {
		return nil
	}
	const indexName = "uk_link_pair"
	if err := normalizeAccountLinksForUniqueIndex(db); err != nil {
		return err
	}
	if db.Migrator().HasIndex(&AccountLink{}, indexName) {
		return nil
	}
	return db.Exec("CREATE UNIQUE INDEX uk_link_pair ON account_links(user_id_a, user_id_b)").Error
}

func normalizeAccountLinksForUniqueIndex(db *gorm.DB) error {
	tx := db.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	var links []AccountLink
	if err := tx.Order("id ASC").Find(&links).Error; err != nil {
		tx.Rollback()
		return err
	}

	type accountLinkGroup struct {
		merged AccountLink
		ids    []int64
	}
	groups := make(map[string]accountLinkGroup, len(links))
	for _, link := range links {
		normalized := link
		normalized.UserIDA, normalized.UserIDB = NormalizePair(link.UserIDA, link.UserIDB)
		normalized.Status = canonicalAccountLinkStatus(link.Status)
		key := fmt.Sprintf("%d:%d", normalized.UserIDA, normalized.UserIDB)
		group, ok := groups[key]
		if !ok {
			groups[key] = accountLinkGroup{merged: normalized, ids: []int64{normalized.ID}}
			continue
		}
		group.merged = mergeAccountLinkRows(group.merged, normalized)
		group.ids = append(group.ids, normalized.ID)
		groups[key] = group
	}

	for _, group := range groups {
		deleteIDs := make([]int64, 0, len(group.ids)-1)
		for _, id := range group.ids {
			if id != group.merged.ID {
				deleteIDs = append(deleteIDs, id)
			}
		}
		if len(deleteIDs) > 0 {
			if err := tx.Where("id IN ?", deleteIDs).Delete(&AccountLink{}).Error; err != nil {
				tx.Rollback()
				return err
			}
		}
		if err := tx.Model(&AccountLink{}).Where("id = ?", group.merged.ID).Updates(map[string]any{
			"user_id_a":        group.merged.UserIDA,
			"user_id_b":        group.merged.UserIDB,
			"confidence":       group.merged.Confidence,
			"match_dimensions": group.merged.MatchDimensions,
			"total_dimensions": group.merged.TotalDimensions,
			"match_details":    group.merged.MatchDetails,
			"status":           group.merged.Status,
			"action_taken":     group.merged.ActionTaken,
			"reviewed_by":      group.merged.ReviewedBy,
			"reviewed_at":      group.merged.ReviewedAt,
			"review_note":      group.merged.ReviewNote,
			"updated_at":       group.merged.UpdatedAt,
			"created_at":       group.merged.CreatedAt,
		}).Error; err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit().Error
}

func canonicalAccountLinkStatus(status string) string {
	status = strings.TrimSpace(status)
	if status == "" {
		return AccountLinkStatusPending
	}
	if !IsValidAccountLinkStatus(status) {
		return status
	}
	return status
}

func accountLinkStatusRank(status string) int {
	switch canonicalAccountLinkStatus(status) {
	case AccountLinkStatusWhitelisted:
		return 4
	case AccountLinkStatusConfirmed, AccountLinkStatusRejected:
		return 3
	case AccountLinkStatusAutoConfirmed:
		return 2
	default:
		return 1
	}
}

func mergeAccountLinkStatus(current, incoming string, currentReviewedAt, incomingReviewedAt *time.Time) string {
	current = canonicalAccountLinkStatus(current)
	incoming = canonicalAccountLinkStatus(incoming)
	currentRank := accountLinkStatusRank(current)
	incomingRank := accountLinkStatusRank(incoming)
	if incomingRank > currentRank {
		return incoming
	}
	if incomingRank < currentRank {
		return current
	}
	if current == incoming {
		return current
	}
	if incomingReviewedAt != nil && (currentReviewedAt == nil || incomingReviewedAt.After(*currentReviewedAt)) {
		return incoming
	}
	return current
}

func mergeAccountLinkRows(current, incoming AccountLink) AccountLink {
	merged := current
	if incoming.Confidence >= merged.Confidence {
		merged.Confidence = incoming.Confidence
		merged.MatchDimensions = incoming.MatchDimensions
		merged.TotalDimensions = incoming.TotalDimensions
		if strings.TrimSpace(incoming.MatchDetails) != "" {
			merged.MatchDetails = incoming.MatchDetails
		}
	} else if strings.TrimSpace(merged.MatchDetails) == "" && strings.TrimSpace(incoming.MatchDetails) != "" {
		merged.MatchDetails = incoming.MatchDetails
	}

	merged.Status = mergeAccountLinkStatus(merged.Status, incoming.Status, merged.ReviewedAt, incoming.ReviewedAt)
	if incoming.ReviewedAt != nil && (merged.ReviewedAt == nil || incoming.ReviewedAt.After(*merged.ReviewedAt)) {
		merged.ReviewedAt = incoming.ReviewedAt
		merged.ReviewedBy = incoming.ReviewedBy
		if strings.TrimSpace(incoming.ReviewNote) != "" {
			merged.ReviewNote = incoming.ReviewNote
		}
	} else {
		if merged.ReviewedBy == 0 && incoming.ReviewedBy > 0 {
			merged.ReviewedBy = incoming.ReviewedBy
		}
		if strings.TrimSpace(merged.ReviewNote) == "" && strings.TrimSpace(incoming.ReviewNote) != "" {
			merged.ReviewNote = incoming.ReviewNote
		}
	}
	if strings.TrimSpace(merged.ActionTaken) == "" && strings.TrimSpace(incoming.ActionTaken) != "" {
		merged.ActionTaken = incoming.ActionTaken
	}
	if incoming.UpdatedAt.After(merged.UpdatedAt) {
		merged.UpdatedAt = incoming.UpdatedAt
	}
	if merged.CreatedAt.IsZero() || (!incoming.CreatedAt.IsZero() && incoming.CreatedAt.Before(merged.CreatedAt)) {
		merged.CreatedAt = incoming.CreatedAt
	}
	merged.UserIDA = current.UserIDA
	merged.UserIDB = current.UserIDB
	merged.ID = current.ID
	return merged
}

func GetLinkByID(linkID int64) *AccountLink {
	var link AccountLink
	if err := DB.First(&link, linkID).Error; err != nil {
		return nil
	}
	return &link
}

// ParseMatchDetails 解析 match_details JSON
func (l *AccountLink) ParseMatchDetails() map[string]any {
	var result map[string]any
	_ = json.Unmarshal([]byte(l.MatchDetails), &result)
	return result
}
