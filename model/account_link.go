package model

import (
	"encoding/json"
	"time"
)

// AccountLink 账号关联结果
type AccountLink struct {
	ID int64 `json:"id" gorm:"primaryKey;autoIncrement"`

	UserIDA int `json:"user_id_a" gorm:"index;not null"`
	UserIDB int `json:"user_id_b" gorm:"index;not null"`

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

	existing := FindExistingLink(a, b)
	if existing != nil {
		// 更新
		return DB.Model(existing).Updates(map[string]interface{}{
			"confidence":       confidence,
			"match_dimensions": matchDims,
			"total_dimensions": totalDims,
			"match_details":    detailsJSON,
			"updated_at":       time.Now(),
		}).Error
	}

	// 新建
	link := AccountLink{
		UserIDA:         a,
		UserIDB:         b,
		Confidence:      confidence,
		MatchDimensions: matchDims,
		TotalDimensions: totalDims,
		MatchDetails:    detailsJSON,
		Status:          "pending",
	}
	return DB.Create(&link).Error
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
		Where("(user_id_a = ? OR user_id_b = ?) AND confidence >= ? AND status != 'rejected' AND status != 'whitelisted'",
			userID, userID, minConf).
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

func UpdateLinkStatus(linkID int64, status string, reviewedBy int, note string) error {
	now := time.Now()
	return DB.Model(&AccountLink{}).Where("id = ?", linkID).Updates(map[string]interface{}{
		"status":      status,
		"reviewed_by": reviewedBy,
		"reviewed_at": &now,
		"review_note": note,
	}).Error
}

func UpdateLinkAction(linkID int64, action string) error {
	return DB.Model(&AccountLink{}).Where("id = ?", linkID).Update("action_taken", action).Error
}

func GetLinkByID(linkID int64) *AccountLink {
	var link AccountLink
	if err := DB.First(&link, linkID).Error; err != nil {
		return nil
	}
	return &link
}

// ParseMatchDetails 解析 match_details JSON
func (l *AccountLink) ParseMatchDetails() map[string]interface{} {
	var result map[string]interface{}
	_ = json.Unmarshal([]byte(l.MatchDetails), &result)
	return result
}
