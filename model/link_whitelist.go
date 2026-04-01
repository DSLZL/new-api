package model

import (
	"time"
)

// LinkWhitelist 关联白名单
type LinkWhitelist struct {
	ID        int64     `json:"id" gorm:"primaryKey;autoIncrement"`
	UserIDA   int       `json:"user_id_a" gorm:"not null"`
	UserIDB   int       `json:"user_id_b" gorm:"not null"`
	Reason    string    `json:"reason" gorm:"type:text;default:''"`
	CreatedBy int       `json:"created_by" gorm:"not null"`
	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
}

func (LinkWhitelist) TableName() string {
	return "link_whitelist"
}

// AddToWhitelist 添加白名单
func AddToWhitelist(userA, userB, createdBy int, reason string) error {
	a, b := NormalizePair(userA, userB)
	wl := LinkWhitelist{
		UserIDA:   a,
		UserIDB:   b,
		Reason:    reason,
		CreatedBy: createdBy,
	}
	// 先检查是否已存在
	var existing LinkWhitelist
	result := DB.Where("user_id_a = ? AND user_id_b = ?", a, b).First(&existing)
	if result.Error == nil {
		return nil // 已存在
	}
	return DB.Create(&wl).Error
}

// IsWhitelisted 检查是否在白名单中
func IsWhitelisted(userA, userB int) bool {
	a, b := NormalizePair(userA, userB)
	var count int64
	DB.Model(&LinkWhitelist{}).Where("user_id_a = ? AND user_id_b = ?", a, b).Count(&count)
	return count > 0
}

// GetWhitelistedPairs 获取指定用户的所有白名单对端用户
func GetWhitelistedPairs(userID int) map[int]bool {
	var whitelist []LinkWhitelist
	DB.Where("user_id_a = ? OR user_id_b = ?", userID, userID).Find(&whitelist)

	result := make(map[int]bool)
	for _, wl := range whitelist {
		if wl.UserIDA == userID {
			result[wl.UserIDB] = true
		} else {
			result[wl.UserIDA] = true
		}
	}
	return result
}

// RemoveFromWhitelist 移除白名单
func RemoveFromWhitelist(userA, userB int) error {
	a, b := NormalizePair(userA, userB)
	return DB.Where("user_id_a = ? AND user_id_b = ?", a, b).Delete(&LinkWhitelist{}).Error
}
