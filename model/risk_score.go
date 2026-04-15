package model

import (
	"time"

	"github.com/QuantumNous/new-api/common"
)

// UserRiskScore 用户风险评分
type UserRiskScore struct {
	ID     int64 `json:"id" gorm:"primaryKey;autoIncrement"`
	UserID int   `json:"user_id" gorm:"uniqueIndex;not null"`

	RiskScore float32 `json:"risk_score" gorm:"default:0"`
	RiskLevel string  `json:"risk_level" gorm:"type:varchar(10);index;default:'low'"` // low/medium/high/critical

	LinkedAccounts       int `json:"linked_accounts" gorm:"default:0"`
	FingerprintAnomalies int `json:"fingerprint_anomalies" gorm:"default:0"`

	// IP维度
	UniqueIPsCount   int     `json:"unique_ips_count" gorm:"default:0"`
	VPNUsageRate     float32 `json:"vpn_usage_rate" gorm:"default:0"`
	DatacenterIPRate float32 `json:"datacenter_ip_rate" gorm:"default:0"`
	TorUsageCount    int     `json:"tor_usage_count" gorm:"default:0"`

	// UA维度
	UniqueUACount   int     `json:"unique_ua_count" gorm:"default:0"`
	UAOSConsistency float32 `json:"ua_os_consistency" gorm:"default:0"`

	// 指纹稳定性
	FingerprintChangeRate float32 `json:"fingerprint_change_rate" gorm:"default:0"`

	Detail string `json:"detail" gorm:"type:text;default:'{}'"`

	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time `json:"updated_at" gorm:"autoUpdateTime"`
}

func (UserRiskScore) TableName() string {
	return "user_risk_scores"
}

func GetUserRiskScore(userID int) *UserRiskScore {
	var score UserRiskScore
	if err := DB.Where("user_id = ?", userID).First(&score).Error; err != nil {
		return nil
	}
	return &score
}

func UpsertRiskScore(score *UserRiskScore) error {
	existing := GetUserRiskScore(score.UserID)
	if existing != nil {
		return DB.Model(existing).Updates(map[string]any{
			"risk_score":              score.RiskScore,
			"risk_level":              score.RiskLevel,
			"linked_accounts":         score.LinkedAccounts,
			"fingerprint_anomalies":   score.FingerprintAnomalies,
			"unique_ips_count":        score.UniqueIPsCount,
			"vpn_usage_rate":          score.VPNUsageRate,
			"datacenter_ip_rate":      score.DatacenterIPRate,
			"tor_usage_count":         score.TorUsageCount,
			"unique_ua_count":         score.UniqueUACount,
			"ua_os_consistency":       score.UAOSConsistency,
			"fingerprint_change_rate": score.FingerprintChangeRate,
			"detail":                  score.Detail,
		}).Error
	}
	return DB.Create(score).Error
}

func CountUsersByRisk(level string) int64 {
	var count int64
	DB.Model(&UserRiskScore{}).Where("risk_level = ?", level).Count(&count)
	return count
}

func GetTopRiskUsers(limit int) []*UserRiskScore {
	var scores []*UserRiskScore
	DB.Order("risk_score DESC").Limit(limit).Find(&scores)
	return scores
}

func GetAllUserIDsWithFingerprints() []int {
	var userIDs []int
	DB.Model(&Fingerprint{}).Distinct("user_id").Pluck("user_id", &userIDs)
	return userIDs
}

func GetActiveUserIDsWithFingerprints(activeWindowHours int, maxUsers int) []int {
	if maxUsers <= 0 {
		return nil
	}
	if activeWindowHours <= 0 {
		activeWindowHours = 24 * 7
	}

	cutoff := time.Now().Add(-time.Duration(activeWindowHours) * time.Hour)
	userIDs := make([]int, 0, maxUsers)
	if err := DB.Model(&Fingerprint{}).
		Where("created_at >= ?", cutoff).
		Select("user_id").
		Group("user_id").
		Order("MAX(created_at) DESC").
		Limit(maxUsers).
		Pluck("user_id", &userIDs).Error; err != nil {
		common.SysError("failed to load active users with fingerprints: " + err.Error())
		fallbackUserIDs := GetAllUserIDsWithFingerprints()
		if len(fallbackUserIDs) > maxUsers {
			return fallbackUserIDs[:maxUsers]
		}
		return fallbackUserIDs
	}
	return userIDs
}
