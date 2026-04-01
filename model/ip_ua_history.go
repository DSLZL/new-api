package model

import (
	"time"

	"github.com/QuantumNous/new-api/common"
)

// IPUAHistory IP/UA 使用历史
type IPUAHistory struct {
	ID int64 `json:"id" gorm:"primaryKey;autoIncrement"`

	UserID    int    `json:"user_id" gorm:"index;not null"`
	IPAddress string `json:"ip_address" gorm:"type:varchar(45);index;not null"`
	UserAgent string `json:"user_agent" gorm:"type:text;default:''"`

	// IP情报
	IPCountry   string  `json:"ip_country" gorm:"type:varchar(10);default:''"`
	IPRegion    string  `json:"ip_region" gorm:"type:varchar(50);default:''"`
	IPCity      string  `json:"ip_city" gorm:"type:varchar(50);default:''"`
	IPISP       string  `json:"ip_isp" gorm:"type:varchar(100);default:''"`
	IPType      string  `json:"ip_type" gorm:"type:varchar(20);default:''"`
	IPRiskScore float32 `json:"ip_risk_score" gorm:"default:0"`

	// UA解析
	UABrowser    string `json:"ua_browser" gorm:"type:varchar(50);default:''"`
	UABrowserVer string `json:"ua_browser_ver" gorm:"type:varchar(20);default:''"`
	UAOS         string `json:"ua_os" gorm:"column:ua_os;type:varchar(50);default:''"`
	UAOSVer      string `json:"ua_os_ver" gorm:"column:ua_os_ver;type:varchar(20);default:''"`
	UADevice     string `json:"ua_device" gorm:"type:varchar(50);default:''"`

	// 访问信息
	Endpoint     string    `json:"endpoint" gorm:"type:varchar(200);default:''"`
	RequestCount int       `json:"request_count" gorm:"default:1"`
	FirstSeen    time.Time `json:"first_seen" gorm:"autoCreateTime"`
	LastSeen     time.Time `json:"last_seen" gorm:"autoUpdateTime"`
}

func (IPUAHistory) TableName() string {
	return "ip_ua_history"
}

// UpsertIPUAHistory 插入或更新 IP/UA 历史记录
func UpsertIPUAHistory(record *IPUAHistory) error {
	if common.UsingPostgreSQL {
		return DB.Exec(`
			INSERT INTO ip_ua_history 
				(user_id, ip_address, user_agent, ip_country, ip_region, ip_city, ip_isp, ip_type, ip_risk_score,
				 ua_browser, ua_browser_ver, ua_os, ua_os_ver, ua_device, endpoint, request_count, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, NOW(), NOW())
			ON CONFLICT (user_id, ip_address, ua_browser, ua_os) 
			DO UPDATE SET 
				request_count = ip_ua_history.request_count + 1,
				last_seen = NOW(),
				user_agent = EXCLUDED.user_agent,
				endpoint = EXCLUDED.endpoint,
				ip_type = COALESCE(NULLIF(EXCLUDED.ip_type, ''), ip_ua_history.ip_type),
				ip_risk_score = CASE WHEN EXCLUDED.ip_risk_score > 0 THEN EXCLUDED.ip_risk_score ELSE ip_ua_history.ip_risk_score END
		`,
			record.UserID, record.IPAddress, record.UserAgent,
			record.IPCountry, record.IPRegion, record.IPCity, record.IPISP, record.IPType, record.IPRiskScore,
			record.UABrowser, record.UABrowserVer, record.UAOS, record.UAOSVer, record.UADevice,
			record.Endpoint,
		).Error
	}

	// MySQL/SQLite: 先查后更新
	var existing IPUAHistory
	result := DB.Where("user_id = ? AND ip_address = ? AND ua_browser = ? AND ua_os = ?",
		record.UserID, record.IPAddress, record.UABrowser, record.UAOS).First(&existing)

	if result.Error != nil {
		// 不存在，创建
		return DB.Create(record).Error
	}
	// 存在，更新
	return DB.Model(&existing).Updates(map[string]interface{}{
		"request_count": existing.RequestCount + 1,
		"last_seen":     time.Now(),
		"user_agent":    record.UserAgent,
		"endpoint":      record.Endpoint,
	}).Error
}

// FindUsersByIP 根据IP查找用户
func FindUsersByIP(ip string) []int {
	var userIDs []int
	DB.Model(&IPUAHistory{}).
		Where("ip_address = ?", ip).
		Distinct("user_id").
		Pluck("user_id", &userIDs)
	return userIDs
}

// FindUsersByIPSubnet 根据IP子网查找用户 (前缀匹配)
func FindUsersByIPSubnet(subnet string) []int {
	var userIDs []int
	DB.Model(&IPUAHistory{}).
		Where("ip_address LIKE ?", subnet+"%").
		Distinct("user_id").
		Pluck("user_id", &userIDs)
	return userIDs
}

// GetUserIPs 获取用户的所有历史IP
func GetUserIPs(userID int) []string {
	var ips []string
	DB.Model(&IPUAHistory{}).
		Where("user_id = ?", userID).
		Distinct("ip_address").
		Pluck("ip_address", &ips)
	return ips
}

// GetIPUAHistory 获取用户的IP/UA历史
func GetIPUAHistory(userID int) []*IPUAHistory {
	var history []*IPUAHistory
	DB.Where("user_id = ?", userID).
		Order("last_seen DESC").
		Find(&history)
	return history
}

// FindOtherUsersByIP 查找同一IP的其他用户
func FindOtherUsersByIP(ip string, excludeUserID int) []int {
	var userIDs []int
	DB.Model(&IPUAHistory{}).
		Where("ip_address = ? AND user_id != ?", ip, excludeUserID).
		Distinct("user_id").
		Pluck("user_id", &userIDs)
	return userIDs
}

// CountUniqueUAs 统计用户的唯一UA数
func CountUniqueUAs(userID int) int {
	var count int64
	if common.UsingPostgreSQL {
		DB.Model(&IPUAHistory{}).
			Where("user_id = ?", userID).
			Select("COUNT(DISTINCT (ua_browser || '|' || ua_os))").
			Count(&count)
	} else {
		DB.Model(&IPUAHistory{}).
			Where("user_id = ?", userID).
			Select("COUNT(DISTINCT CONCAT(ua_browser, '|', ua_os))").
			Count(&count)
	}
	return int(count)
}

// CountRecentRegistrationsByIP 统计某IP近期注册数 (通过 IP/UA 历史中首次出现的记录来近似)
func CountRecentRegistrationsByIP(ip string, since time.Time) int {
	var count int64
	DB.Model(&IPUAHistory{}).
		Where("ip_address = ? AND first_seen >= ?", ip, since).
		Distinct("user_id").
		Count(&count)
	return int(count)
}

// GetVPNUsageStats 获取VPN使用统计
func GetVPNUsageStats() map[string]int64 {
	stats := map[string]int64{}
	types := []string{"residential", "datacenter", "vpn", "proxy", "tor"}
	for _, t := range types {
		var count int64
		DB.Model(&IPUAHistory{}).Where("ip_type = ?", t).Count(&count)
		stats[t] = count
	}
	return stats
}
