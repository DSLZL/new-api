package model

import (
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
)

// IPUAHistory IP/UA 使用历史
type IPUAHistory struct {
	ID int64 `json:"id" gorm:"primaryKey;autoIncrement"`

	UserID    int    `json:"user_id" gorm:"index;not null"`
	IPAddress string `json:"ip_address" gorm:"type:varchar(45);index;not null"`
	UserAgent string `json:"user_agent" gorm:"type:text;default:''"`

	// IP情报
	IPCountry    string  `json:"ip_country" gorm:"type:varchar(10);default:''"`
	IPRegion     string  `json:"ip_region" gorm:"type:varchar(50);default:''"`
	IPCity       string  `json:"ip_city" gorm:"type:varchar(50);default:''"`
	IPISP        string  `json:"ip_isp" gorm:"type:varchar(100);default:''"`
	IPType       string  `json:"ip_type" gorm:"type:varchar(20);default:''"`
	ASN          int     `json:"asn" gorm:"default:0;index"`
	ASNOrg       string  `json:"asn_org" gorm:"type:varchar(160);default:''"`
	IsDatacenter bool    `json:"is_datacenter" gorm:"default:false"`
	IPRiskScore  float32 `json:"ip_risk_score" gorm:"default:0"`

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

var (
	ipuaWriteGateMu      sync.Mutex
	ipuaLastWriteByKey   = make(map[string]time.Time)
	ipuaReservedByKey    = make(map[string]time.Time)
	ipuaWriteGateSweeps  int64
)

func shouldSampleIPUAWrite() bool {
	sampleRate := common.GetFingerprintIPUAWriteSampleRate()
	if sampleRate >= 100 {
		return true
	}
	if sampleRate <= 1 {
		return rand.Intn(100) == 0
	}
	return rand.Intn(100) < sampleRate
}

func buildIPUAWriteGateKey(record *IPUAHistory) string {
	if record == nil {
		return ""
	}
	return fmt.Sprintf("%d|%s|%s|%s", record.UserID, record.IPAddress, record.UABrowser, record.UAOS)
}

func reserveIPUAWriteSlot(key string, now time.Time) bool {
	if key == "" {
		return true
	}
	minIntervalSeconds := common.GetFingerprintIPUAWriteMinIntervalSeconds()
	if minIntervalSeconds <= 0 {
		return true
	}
	interval := time.Duration(minIntervalSeconds) * time.Second

	ipuaWriteGateMu.Lock()
	defer ipuaWriteGateMu.Unlock()

	if reservedAt, exists := ipuaReservedByKey[key]; exists {
		if now.Sub(reservedAt) < interval {
			return false
		}
	}
	if lastWriteAt, exists := ipuaLastWriteByKey[key]; exists {
		if now.Sub(lastWriteAt) < interval {
			return false
		}
	}

	ipuaReservedByKey[key] = now
	return true
}

func completeIPUAWriteSlot(key string, now time.Time, success bool) {
	if key == "" {
		return
	}
	minIntervalSeconds := common.GetFingerprintIPUAWriteMinIntervalSeconds()
	if minIntervalSeconds <= 0 {
		return
	}
	interval := time.Duration(minIntervalSeconds) * time.Second

	ipuaWriteGateMu.Lock()
	defer ipuaWriteGateMu.Unlock()

	delete(ipuaReservedByKey, key)
	if success {
		ipuaLastWriteByKey[key] = now
	}
	ipuaWriteGateSweeps++
	if ipuaWriteGateSweeps%256 != 0 {
		return
	}

	expiredBefore := now.Add(-3 * interval)
	for gateKey, gateTime := range ipuaLastWriteByKey {
		if gateTime.Before(expiredBefore) {
			delete(ipuaLastWriteByKey, gateKey)
		}
	}
	for gateKey, gateTime := range ipuaReservedByKey {
		if gateTime.Before(expiredBefore) {
			delete(ipuaReservedByKey, gateKey)
		}
	}
}

func trimIPUAHistoryByUser(userID int) error {
	if userID <= 0 {
		return nil
	}
	limit := common.GetFingerprintIPUAUserHistoryLimit()
	cleanupBatch := common.GetFingerprintIPUAUserHistoryCleanupBatch()
	if cleanupBatch > limit {
		cleanupBatch = limit
	}

	var count int64
	if err := DB.Model(&IPUAHistory{}).Where("user_id = ?", userID).Count(&count).Error; err != nil {
		return err
	}
	if count <= int64(limit) {
		return nil
	}

	toDelete := int(count) - limit
	if toDelete > cleanupBatch {
		toDelete = cleanupBatch
	}
	if toDelete <= 0 {
		return nil
	}

	staleIDs := make([]int64, 0, toDelete)
	if err := DB.Model(&IPUAHistory{}).
		Where("user_id = ?", userID).
		Order("last_seen ASC, id ASC").
		Limit(toDelete).
		Pluck("id", &staleIDs).Error; err != nil {
		return err
	}
	if len(staleIDs) == 0 {
		return nil
	}
	return DB.Where("id IN ?", staleIDs).Delete(&IPUAHistory{}).Error
}

func DeleteOldIPUAHistory(before time.Time) (int64, error) {
	result := DB.Where("last_seen < ?", before).Delete(&IPUAHistory{})
	return result.RowsAffected, result.Error
}

// UpsertIPUAHistory 插入或更新 IP/UA 历史记录
func UpsertIPUAHistory(record *IPUAHistory) error {
	if record == nil || record.UserID <= 0 || record.IPAddress == "" {
		return nil
	}
	now := time.Now()
	if !shouldSampleIPUAWrite() {
		return nil
	}
	gateKey := buildIPUAWriteGateKey(record)
	if !reserveIPUAWriteSlot(gateKey, now) {
		return nil
	}
	var err error
	defer func() {
		if err != nil {
			completeIPUAWriteSlot(gateKey, now, false)
		}
	}()
	if common.UsingPostgreSQL {
		err = DB.Exec(`
			INSERT INTO ip_ua_history
				(user_id, ip_address, user_agent, ip_country, ip_region, ip_city, ip_isp, ip_type, asn, asn_org, is_datacenter, ip_risk_score,
				 ua_browser, ua_browser_ver, ua_os, ua_os_ver, ua_device, endpoint, request_count, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, NOW(), NOW())
			ON CONFLICT (user_id, ip_address, ua_browser, ua_os)
			DO UPDATE SET
				request_count = ip_ua_history.request_count + 1,
				last_seen = NOW(),
				user_agent = EXCLUDED.user_agent,
				endpoint = EXCLUDED.endpoint,
				ip_type = COALESCE(NULLIF(EXCLUDED.ip_type, ''), ip_ua_history.ip_type),
				asn = CASE WHEN EXCLUDED.asn > 0 THEN EXCLUDED.asn ELSE ip_ua_history.asn END,
				asn_org = COALESCE(NULLIF(EXCLUDED.asn_org, ''), ip_ua_history.asn_org),
				is_datacenter = CASE
					WHEN EXCLUDED.asn > 0 OR NULLIF(EXCLUDED.asn_org, '') IS NOT NULL OR EXCLUDED.is_datacenter
					THEN EXCLUDED.is_datacenter
					ELSE ip_ua_history.is_datacenter
				END,
				ip_risk_score = CASE WHEN EXCLUDED.ip_risk_score > 0 THEN EXCLUDED.ip_risk_score ELSE ip_ua_history.ip_risk_score END
		`,
			record.UserID, record.IPAddress, record.UserAgent,
			record.IPCountry, record.IPRegion, record.IPCity, record.IPISP, record.IPType, record.ASN, record.ASNOrg, record.IsDatacenter, record.IPRiskScore,
			record.UABrowser, record.UABrowserVer, record.UAOS, record.UAOSVer, record.UADevice,
			record.Endpoint,
		).Error
	} else {
		// MySQL/SQLite: 先查后更新
		var existing IPUAHistory
		result := DB.Where("user_id = ? AND ip_address = ? AND ua_browser = ? AND ua_os = ?",
			record.UserID, record.IPAddress, record.UABrowser, record.UAOS).First(&existing)

		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				err = DB.Create(record).Error
			} else {
				err = result.Error
			}
		} else {
			ipType := existing.IPType
			if record.IPType != "" {
				ipType = record.IPType
			}
			asn := existing.ASN
			if record.ASN > 0 {
				asn = record.ASN
			}
			asnOrg := existing.ASNOrg
			if record.ASNOrg != "" {
				asnOrg = record.ASNOrg
			}
			isDatacenter := existing.IsDatacenter
			if record.ASN > 0 || record.ASNOrg != "" || record.IsDatacenter {
				isDatacenter = record.IsDatacenter
			}
			ipRiskScore := existing.IPRiskScore
			if record.IPRiskScore > 0 {
				ipRiskScore = record.IPRiskScore
			}

			err = DB.Model(&existing).Updates(map[string]any{
				"request_count": existing.RequestCount + 1,
				"last_seen":     now,
				"user_agent":    record.UserAgent,
				"endpoint":      record.Endpoint,
				"ip_type":       ipType,
				"asn":           asn,
				"asn_org":       asnOrg,
				"is_datacenter": isDatacenter,
				"ip_risk_score": ipRiskScore,
			}).Error
		}
	}
	if err != nil {
		return err
	}
	completeIPUAWriteSlot(gateKey, now, true)
	return trimIPUAHistoryByUser(record.UserID)
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
