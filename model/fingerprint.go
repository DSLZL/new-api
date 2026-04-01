package model

import (
	"crypto/sha256"
	"fmt"
	"time"
)

// Fingerprint 用户指纹记录
type Fingerprint struct {
	ID int64 `json:"id" gorm:"primaryKey;autoIncrement"`

	UserID int `json:"user_id" gorm:"index;not null"`

	// ─── 网络层指纹 ───
	IPAddress string `json:"ip_address" gorm:"type:varchar(45);index;not null;default:''"`
	IPCountry string `json:"ip_country" gorm:"type:varchar(10);default:''"`
	IPRegion  string `json:"ip_region" gorm:"type:varchar(50);default:''"`
	IPCity    string `json:"ip_city" gorm:"type:varchar(50);default:''"`
	IPISP     string `json:"ip_isp" gorm:"type:varchar(100);default:''"`
	IPType    string `json:"ip_type" gorm:"type:varchar(20);default:''"` // residential/datacenter/vpn/proxy/tor

	UserAgent    string `json:"user_agent" gorm:"type:text;default:''"`
	UABrowser    string `json:"ua_browser" gorm:"type:varchar(50);default:''"`
	UABrowserVer string `json:"ua_browser_ver" gorm:"type:varchar(20);default:''"`
	UAOS         string `json:"ua_os" gorm:"type:varchar(50);default:''"`
	UAOSVer      string `json:"ua_os_ver" gorm:"type:varchar(20);default:''"`
	UADeviceType string `json:"ua_device_type" gorm:"type:varchar(20);default:''"`

	// ─── 协议层指纹 ───
	TLSJA3Hash string `json:"tls_ja3_hash" gorm:"type:varchar(32);default:''"`
	HTTP2FP    string `json:"http2_fp" gorm:"type:varchar(64);default:''"`
	TCPOSGuess string `json:"tcp_os_guess" gorm:"type:varchar(50);default:''"`

	// ─── 浏览器指纹 ───
	CanvasHash    string `json:"canvas_hash" gorm:"type:varchar(64);index;default:''"`
	WebGLHash     string `json:"webgl_hash" gorm:"column:webgl_hash;type:varchar(64);index;default:''"`
	WebGLVendor   string `json:"webgl_vendor" gorm:"type:varchar(100);default:''"`
	WebGLRenderer string `json:"webgl_renderer" gorm:"type:varchar(200);default:''"`
	AudioHash     string `json:"audio_hash" gorm:"type:varchar(64);index;default:''"`
	FontsHash     string `json:"fonts_hash" gorm:"type:varchar(64);index;default:''"`
	FontsList     string `json:"fonts_list" gorm:"type:text;default:''"`

	// ─── 硬件特征 ───
	ScreenWidth  int     `json:"screen_width" gorm:"default:0"`
	ScreenHeight int     `json:"screen_height" gorm:"default:0"`
	ColorDepth   int     `json:"color_depth" gorm:"default:0"`
	PixelRatio   float32 `json:"pixel_ratio" gorm:"default:0"`
	CPUCores     int     `json:"cpu_cores" gorm:"default:0"`
	DeviceMemory float32 `json:"device_memory" gorm:"default:0"`
	MaxTouch     int     `json:"max_touch" gorm:"default:0"`

	// ─── 环境特征 ───
	Timezone      string `json:"timezone" gorm:"type:varchar(50);default:''"`
	TZOffset      int    `json:"tz_offset" gorm:"default:0"`
	Languages     string `json:"languages" gorm:"type:varchar(200);default:''"`
	Platform      string `json:"platform" gorm:"type:varchar(50);default:''"`
	DoNotTrack    string `json:"do_not_track" gorm:"type:varchar(5);default:''"`
	CookieEnabled bool   `json:"cookie_enabled" gorm:"default:true"`

	// ─── 持久化追踪 ───
	LocalDeviceID string `json:"local_device_id" gorm:"type:varchar(64);index;default:''"`

	// ─── 综合指纹 ───
	CompositeHash string `json:"composite_hash" gorm:"type:varchar(64);index;not null;default:''"`

	// ─── 元数据 ───
	PageURL   string    `json:"page_url" gorm:"type:varchar(500);default:''"`
	SessionID string    `json:"session_id" gorm:"type:varchar(64);default:''"`
	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
}

func (Fingerprint) TableName() string {
	return "user_fingerprints"
}

// ─── 写入方法 ───

func (fp *Fingerprint) Insert() error {
	return DB.Create(fp).Error
}

// ─── 查询方法 ───

func GetLatestFingerprints(userID int, limit int) []*Fingerprint {
	var fps []*Fingerprint
	DB.Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(limit).
		Find(&fps)
	return fps
}

func GetFingerprintByID(id int64) *Fingerprint {
	var fp Fingerprint
	if err := DB.First(&fp, id).Error; err != nil {
		return nil
	}
	return &fp
}

// ─── 设备指纹候选发现 ───

func FindUsersByCanvasHash(hash string) []int {
	if hash == "" {
		return nil
	}
	var userIDs []int
	DB.Model(&Fingerprint{}).
		Where("canvas_hash = ? AND canvas_hash != ''", hash).
		Distinct("user_id").
		Pluck("user_id", &userIDs)
	return userIDs
}

func FindUsersByWebGLHash(hash string) []int {
	if hash == "" {
		return nil
	}
	var userIDs []int
	DB.Model(&Fingerprint{}).
		Where("webgl_hash = ? AND webgl_hash != ''", hash).
		Distinct("user_id").
		Pluck("user_id", &userIDs)
	return userIDs
}

func FindUsersByAudioHash(hash string) []int {
	if hash == "" {
		return nil
	}
	var userIDs []int
	DB.Model(&Fingerprint{}).
		Where("audio_hash = ? AND audio_hash != ''", hash).
		Distinct("user_id").
		Pluck("user_id", &userIDs)
	return userIDs
}

func FindUsersByFontsHash(hash string) []int {
	if hash == "" {
		return nil
	}
	var userIDs []int
	DB.Model(&Fingerprint{}).
		Where("fonts_hash = ? AND fonts_hash != ''", hash).
		Distinct("user_id").
		Pluck("user_id", &userIDs)
	return userIDs
}

func FindUsersByDeviceID(deviceID string) []int {
	if deviceID == "" {
		return nil
	}
	var userIDs []int
	DB.Model(&Fingerprint{}).
		Where("local_device_id = ? AND local_device_id != ''", deviceID).
		Distinct("user_id").
		Pluck("user_id", &userIDs)
	return userIDs
}

func FindUsersByCompositeHash(hash string) []int {
	if hash == "" {
		return nil
	}
	var userIDs []int
	DB.Model(&Fingerprint{}).
		Where("composite_hash = ?", hash).
		Distinct("user_id").
		Pluck("user_id", &userIDs)
	return userIDs
}

func FindUsersByJA3(ja3 string) []int {
	if ja3 == "" {
		return nil
	}
	var userIDs []int
	DB.Model(&Fingerprint{}).
		Where("tls_ja3_hash = ? AND tls_ja3_hash != ''", ja3).
		Distinct("user_id").
		Pluck("user_id", &userIDs)
	return userIDs
}

// ─── 统计与维护 ───

func CountFingerprints() int64 {
	var count int64
	DB.Model(&Fingerprint{}).Count(&count)
	return count
}

// GroupUsersByField 按指定字段分组，返回有多个用户的组
func GroupUsersByField(field string) map[string][]int {
	type Result struct {
		FieldVal string `gorm:"column:field_val"`
		UserID   int    `gorm:"column:user_id"`
	}
	var results []Result
	DB.Model(&Fingerprint{}).
		Select("DISTINCT " + field + " as field_val, user_id").
		Where(field + " != ''").
		Find(&results)

	groups := make(map[string][]int)
	for _, r := range results {
		groups[r.FieldVal] = append(groups[r.FieldVal], r.UserID)
	}
	return groups
}

func DeleteOldFingerprints(before time.Time) int64 {
	result := DB.Where("created_at < ?", before).Delete(&Fingerprint{})
	return result.RowsAffected
}

// ═══════════════════════════════════════════════════════════════
// UserDeviceProfile — 设备档案表（永久保留，每台设备一行）
// ═══════════════════════════════════════════════════════════════

type UserDeviceProfile struct {
	ID            int64     `json:"id" gorm:"primaryKey;autoIncrement"`
	UserID        int       `json:"user_id" gorm:"index;not null"`
	DeviceKey     string    `json:"device_key" gorm:"type:varchar(64);not null"` // 稳定设备标识
	CanvasHash    string    `json:"canvas_hash" gorm:"type:varchar(64)"`
	WebGLHash     string    `json:"webgl_hash" gorm:"type:varchar(64)"`
	AudioHash     string    `json:"audio_hash" gorm:"type:varchar(64)"`
	FontsHash     string    `json:"fonts_hash" gorm:"type:varchar(64)"`
	LocalDeviceID string    `json:"local_device_id" gorm:"type:varchar(64)"`
	CompositeHash string    `json:"composite_hash" gorm:"type:varchar(64)"`
	UABrowser     string    `json:"ua_browser" gorm:"type:varchar(50)"`
	UAOS          string    `json:"ua_os" gorm:"type:varchar(50)"`
	UADeviceType  string    `json:"ua_device_type" gorm:"type:varchar(20)"`
	LastSeenIP    string    `json:"last_seen_ip" gorm:"type:varchar(45)"`
	FirstSeenAt   time.Time `json:"first_seen_at" gorm:"autoCreateTime"`
	LastSeenAt    time.Time `json:"last_seen_at" gorm:"autoUpdateTime"`
	SeenCount     int       `json:"seen_count" gorm:"default:1"`
}

func (UserDeviceProfile) TableName() string {
	return "user_device_profiles"
}

// BuildDeviceKey 生成稳定的设备标识：local_device_id 优先，否则取三个硬件 hash 组合
func BuildDeviceKey(localDeviceID, canvasHash, webGLHash, audioHash string) string {
	if localDeviceID != "" {
		return "lid:" + localDeviceID
	}
	if canvasHash == "" && webGLHash == "" && audioHash == "" {
		return ""
	}
	raw := canvasHash + "|" + webGLHash + "|" + audioHash
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("hw:%x", sum[:16]) // 32 字符
}

// UpsertDeviceProfile 写入或更新设备档案（幂等）
// unique index: (user_id, device_key)
func UpsertDeviceProfile(profile *UserDeviceProfile) error {
	if profile.DeviceKey == "" {
		return nil
	}

	// 先尝试查找已有档案
	var existing UserDeviceProfile
	err := DB.Where("user_id = ? AND device_key = ?", profile.UserID, profile.DeviceKey).
		First(&existing).Error

	if err != nil {
		// 不存在 → 新建
		return DB.Create(profile).Error
	}

	// 存在 → 更新 last_seen_ip 和 seen_count
	return DB.Model(&existing).Updates(map[string]interface{}{
		"last_seen_ip": profile.LastSeenIP,
		"last_seen_at": time.Now(),
		"seen_count":   existing.SeenCount + 1,
	}).Error
}

// GetDeviceProfiles 获取指定用户的所有设备档案
func GetDeviceProfiles(userID int) []*UserDeviceProfile {
	var profiles []*UserDeviceProfile
	DB.Where("user_id = ?", userID).
		Order("last_seen_at DESC").
		Find(&profiles)
	return profiles
}

// FindUsersByDeviceKey 查找使用同一 device_key 的所有用户 ID（跨账号检测）
func FindUsersByDeviceKey(deviceKey string) []int {
	if deviceKey == "" {
		return nil
	}
	var userIDs []int
	DB.Model(&UserDeviceProfile{}).
		Where("device_key = ?", deviceKey).
		Distinct("user_id").
		Pluck("user_id", &userIDs)
	return userIDs
}

// CheckDeviceKeyConflict 检测 device_key 是否已被其他账号使用
// 返回与之冲突的 user_id 列表（排除自身）
func CheckDeviceKeyConflict(userID int, deviceKey string) []int {
	if deviceKey == "" {
		return nil
	}
	var userIDs []int
	DB.Model(&UserDeviceProfile{}).
		Where("device_key = ? AND user_id != ?", deviceKey, userID).
		Distinct("user_id").
		Pluck("user_id", &userIDs)
	return userIDs
}

// GetDeviceProfilesAsFingerprints 将用户设备档案转为 Fingerprint 切片
// 供 CompareFingerprints 直接使用，避免依赖流水表
func GetDeviceProfilesAsFingerprints(userID int) []*Fingerprint {
	profiles := GetDeviceProfiles(userID)
	if len(profiles) == 0 {
		return nil
	}
	result := make([]*Fingerprint, 0, len(profiles))
	for _, p := range profiles {
		result = append(result, &Fingerprint{
			UserID:        p.UserID,
			CanvasHash:    p.CanvasHash,
			WebGLHash:     p.WebGLHash,
			AudioHash:     p.AudioHash,
			FontsHash:     p.FontsHash,
			LocalDeviceID: p.LocalDeviceID,
			CompositeHash: p.CompositeHash,
			UABrowser:     p.UABrowser,
			UAOS:          p.UAOS,
			UADeviceType:  p.UADeviceType,
			IPAddress:     p.LastSeenIP,
			CreatedAt:     p.LastSeenAt,
		})
	}
	return result
}
