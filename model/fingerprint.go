package model

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Fingerprint 用户指纹记录
type Fingerprint struct {
	ID int64 `json:"id" gorm:"primaryKey;autoIncrement"`

	UserID int `json:"user_id" gorm:"index;not null"`

	// ─── 网络层指纹 ───
	IPAddress    string `json:"ip_address" gorm:"type:varchar(45);index;not null;default:''"`
	IPCountry    string `json:"ip_country" gorm:"type:varchar(10);default:''"`
	IPRegion     string `json:"ip_region" gorm:"type:varchar(50);default:''"`
	IPCity       string `json:"ip_city" gorm:"type:varchar(50);default:''"`
	IPISP        string `json:"ip_isp" gorm:"type:varchar(100);default:''"`
	IPType       string `json:"ip_type" gorm:"type:varchar(20);default:''"` // residential/datacenter/vpn/proxy/tor
	DNSResolverIP string `json:"dns_resolver_ip" gorm:"type:varchar(45);index;default:''"`
	ASN          int    `json:"asn" gorm:"default:0"`
	ASNOrg       string `json:"asn_org" gorm:"type:varchar(160);default:''"`
	IsDatacenter bool   `json:"is_datacenter" gorm:"default:false"`

	UserAgent    string `json:"user_agent" gorm:"type:text;default:''"`
	UABrowser    string `json:"ua_browser" gorm:"type:varchar(50);default:''"`
	UABrowserVer string `json:"ua_browser_ver" gorm:"type:varchar(20);default:''"`
	UAOS         string `json:"ua_os" gorm:"type:varchar(50);default:''"`
	UAOSVer      string `json:"ua_os_ver" gorm:"type:varchar(20);default:''"`
	UADeviceType string `json:"ua_device_type" gorm:"type:varchar(20);default:''"`

	// ─── 协议层指纹 ───
	TLSJA3Hash     string `json:"tls_ja3_hash" gorm:"type:varchar(32);default:''"`
	JA4            string `json:"ja4" gorm:"type:varchar(128);index;default:''"`
	HTTPHeaderHash string `json:"http_header_hash" gorm:"type:varchar(32);index;default:''"`
	HTTP2FP        string `json:"http2_fp" gorm:"type:varchar(64);default:''"`
	TCPOSGuess     string `json:"tcp_os_guess" gorm:"type:varchar(50);default:''"`

	// ─── 浏览器指纹 ───
	CanvasHash            string `json:"canvas_hash" gorm:"type:varchar(64);index;default:''"`
	WebGLHash             string `json:"webgl_hash" gorm:"column:webgl_hash;type:varchar(64);index;default:''"`
	WebGLDeepHash         string `json:"webgl_deep_hash" gorm:"type:varchar(64);index;default:''"`
	ClientRectsHash       string `json:"client_rects_hash" gorm:"type:varchar(64);index;default:''"`
	WebGLVendor           string `json:"webgl_vendor" gorm:"type:varchar(100);default:''"`
	WebGLRenderer         string `json:"webgl_renderer" gorm:"type:varchar(200);default:''"`
	MediaDevicesHash      string `json:"media_devices_hash" gorm:"type:varchar(64);index;default:''"`
	MediaDeviceCount      string `json:"media_device_count" gorm:"type:varchar(32);default:''"`
	MediaDeviceGroupHash  string `json:"media_device_group_hash" gorm:"type:varchar(64);index;default:''"`
	MediaDeviceTotal      int    `json:"media_device_total" gorm:"default:0"`
	SpeechVoicesHash      string `json:"speech_voices_hash" gorm:"type:varchar(64);index;default:''"`
	SpeechVoiceCount      int    `json:"speech_voice_count" gorm:"default:0"`
	SpeechLocalVoiceCount int    `json:"speech_local_voice_count" gorm:"default:0"`
	AudioHash             string `json:"audio_hash" gorm:"type:varchar(64);index;default:''"`
	FontsHash             string `json:"fonts_hash" gorm:"type:varchar(64);index;default:''"`
	FontsList             string `json:"fonts_list" gorm:"type:text;default:''"`

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
	LocalDeviceID      string `json:"local_device_id" gorm:"type:varchar(64);index;default:''"`
	ETagID             string `json:"etag_id" gorm:"column:etag_id;type:varchar(64);index;default:''"`
	PersistentID       string `json:"persistent_id" gorm:"type:varchar(64);index;default:''"`
	PersistentIDSource string `json:"persistent_id_source" gorm:"type:varchar(32);default:''"`

	// ─── WebRTC IP 指纹 ───
	WebRTCLocalIPs  string `json:"webrtc_local_ips" gorm:"type:text;default:''"`
	WebRTCPublicIPs string `json:"webrtc_public_ips" gorm:"type:text;default:''"`

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

func trimFingerprintText(raw string, maxLen int) string {
	trimmed := strings.TrimSpace(raw)
	if maxLen <= 0 || trimmed == "" {
		return ""
	}
	runes := []rune(trimmed)
	if len(runes) <= maxLen {
		return trimmed
	}
	return string(runes[:maxLen])
}

func normalizeWebRTCIPList(raw string, maxLen int) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if maxLen <= 0 {
		return "[]"
	}

	var ips []string
	if err := common.UnmarshalJsonStr(trimmed, &ips); err != nil {
		return "[]"
	}
	payload, err := common.Marshal(ips)
	if err != nil {
		return "[]"
	}
	canonical := string(payload)
	if len([]rune(canonical)) > maxLen {
		return "[]"
	}
	return canonical
}

func normalizeFingerprintForStorage(fp *Fingerprint) {
	if fp == nil {
		return
	}
	fp.UserAgent = trimFingerprintText(fp.UserAgent, common.GetFingerprintMaxUserAgentLength())
	fp.FontsList = trimFingerprintText(fp.FontsList, common.GetFingerprintMaxFontsListLength())
	fp.WebRTCLocalIPs = normalizeWebRTCIPList(fp.WebRTCLocalIPs, common.GetFingerprintMaxWebRTCIPsLength())
	fp.WebRTCPublicIPs = normalizeWebRTCIPList(fp.WebRTCPublicIPs, common.GetFingerprintMaxWebRTCIPsLength())
	fp.PageURL = trimFingerprintText(fp.PageURL, common.GetFingerprintMaxPageURLLength())
}

// ─── 写入方法 ───

func (fp *Fingerprint) Insert() error {
	normalizeFingerprintForStorage(fp)
	return DB.Create(fp).Error
}

func insertFingerprintWithDB(db *gorm.DB, fp *Fingerprint) error {
	normalizeFingerprintForStorage(fp)
	return db.Create(fp).Error
}

var (
	ErrFingerprintPersistInsert   = errors.New("fingerprint persist insert")
	ErrFingerprintPersistDevice   = errors.New("fingerprint persist device")
	ErrFingerprintPersistSession  = errors.New("fingerprint persist session")
	ErrFingerprintPersistBehavior = errors.New("fingerprint persist behavior")
)

func PersistFingerprintReportAtomic(fp *Fingerprint, profile *UserDeviceProfile, session *UserSession, keystroke *KeystrokeProfile, mouse *MouseProfile) error {
	return DB.Transaction(func(tx *gorm.DB) error {
		if err := insertFingerprintWithDB(tx, fp); err != nil {
			return fmt.Errorf("%w: %w", ErrFingerprintPersistInsert, err)
		}
		if err := upsertDeviceProfileWithDB(tx, profile); err != nil {
			return fmt.Errorf("%w: %w", ErrFingerprintPersistDevice, err)
		}
		if err := upsertUserSessionWithDB(tx, session); err != nil {
			return fmt.Errorf("%w: %w", ErrFingerprintPersistSession, err)
		}
		if err := upsertBehaviorProfilesAtomicWithDB(tx, keystroke, mouse); err != nil {
			return fmt.Errorf("%w: %w", ErrFingerprintPersistBehavior, err)
		}
		return nil
	})
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

func FindUsersByWebGLDeepHash(hash string) []int {
	if hash == "" {
		return nil
	}
	var userIDs []int
	DB.Model(&Fingerprint{}).
		Where("webgl_deep_hash = ? AND webgl_deep_hash != ''", hash).
		Distinct("user_id").
		Pluck("user_id", &userIDs)
	return userIDs
}

func FindUsersByClientRectsHash(hash string) []int {
	if hash == "" {
		return nil
	}
	var userIDs []int
	DB.Model(&Fingerprint{}).
		Where("client_rects_hash = ? AND client_rects_hash != ''", hash).
		Distinct("user_id").
		Pluck("user_id", &userIDs)
	return userIDs
}

func FindUsersByMediaDevicesHash(hash string) []int {
	if hash == "" {
		return nil
	}
	var userIDs []int
	DB.Model(&Fingerprint{}).
		Where("media_devices_hash = ? AND media_devices_hash != ''", hash).
		Distinct("user_id").
		Pluck("user_id", &userIDs)
	return userIDs
}

func FindUsersByMediaDeviceGroupHash(hash string) []int {
	if hash == "" {
		return nil
	}
	var userIDs []int
	DB.Model(&Fingerprint{}).
		Where("media_device_group_hash = ? AND media_device_group_hash != ''", hash).
		Distinct("user_id").
		Pluck("user_id", &userIDs)
	return userIDs
}

func FindUsersBySpeechVoicesHash(hash string) []int {
	if hash == "" {
		return nil
	}
	var userIDs []int
	DB.Model(&Fingerprint{}).
		Where("speech_voices_hash = ? AND speech_voices_hash != ''", hash).
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

func FindUsersByJA4(ja4 string) []int {
	if ja4 == "" {
		return nil
	}
	var userIDs []int
	DB.Model(&Fingerprint{}).
		Where("ja4 = ? AND ja4 != ''", ja4).
		Distinct("user_id").
		Pluck("user_id", &userIDs)
	return userIDs
}

func FindUsersByHTTPHeaderHash(httpHeaderHash string) []int {
	if httpHeaderHash == "" {
		return nil
	}
	var userIDs []int
	DB.Model(&Fingerprint{}).
		Where("http_header_hash = ? AND http_header_hash != ''", httpHeaderHash).
		Distinct("user_id").
		Pluck("user_id", &userIDs)
	return userIDs
}

func FindUsersByETagID(etagID string) []int {
	if etagID == "" {
		return nil
	}
	var userIDs []int
	DB.Model(&Fingerprint{}).
		Where("etag_id = ? AND etag_id != ''", etagID).
		Distinct("user_id").
		Pluck("user_id", &userIDs)
	return userIDs
}

func FindUsersByPersistentID(persistentID string) []int {
	if persistentID == "" {
		return nil
	}
	var userIDs []int
	DB.Model(&Fingerprint{}).
		Where("persistent_id = ? AND persistent_id != ''", persistentID).
		Distinct("user_id").
		Pluck("user_id", &userIDs)
	return userIDs
}

func FindUsersByDNSResolverIP(resolverIP string) []int {
	if resolverIP == "" {
		return nil
	}
	var userIDs []int
	DB.Model(&Fingerprint{}).
		Where("dns_resolver_ip = ? AND dns_resolver_ip != ''", resolverIP).
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
	ID                    int64     `json:"id" gorm:"primaryKey;autoIncrement"`
	UserID                int       `json:"user_id" gorm:"not null;index;uniqueIndex:uk_udp_user_device_key,priority:1"`
	DeviceKey             string    `json:"device_key" gorm:"type:varchar(64);not null;index:idx_udp_device_key;uniqueIndex:uk_udp_user_device_key,priority:2"` // 稳定设备标识
	CanvasHash            string    `json:"canvas_hash" gorm:"type:varchar(64)"`
	WebGLHash             string    `json:"webgl_hash" gorm:"type:varchar(64)"`
	WebGLDeepHash         string    `json:"webgl_deep_hash" gorm:"type:varchar(64);index"`
	ClientRectsHash       string    `json:"client_rects_hash" gorm:"type:varchar(64);index"`
	MediaDevicesHash      string    `json:"media_devices_hash" gorm:"type:varchar(64);index"`
	MediaDeviceCount      string    `json:"media_device_count" gorm:"type:varchar(32)"`
	MediaDeviceGroupHash  string    `json:"media_device_group_hash" gorm:"type:varchar(64);index"`
	MediaDeviceTotal      int       `json:"media_device_total" gorm:"default:0"`
	SpeechVoicesHash      string    `json:"speech_voices_hash" gorm:"type:varchar(64);index"`
	SpeechVoiceCount      int       `json:"speech_voice_count" gorm:"default:0"`
	SpeechLocalVoiceCount int       `json:"speech_local_voice_count" gorm:"default:0"`
	AudioHash             string    `json:"audio_hash" gorm:"type:varchar(64)"`
	FontsHash             string    `json:"fonts_hash" gorm:"type:varchar(64)"`
	LocalDeviceID         string    `json:"local_device_id" gorm:"type:varchar(64)"`
	CompositeHash         string    `json:"composite_hash" gorm:"type:varchar(64)"`
	HTTPHeaderHash        string    `json:"http_header_hash" gorm:"type:varchar(32);index"`
	UABrowser             string    `json:"ua_browser" gorm:"type:varchar(50)"`
	UAOS                  string    `json:"ua_os" gorm:"type:varchar(50)"`
	UADeviceType          string    `json:"ua_device_type" gorm:"type:varchar(20)"`
	LastSeenIP            string    `json:"last_seen_ip" gorm:"type:varchar(45)"`
	FirstSeenAt           time.Time `json:"first_seen_at" gorm:"autoCreateTime"`
	LastSeenAt            time.Time `json:"last_seen_at" gorm:"autoUpdateTime"`
	SeenCount             int       `json:"seen_count" gorm:"default:1"`
}

func (UserDeviceProfile) TableName() string {
	return "user_device_profiles"
}

// ═══════════════════════════════════════════════════════════════
// UserTemporalProfile — 用户时序画像（日聚合）
// ═══════════════════════════════════════════════════════════════

type UserTemporalProfile struct {
	ID int64 `json:"id" gorm:"primaryKey;autoIncrement"`

	UserID int `json:"user_id" gorm:"index;not null"`

	// ProfileDate: YYYY-MM-DD（UTC 日期）
	ProfileDate string `json:"profile_date" gorm:"type:varchar(10);not null"`
	Timezone    string `json:"timezone" gorm:"type:varchar(50);default:''"`

	// 48-bin（30分钟）分布，JSON 字符串存储，兼容三库
	ActivityBins string `json:"activity_bins" gorm:"type:text;not null;default:''"`
	PeakBin      int    `json:"peak_bin" gorm:"default:0"`

	SampleCount    int       `json:"sample_count" gorm:"default:0"`
	LastActivityAt time.Time `json:"last_activity_at" gorm:"index"`
	CreatedAt      time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt      time.Time `json:"updated_at" gorm:"autoUpdateTime"`
}

func (UserTemporalProfile) TableName() string {
	return "user_temporal_profiles"
}

// ═══════════════════════════════════════════════════════════════
// UserSession — 用户会话窗口（用于互斥/切换分析）
// ═══════════════════════════════════════════════════════════════

type UserSession struct {
	ID int64 `json:"id" gorm:"primaryKey;autoIncrement"`

	UserID int `json:"user_id" gorm:"index;not null"`

	SessionID string `json:"session_id" gorm:"type:varchar(64);index;default:''"`
	DeviceKey string `json:"device_key" gorm:"type:varchar(64);index;default:''"`
	IPAddress string `json:"ip_address" gorm:"type:varchar(45);index;default:''"`

	StartedAt       time.Time `json:"started_at" gorm:"index;not null"`
	EndedAt         time.Time `json:"ended_at" gorm:"index"`
	DurationSeconds int       `json:"duration_seconds" gorm:"default:0"`
	EventCount      int       `json:"event_count" gorm:"default:1"`
	IsBurst         bool      `json:"is_burst" gorm:"default:false"`
	Source          string    `json:"source" gorm:"type:varchar(20);default:fingerprint"`

	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time `json:"updated_at" gorm:"autoUpdateTime"`
}

func (UserSession) TableName() string {
	return "user_sessions"
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
	return upsertDeviceProfileWithDB(DB, profile)
}

func upsertDeviceProfileWithDB(db *gorm.DB, profile *UserDeviceProfile) error {
	if profile == nil || profile.DeviceKey == "" {
		return nil
	}

	now := time.Now()
	insertProfile := *profile
	insertProfile.LastSeenAt = now
	if insertProfile.SeenCount <= 0 {
		insertProfile.SeenCount = 1
	}

	createResult := db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}, {Name: "device_key"}},
		DoNothing: true,
	}).Create(&insertProfile)
	if createResult.Error != nil {
		return createResult.Error
	}
	if createResult.RowsAffected > 0 {
		return nil
	}

	updates := UserDeviceProfile{
		CanvasHash:            profile.CanvasHash,
		WebGLHash:             profile.WebGLHash,
		WebGLDeepHash:         profile.WebGLDeepHash,
		ClientRectsHash:       profile.ClientRectsHash,
		MediaDevicesHash:      profile.MediaDevicesHash,
		MediaDeviceCount:      profile.MediaDeviceCount,
		MediaDeviceGroupHash:  profile.MediaDeviceGroupHash,
		MediaDeviceTotal:      profile.MediaDeviceTotal,
		SpeechVoicesHash:      profile.SpeechVoicesHash,
		SpeechVoiceCount:      profile.SpeechVoiceCount,
		SpeechLocalVoiceCount: profile.SpeechLocalVoiceCount,
		AudioHash:             profile.AudioHash,
		FontsHash:             profile.FontsHash,
		LocalDeviceID:         profile.LocalDeviceID,
		CompositeHash:         profile.CompositeHash,
		HTTPHeaderHash:        profile.HTTPHeaderHash,
		UABrowser:             profile.UABrowser,
		UAOS:                  profile.UAOS,
		UADeviceType:          profile.UADeviceType,
		LastSeenIP:            profile.LastSeenIP,
		LastSeenAt:            now,
	}
	if err := db.Model(&UserDeviceProfile{}).
		Where("user_id = ? AND device_key = ?", profile.UserID, profile.DeviceKey).
		Select(
			"CanvasHash",
			"WebGLHash",
			"WebGLDeepHash",
			"ClientRectsHash",
			"MediaDevicesHash",
			"MediaDeviceCount",
			"MediaDeviceGroupHash",
			"MediaDeviceTotal",
			"SpeechVoicesHash",
			"SpeechVoiceCount",
			"SpeechLocalVoiceCount",
			"AudioHash",
			"FontsHash",
			"LocalDeviceID",
			"CompositeHash",
			"HTTPHeaderHash",
			"UABrowser",
			"UAOS",
			"UADeviceType",
			"LastSeenIP",
			"LastSeenAt",
		).
		Updates(&updates).Error; err != nil {
		return err
	}
	return db.Model(&UserDeviceProfile{}).
		Where("user_id = ? AND device_key = ?", profile.UserID, profile.DeviceKey).
		UpdateColumn("SeenCount", gorm.Expr("seen_count + ?", 1)).Error
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
			ID:                    p.ID,
			UserID:                p.UserID,
			CanvasHash:            p.CanvasHash,
			WebGLHash:             p.WebGLHash,
			WebGLDeepHash:         p.WebGLDeepHash,
			ClientRectsHash:       p.ClientRectsHash,
			MediaDevicesHash:      p.MediaDevicesHash,
			MediaDeviceCount:      p.MediaDeviceCount,
			MediaDeviceGroupHash:  p.MediaDeviceGroupHash,
			MediaDeviceTotal:      p.MediaDeviceTotal,
			SpeechVoicesHash:      p.SpeechVoicesHash,
			SpeechVoiceCount:      p.SpeechVoiceCount,
			SpeechLocalVoiceCount: p.SpeechLocalVoiceCount,
			AudioHash:             p.AudioHash,
			FontsHash:             p.FontsHash,
			LocalDeviceID:         p.LocalDeviceID,
			CompositeHash:         p.CompositeHash,
			HTTPHeaderHash:        p.HTTPHeaderHash,
			UABrowser:             p.UABrowser,
			UAOS:                  p.UAOS,
			UADeviceType:          p.UADeviceType,
			IPAddress:             p.LastSeenIP,
			CreatedAt:             p.LastSeenAt,
		})
	}
	return result
}

// GetDeviceProfileByID 根据主键查询设备档案（user_device_profiles 表）
func GetDeviceProfileByID(id int64) *UserDeviceProfile {
	var dp UserDeviceProfile
	if err := DB.First(&dp, id).Error; err != nil {
		return nil
	}
	return &dp
}

// DeviceProfileToFingerprint 将单个设备档案转换为 Fingerprint 结构
// 供关联分析时作为比对基准使用
func DeviceProfileToFingerprint(p *UserDeviceProfile) *Fingerprint {
	return &Fingerprint{
		ID:                    p.ID,
		UserID:                p.UserID,
		CanvasHash:            p.CanvasHash,
		WebGLHash:             p.WebGLHash,
		WebGLDeepHash:         p.WebGLDeepHash,
		ClientRectsHash:       p.ClientRectsHash,
		MediaDevicesHash:      p.MediaDevicesHash,
		MediaDeviceCount:      p.MediaDeviceCount,
		MediaDeviceGroupHash:  p.MediaDeviceGroupHash,
		MediaDeviceTotal:      p.MediaDeviceTotal,
		SpeechVoicesHash:      p.SpeechVoicesHash,
		SpeechVoiceCount:      p.SpeechVoiceCount,
		SpeechLocalVoiceCount: p.SpeechLocalVoiceCount,
		AudioHash:             p.AudioHash,
		FontsHash:             p.FontsHash,
		LocalDeviceID:         p.LocalDeviceID,
		CompositeHash:         p.CompositeHash,
		HTTPHeaderHash:        p.HTTPHeaderHash,
		UABrowser:             p.UABrowser,
		UAOS:                  p.UAOS,
		UADeviceType:          p.UADeviceType,
		IPAddress:             p.LastSeenIP,
		CreatedAt:             p.LastSeenAt,
	}
}
