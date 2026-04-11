package controller

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

const fingerprintReportRequestBodyLimit = 1 << 20 // 1 MiB
const fingerprintSessionTimestampSkewLimit = 24 * time.Hour
const fingerprintKeystrokeSampleCountLimit = 10000
const fingerprintKeystrokeMetricLimit = 10000
const fingerprintMouseSampleCountLimit = 100000
const fingerprintMouseMetricLimit = 100000
const fingerprintSessionIDMaxLength = 64

// FingerprintReportRequest 指纹上报请求
type FingerprintReportRequest struct {
	CanvasHash            string                       `json:"canvas_hash"`
	WebGLHash             string                       `json:"webgl_hash"`
	WebGLDeepHash         string                       `json:"webgl_deep_hash"`
	ClientRectsHash       string                       `json:"client_rects_hash"`
	WebGLVendor           string                       `json:"webgl_vendor"`
	WebGLRenderer         string                       `json:"webgl_renderer"`
	MediaDevicesHash      string                       `json:"media_devices_hash"`
	MediaDeviceCount      string                       `json:"media_device_count"`
	MediaDeviceGroupHash  string                       `json:"media_device_group_hash"`
	MediaDeviceTotal      int                          `json:"media_device_total"`
	SpeechVoicesHash      string                       `json:"speech_voices_hash"`
	SpeechVoiceCount      int                          `json:"speech_voice_count"`
	SpeechLocalVoiceCount int                          `json:"speech_local_voice_count"`
	AudioHash             string                       `json:"audio_hash"`
	FontsHash             string                       `json:"fonts_hash"`
	FontsList             string                       `json:"fonts_list"`
	ScreenWidth           int                          `json:"screen_width"`
	ScreenHeight          int                          `json:"screen_height"`
	ColorDepth            int                          `json:"color_depth"`
	PixelRatio            float32                      `json:"pixel_ratio"`
	CPUCores              int                          `json:"cpu_cores"`
	DeviceMemory          float32                      `json:"device_memory"`
	MaxTouch              int                          `json:"max_touch"`
	Timezone              string                       `json:"timezone"`
	TZOffset              int                          `json:"tz_offset"`
	Languages             string                       `json:"languages"`
	Platform              string                       `json:"platform"`
	DoNotTrack            string                       `json:"do_not_track"`
	CookieEnabled         bool                         `json:"cookie_enabled"`
	LocalDeviceID         string                       `json:"local_device_id"`
	PersistentID          string                       `json:"persistent_id"`
	PersistentIDSource    string                       `json:"id_source"`
	ETagID                string                       `json:"etag_id"`
	HTTPHeaderHash        string                       `json:"http_header_hash"`
	WebRTCLocalIPs        []string                     `json:"webrtc_local_ips"`
	WebRTCPublicIPs       []string                     `json:"webrtc_public_ips"`
	CompositeHash         string                       `json:"composite_hash"`
	DNSResolverIP         string                       `json:"dns_resolver_ip"`
	DNSProbeID            string                       `json:"dns_probe_id"`
	SessionID             string                       `json:"session_id"`
	SessionStartAt        int64                        `json:"session_start_at"`
	SessionEndAt          int64                        `json:"session_end_at"`
	Keystroke             *KeystrokeFingerprintRequest `json:"keystroke,omitempty"`
	Mouse                 *MouseFingerprintRequest     `json:"mouse,omitempty"`
}

type KeystrokeDigraphRequest struct {
	Digraph       string  `json:"digraph"`
	AvgFlightTime float64 `json:"avgFlightTime"`
	StdFlightTime float64 `json:"stdFlightTime"`
	SampleCount   int     `json:"sampleCount"`
}

// KeystrokeFingerprintRequest 打字节奏统计（仅时间模式，不含按键内容）。
type KeystrokeFingerprintRequest struct {
	AvgHoldTime    float64                   `json:"avgHoldTime"`
	StdHoldTime    float64                   `json:"stdHoldTime"`
	AvgFlightTime  float64                   `json:"avgFlightTime"`
	StdFlightTime  float64                   `json:"stdFlightTime"`
	TypingSpeed    float64                   `json:"typingSpeed"`
	CommonDigraphs []KeystrokeDigraphRequest `json:"commonDigraphs"`
	SampleCount    int                       `json:"sampleCount"`
}

type MouseClickDistributionRequest struct {
	TopLeft     float64 `json:"topLeft"`
	TopRight    float64 `json:"topRight"`
	BottomLeft  float64 `json:"bottomLeft"`
	BottomRight float64 `json:"bottomRight"`
}

// MouseFingerprintRequest 鼠标行为统计（仅统计特征，不含原始坐标）。
type MouseFingerprintRequest struct {
	AvgSpeed            float64                       `json:"avgSpeed"`
	MaxSpeed            float64                       `json:"maxSpeed"`
	SpeedStd            float64                       `json:"speedStd"`
	AvgAcceleration     float64                       `json:"avgAcceleration"`
	AccStd              float64                       `json:"accStd"`
	DirectionChangeRate float64                       `json:"directionChangeRate"`
	AvgScrollDelta      float64                       `json:"avgScrollDelta"`
	ScrollDeltaMode     int                           `json:"scrollDeltaMode"`
	ClickDistribution   MouseClickDistributionRequest `json:"clickDistribution"`
	SampleCount         int                           `json:"sampleCount"`
}

type BehaviorFingerprintReportRequest struct {
	SessionID      string                       `json:"session_id"`
	SessionStartAt int64                        `json:"session_start_at"`
	SessionEndAt   int64                        `json:"session_end_at"`
	Keystroke      *KeystrokeFingerprintRequest `json:"keystroke,omitempty"`
	Mouse          *MouseFingerprintRequest     `json:"mouse,omitempty"`
}

// ReportFingerprint POST /api/fingerprint/report
func ReportFingerprint(c *gin.Context) {
	if !common.FingerprintEnabled {
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "fingerprint system disabled"})
		return
	}

	userID := c.GetInt("id")
	if userID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "unauthorized"})
		return
	}

	var req FingerprintReportRequest
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, fingerprintReportRequestBodyLimit)
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid request body"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid request body"})
		return
	}
	if err = common.DecodeJsonStrict(bytes.NewReader(body), &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid request body"})
		return
	}
	req.SessionID = strings.TrimSpace(req.SessionID)
	if len(req.SessionID) > fingerprintSessionIDMaxLength {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid request body"})
		return
	}
	behaviorEnabled := common.FingerprintEnableBehaviorAnalysis
	if behaviorEnabled {
		if err = ValidateKeystrokeFingerprintRequest(req.Keystroke); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid request body"})
			return
		}
		if err = ValidateMouseFingerprintRequest(req.Mouse); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid request body"})
			return
		}
	}

	realIP := c.GetString("real_ip")
	if realIP == "" {
		realIP = middleware.ExtractRealIP(c)
	}
	ja4 := c.GetString("ja4_fingerprint")
	httpHeaderFP := c.GetString("http_header_fingerprint")
	userAgent := c.GetHeader("User-Agent")
	parsedUA := common.ParseUserAgent(userAgent)
	ipInfo := service.LookupIP(realIP)

	if !common.FingerprintEnableJA4 {
		ja4 = ""
	}

	dnsResolverIP := ""
	if common.FingerprintEnableDNSLeak {
		dnsResolverIP = service.ResolveDNSResolverIP(c.Request.Context(), req.DNSResolverIP, req.DNSProbeID)
	}

	clientFP := &ClientFingerprintData{
		CanvasHash:            req.CanvasHash,
		WebGLHash:             req.WebGLHash,
		WebGLDeepHash:         req.WebGLDeepHash,
		ClientRectsHash:       req.ClientRectsHash,
		WebGLVendor:           req.WebGLVendor,
		WebGLRenderer:         req.WebGLRenderer,
		MediaDevicesHash:      req.MediaDevicesHash,
		MediaDeviceCount:      req.MediaDeviceCount,
		MediaDeviceGroupHash:  req.MediaDeviceGroupHash,
		MediaDeviceTotal:      req.MediaDeviceTotal,
		SpeechVoicesHash:      req.SpeechVoicesHash,
		SpeechVoiceCount:      req.SpeechVoiceCount,
		SpeechLocalVoiceCount: req.SpeechLocalVoiceCount,
		AudioHash:             req.AudioHash,
		FontsHash:             req.FontsHash,
		FontsList:             req.FontsList,
		ScreenWidth:           req.ScreenWidth,
		ScreenHeight:          req.ScreenHeight,
		ColorDepth:            req.ColorDepth,
		PixelRatio:            req.PixelRatio,
		CPUCores:              req.CPUCores,
		DeviceMemory:          req.DeviceMemory,
		MaxTouch:              req.MaxTouch,
		Timezone:              req.Timezone,
		TZOffset:              req.TZOffset,
		Languages:             req.Languages,
		Platform:              req.Platform,
		DoNotTrack:            req.DoNotTrack,
		CookieEnabled:         req.CookieEnabled,
		LocalDeviceID:         req.LocalDeviceID,
		PersistentID:          req.PersistentID,
		PersistentIDSource:    req.PersistentIDSource,
		ETagID:                req.ETagID,
		WebRTCLocalIPs:        req.WebRTCLocalIPs,
		WebRTCPublicIPs:       req.WebRTCPublicIPs,
		CompositeHash:         req.CompositeHash,
	}

	fp := &model.Fingerprint{
		UserID:         userID,
		IPAddress:      realIP,
		IPCountry:      ipInfo.Country,
		IPRegion:       ipInfo.Region,
		IPCity:         ipInfo.City,
		IPISP:          ipInfo.ISP,
		IPType:         ipInfo.Type,
		DNSResolverIP:  dnsResolverIP,
		ASN:            ipInfo.ASN,
		ASNOrg:         ipInfo.ASNOrg,
		IsDatacenter:   ipInfo.IsDatacenter,
		UserAgent:      userAgent,
		JA4:            ja4,
		HTTPHeaderHash: httpHeaderFP,
		UABrowser:      parsedUA.Browser,
		UABrowserVer:   parsedUA.BrowserVer,
		UAOS:           parsedUA.OS,
		UAOSVer:        parsedUA.OSVer,
		UADeviceType:   parsedUA.DeviceType,
		PageURL:        sanitizePageURL(c.GetHeader("Referer")),
		SessionID:      req.SessionID,
	}
	applyClientFingerprintData(fp, clientFP)
	applyFingerprintFeatureSwitches(fp)

	profile := buildUserDeviceProfileFromFingerprint(userID, realIP, parsedUA, fp)
	deviceKey := ""
	if profile != nil {
		deviceKey = profile.DeviceKey
	}
	var keystrokeProfile *model.KeystrokeProfile
	var mouseProfile *model.MouseProfile
	if behaviorEnabled {
		keystrokeProfile = buildKeystrokeProfileFromRequest(userID, req.Keystroke)
		mouseProfile = buildMouseProfileFromRequest(userID, req.Mouse)
	}

	session := buildUserSessionFromRequest(userID, req, deviceKey, realIP)
	if err := model.PersistFingerprintReportAtomic(fp, profile, session, keystrokeProfile, mouseProfile); err != nil {
		common.SysLog("fingerprint report persistence failed: " + err.Error())
		switch {
		case errors.Is(err, model.ErrFingerprintPersistDevice):
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "failed to save device profile"})
		case errors.Is(err, model.ErrFingerprintPersistSession):
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "failed to save session"})
		case errors.Is(err, model.ErrFingerprintPersistBehavior):
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "failed to save behavior profile"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "failed to save fingerprint"})
		}
		return
	}

	if profile != nil {
		go func(deviceKey string) {
			defer func() {
				if r := recover(); r != nil {
					common.SysError(fmt.Sprintf("panic in fingerprint device-key conflict analyzer: %v", r))
				}
			}()
			conflicts := model.CheckDeviceKeyConflict(userID, deviceKey)
			for _, otherUID := range conflicts {
				if model.IsWhitelisted(userID, otherUID) {
					continue
				}
				_ = model.UpsertLink(userID, otherUID, 0.95, 1, 1,
					`[{"dimension":"device_key","display_name":"设备档案(同设备多账号)","score":0.95,"weight":0.95,"matched":true,"category":"device"}]`)
			}
		}(profile.DeviceKey)
	}

	go func(uid int, persistedFP *model.Fingerprint) {
		defer func() {
			if r := recover(); r != nil {
				common.SysError(fmt.Sprintf("panic in fingerprint account-link analyzer: %v", r))
			}
		}()
		service.AnalyzeAccountLinks(uid, persistedFP)
	}(userID, fp)

	c.JSON(http.StatusOK, gin.H{"success": true})
}

// ReportBehaviorFingerprint POST /api/fingerprint/behavior
func ReportBehaviorFingerprint(c *gin.Context) {
	if !common.FingerprintEnabled {
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "fingerprint system disabled"})
		return
	}
	if !common.FingerprintEnableBehaviorAnalysis {
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "behavior analysis disabled"})
		return
	}

	userID := c.GetInt("id")
	if userID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "unauthorized"})
		return
	}

	var req BehaviorFingerprintReportRequest
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, fingerprintReportRequestBodyLimit)
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid request body"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid request body"})
		return
	}
	if err = common.DecodeJsonStrict(bytes.NewReader(body), &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid request body"})
		return
	}
	req.SessionID = strings.TrimSpace(req.SessionID)
	if len(req.SessionID) > fingerprintSessionIDMaxLength {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid request body"})
		return
	}
	if req.Keystroke == nil && req.Mouse == nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid request body"})
		return
	}
	if err = ValidateKeystrokeFingerprintRequest(req.Keystroke); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid request body"})
		return
	}
	if err = ValidateMouseFingerprintRequest(req.Mouse); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid request body"})
		return
	}

	if err := upsertBehaviorProfiles(userID, req.Keystroke, req.Mouse); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "failed to save behavior profile"})
		return
	}

	go func(uid int) {
		defer func() {
			if r := recover(); r != nil {
				common.SysError(fmt.Sprintf("panic in behavior incremental link scan: %v", r))
			}
		}()
		service.IncrementalLinkScan(uid, nil)
	}(userID)

	c.JSON(http.StatusOK, gin.H{"success": true})
}

func upsertBehaviorProfiles(userID int, keystroke *KeystrokeFingerprintRequest, mouse *MouseFingerprintRequest) error {
	if err := model.UpsertBehaviorProfilesAtomic(
		buildKeystrokeProfileFromRequest(userID, keystroke),
		buildMouseProfileFromRequest(userID, mouse),
	); err != nil {
		return fmt.Errorf("upsert behavior profiles: %w", err)
	}
	return nil
}

func applyFingerprintFeatureSwitches(fp *model.Fingerprint) {
	if fp == nil {
		return
	}
	if !common.FingerprintEnableJA4 {
		fp.JA4 = ""
	}
	if !common.FingerprintEnableETag {
		fp.ETagID = ""
	}
	if !common.FingerprintEnableWebRTC {
		fp.WebRTCLocalIPs = ""
		fp.WebRTCPublicIPs = ""
	}
	if !common.FingerprintEnableDNSLeak {
		fp.DNSResolverIP = ""
	}
}

func buildKeystrokeProfileFromRequest(userID int, req *KeystrokeFingerprintRequest) *model.KeystrokeProfile {
	if req == nil {
		return nil
	}
	digraphRaw, err := common.Marshal(req.CommonDigraphs)
	if err != nil {
		digraphRaw = []byte("[]")
	}
	return &model.KeystrokeProfile{
		UserID:        userID,
		AvgHoldTime:   req.AvgHoldTime,
		StdHoldTime:   req.StdHoldTime,
		AvgFlightTime: req.AvgFlightTime,
		StdFlightTime: req.StdFlightTime,
		TypingSpeed:   req.TypingSpeed,
		DigraphData:   string(digraphRaw),
		SampleCount:   req.SampleCount,
	}
}

func buildMouseProfileFromRequest(userID int, req *MouseFingerprintRequest) *model.MouseProfile {
	if req == nil {
		return nil
	}

	clickDistRaw, err := common.Marshal(req.ClickDistribution)
	if err != nil {
		clickDistRaw = []byte("{}")
	}

	return &model.MouseProfile{
		UserID:              userID,
		AvgSpeed:            req.AvgSpeed,
		MaxSpeed:            req.MaxSpeed,
		SpeedStd:            req.SpeedStd,
		AvgAcceleration:     req.AvgAcceleration,
		AccStd:              req.AccStd,
		DirectionChangeRate: req.DirectionChangeRate,
		AvgScrollDelta:      req.AvgScrollDelta,
		ScrollDeltaMode:     req.ScrollDeltaMode,
		ClickDistribution:   string(clickDistRaw),
		SampleCount:         req.SampleCount,
	}
}

func isAllowedKeystrokeDigraphClass(value string) bool {
	switch strings.TrimSpace(value) {
	case "alpha", "digit", "space", "enter", "backspace", "tab", "arrow", "control", "other":
		return true
	default:
		return false
	}
}

func isAllowedKeystrokeDigraphValue(value string) bool {
	trimmed := strings.TrimSpace(value)
	left, right, ok := strings.Cut(trimmed, "->")
	if !ok || strings.Contains(right, "->") {
		return false
	}
	return isAllowedKeystrokeDigraphClass(left) && isAllowedKeystrokeDigraphClass(right)
}

func isValidKeystrokeMetric(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0 && value <= fingerprintKeystrokeMetricLimit
}

func isFiniteNonNegativeMouseMetric(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0 && value <= fingerprintMouseMetricLimit
}

func ValidateKeystrokeFingerprintRequest(req *KeystrokeFingerprintRequest) error {
	if req == nil {
		return nil
	}
	if req.SampleCount < 0 || req.SampleCount > fingerprintKeystrokeSampleCountLimit {
		return fmt.Errorf("invalid sampleCount")
	}
	if !isValidKeystrokeMetric(req.AvgHoldTime) ||
		!isValidKeystrokeMetric(req.StdHoldTime) ||
		!isValidKeystrokeMetric(req.AvgFlightTime) ||
		!isValidKeystrokeMetric(req.StdFlightTime) ||
		!isValidKeystrokeMetric(req.TypingSpeed) {
		return fmt.Errorf("invalid keystroke metric")
	}
	if len(req.CommonDigraphs) > 10 {
		return fmt.Errorf("too many commonDigraphs")
	}
	for _, item := range req.CommonDigraphs {
		if !isAllowedKeystrokeDigraphValue(item.Digraph) {
			return fmt.Errorf("invalid digraph")
		}
		if item.SampleCount < 0 || item.SampleCount > fingerprintKeystrokeSampleCountLimit {
			return fmt.Errorf("invalid digraph sampleCount")
		}
		if !isValidKeystrokeMetric(item.AvgFlightTime) || !isValidKeystrokeMetric(item.StdFlightTime) {
			return fmt.Errorf("invalid digraph metric")
		}
	}
	return nil
}

func ValidateMouseFingerprintRequest(req *MouseFingerprintRequest) error {
	if req == nil {
		return nil
	}
	if req.SampleCount < 0 || req.SampleCount > fingerprintMouseSampleCountLimit {
		return fmt.Errorf("invalid mouse sampleCount")
	}
	if req.ScrollDeltaMode < 0 || req.ScrollDeltaMode > 2 {
		return fmt.Errorf("invalid scrollDeltaMode")
	}
	if !isFiniteNonNegativeMouseMetric(req.AvgSpeed) ||
		!isFiniteNonNegativeMouseMetric(req.MaxSpeed) ||
		!isFiniteNonNegativeMouseMetric(req.SpeedStd) ||
		!isFiniteNonNegativeMouseMetric(req.AvgAcceleration) ||
		!isFiniteNonNegativeMouseMetric(req.AccStd) ||
		!isFiniteNonNegativeMouseMetric(req.DirectionChangeRate) ||
		!isFiniteNonNegativeMouseMetric(req.AvgScrollDelta) {
		return fmt.Errorf("invalid mouse metric")
	}
	if req.DirectionChangeRate > 1 {
		return fmt.Errorf("invalid directionChangeRate")
	}
	clickDist := req.ClickDistribution
	if !isFiniteNonNegativeMouseMetric(clickDist.TopLeft) ||
		!isFiniteNonNegativeMouseMetric(clickDist.TopRight) ||
		!isFiniteNonNegativeMouseMetric(clickDist.BottomLeft) ||
		!isFiniteNonNegativeMouseMetric(clickDist.BottomRight) {
		return fmt.Errorf("invalid clickDistribution metric")
	}
	total := clickDist.TopLeft + clickDist.TopRight + clickDist.BottomLeft + clickDist.BottomRight
	if total <= 0 {
		return fmt.Errorf("invalid clickDistribution total")
	}
	return nil
}

func clampFingerprintSessionTimestamp(ts time.Time, now time.Time) time.Time {
	if ts.IsZero() {
		return now
	}
	if ts.Before(now.Add(-fingerprintSessionTimestampSkewLimit)) || ts.After(now.Add(fingerprintSessionTimestampSkewLimit)) {
		return now
	}
	return ts
}

func buildUserSessionFromRequest(userID int, req FingerprintReportRequest, deviceKey string, realIP string) *model.UserSession {
	now := time.Now().UTC()
	startedAt := now
	if req.SessionStartAt > 0 {
		startedAt = time.Unix(req.SessionStartAt, 0).UTC()
	}
	endedAt := startedAt
	if req.SessionEndAt > 0 {
		endedAt = time.Unix(req.SessionEndAt, 0).UTC()
	}
	startedAt = clampFingerprintSessionTimestamp(startedAt, now)
	endedAt = clampFingerprintSessionTimestamp(endedAt, now)
	if endedAt.Before(startedAt) {
		endedAt = startedAt
	}
	duration := int(endedAt.Sub(startedAt).Seconds())
	if duration < 0 {
		duration = 0
	}

	return &model.UserSession{
		UserID:          userID,
		SessionID:       req.SessionID,
		DeviceKey:       deviceKey,
		IPAddress:       realIP,
		StartedAt:       startedAt,
		EndedAt:         endedAt,
		DurationSeconds: duration,
		EventCount:      1,
		IsBurst:         duration <= 90,
		Source:          "fingerprint",
	}
}

// GetFingerprintAccess GET /api/fingerprint/access
func GetFingerprintAccess(c *gin.Context) {
	role, exists := c.Get("role")
	if !exists {
		c.JSON(http.StatusOK, gin.H{
			"success":    true,
			"has_access": false,
			"enabled":    common.FingerprintEnabled,
		})
		return
	}

	userRole, ok := role.(int)
	if !ok {
		userRole = 0
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"has_access": common.HasFingerprintAccess(userRole),
		"enabled":    common.FingerprintEnabled,
	})
}
