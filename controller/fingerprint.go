package controller

import (
	"net/http"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

// FingerprintReportRequest 指纹上报请求
type FingerprintReportRequest struct {
	CanvasHash    string  `json:"canvas_hash"`
	WebGLHash     string  `json:"webgl_hash"`
	WebGLVendor   string  `json:"webgl_vendor"`
	WebGLRenderer string  `json:"webgl_renderer"`
	AudioHash     string  `json:"audio_hash"`
	FontsHash     string  `json:"fonts_hash"`
	FontsList     string  `json:"fonts_list"`
	ScreenWidth   int     `json:"screen_width"`
	ScreenHeight  int     `json:"screen_height"`
	ColorDepth    int     `json:"color_depth"`
	PixelRatio    float32 `json:"pixel_ratio"`
	CPUCores      int     `json:"cpu_cores"`
	DeviceMemory  float32 `json:"device_memory"`
	MaxTouch      int     `json:"max_touch"`
	Timezone      string  `json:"timezone"`
	TZOffset      int     `json:"tz_offset"`
	Languages     string  `json:"languages"`
	Platform      string  `json:"platform"`
	DoNotTrack    string  `json:"do_not_track"`
	CookieEnabled bool    `json:"cookie_enabled"`
	LocalDeviceID string  `json:"local_device_id"`
	CompositeHash string  `json:"composite_hash"`
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
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid request body"})
		return
	}

	// 服务端采集
	realIP := c.GetString("real_ip")
	if realIP == "" {
		realIP = middleware.ExtractRealIP(c)
	}
	userAgent := c.GetHeader("User-Agent")
	parsedUA := common.ParseUserAgent(userAgent)

	// IP情报
	ipInfo := service.LookupIP(realIP)

	fp := &model.Fingerprint{
		UserID:        userID,
		IPAddress:     realIP,
		IPCountry:     ipInfo.Country,
		IPRegion:      ipInfo.Region,
		IPCity:        ipInfo.City,
		IPISP:         ipInfo.ISP,
		IPType:        ipInfo.Type,
		UserAgent:     userAgent,
		UABrowser:     parsedUA.Browser,
		UABrowserVer:  parsedUA.BrowserVer,
		UAOS:          parsedUA.OS,
		UAOSVer:       parsedUA.OSVer,
		UADeviceType:  parsedUA.DeviceType,
		CanvasHash:    req.CanvasHash,
		WebGLHash:     req.WebGLHash,
		WebGLVendor:   req.WebGLVendor,
		WebGLRenderer: req.WebGLRenderer,
		AudioHash:     req.AudioHash,
		FontsHash:     req.FontsHash,
		FontsList:     req.FontsList,
		ScreenWidth:   req.ScreenWidth,
		ScreenHeight:  req.ScreenHeight,
		ColorDepth:    req.ColorDepth,
		PixelRatio:    req.PixelRatio,
		CPUCores:      req.CPUCores,
		DeviceMemory:  req.DeviceMemory,
		MaxTouch:      req.MaxTouch,
		Timezone:      req.Timezone,
		TZOffset:      req.TZOffset,
		Languages:     req.Languages,
		Platform:      req.Platform,
		DoNotTrack:    req.DoNotTrack,
		CookieEnabled: req.CookieEnabled,
		LocalDeviceID: req.LocalDeviceID,
		CompositeHash: req.CompositeHash,
		PageURL:       c.GetHeader("Referer"),
	}

	if err := fp.Insert(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "failed to save fingerprint"})
		return
	}

	// 写入设备档案（永久保留，幂等 upsert）
	deviceKey := model.BuildDeviceKey(req.LocalDeviceID, req.CanvasHash, req.WebGLHash, req.AudioHash)
	if deviceKey != "" {
		profile := &model.UserDeviceProfile{
			UserID:        userID,
			DeviceKey:     deviceKey,
			CanvasHash:    req.CanvasHash,
			WebGLHash:     req.WebGLHash,
			AudioHash:     req.AudioHash,
			FontsHash:     req.FontsHash,
			LocalDeviceID: req.LocalDeviceID,
			CompositeHash: req.CompositeHash,
			UABrowser:     parsedUA.Browser,
			UAOS:          parsedUA.OS,
			UADeviceType:  parsedUA.DeviceType,
			LastSeenIP:    realIP,
		}
		_ = model.UpsertDeviceProfile(profile)

		// 异步：检测同设备跨账号使用（高优先级关联信号）
		go func() {
			conflicts := model.CheckDeviceKeyConflict(userID, deviceKey)
			for _, otherUID := range conflicts {
				if model.IsWhitelisted(userID, otherUID) {
					continue
				}
				// 同设备直接使用高置信度（0.95），无需再做特征对比
				_ = model.UpsertLink(userID, otherUID, 0.95, 1, 1,
					`[{"dimension":"device_key","display_name":"设备档案(同设备多账号)","score":0.95,"weight":0.95,"matched":true,"category":"device"}]`)
			}
		}()
	}

	// 异步触发关联分析
	go service.AnalyzeAccountLinks(userID, fp)

	c.JSON(http.StatusOK, gin.H{"success": true})
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
