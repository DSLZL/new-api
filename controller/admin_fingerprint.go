/*
Copyright (C) 2025 QuantumNous

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please contact support@quantumnous.com
*/

package controller

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

var fingerprintWeightsUpdateMu sync.Mutex

// FPDashboard GET /api/admin/fingerprint/dashboard
func FPDashboard(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"total_fingerprints":    model.CountFingerprints(),
			"total_links_pending":   model.CountLinks("pending"),
			"total_links_confirmed": model.CountLinks("confirmed"),
			"critical_risk_users":   model.CountUsersByRisk("critical"),
			"high_risk_users":       model.CountUsersByRisk("high"),
			"recent_links":          model.GetRecentLinks(10),
			"top_risk_users":        model.GetTopRiskUsers(10),
			"vpn_usage_stats":       model.GetVPNUsageStats(),
		},
	})
}

// FPGetLinks GET /api/admin/fingerprint/links
func FPGetLinks(c *gin.Context) {
	status := c.DefaultQuery("status", "pending")
	minConf, _ := strconv.ParseFloat(c.DefaultQuery("min_confidence", "0"), 64)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	links, total := model.GetAccountLinks(status, minConf, page, pageSize)

	type EnrichedLink struct {
		*model.AccountLink
		UserAInfo service.UserBrief `json:"user_a_info"`
		UserBInfo service.UserBrief `json:"user_b_info"`
	}
	enriched := make([]EnrichedLink, len(links))
	for i, link := range links {
		enriched[i] = EnrichedLink{
			AccountLink: link,
			UserAInfo:   getUserBriefByID(link.UserIDA),
			UserBInfo:   getUserBriefByID(link.UserIDB),
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    enriched,
		"total":   total,
		"page":    page,
	})
}

// FPGetLinkDetail GET /api/admin/fingerprint/links/:id
func FPGetLinkDetail(c *gin.Context) {
	linkID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid link id"})
		return
	}

	link := model.GetLinkByID(linkID)
	if link == nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "link not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":     true,
		"data":        link,
		"user_a_info": getUserBriefByID(link.UserIDA),
		"user_b_info": getUserBriefByID(link.UserIDB),
	})
}

// FPReviewLink POST /api/admin/fingerprint/links/:id/review
func FPReviewLink(c *gin.Context) {
	linkID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid link id"})
		return
	}

	var req struct {
		Action string `json:"action"` // confirm, reject, whitelist, ban_newer
		Note   string `json:"note"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid request"})
		return
	}

	err = service.ReviewLink(linkID, req.Action, req.Note)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

// ═══════════════════════════════════════════════════════════════
// ★★★ 核心修改：FPGetUserAssociations ★★★
// GET /api/admin/fingerprint/user/:id/associations
//
// 旧逻辑: fingerprint_id → GetFingerprintByID() → 查 user_fingerprints（流水表，会被清理）
// 新逻辑: device_profile_id → GetDeviceProfileByID() → 查 user_device_profiles（永久表）
//
//	→ DeviceProfileToFingerprint() → 转为 Fingerprint 结构供比对
//
// ═══════════════════════════════════════════════════════════════
func FPGetUserAssociations(c *gin.Context) {
	targetUserID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid user id"})
		return
	}

	minConf, _ := strconv.ParseFloat(c.DefaultQuery("min_confidence", "0.3"), 64)
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	refresh := c.DefaultQuery("refresh", "false") == "true"
	includeDetails := c.DefaultQuery("include_details", "false") == "true"
	includeSharedIPs := c.DefaultQuery("include_shared_ips", "false") == "true"
	candidateUserID, _ := strconv.Atoi(c.DefaultQuery("candidate_user_id", "0"))

	if limit < 1 || limit > 100 {
		limit = 20
	}

	// ──────────────────────────────────────────────────────────
	// ★ 改动 1: 读取 device_profile_id（来自 user_device_profiles 表）
	//           替代原来的 fingerprint_id（来自 user_fingerprints 表）
	// ──────────────────────────────────────────────────────────
	dpIDStr := c.Query("device_profile_id")
	dpID := int64(0)
	if dpIDStr != "" {
		var parseErr error
		dpID, parseErr = strconv.ParseInt(dpIDStr, 10, 64)
		if parseErr != nil || dpID <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid device_profile_id"})
			return
		}
	}

	// ──────────────────────────────────────────────────────────
	// ★ 改动 2: 查 user_device_profiles 表，转为 Fingerprint 结构
	// ──────────────────────────────────────────────────────────
	var baseFingerprint *model.Fingerprint // nil = 使用默认逻辑（自动选最近指纹）

	if dpID > 0 {
		profile := model.GetDeviceProfileByID(dpID)
		if profile == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"success": false,
				"message": fmt.Sprintf("设备档案 %d 不存在", dpID),
			})
			return
		}
		if profile.UserID != targetUserID {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": fmt.Sprintf("设备档案 %d 不属于用户 %d", dpID, targetUserID),
			})
			return
		}

		// 转为 Fingerprint 结构，作为比对基准
		baseFingerprint = model.DeviceProfileToFingerprint(profile)
	}

	// ──────────────────────────────────────────────────────────
	// ★ 改动 3: 传 *model.Fingerprint 而非 int64 fpID
	//           service.QueryUserAssociations 签名需同步修改（见下方说明）
	// ──────────────────────────────────────────────────────────
	result, err := service.QueryUserAssociationsWithOptions(targetUserID, minConf, limit, refresh, baseFingerprint, &service.AssociationQueryOptions{
		IncludeDetails:   includeDetails,
		IncludeSharedIPs: includeSharedIPs,
		CandidateUserID:  candidateUserID,
	})
	if err != nil {
		// 区分"无数据"与"真正的服务器错误"
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data": gin.H{
				"associations": []any{},
				"message":      err.Error(),
			},
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    result,
	})
}

// FPGetWeights GET /api/admin/fingerprint/weights
func FPGetWeights(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"weights": common.GetWeights(),
		},
	})
}

// FPUpdateWeights PUT /api/admin/fingerprint/weights
func FPUpdateWeights(c *gin.Context) {
	var req struct {
		Weights map[string]float64 `json:"weights"`
	}

	if err := common.DecodeJson(c.Request.Body, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid request"})
		return
	}
	if len(req.Weights) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid request"})
		return
	}

	aliasToKey := common.FingerprintWeightAliasToOptionKey()
	aliases := make([]string, 0, len(req.Weights))
	for alias := range req.Weights {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)

	type validatedWeight struct {
		alias     string
		optionKey string
		value     string
	}
	validated := make([]validatedWeight, 0, len(aliases))

	for _, alias := range aliases {
		value := req.Weights[alias]
		optionKey, ok := aliasToKey[alias]
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": fmt.Sprintf("invalid weight key: %s", alias)})
			return
		}
		if value <= 0 || value > 1 {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": fmt.Sprintf("invalid weight value: %s", alias)})
			return
		}
		validated = append(validated, validatedWeight{
			alias:     alias,
			optionKey: optionKey,
			value:     strconv.FormatFloat(value, 'f', -1, 64),
		})
	}

	updates := make([]model.OptionUpdate, 0, len(validated))
	for _, item := range validated {
		updates = append(updates, model.OptionUpdate{Key: item.optionKey, Value: item.value})
	}

	fingerprintWeightsUpdateMu.Lock()
	defer fingerprintWeightsUpdateMu.Unlock()

	if err := model.PersistOptionsAtomically(updates); err != nil {
		common.SysError("failed to update fingerprint weights: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "failed to update weights"})
		return
	}

	common.OptionMapRWMutex.Lock()
	for _, item := range validated {
		common.OptionMap[item.optionKey] = item.value
	}
	common.OptionMapRWMutex.Unlock()

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"weights": common.GetWeights()}})
}

// FPGetUserFingerprints GET /api/admin/fingerprint/user/:id/fingerprints
func FPGetUserFingerprints(c *gin.Context) {
	userID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid user id"})
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if limit < 1 || limit > 100 {
		limit = 20
	}

	fps := model.GetLatestFingerprints(userID, limit)
	keystroke := model.GetLatestKeystrokeProfile(userID)
	mouse := model.GetLatestMouseProfile(userID)

	mapFingerprint := func(fp *model.Fingerprint) gin.H {
		if fp == nil {
			return gin.H{}
		}
		item := gin.H{
			"id":                       fp.ID,
			"user_id":                  fp.UserID,
			"ip_address":               fp.IPAddress,
			"ip_country":               fp.IPCountry,
			"ip_region":                fp.IPRegion,
			"ip_city":                  fp.IPCity,
			"ip_isp":                   fp.IPISP,
			"ip_type":                  fp.IPType,
			"dns_resolver_ip":          fp.DNSResolverIP,
			"asn":                      fp.ASN,
			"asn_org":                  fp.ASNOrg,
			"is_datacenter":            fp.IsDatacenter,
			"user_agent":               fp.UserAgent,
			"ua_browser":               fp.UABrowser,
			"ua_browser_ver":           fp.UABrowserVer,
			"ua_os":                    fp.UAOS,
			"ua_os_ver":                fp.UAOSVer,
			"ua_device_type":           fp.UADeviceType,
			"tls_ja3_hash":             fp.TLSJA3Hash,
			"ja4":                      fp.JA4,
			"http_header_hash":         fp.HTTPHeaderHash,
			"http2_fp":                 fp.HTTP2FP,
			"tcp_os_guess":             fp.TCPOSGuess,
			"canvas_hash":              fp.CanvasHash,
			"webgl_hash":               fp.WebGLHash,
			"webgl_deep_hash":          fp.WebGLDeepHash,
			"client_rects_hash":        fp.ClientRectsHash,
			"webgl_vendor":             fp.WebGLVendor,
			"webgl_renderer":           fp.WebGLRenderer,
			"media_devices_hash":       fp.MediaDevicesHash,
			"media_device_count":       fp.MediaDeviceCount,
			"media_device_group_hash":  fp.MediaDeviceGroupHash,
			"media_device_total":       fp.MediaDeviceTotal,
			"speech_voices_hash":       fp.SpeechVoicesHash,
			"speech_voice_count":       fp.SpeechVoiceCount,
			"speech_local_voice_count": fp.SpeechLocalVoiceCount,
			"audio_hash":               fp.AudioHash,
			"fonts_hash":               fp.FontsHash,
			"fonts_list":               fp.FontsList,
			"screen_width":             fp.ScreenWidth,
			"screen_height":            fp.ScreenHeight,
			"color_depth":              fp.ColorDepth,
			"pixel_ratio":              fp.PixelRatio,
			"cpu_cores":                fp.CPUCores,
			"device_memory":            fp.DeviceMemory,
			"max_touch":                fp.MaxTouch,
			"timezone":                 fp.Timezone,
			"tz_offset":                fp.TZOffset,
			"languages":                fp.Languages,
			"platform":                 fp.Platform,
			"do_not_track":             fp.DoNotTrack,
			"cookie_enabled":           fp.CookieEnabled,
			"local_device_id":          fp.LocalDeviceID,
			"etag_id":                  fp.ETagID,
			"persistent_id":            fp.PersistentID,
			"persistent_id_source":     fp.PersistentIDSource,
			"webrtc_local_ips":         fp.WebRTCLocalIPs,
			"webrtc_public_ips":        fp.WebRTCPublicIPs,
			"composite_hash":           fp.CompositeHash,
			"page_url":                 fp.PageURL,
			"session_id":               fp.SessionID,
			"created_at":               fp.CreatedAt,
		}
		return item
	}

	items := make([]gin.H, 0, len(fps))
	for _, fp := range fps {
		items = append(items, mapFingerprint(fp))
	}

	behaviorProfile := gin.H{}
	if keystroke != nil && keystroke.SampleCount > 0 {
		behaviorProfile["typing_speed"] = keystroke.TypingSpeed
		behaviorProfile["typing_samples"] = keystroke.SampleCount
	}
	if mouse != nil && mouse.SampleCount > 0 {
		behaviorProfile["mouse_avg_speed"] = mouse.AvgSpeed
		behaviorProfile["mouse_samples"] = mouse.SampleCount
	}

	response := gin.H{
		"success": true,
		"data":    items,
	}
	if len(behaviorProfile) > 0 {
		response["behavior_profile"] = behaviorProfile
	}

	c.JSON(http.StatusOK, response)
}

// FPGetUserRisk GET /api/admin/fingerprint/user/:id/risk
func FPGetUserRisk(c *gin.Context) {
	userID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid user id"})
		return
	}

	score := model.GetUserRiskScore(userID)
	if score == nil {
		service.UpdateRiskScore(userID)
		score = model.GetUserRiskScore(userID)
	}

	if score == nil {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    nil,
			"message": "该用户暂无风险评分数据",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    score,
	})
}

// FPGetUserIPHistory GET /api/admin/fingerprint/user/:id/ip-history
func FPGetUserIPHistory(c *gin.Context) {
	userID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid user id"})
		return
	}

	history := model.GetIPUAHistory(userID)

	type EnrichedHistory struct {
		*model.IPUAHistory
		OtherUsers []int `json:"other_users"`
	}
	enriched := make([]EnrichedHistory, len(history))
	for i, h := range history {
		enriched[i] = EnrichedHistory{
			IPUAHistory: h,
			OtherUsers:  model.FindOtherUsersByIP(h.IPAddress, userID),
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    enriched,
	})
}

// FPCompareUsers POST /api/admin/fingerprint/compare
func FPCompareUsers(c *gin.Context) {
	var req struct {
		UserA int `json:"user_a"`
		UserB int `json:"user_b"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "需要提供有效的 user_a 和 user_b"})
		return
	}
	if req.UserA <= 0 || req.UserB <= 0 || req.UserA == req.UserB {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid compare users"})
		return
	}

	fpsA := model.GetLatestFingerprints(req.UserA, 5)
	if len(fpsA) == 0 {
		fpsA = model.GetDeviceProfilesAsFingerprints(req.UserA)
	}
	fpsB := model.GetLatestFingerprints(req.UserB, 5)
	if len(fpsB) == 0 {
		fpsB = model.GetDeviceProfilesAsFingerprints(req.UserB)
	}

	if len(fpsA) == 0 || len(fpsB) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "一方或双方无指纹数据",
			"data": gin.H{
				"confidence": 0,
				"details":    []any{},
			},
		})
		return
	}

	best := service.SimilarityResult{}

	for _, fpA := range fpsA {
		for _, fpB := range fpsB {
			similarity := service.CalculateSimilarity(fpA, fpB, req.UserA, req.UserB)
			if similarity.Score > best.Score {
				best = similarity
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"confidence":         best.Score,
			"tier":               best.Tier,
			"explanation":        best.Explanation,
			"matched_dimensions": best.MatchedDimensions,
			"match_dimensions":   best.MatchDimensions,
			"total_dimensions":   best.TotalDimensions,
			"details":            best.Details,
			"user_a_info":        getUserBriefByID(req.UserA),
			"user_b_info":        getUserBriefByID(req.UserB),
		},
	})
}

// FPTriggerFullScan POST /api/admin/fingerprint/scan
func FPTriggerFullScan(c *gin.Context) {
	go service.FullLinkScan()
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "全量扫描已触发，将在后台运行"})
}

// FPResetUserFingerprintTestData POST /api/admin/fingerprint/user/:id/reset-test-data
// 仅用于集成测试隔离；默认关闭（需开启 FINGERPRINT_TEST_RESET_ENABLED）
func FPResetUserFingerprintTestData(c *gin.Context) {
	if !common.FingerprintTestResetEnabled {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "message": "fingerprint test reset disabled"})
		return
	}

	userID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid user id"})
		return
	}

	tx := model.DB.Begin()
	if tx.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "failed to begin transaction"})
		return
	}

	rollback := func(msg string) {
		_ = tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": msg})
	}

	if err := tx.Where("user_id = ?", userID).Delete(&model.Fingerprint{}).Error; err != nil {
		rollback("failed to delete fingerprints")
		return
	}
	if err := tx.Where("user_id_a = ? OR user_id_b = ?", userID, userID).Delete(&model.AccountLink{}).Error; err != nil {
		rollback("failed to delete account links")
		return
	}
	if err := tx.Where("user_id = ?", userID).Delete(&model.IPUAHistory{}).Error; err != nil {
		rollback("failed to delete ip ua history")
		return
	}
	if err := tx.Where("user_id = ?", userID).Delete(&model.UserRiskScore{}).Error; err != nil {
		rollback("failed to delete risk scores")
		return
	}
	if err := tx.Where("user_id = ?", userID).Delete(&model.UserDeviceProfile{}).Error; err != nil {
		rollback("failed to delete device profiles")
		return
	}
	if err := tx.Where("user_id = ?", userID).Delete(&model.KeystrokeProfile{}).Error; err != nil {
		rollback("failed to delete keystroke profiles")
		return
	}
	if err := tx.Where("user_id = ?", userID).Delete(&model.MouseProfile{}).Error; err != nil {
		rollback("failed to delete mouse profiles")
		return
	}
	if err := tx.Where("user_id = ?", userID).Delete(&model.UserTemporalProfile{}).Error; err != nil {
		rollback("failed to delete temporal profiles")
		return
	}
	if err := tx.Where("user_id = ?", userID).Delete(&model.UserSession{}).Error; err != nil {
		rollback("failed to delete user sessions")
		return
	}

	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "failed to commit reset transaction"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "fingerprint test data reset"})
}

// FPGetUserNetworkProfile GET /api/admin/fingerprint/user/:id/network
func FPGetUserNetworkProfile(c *gin.Context) {
	userID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid user id"})
		return
	}

	history := model.GetIPUAHistory(userID)
	type asnStat struct {
		ASN          int    `json:"asn"`
		ASNOrg       string `json:"asn_org"`
		Count        int    `json:"count"`
		IsDatacenter bool   `json:"is_datacenter"`
	}
	statsMap := make(map[int]*asnStat)
	datacenterCount := 0
	for _, h := range history {
		if h == nil {
			continue
		}
		if h.IsDatacenter {
			datacenterCount++
		}
		if h.ASN <= 0 {
			continue
		}
		st, ok := statsMap[h.ASN]
		if !ok {
			st = &asnStat{ASN: h.ASN, ASNOrg: h.ASNOrg, IsDatacenter: h.IsDatacenter}
			statsMap[h.ASN] = st
		}
		st.Count++
	}
	stats := make([]asnStat, 0, len(statsMap))
	for _, st := range statsMap {
		stats = append(stats, *st)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"user_id":          userID,
			"asn_stats":        stats,
			"history_count":    len(history),
			"datacenter_count": datacenterCount,
			"datacenter_rate": func() float64 {
				if len(history) == 0 {
					return 0
				}
				return float64(datacenterCount) / float64(len(history))
			}(),
		},
	})
}

// FPGetUserTemporalProfile GET /api/admin/fingerprint/user/:id/temporal
func FPGetUserTemporalProfile(c *gin.Context) {
	userID, err := strconv.Atoi(c.Param("id"))
	if err != nil || userID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid user id"})
		return
	}

	profileRaw := model.GetLatestTemporalProfile(userID)
	if common.FingerprintEnableTemporalPrecomputeRead && profileRaw != nil && profileRaw.ActivityBins != "" {
		bins := make([]float64, 0)
		if err := common.UnmarshalJsonStr(profileRaw.ActivityBins, &bins); err == nil && len(bins) > 0 {
			computedAt := profileRaw.LastActivityAt
			if computedAt.IsZero() {
				computedAt = profileRaw.UpdatedAt
			}
			c.JSON(http.StatusOK, gin.H{
				"success": true,
				"data": gin.H{
					"user_id":      userID,
					"sample_count": profileRaw.SampleCount,
					"profile_bins": bins,
					"source":       "precomputed",
					"computed_at":  computedAt,
				},
			})
			return
		}
	}

	fps := model.GetLatestFingerprints(userID, 80)
	profileTs := make([]time.Time, 0, len(fps))
	computedAt := time.Time{}
	for _, fp := range fps {
		if fp == nil || fp.CreatedAt.IsZero() {
			continue
		}
		profileTs = append(profileTs, fp.CreatedAt)
		if fp.CreatedAt.After(computedAt) {
			computedAt = fp.CreatedAt
		}
	}
	profile := service.BuildActivityProfile(profileTs)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"user_id":      userID,
			"sample_count": len(profileTs),
			"profile_bins": profile,
			"source":       "realtime",
			"computed_at":  computedAt,
		},
	})
}

// ─── 辅助函数 ───

func getUserBriefByID(userID int) service.UserBrief {
	var user model.User
	if err := model.DB.Select("id, username, email, display_name, role, status, quota, used_quota").
		First(&user, userID).Error; err != nil {
		return service.UserBrief{ID: userID}
	}
	return service.UserBrief{
		ID:          user.Id,
		Username:    user.Username,
		Email:       user.Email,
		DisplayName: user.DisplayName,
		Role:        user.Role,
		Status:      user.Status,
		Quota:       user.Quota,
		UsedQuota:   user.UsedQuota,
	}
}

// FPGetUserDevices GET /api/admin/fingerprint/user/:id/devices
func FPGetUserDevices(c *gin.Context) {
	userID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid user id"})
		return
	}

	profiles := model.GetDeviceProfiles(userID)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    profiles,
		"total":   len(profiles),
	})
}
