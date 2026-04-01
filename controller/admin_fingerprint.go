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
	"strconv"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

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
		Action string `json:"action"` // confirmed, ignored, blocked
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

	if limit < 1 || limit > 100 {
		limit = 20
	}

	// ──────────────────────────────────────────────────────────
	// ★ 改动 1: 读取 device_profile_id（来自 user_device_profiles 表）
	//           替代原来的 fingerprint_id（来自 user_fingerprints 表）
	// ──────────────────────────────────────────────────────────
	dpIDStr := c.DefaultQuery("device_profile_id", "0")
	dpID, parseErr := strconv.ParseInt(dpIDStr, 10, 64)
	if parseErr != nil {
		dpID = 0 // 解析失败则忽略，不按指定设备档案过滤
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

		// 转为 Fingerprint 结构，作为比对基准
		baseFingerprint = model.DeviceProfileToFingerprint(profile)
	}

	// ──────────────────────────────────────────────────────────
	// ★ 改动 3: 传 *model.Fingerprint 而非 int64 fpID
	//           service.QueryUserAssociations 签名需同步修改（见下方说明）
	// ──────────────────────────────────────────────────────────
	result, err := service.QueryUserAssociations(targetUserID, minConf, limit, refresh, baseFingerprint)
	if err != nil {
		// 区分"无数据"与"真正的服务器错误"
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data": gin.H{
				"associations": []interface{}{},
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
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    fps,
	})
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
	if err := c.ShouldBindJSON(&req); err != nil || req.UserA == 0 || req.UserB == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "需要提供 user_a 和 user_b"})
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
				"details":    []interface{}{},
			},
		})
		return
	}

	bestConf := 0.0
	var bestDetails []service.DimensionMatch
	bestMatch := 0
	bestTotal := 0

	for _, fpA := range fpsA {
		for _, fpB := range fpsB {
			conf, details, m, t := service.CompareFingerprints(fpA, fpB, req.UserA, req.UserB)
			if conf > bestConf {
				bestConf = conf
				bestDetails = details
				bestMatch = m
				bestTotal = t
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"confidence":       bestConf,
			"match_dimensions": bestMatch,
			"total_dimensions": bestTotal,
			"details":          bestDetails,
			"user_a_info":      getUserBriefByID(req.UserA),
			"user_b_info":      getUserBriefByID(req.UserB),
		},
	})
}

// FPTriggerFullScan POST /api/admin/fingerprint/scan
func FPTriggerFullScan(c *gin.Context) {
	go service.FullLinkScan()
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "全量扫描已触发，将在后台运行"})
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

func banNewerAccount(userA, userB int) {
	if userA > userB {
		banUserByID(userA)
	} else {
		banUserByID(userB)
	}
}

func banUserByID(userID int) {
	model.DB.Model(&model.User{}).Where("id = ?", userID).
		Update("status", common.UserStatusDisabled)
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
