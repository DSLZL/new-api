package controller

import (
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

// FPGetUserAssociations GET /api/admin/fingerprint/user/:id/associations
func FPGetUserAssociations(c *gin.Context) {
	targetUserID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid user id"})
		return
	}

	minConf, _ := strconv.ParseFloat(c.DefaultQuery("min_confidence", "0.3"), 64)
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	refresh := c.DefaultQuery("refresh", "false") == "true"
	fpID, _ := strconv.ParseInt(c.DefaultQuery("fingerprint_id", "0"), 10, 64)

	if limit < 1 || limit > 100 {
		limit = 20
	}

	result, err := service.QueryUserAssociations(targetUserID, minConf, limit, refresh, fpID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": err.Error()})
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
	fpsB := model.GetLatestFingerprints(req.UserB, 5)

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

// banNewerAccount 封禁较新注册的账号
// 使用 ID 大小判断: 更大的 ID = 更晚注册的账号
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
// 返回用户所有设备档案（永久保留，不受流水清理影响）
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
