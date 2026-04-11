package service

import (
	"fmt"
	"sort"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
)

// AssociationResult 关联度查询返回结果
type AssociationResult struct {
	TargetUser      UserBrief         `json:"target_user"`
	Associations    []AssociationItem `json:"associations"`
	AnalyzedAt      time.Time         `json:"analyzed_at"`
	CandidatesFound int               `json:"candidates_found"`
	TimeCostMs      int64             `json:"time_cost_ms"`
}

// AssociationItem 单个关联账号信息
type AssociationItem struct {
	User              UserBrief         `json:"user"`
	Confidence        float64           `json:"confidence"`
	Tier              string            `json:"tier"`
	Explanation       string            `json:"explanation"`
	MatchedDimensions []string          `json:"matched_dimensions"`
	RiskLevel         string            `json:"risk_level"`
	MatchDimensions   int               `json:"match_dimensions"`
	TotalDimensions   int               `json:"total_dimensions"`
	Details           []DimensionMatch  `json:"details"`
	SharedIPs         []string          `json:"shared_ips"`
	ExistingLink      *ExistingLinkInfo `json:"existing_link,omitempty"`
}

// UserBrief 用户摘要信息
type UserBrief struct {
	ID          int    `json:"id"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Role        int    `json:"role"`
	Status      int    `json:"status"`
	Quota       int    `json:"quota"`
	UsedQuota   int    `json:"used_quota"`
	Group       string `json:"group"`
}

// ExistingLinkInfo 已有关联记录信息
type ExistingLinkInfo struct {
	LinkID int64  `json:"link_id"`
	Status string `json:"status"`
}

// ═══════════════════════════════════════════════════════════════════════
// ★★★ 核心修改：QueryUserAssociations ★★★
//
// 旧签名: func QueryUserAssociations(... selectedFPID int64)
//
//	→ 内部调 model.GetFingerprintByID(selectedFPID) 查 user_fingerprints 流水表
//
// 新签名: func QueryUserAssociations(... baseFingerprint *model.Fingerprint)
//
//	→ controller 层已完成:
//	    device_profile_id → GetDeviceProfileByID() → DeviceProfileToFingerprint()
//	  此处直接使用传入的 *model.Fingerprint，无需再查表
//	→ 当 baseFingerprint == nil 时，自动从流水表 / 设备档案表获取
//
// ═══════════════════════════════════════════════════════════════════════
func QueryUserAssociations(
	targetUserID int,
	minConfidence float64,
	limit int,
	forceRefresh bool,
	baseFingerprint *model.Fingerprint, // ★ 改动: int64 → *model.Fingerprint
) (*AssociationResult, error) {
	startTime := time.Now()

	if !common.FingerprintEnabled {
		return nil, fmt.Errorf("fingerprint system is not enabled")
	}

	// ──────────────────────────────────────────────────────────
	// 1. 检查缓存
	//    ★ 改动: selectedFPID == 0 → baseFingerprint == nil
	//    指定了特定设备档案比对时不使用全局缓存
	// ──────────────────────────────────────────────────────────
	if !forceRefresh && common.RedisEnabled && baseFingerprint == nil {
		cacheKey := fmt.Sprintf("fp:assoc:%d", targetUserID)
		cached, err := common.RedisGet(cacheKey)
		if err == nil && cached != "" {
			var result AssociationResult
			if common.Unmarshal([]byte(cached), &result) == nil {
				filtered := make([]AssociationItem, 0)
				for _, a := range result.Associations {
					if a.Confidence >= minConfidence {
						filtered = append(filtered, a)
					}
				}
				result.Associations = filtered
				if len(result.Associations) > limit {
					result.Associations = result.Associations[:limit]
				}
				return &result, nil
			}
		}
	}

	// ──────────────────────────────────────────────────────────
	// 2. 获取目标用户的指纹（比对基准）
	//
	// ★ 改动:
	//   旧: if selectedFPID > 0 { model.GetFingerprintByID(selectedFPID) }
	//   新: if baseFingerprint != nil { 直接使用 controller 传入的已转换指纹 }
	//       else { 流水表 → 设备档案表 兜底 }
	// ──────────────────────────────────────────────────────────
	var targetFPs []*model.Fingerprint

	if baseFingerprint != nil {
		// ★ 管理员指定了某个设备档案，controller 已转为 Fingerprint，直接用
		targetFPs = []*model.Fingerprint{baseFingerprint}
	} else {
		// 默认逻辑：先查流水表
		targetFPs = model.GetLatestFingerprints(targetUserID, 10)
		// ★ 新增兜底: 流水表可能已被定期清理，改从设备档案表获取
		if len(targetFPs) == 0 {
			targetFPs = model.GetDeviceProfilesAsFingerprints(targetUserID)
		}
	}

	if len(targetFPs) == 0 {
		return &AssociationResult{
			TargetUser:      getUserBrief(targetUserID),
			Associations:    []AssociationItem{},
			AnalyzedAt:      time.Now(),
			CandidatesFound: 0,
			TimeCostMs:      time.Since(startTime).Milliseconds(),
		}, nil
	}

	// ──────────────────────────────────────────────────────────
	// 3. 搜索候选账号（此部分逻辑不变）
	// ──────────────────────────────────────────────────────────
	candidateSet := make(map[int]bool)
	for _, fp := range targetFPs {
		appendUnique := func(ids []int) {
			for _, uid := range ids {
				if uid != targetUserID {
					candidateSet[uid] = true
				}
			}
		}

		appendUnique(model.FindUsersByDeviceID(fp.LocalDeviceID))
		appendUnique(model.FindUsersByCanvasHash(fp.CanvasHash))
		appendUnique(model.FindUsersByWebGLHash(fp.WebGLHash))
		appendUnique(model.FindUsersByWebGLDeepHash(fp.WebGLDeepHash))
		appendUnique(model.FindUsersByClientRectsHash(fp.ClientRectsHash))
		appendUnique(model.FindUsersByMediaDevicesHash(fp.MediaDevicesHash))
		appendUnique(model.FindUsersByMediaDeviceGroupHash(fp.MediaDeviceGroupHash))
		appendUnique(model.FindUsersBySpeechVoicesHash(fp.SpeechVoicesHash))
		appendUnique(model.FindUsersByAudioHash(fp.AudioHash))
		appendUnique(model.FindUsersByFontsHash(fp.FontsHash))
		appendUnique(model.FindUsersByCompositeHash(fp.CompositeHash))
		appendUnique(model.FindUsersByJA3(fp.TLSJA3Hash))
		if common.FingerprintEnableJA4 {
			appendUnique(model.FindUsersByJA4(fp.JA4))
		}
		if common.FingerprintEnableETag {
			appendUnique(model.FindUsersByETagID(fp.ETagID))
		}
		appendUnique(model.FindUsersByHTTPHeaderHash(fp.HTTPHeaderHash))
		if common.FingerprintEnableDNSLeak {
			appendUnique(model.FindUsersByDNSResolverIP(fp.DNSResolverIP))
		}
		appendUnique(model.FindUsersByPersistentID(fp.PersistentID))
		appendUnique(model.FindUsersByIP(fp.IPAddress))
		subnet := GetSubnet24(fp.IPAddress)
		appendUnique(model.FindUsersByIPSubnet(subnet))
	}

	// 通过IP历史交叉查找
	targetIPs := model.GetUserIPs(targetUserID)
	for _, ip := range targetIPs {
		for _, uid := range model.FindUsersByIP(ip) {
			if uid != targetUserID {
				candidateSet[uid] = true
			}
		}
	}

	// 4. 移除白名单
	whitelisted := model.GetWhitelistedPairs(targetUserID)
	for uid := range whitelisted {
		delete(candidateSet, uid)
	}

	// ──────────────────────────────────────────────────────────
	// 5. 计算关联度
	//    ★ 改动: 候选用户的指纹也增加设备档案兜底
	// ──────────────────────────────────────────────────────────
	associations := make([]AssociationItem, 0)

	for candidateUID := range candidateSet {
		candidateFPs := model.GetLatestFingerprints(candidateUID, 10)
		// ★ 新增兜底: 候选用户流水表也可能为空
		if len(candidateFPs) == 0 {
			candidateFPs = model.GetDeviceProfilesAsFingerprints(candidateUID)
		}
		if len(candidateFPs) == 0 {
			continue
		}

		bestConf := 0.0
		bestTier := ""
		bestExplanation := ""
		var bestMatchedDimensions []string
		var bestDetails []DimensionMatch
		bestMatchDims := 0
		bestTotalDims := 0

		for _, tFP := range targetFPs {
			for _, cFP := range candidateFPs {
				similarity := CalculateSimilarity(tFP, cFP, targetUserID, candidateUID)
				if similarity.Score > bestConf {
					bestConf = similarity.Score
					bestTier = similarity.Tier
					bestExplanation = similarity.Explanation
					bestMatchedDimensions = similarity.MatchedDimensions
					bestDetails = similarity.Details
					bestMatchDims = similarity.MatchDimensions
					bestTotalDims = similarity.TotalDimensions
				}
			}
		}

		if bestConf < 0.20 {
			continue
		}

		sharedIPs := GetSharedIPs(targetUserID, candidateUID)

		item := AssociationItem{
			User:              getUserBrief(candidateUID),
			Confidence:        bestConf,
			Tier:              bestTier,
			Explanation:       bestExplanation,
			MatchedDimensions: bestMatchedDimensions,
			RiskLevel:         confidenceToRiskLevel(bestConf),
			MatchDimensions:   bestMatchDims,
			TotalDimensions:   bestTotalDims,
			Details:           bestDetails,
			SharedIPs:         sharedIPs,
		}

		// 检查是否已有 Link 记录
		link := model.GetLinkByUsers(targetUserID, candidateUID)
		if link != nil {
			item.ExistingLink = &ExistingLinkInfo{
				LinkID: link.ID,
				Status: link.Status,
			}
		}

		associations = append(associations, item)
	}

	// ──────────────────────────────────────────────────────────
	// 6. 排序并缓存
	//    ★ 改动: selectedFPID == 0 → baseFingerprint == nil
	// ──────────────────────────────────────────────────────────
	sort.Slice(associations, func(i, j int) bool {
		return associations[i].Confidence > associations[j].Confidence
	})

	fullResult := &AssociationResult{
		TargetUser:      getUserBrief(targetUserID),
		Associations:    associations,
		AnalyzedAt:      time.Now(),
		CandidatesFound: len(candidateSet),
		TimeCostMs:      time.Since(startTime).Milliseconds(),
	}

	// ★ 改动: 仅在未指定特定设备档案时缓存（全局结果）
	if common.RedisEnabled && baseFingerprint == nil {
		if data, err := common.Marshal(fullResult); err == nil {
			cacheKey := fmt.Sprintf("fp:assoc:%d", targetUserID)
			common.RedisSet(cacheKey, string(data), 30*time.Minute)
		}
	}

	// 按 minConfidence 过滤返回
	filtered := make([]AssociationItem, 0)
	for _, a := range associations {
		if a.Confidence >= minConfidence {
			filtered = append(filtered, a)
		}
	}
	if len(filtered) > limit {
		filtered = filtered[:limit]
	}

	fullResult.Associations = filtered
	return fullResult, nil
}

func getUserBrief(userID int) UserBrief {
	var user model.User
	if err := model.DB.First(&user, userID).Error; err != nil {
		return UserBrief{ID: userID}
	}
	return UserBrief{
		ID:          user.Id,
		Username:    user.Username,
		Email:       user.Email,
		DisplayName: user.DisplayName,
		Role:        user.Role,
		Status:      user.Status,
		Quota:       user.Quota,
		UsedQuota:   user.UsedQuota,
		Group:       user.Group,
	}
}

func confidenceToRiskLevel(conf float64) string {
	switch {
	case conf >= 0.85:
		return "critical"
	case conf >= 0.70:
		return "high"
	case conf >= 0.50:
		return "medium"
	default:
		return "low"
	}
}
