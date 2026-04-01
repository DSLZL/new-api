package service

import (
	"encoding/json"
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
	User            UserBrief         `json:"user"`
	Confidence      float64           `json:"confidence"`
	RiskLevel       string            `json:"risk_level"`
	MatchDimensions int               `json:"match_dimensions"`
	TotalDimensions int               `json:"total_dimensions"`
	Details         []DimensionMatch  `json:"details"`
	SharedIPs       []string          `json:"shared_ips"`
	ExistingLink    *ExistingLinkInfo `json:"existing_link,omitempty"`
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

// QueryUserAssociations 查询用户关联账号 (核心功能)
func QueryUserAssociations(targetUserID int, minConfidence float64, limit int, forceRefresh bool, selectedFPID int64) (*AssociationResult, error) {
	startTime := time.Now()

	if !common.FingerprintEnabled {
		return nil, fmt.Errorf("fingerprint system is not enabled")
	}

	// 1. 检查缓存 (如果指定了特定的指纹比对，则不使用全局缓存)
	if !forceRefresh && common.RedisEnabled && selectedFPID == 0 {
		cacheKey := fmt.Sprintf("fp:assoc:%d", targetUserID)
		cached, err := common.RedisGet(cacheKey)
		if err == nil && cached != "" {
			var result AssociationResult
			if json.Unmarshal([]byte(cached), &result) == nil {
				// 根据 minConfidence 过滤
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

	// 2. 获取目标用户的指纹
	var targetFPs []*model.Fingerprint
	if selectedFPID > 0 {
		fp := model.GetFingerprintByID(selectedFPID)
		if fp != nil && fp.UserID == targetUserID {
			targetFPs = []*model.Fingerprint{fp}
		} else {
			return nil, fmt.Errorf("selected fingerprint not found or doesn't belong to the user")
		}
	} else {
		targetFPs = model.GetLatestFingerprints(targetUserID, 10)
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

	// 3. 搜索候选账号
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
		appendUnique(model.FindUsersByAudioHash(fp.AudioHash))
		appendUnique(model.FindUsersByFontsHash(fp.FontsHash))
		appendUnique(model.FindUsersByCompositeHash(fp.CompositeHash))
		appendUnique(model.FindUsersByJA3(fp.TLSJA3Hash))
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

	// 5. 计算关联度
	associations := make([]AssociationItem, 0)

	for candidateUID := range candidateSet {
		candidateFPs := model.GetLatestFingerprints(candidateUID, 10)
		if len(candidateFPs) == 0 {
			continue
		}

		bestConf := 0.0
		var bestDetails []DimensionMatch
		bestMatchDims := 0
		bestTotalDims := 0

		for _, tFP := range targetFPs {
			for _, cFP := range candidateFPs {
				conf, details, matchDims, totalDims := CompareFingerprints(tFP, cFP, targetUserID, candidateUID)
				if conf > bestConf {
					bestConf = conf
					bestDetails = details
					bestMatchDims = matchDims
					bestTotalDims = totalDims
				}
			}
		}

		if bestConf < 0.20 {
			continue
		}

		sharedIPs := GetSharedIPs(targetUserID, candidateUID)

		item := AssociationItem{
			User:            getUserBrief(candidateUID),
			Confidence:      bestConf,
			RiskLevel:       confidenceToRiskLevel(bestConf),
			MatchDimensions: bestMatchDims,
			TotalDimensions: bestTotalDims,
			Details:         bestDetails,
			SharedIPs:       sharedIPs,
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

	// 6. 排序并缓存
	sort.Slice(associations, func(i, j int) bool {
		return associations[i].Confidence > associations[j].Confidence
	})

	// 保存完整结果到缓存
	fullResult := &AssociationResult{
		TargetUser:      getUserBrief(targetUserID),
		Associations:    associations,
		AnalyzedAt:      time.Now(),
		CandidatesFound: len(candidateSet),
		TimeCostMs:      time.Since(startTime).Milliseconds(),
	}

	// 缓存
	if common.RedisEnabled && selectedFPID == 0 {
		if data, err := json.Marshal(fullResult); err == nil {
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
	if err := model.DB.Select("id, username, email, display_name, role, status, quota, used_quota").
		First(&user, userID).Error; err != nil {
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
