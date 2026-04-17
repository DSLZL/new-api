package service

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
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

// AssociationQueryOptions 关联查询选项
// 默认行为：包含 details 与 shared_ips，且不过滤候选用户。
type AssociationQueryOptions struct {
	IncludeDetails    bool
	IncludeSharedIPs  bool
	CandidateUserID   int
	Mode              string
	TargetFingerprintLimit    int
	CandidateFingerprintLimit int
}

const (
	associationModeFast = "fast"
	associationModeFull = "full"
)

const (
	associationCacheVersion      = "v2"
	associationCacheBaseMode     = "default"
	associationCacheBasePrefix   = "dp"
	associationCacheNegative     = "__none__"
	associationCacheTTL          = 30 * time.Minute
	associationNegativeCacheTTL  = 5 * time.Minute
)

func normalizeAssociationMinConfidence(val float64) float64 {
	if math.IsNaN(val) || math.IsInf(val, 0) {
		return 0
	}
	if val < 0 {
		return 0
	}
	if val > 1 {
		return 1
	}
	return math.Round(val*1000) / 1000
}

func normalizeAssociationLimit(limit int) int {
	if limit < 1 {
		return 1
	}
	if limit > 100 {
		return 100
	}
	return limit
}

func buildAssociationCacheBaseTag(baseFingerprint *model.Fingerprint) string {
	if baseFingerprint == nil {
		return associationCacheBaseMode
	}
	if baseFingerprint.ID > 0 {
		return associationCacheBasePrefix + strconv.FormatInt(baseFingerprint.ID, 10)
	}
	if baseFingerprint.UserID > 0 {
		return associationCacheBasePrefix + "u" + strconv.Itoa(baseFingerprint.UserID)
	}
	return associationCacheBasePrefix + "custom"
}

func normalizeAssociationCandidateUserID(candidateUserID int) int {
	if candidateUserID > 0 {
		return candidateUserID
	}
	return 0
}

func normalizeAssociationMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case associationModeFull:
		return associationModeFull
	default:
		return associationModeFast
	}
}

func normalizeAssociationFingerprintLimit(limit int, defaultVal int) int {
	if limit <= 0 {
		return defaultVal
	}
	if limit > 20 {
		return 20
	}
	return limit
}

func parseAssociationCacheNegativePayload(payload string) (int, bool) {
	if payload == associationCacheNegative {
		return 0, true
	}
	if !strings.HasPrefix(payload, associationCacheNegative+":") {
		return 0, false
	}
	countStr := strings.TrimPrefix(payload, associationCacheNegative+":")
	count, err := strconv.Atoi(countStr)
	if err != nil || count < 0 {
		return 0, false
	}
	return count, true
}

func buildAssociationCacheNegativePayload(candidatesFound int) string {
	if candidatesFound < 0 {
		candidatesFound = 0
	}
	return associationCacheNegative + ":" + strconv.Itoa(candidatesFound)
}

func normalizeAssociationQueryOptions(options *AssociationQueryOptions) AssociationQueryOptions {
	normalized := AssociationQueryOptions{
		IncludeDetails:          false,
		IncludeSharedIPs:        false,
		Mode:                    associationModeFast,
		TargetFingerprintLimit:  common.GetFingerprintAssociationFastTargetLimit(),
		CandidateFingerprintLimit: common.GetFingerprintAssociationFastCandidateLimit(),
	}
	if options == nil {
		return normalized
	}
	normalized.IncludeDetails = options.IncludeDetails
	normalized.IncludeSharedIPs = options.IncludeSharedIPs
	if options.CandidateUserID > 0 {
		normalized.CandidateUserID = options.CandidateUserID
	}
	normalized.Mode = normalizeAssociationMode(options.Mode)
	if normalized.Mode == associationModeFull {
		normalized.TargetFingerprintLimit = normalizeAssociationFingerprintLimit(options.TargetFingerprintLimit, common.GetFingerprintAssociationFullTargetLimit())
		normalized.CandidateFingerprintLimit = normalizeAssociationFingerprintLimit(options.CandidateFingerprintLimit, common.GetFingerprintAssociationFullCandidateLimit())
	} else {
		normalized.TargetFingerprintLimit = normalizeAssociationFingerprintLimit(options.TargetFingerprintLimit, common.GetFingerprintAssociationFastTargetLimit())
		normalized.CandidateFingerprintLimit = normalizeAssociationFingerprintLimit(options.CandidateFingerprintLimit, common.GetFingerprintAssociationFastCandidateLimit())
	}
	return normalized
}

func buildAssociationCacheKey(targetUserID int, minConfidence float64, limit int, baseFingerprint *model.Fingerprint, queryOptions AssociationQueryOptions) string {
	normalizedMin := normalizeAssociationMinConfidence(minConfidence)
	normalizedLimit := normalizeAssociationLimit(limit)
	baseTag := buildAssociationCacheBaseTag(baseFingerprint)
	detailFlag := 0
	if queryOptions.IncludeDetails {
		detailFlag = 1
	}
	sharedIPFlag := 0
	if queryOptions.IncludeSharedIPs {
		sharedIPFlag = 1
	}
	return fmt.Sprintf(
		"fp:assoc:%s:u:%d:min:%.3f:limit:%d:base:%s:d:%d:s:%d:c:%d:m:%s:tfl:%d:cfl:%d",
		associationCacheVersion,
		targetUserID,
		normalizedMin,
		normalizedLimit,
		baseTag,
		detailFlag,
		sharedIPFlag,
		queryOptions.CandidateUserID,
		queryOptions.Mode,
		queryOptions.TargetFingerprintLimit,
		queryOptions.CandidateFingerprintLimit,
	)
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
	return QueryUserAssociationsWithOptions(targetUserID, minConfidence, limit, forceRefresh, baseFingerprint, nil)
}

func QueryUserAssociationsWithOptions(
	targetUserID int,
	minConfidence float64,
	limit int,
	forceRefresh bool,
	baseFingerprint *model.Fingerprint,
	options *AssociationQueryOptions,
) (*AssociationResult, error) {
	startTime := time.Now()

	if !common.FingerprintEnabled {
		return nil, fmt.Errorf("fingerprint system is not enabled")
	}

	normalizedOptions := normalizeAssociationQueryOptions(options)
	candidateUserID := normalizeAssociationCandidateUserID(normalizedOptions.CandidateUserID)
	if candidateUserID == targetUserID {
		candidateUserID = 0
	}
	normalizedOptions.CandidateUserID = candidateUserID
	includeDetails := normalizedOptions.IncludeDetails
	includeSharedIPs := normalizedOptions.IncludeSharedIPs

	normalizedMinConfidence := normalizeAssociationMinConfidence(minConfidence)
	normalizedLimit := normalizeAssociationLimit(limit)
	cacheKey := buildAssociationCacheKey(targetUserID, normalizedMinConfidence, normalizedLimit, baseFingerprint, normalizedOptions)

	// ──────────────────────────────────────────────────────────
	// 1. 检查缓存
	//    缓存键纳入 user/min_confidence/limit/baseFingerprint 标识
	// ──────────────────────────────────────────────────────────
	if !forceRefresh && common.RedisEnabled {
		cached, err := common.RedisGet(cacheKey)
		if err == nil && cached != "" {
			if candidatesFound, ok := parseAssociationCacheNegativePayload(cached); ok {
				return &AssociationResult{
					TargetUser:      getUserBrief(targetUserID),
					Associations:    []AssociationItem{},
					AnalyzedAt:      time.Now(),
					CandidatesFound: candidatesFound,
					TimeCostMs:      time.Since(startTime).Milliseconds(),
				}, nil
			}
			var result AssociationResult
			if common.Unmarshal([]byte(cached), &result) == nil {
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
		targetFPs = model.GetLatestFingerprints(targetUserID, normalizedOptions.TargetFingerprintLimit)
		// ★ 新增兜底: 流水表可能已被定期清理，改从设备档案表获取
		if len(targetFPs) == 0 {
			targetFPs = model.GetDeviceProfilesAsFingerprints(targetUserID)
			if len(targetFPs) > normalizedOptions.TargetFingerprintLimit {
				targetFPs = targetFPs[:normalizedOptions.TargetFingerprintLimit]
			}
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
	// 3. 搜索候选账号（预算化召回）
	// ──────────────────────────────────────────────────────────
	candidateSet := make(map[int]struct{})
	for _, fp := range targetFPs {
		collectCandidatesByFingerprint(targetUserID, fp, candidateSet, candidateUserID)
		if len(candidateSet) >= common.GetFingerprintCandidateMaxTotal() {
			break
		}
	}

	// 通过IP历史交叉查找（低区分度来源，使用更严格预算）
	collectCandidatesByIPHistory(targetUserID, candidateSet, candidateUserID)

	// 4. 移除白名单
	whitelisted := model.GetWhitelistedPairs(targetUserID)
	for uid := range whitelisted {
		delete(candidateSet, uid)
	}

	// ──────────────────────────────────────────────────────────
	// 5. 计算关联度
	//    ★ 改动: 先粗算候选结果，再对最终结果补充 user/link/sharedIPs
	// ──────────────────────────────────────────────────────────
	type associationCandidateResult struct {
		CandidateUserID    int
		Confidence         float64
		Tier               string
		Explanation        string
		MatchedDimensions  []string
		RiskLevel          string
		MatchDimensions    int
		TotalDimensions    int
		Details            []DimensionMatch
	}
	candidateResults := make([]associationCandidateResult, 0, len(candidateSet))

	for candidateUID := range candidateSet {
		if candidateUserID > 0 && candidateUID != candidateUserID {
			continue
		}
		candidateFPs := model.GetLatestFingerprints(candidateUID, normalizedOptions.CandidateFingerprintLimit)
		// ★ 新增兜底: 候选用户流水表也可能为空
		if len(candidateFPs) == 0 {
			candidateFPs = model.GetDeviceProfilesAsFingerprints(candidateUID)
			if len(candidateFPs) > normalizedOptions.CandidateFingerprintLimit {
				candidateFPs = candidateFPs[:normalizedOptions.CandidateFingerprintLimit]
			}
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

		candidateResults = append(candidateResults, associationCandidateResult{
			CandidateUserID:   candidateUID,
			Confidence:        bestConf,
			Tier:              bestTier,
			Explanation:       bestExplanation,
			MatchedDimensions: bestMatchedDimensions,
			RiskLevel:         confidenceToRiskLevel(bestConf),
			MatchDimensions:   bestMatchDims,
			TotalDimensions:   bestTotalDims,
			Details:           bestDetails,
		})
	}

	// ──────────────────────────────────────────────────────────
	// 6. 排序、过滤、截断后再补充重字段
	// ──────────────────────────────────────────────────────────
	sort.Slice(candidateResults, func(i, j int) bool {
		return candidateResults[i].Confidence > candidateResults[j].Confidence
	})

	filteredCandidates := make([]associationCandidateResult, 0, len(candidateResults))
	for _, candidate := range candidateResults {
		if candidate.Confidence >= normalizedMinConfidence {
			filteredCandidates = append(filteredCandidates, candidate)
		}
	}
	if len(filteredCandidates) > normalizedLimit {
		filteredCandidates = filteredCandidates[:normalizedLimit]
	}

	finalCandidateUserIDs := make([]int, 0, len(filteredCandidates))
	for _, candidate := range filteredCandidates {
		finalCandidateUserIDs = append(finalCandidateUserIDs, candidate.CandidateUserID)
	}
	candidateUserBriefs := getUserBriefs(finalCandidateUserIDs)
	linksByPeer := model.GetLinksByUserAndCandidates(targetUserID, finalCandidateUserIDs)

	associations := make([]AssociationItem, 0, len(filteredCandidates))
	for _, candidate := range filteredCandidates {
		item := AssociationItem{
			User:              candidateUserBriefs[candidate.CandidateUserID],
			Confidence:        candidate.Confidence,
			Tier:              candidate.Tier,
			Explanation:       candidate.Explanation,
			MatchedDimensions: candidate.MatchedDimensions,
			RiskLevel:         candidate.RiskLevel,
			MatchDimensions:   candidate.MatchDimensions,
			TotalDimensions:   candidate.TotalDimensions,
		}
		if item.User.ID == 0 {
			item.User = UserBrief{ID: candidate.CandidateUserID}
		}
		if includeDetails {
			item.Details = candidate.Details
		}
		if includeSharedIPs {
			item.SharedIPs = GetSharedIPs(targetUserID, candidate.CandidateUserID)
		}
		if link := linksByPeer[candidate.CandidateUserID]; link != nil {
			item.ExistingLink = &ExistingLinkInfo{
				LinkID: link.ID,
				Status: link.Status,
			}
		}
		associations = append(associations, item)
	}

	fullResult := &AssociationResult{
		TargetUser:      getUserBrief(targetUserID),
		Associations:    associations,
		AnalyzedAt:      time.Now(),
		CandidatesFound: len(candidateSet),
		TimeCostMs:      time.Since(startTime).Milliseconds(),
	}

	if common.RedisEnabled {
		if len(fullResult.Associations) == 0 {
			negativePayload := buildAssociationCacheNegativePayload(fullResult.CandidatesFound)
			_ = common.RedisSet(cacheKey, negativePayload, associationNegativeCacheTTL)
			return fullResult, nil
		}
		if data, err := common.Marshal(fullResult); err == nil {
			_ = common.RedisSet(cacheKey, string(data), associationCacheTTL)
		}
	}

	return fullResult, nil
}

func getUserBriefs(userIDs []int) map[int]UserBrief {
	briefs := make(map[int]UserBrief)
	if len(userIDs) == 0 || model.DB == nil {
		return briefs
	}

	uniqueIDs := make([]int, 0, len(userIDs))
	seen := make(map[int]struct{}, len(userIDs))
	for _, userID := range userIDs {
		if userID <= 0 {
			continue
		}
		if _, exists := seen[userID]; exists {
			continue
		}
		seen[userID] = struct{}{}
		uniqueIDs = append(uniqueIDs, userID)
	}
	if len(uniqueIDs) == 0 {
		return briefs
	}

	var users []model.User
	if err := model.DB.Where("id IN ?", uniqueIDs).Find(&users).Error; err != nil {
		return briefs
	}
	for _, user := range users {
		briefs[user.Id] = UserBrief{
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
	return briefs
}

func getUserBrief(userID int) UserBrief {
	if userID <= 0 {
		return UserBrief{}
	}
	brief, ok := getUserBriefs([]int{userID})[userID]
	if !ok {
		return UserBrief{ID: userID}
	}
	return brief
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
