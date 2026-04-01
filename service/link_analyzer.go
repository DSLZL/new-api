package service

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
)

// FeatureWeights 各特征维度权重
var FeatureWeights = map[string]float64{
	"local_device_id":    0.95,
	"canvas_hash":        0.90,
	"webgl_hash":         0.85,
	"audio_hash":         0.80,
	"webgl_renderer":     0.75,
	"tls_ja3_hash":       0.75,
	"fonts_hash":         0.70,
	"ip_history_overlap": 0.55,
	"ip_exact":           0.50,
	"ip_subnet":          0.40,
	"ua_similarity":      0.35,
	"screen_resolution":  0.25,
	"timezone":           0.20,
	"cpu_cores":          0.15,
	"languages":          0.15,
	"platform":           0.10,
}

// DimensionMatch 维度匹配详情
type DimensionMatch struct {
	Dimension   string  `json:"dimension"`
	DisplayName string  `json:"display_name"`
	Score       float64 `json:"score"`
	Weight      float64 `json:"weight"`
	ValueA      string  `json:"value_a"`
	ValueB      string  `json:"value_b"`
	Matched     bool    `json:"matched"`
	Category    string  `json:"category"` // device/network/environment
}

// LinkResult 关联分析结果
type LinkResult struct {
	UserA           int              `json:"user_a"`
	UserB           int              `json:"user_b"`
	Confidence      float64          `json:"confidence"`
	MatchDimensions int              `json:"match_dimensions"`
	TotalDimensions int              `json:"total_dimensions"`
	Details         []DimensionMatch `json:"details"`
}

// AnalyzeAccountLinks 分析新指纹触发的关联 (异步调用)
func AnalyzeAccountLinks(userID int, newFP *model.Fingerprint) {
	if !common.FingerprintEnabled {
		return
	}

	candidates := findCandidates(userID, newFP)
	if len(candidates) == 0 {
		return
	}

	whitelisted := model.GetWhitelistedPairs(userID)

	for _, candidateUID := range candidates {
		if whitelisted[candidateUID] {
			continue
		}

		candidateFPs := model.GetLatestFingerprints(candidateUID, 10)
		if len(candidateFPs) == 0 {
			continue
		}

		result := computeBestLinkScore(userID, newFP, candidateUID, candidateFPs)
		if result.Confidence < 0.30 {
			continue
		}

		detailsJSON, _ := json.Marshal(result.Details)
		_ = model.UpsertLink(userID, candidateUID, result.Confidence,
			result.MatchDimensions, result.TotalDimensions, string(detailsJSON))

		if result.Confidence >= common.GetFingerprintAutoConfirmThreshold() {
			a, b := model.NormalizePair(userID, candidateUID)
			link := model.FindExistingLink(a, b)
			if link != nil && link.Status == "pending" {
				_ = model.UpdateLinkStatus(link.ID, "auto_confirmed", 0, "auto confirmed by system")
			}
		}
	}

	// 更新风险评分
	UpdateRiskScore(userID)
}

// findCandidates 根据指纹各维度查找候选关联用户
// 同时通过设备指纹（高权重）和网络指纹（IP/子网）两条路径发现候选，
// 确保即使浏览器处于无痕模式（高权重哈希被随机化），
// 仍能通过IP匹配发现候选用户进入打分流程。
func findCandidates(userID int, fp *model.Fingerprint) []int {
	candidateSet := make(map[int]bool)

	appendCandidates := func(ids []int) {
		for _, uid := range ids {
			if uid != userID {
				candidateSet[uid] = true
			}
		}
	}

	// ─── 路径1: 设备指纹匹配（正常浏览器模式下高命中率）───
	appendCandidates(model.FindUsersByDeviceID(fp.LocalDeviceID))
	appendCandidates(model.FindUsersByCanvasHash(fp.CanvasHash))
	appendCandidates(model.FindUsersByWebGLHash(fp.WebGLHash))
	appendCandidates(model.FindUsersByAudioHash(fp.AudioHash))
	appendCandidates(model.FindUsersByFontsHash(fp.FontsHash))
	appendCandidates(model.FindUsersByCompositeHash(fp.CompositeHash))

	// ─── 路径2: 协议层指纹 ───
	appendCandidates(model.FindUsersByJA3(fp.TLSJA3Hash))

	// ─── 路径3: IP/子网匹配（无痕模式下的关键发现路径）───
	// 即使所有浏览器指纹哈希因无痕噪声而不同，
	// 同一台机器的IP地址不变，仍可发现候选用户。
	appendCandidates(model.FindUsersByIP(fp.IPAddress))
	subnet := GetSubnet24(fp.IPAddress)
	appendCandidates(model.FindUsersByIPSubnet(subnet))

	result := make([]int, 0, len(candidateSet))
	for uid := range candidateSet {
		result = append(result, uid)
	}
	return result
}

func computeBestLinkScore(userA int, fpA *model.Fingerprint, userB int, fpsB []*model.Fingerprint) *LinkResult {
	best := &LinkResult{UserA: userA, UserB: userB}

	for _, fpB := range fpsB {
		conf, details, matchDims, totalDims := CompareFingerprints(fpA, fpB, userA, userB)
		if conf > best.Confidence {
			best.Confidence = conf
			best.Details = details
			best.MatchDimensions = matchDims
			best.TotalDimensions = totalDims
		}
	}

	return best
}

// CompareFingerprints 比较两条指纹记录，返回置信度、维度详情、匹配维度数、总维度数
func CompareFingerprints(a, b *model.Fingerprint, userA, userB int) (float64, []DimensionMatch, int, int) {
	type dimDef struct {
		Name        string
		DisplayName string
		Weight      float64
		Category    string
		ValA        string
		ValB        string
	}

	dimensions := []dimDef{
		// 设备级指纹 (高权重)
		{"local_device_id", "设备追踪ID", 0.95, "device", a.LocalDeviceID, b.LocalDeviceID},
		{"canvas_hash", "Canvas指纹", 0.90, "device", a.CanvasHash, b.CanvasHash},
		{"webgl_hash", "WebGL指纹", 0.85, "device", a.WebGLHash, b.WebGLHash},
		{"audio_hash", "Audio指纹", 0.80, "device", a.AudioHash, b.AudioHash},
		{"webgl_renderer", "GPU型号", 0.75, "device", a.WebGLRenderer, b.WebGLRenderer},
		{"fonts_hash", "字体列表指纹", 0.70, "device", a.FontsHash, b.FontsHash},

		// 网络层 (中权重)
		{"tls_ja3_hash", "TLS/JA3指纹", 0.75, "network", a.TLSJA3Hash, b.TLSJA3Hash},
		{"ip_exact", "IP地址(精确)", 0.50, "network", a.IPAddress, b.IPAddress},
		{"ip_subnet", "IP子网(/24)", 0.40, "network", GetSubnet24(a.IPAddress), GetSubnet24(b.IPAddress)},

		// 环境特征 (低权重)
		{"screen_resolution", "屏幕分辨率", 0.25, "environment",
			fmt.Sprintf("%dx%d", a.ScreenWidth, a.ScreenHeight),
			fmt.Sprintf("%dx%d", b.ScreenWidth, b.ScreenHeight)},
		{"timezone", "时区", 0.20, "environment", a.Timezone, b.Timezone},
		{"languages", "语言偏好", 0.15, "environment", a.Languages, b.Languages},
		{"cpu_cores", "CPU核心数", 0.15, "environment", fmt.Sprint(a.CPUCores), fmt.Sprint(b.CPUCores)},
		{"platform", "系统平台", 0.10, "environment", a.Platform, b.Platform},
	}

	var details []DimensionMatch
	totalWeight := 0.0
	weightedScore := 0.0
	matchDims := 0
	totalDims := 0

	for _, dim := range dimensions {
		if dim.ValA == "" && dim.ValB == "" {
			continue
		}
		totalDims++
		matched := dim.ValA != "" && dim.ValB != "" && dim.ValA == dim.ValB
		score := 0.0
		if matched {
			score = 1.0
			matchDims++
		}

		details = append(details, DimensionMatch{
			Dimension:   dim.Name,
			DisplayName: dim.DisplayName,
			Score:       score,
			Weight:      dim.Weight,
			ValueA:      truncateStr(dim.ValA, 60),
			ValueB:      truncateStr(dim.ValB, 60),
			Matched:     matched,
			Category:    dim.Category,
		})

		if dim.ValA != "" && dim.ValB != "" {
			totalWeight += dim.Weight
			weightedScore += score * dim.Weight
		}
	}

	// UA相似度 (特殊计算)
	uaSim := computeUASimilarity(a, b)
	uaWeight := 0.35
	totalDims++
	uaMatched := uaSim > 0.7
	if uaMatched {
		matchDims++
	}
	details = append(details, DimensionMatch{
		Dimension:   "ua_similarity",
		DisplayName: "UA相似度",
		Score:       uaSim,
		Weight:      uaWeight,
		ValueA:      fmt.Sprintf("%s/%s on %s", a.UABrowser, a.UABrowserVer, a.UAOS),
		ValueB:      fmt.Sprintf("%s/%s on %s", b.UABrowser, b.UABrowserVer, b.UAOS),
		Matched:     uaMatched,
		Category:    "network",
	})
	totalWeight += uaWeight
	weightedScore += uaSim * uaWeight

	// IP历史重叠度
	ipOverlap := ComputeIPOverlap(userA, userB)
	ipHistWeight := 0.55
	totalDims++
	ipMatched := ipOverlap > 0.2
	if ipMatched {
		matchDims++
	}
	ipsA := model.GetUserIPs(userA)
	ipsB := model.GetUserIPs(userB)
	details = append(details, DimensionMatch{
		Dimension:   "ip_history_overlap",
		DisplayName: "历史IP重叠度",
		Score:       ipOverlap,
		Weight:      ipHistWeight,
		ValueA:      fmt.Sprintf("%d个唯一IP", len(ipsA)),
		ValueB:      fmt.Sprintf("%d个唯一IP", len(ipsB)),
		Matched:     ipMatched,
		Category:    "network",
	})
	totalWeight += ipHistWeight
	weightedScore += ipOverlap * ipHistWeight

	// 按权重排序
	sort.Slice(details, func(i, j int) bool {
		return details[i].Weight > details[j].Weight
	})

	confidence := 0.0
	if totalWeight > 0 {
		confidence = weightedScore / totalWeight
	}

	return confidence, details, matchDims, totalDims
}

func computeUASimilarity(a, b *model.Fingerprint) float64 {
	score := 0.0
	count := 0.0

	if a.UAOS != "" && b.UAOS != "" {
		count++
		if a.UAOS == b.UAOS {
			score += 1.0
			if a.UAOSVer != "" && b.UAOSVer != "" && a.UAOSVer == b.UAOSVer {
				score += 0.5
				count += 0.5
			}
		}
	}

	if a.UABrowser != "" && b.UABrowser != "" {
		count++
		if a.UABrowser == b.UABrowser {
			score += 1.0
		}
	}

	if a.UADeviceType != "" && b.UADeviceType != "" {
		count++
		if a.UADeviceType == b.UADeviceType {
			score += 1.0
		}
	}

	if count == 0 {
		return 0
	}
	return score / count
}

// ComputeIPOverlap 计算两个用户的IP历史重叠度 (Jaccard 系数)
func ComputeIPOverlap(userA, userB int) float64 {
	ipsA := model.GetUserIPs(userA)
	ipsB := model.GetUserIPs(userB)

	if len(ipsA) == 0 || len(ipsB) == 0 {
		return 0
	}

	setA := make(map[string]bool)
	for _, ip := range ipsA {
		setA[ip] = true
	}

	intersection := 0
	for _, ip := range ipsB {
		if setA[ip] {
			intersection++
		}
	}

	union := len(setA) + len(ipsB) - intersection
	if union == 0 {
		return 0
	}

	return float64(intersection) / float64(union)
}

// GetSharedIPs 获取两个用户的共享IP
func GetSharedIPs(userA, userB int) []string {
	ipsA := model.GetUserIPs(userA)
	ipsB := model.GetUserIPs(userB)

	setA := make(map[string]bool)
	for _, ip := range ipsA {
		setA[ip] = true
	}

	var shared []string
	for _, ip := range ipsB {
		if setA[ip] {
			shared = append(shared, ip)
		}
	}
	return shared
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ReviewLink 处理关联审核
func ReviewLink(linkID int64, action string, note string) error {
	link := model.GetLinkByID(linkID)
	if link == nil {
		return fmt.Errorf("link not found")
	}

	err := model.UpdateLinkStatus(linkID, action, 0, note) // 0 表示管理员系统操作
	if err != nil {
		return err
	}

	// 如果是封禁操作
	if action == "blocked" {
		// 找出较新注册的账号并封禁
		banNewerAccount(link.UserIDA, link.UserIDB)
		_ = model.UpdateLinkAction(linkID, "ban_newer_account")
	}

	return nil
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
