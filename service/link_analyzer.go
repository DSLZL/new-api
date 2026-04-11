package service

import (
	"fmt"
	"sort"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
)

// FeatureWeights 各特征维度权重（静态默认值）
var FeatureWeights = map[string]float64{}

type fingerprintWeights struct {
	PersistentID          float64
	ETagID                float64
	WebRTCBothIP          float64
	WebRTCLocalIP         float64
	WebRTCPublicIP        float64
	JA4                   float64
	HTTPHeaderHash        float64
	LocalDeviceID         float64
	CanvasHash            float64
	WebGLHash             float64
	WebGLDeepHash         float64
	ClientRectsHash       float64
	MediaDevicesHash      float64
	MediaDeviceGroupHash  float64
	MediaDeviceCount      float64
	SpeechVoicesHash      float64
	SpeechVoiceCount      float64
	SpeechLocalVoiceCount float64
	AudioHash             float64
	WebGLVendor           float64
	WebGLRenderer         float64
	TLSJA3Hash            float64
	FontsHash             float64
	IPHistoryOverlap      float64
	IPExact               float64
	IPSubnet              float64
	DNSResolverIP         float64
	ASNSimilarity         float64
	UASimilarity          float64
	TimeSimilarity        float64
	MutualExclusion       float64
	ScreenResolution      float64
	Timezone              float64
	CPUCores              float64
	Languages             float64
	Platform              float64
	KeystrokeSimilarity   float64
	MouseSimilarity       float64
}

func getFeatureWeights() fingerprintWeights {
	liveWeights := common.GetWeights()
	return fingerprintWeights{
		PersistentID:          liveWeights["persistent_id"],
		ETagID:                liveWeights["etag_id"],
		WebRTCBothIP:          liveWeights["webrtc_both"],
		WebRTCLocalIP:         liveWeights["webrtc_local"],
		WebRTCPublicIP:        liveWeights["webrtc_public"],
		JA4:                   liveWeights["ja4"],
		HTTPHeaderHash:        liveWeights["http_header_hash"],
		LocalDeviceID:         liveWeights["local_device_id"],
		CanvasHash:            liveWeights["canvas_hash"],
		WebGLHash:             liveWeights["webgl_hash"],
		WebGLDeepHash:         liveWeights["webgl_deep_hash"],
		ClientRectsHash:       liveWeights["client_rects_hash"],
		MediaDevicesHash:      liveWeights["media_devices_hash"],
		MediaDeviceGroupHash:  liveWeights["media_device_group_hash"],
		MediaDeviceCount:      liveWeights["media_device_count"],
		SpeechVoicesHash:      liveWeights["speech_voices_hash"],
		SpeechVoiceCount:      liveWeights["speech_voice_count"],
		SpeechLocalVoiceCount: liveWeights["speech_local_voice_count"],
		AudioHash:             liveWeights["audio_hash"],
		WebGLVendor:           liveWeights["webgl_vendor"],
		WebGLRenderer:         liveWeights["webgl_renderer"],
		TLSJA3Hash:            liveWeights["tls_ja3_hash"],
		FontsHash:             liveWeights["fonts_hash"],
		IPHistoryOverlap:      liveWeights["ip_history_overlap"],
		IPExact:               liveWeights["ip_exact"],
		IPSubnet:              liveWeights["ip_subnet"],
		DNSResolverIP:         liveWeights["dns_resolver"],
		ASNSimilarity:         liveWeights["asn"],
		UASimilarity:          liveWeights["ua_similarity"],
		TimeSimilarity:        liveWeights["time_similarity"],
		MutualExclusion:       liveWeights["mutual_exclusion"],
		KeystrokeSimilarity:   liveWeights["keystroke"],
		MouseSimilarity:       liveWeights["mouse"],
		ScreenResolution:      liveWeights["screen_resolution"],
		Timezone:              liveWeights["timezone"],
		CPUCores:              liveWeights["cpu_cores"],
		Languages:             liveWeights["languages"],
		Platform:              liveWeights["platform"],
	}
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
	UserA             int              `json:"user_a"`
	UserB             int              `json:"user_b"`
	Confidence        float64          `json:"confidence"`
	Tier              string           `json:"tier"`
	Explanation       string           `json:"explanation"`
	MatchedDimensions []string         `json:"matched_dimensions"`
	MatchDimensions   int              `json:"match_dimensions"`
	TotalDimensions   int              `json:"total_dimensions"`
	Details           []DimensionMatch `json:"details"`
}

type SimilarityResult struct {
	Score             float64
	Tier              string
	MatchedDimensions []string
	Explanation       string
	Details           []DimensionMatch
	MatchDimensions   int
	TotalDimensions   int
}

// AnalyzeAccountLinks 分析新指纹触发的关联 (异步调用)
func AnalyzeAccountLinks(userID int, newFP *model.Fingerprint) {
	if !common.FingerprintEnabled {
		return
	}
	IncrementalLinkScan(userID, newFP)
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
	appendCandidates(model.FindUsersByWebGLDeepHash(fp.WebGLDeepHash))
	appendCandidates(model.FindUsersByClientRectsHash(fp.ClientRectsHash))
	appendCandidates(model.FindUsersByMediaDevicesHash(fp.MediaDevicesHash))
	appendCandidates(model.FindUsersByMediaDeviceGroupHash(fp.MediaDeviceGroupHash))
	appendCandidates(model.FindUsersBySpeechVoicesHash(fp.SpeechVoicesHash))
	appendCandidates(model.FindUsersByAudioHash(fp.AudioHash))
	appendCandidates(model.FindUsersByFontsHash(fp.FontsHash))
	appendCandidates(model.FindUsersByCompositeHash(fp.CompositeHash))

	// ─── 路径2: 协议层指纹 ───
	appendCandidates(model.FindUsersByJA3(fp.TLSJA3Hash))
	if common.FingerprintEnableJA4 {
		appendCandidates(model.FindUsersByJA4(fp.JA4))
	}
	appendCandidates(model.FindUsersByHTTPHeaderHash(fp.HTTPHeaderHash))
	if common.FingerprintEnableDNSLeak {
		appendCandidates(model.FindUsersByDNSResolverIP(fp.DNSResolverIP))
	}
	if common.FingerprintEnableETag {
		appendCandidates(model.FindUsersByETagID(fp.ETagID))
	}
	appendCandidates(model.FindUsersByPersistentID(fp.PersistentID))

	// ─── 路径3: IP/子网匹配（无痕模式下的关键发现路径）───
	// 即使所有浏览器指纹哈希因无痕噪声而不同，
	// 同一台机器的IP地址不变，仍可发现候选用户。
	appendCandidates(model.FindUsersByIP(fp.IPAddress))
	subnet := GetSubnet24(fp.IPAddress)
	if subnet != "" {
		appendCandidates(model.FindUsersByIPSubnet(subnet))
	}

	result := make([]int, 0, len(candidateSet))
	for uid := range candidateSet {
		result = append(result, uid)
	}
	return result
}

func computeBestLinkScore(userA int, fpA *model.Fingerprint, userB int, fpsB []*model.Fingerprint) *LinkResult {
	best := &LinkResult{UserA: userA, UserB: userB}

	for _, fpB := range fpsB {
		similarity := CalculateSimilarity(fpA, fpB, userA, userB)
		if similarity.Score > best.Confidence {
			best.Confidence = similarity.Score
			best.Tier = similarity.Tier
			best.Explanation = similarity.Explanation
			best.MatchedDimensions = similarity.MatchedDimensions
			best.Details = similarity.Details
			best.MatchDimensions = similarity.MatchDimensions
			best.TotalDimensions = similarity.TotalDimensions
		}
	}

	return best
}

func calculateFallbackSimilarity(a, b *model.Fingerprint, userA, userB int) (float64, []DimensionMatch, int, int) {
	weights := getFeatureWeights()
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
		{"persistent_id", "持久追踪ID", weights.PersistentID, "device", a.PersistentID, b.PersistentID},
		{"etag_id", "ETag追踪ID", weights.ETagID, "device", a.ETagID, b.ETagID},
		{"local_device_id", "设备追踪ID", weights.LocalDeviceID, "device", a.LocalDeviceID, b.LocalDeviceID},
		{"canvas_hash", "Canvas指纹", weights.CanvasHash, "device", a.CanvasHash, b.CanvasHash},
		{"webgl_hash", "WebGL指纹", weights.WebGLHash, "device", a.WebGLHash, b.WebGLHash},
		{"webgl_deep_hash", "WebGL深度指纹", weights.WebGLDeepHash, "device", a.WebGLDeepHash, b.WebGLDeepHash},
		{"client_rects_hash", "ClientRects指纹", weights.ClientRectsHash, "device", a.ClientRectsHash, b.ClientRectsHash},
		{"media_devices_hash", "媒体设备指纹", weights.MediaDevicesHash, "device", a.MediaDevicesHash, b.MediaDevicesHash},
		{"media_device_group_hash", "媒体设备分组指纹", weights.MediaDeviceGroupHash, "device", a.MediaDeviceGroupHash, b.MediaDeviceGroupHash},
		{"media_device_count", "媒体设备数量特征", weights.MediaDeviceCount, "device", a.MediaDeviceCount, b.MediaDeviceCount},
		{"speech_voices_hash", "语音列表指纹", weights.SpeechVoicesHash, "device", a.SpeechVoicesHash, b.SpeechVoicesHash},
		{"speech_voice_count", "语音数量特征", weights.SpeechVoiceCount, "device", intToDimensionValue(a.SpeechVoiceCount), intToDimensionValue(b.SpeechVoiceCount)},
		{"speech_local_voice_count", "本地语音数量特征", weights.SpeechLocalVoiceCount, "device", intToDimensionValue(a.SpeechLocalVoiceCount), intToDimensionValue(b.SpeechLocalVoiceCount)},
		{"audio_hash", "Audio指纹", weights.AudioHash, "device", a.AudioHash, b.AudioHash},
		{"webgl_vendor", "GPU厂商", weights.WebGLVendor, "device", a.WebGLVendor, b.WebGLVendor},
		{"webgl_renderer", "GPU型号", weights.WebGLRenderer, "device", a.WebGLRenderer, b.WebGLRenderer},
		{"fonts_hash", "字体列表指纹", weights.FontsHash, "device", a.FontsHash, b.FontsHash},

		// 网络层 (中权重)
		{"ja4", "TLS/JA4指纹", weights.JA4, "network", a.JA4, b.JA4},
		{"http_header_hash", "HTTP请求头指纹", weights.HTTPHeaderHash, "network", a.HTTPHeaderHash, b.HTTPHeaderHash},
		{"tls_ja3_hash", "TLS/JA3指纹", weights.TLSJA3Hash, "network", a.TLSJA3Hash, b.TLSJA3Hash},
		{"dns_resolver_ip", "DNS解析器IP", weights.DNSResolverIP, "network", a.DNSResolverIP, b.DNSResolverIP},
		{"ip_exact", "IP地址(精确)", weights.IPExact, "network", a.IPAddress, b.IPAddress},
		{"ip_subnet", "IP子网(/24)", weights.IPSubnet, "network", GetSubnet24(a.IPAddress), GetSubnet24(b.IPAddress)},

		// 环境特征 (低权重)
		{"screen_resolution", "屏幕分辨率", weights.ScreenResolution, "environment",
			fmt.Sprintf("%dx%d", a.ScreenWidth, a.ScreenHeight),
			fmt.Sprintf("%dx%d", b.ScreenWidth, b.ScreenHeight)},
		{"timezone", "时区", weights.Timezone, "environment", a.Timezone, b.Timezone},
		{"languages", "语言偏好", weights.Languages, "environment", a.Languages, b.Languages},
		{"cpu_cores", "CPU核心数", weights.CPUCores, "environment", fmt.Sprint(a.CPUCores), fmt.Sprint(b.CPUCores)},
		{"platform", "系统平台", weights.Platform, "environment", a.Platform, b.Platform},
	}

	filtered := make([]dimDef, 0, len(dimensions))
	for _, dim := range dimensions {
		if dim.Name == "ja4" && !common.FingerprintEnableJA4 {
			continue
		}
		if dim.Name == "etag_id" && !common.FingerprintEnableETag {
			continue
		}
		if dim.Name == "dns_resolver_ip" && !common.FingerprintEnableDNSLeak {
			continue
		}
		filtered = append(filtered, dim)
	}
	dimensions = filtered

	var details []DimensionMatch
	totalWeight := 0.0
	weightedScore := 0.0
	matchDims := 0
	totalDims := 0

	for _, dim := range dimensions {
		if dim.ValA == "" && dim.ValB == "" {
			continue
		}
		if dim.Name == "screen_resolution" {
			if dim.ValA == "0x0" || dim.ValB == "0x0" {
				continue
			}
		}
		if dim.Name == "cpu_cores" {
			if dim.ValA == "0" || dim.ValB == "0" {
				continue
			}
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

	// WebRTC IP 匹配 (P0)
	webrtcScore, webrtcDetails, webrtcMatched := compareWebRTC(a, b, weights)
	if common.FingerprintEnableWebRTC && len(webrtcDetails) > 0 {
		details = append(details, webrtcDetails...)
		totalDims += len(webrtcDetails)
		if webrtcMatched {
			matchDims++
		}
		webrtcWeight := webrtcDetails[0].Weight
		totalWeight += webrtcWeight
		weightedScore += webrtcScore * webrtcWeight
	}

	// UA相似度 (特殊计算)
	uaSim := computeUASimilarity(a, b)
	uaWeight := weights.UASimilarity
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
	ipHistWeight := weights.IPHistoryOverlap
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

	// ASN 相似度（用户级）
	if common.FingerprintEnableASNAnalysis && hasASNEvidence(userA, userB) {
		asnSim := ComputeASNOverlap(userA, userB)
		asnWeight := weights.ASNSimilarity
		totalDims++
		asnMatched := asnSim > 0.2
		if asnMatched {
			matchDims++
		}
		details = append(details, DimensionMatch{
			Dimension:   "asn_similarity",
			DisplayName: "ASN相似度",
			Score:       asnSim,
			Weight:      asnWeight,
			ValueA:      fmt.Sprintf("u%d", userA),
			ValueB:      fmt.Sprintf("u%d", userB),
			Matched:     asnMatched,
			Category:    "network",
		})
		totalWeight += asnWeight
		weightedScore += asnSim * asnWeight
	}

	// 时间模式相似度 / 互斥切换分析（用户级）
	if common.FingerprintEnableTemporalAnalysis {
		timeSim := ComputeTimeSimilarity(userA, userB)
		if timeSim > 0 {
			timeWeight := weights.TimeSimilarity
			totalDims++
			timeMatched := timeSim > 0.5
			if timeMatched {
				matchDims++
			}
			details = append(details, DimensionMatch{
				Dimension:   "time_similarity",
				DisplayName: "时间模式相似度",
				Score:       timeSim,
				Weight:      timeWeight,
				ValueA:      fmt.Sprintf("u%d", userA),
				ValueB:      fmt.Sprintf("u%d", userB),
				Matched:     timeMatched,
				Category:    "behavior",
			})
			totalWeight += timeWeight
			weightedScore += timeSim * timeWeight
		}

		switches := CheckMutualExclusionByUsers(userA, userB, 5)
		if switches > 0 {
			mutualScore := normalizeMutualExclusion(switches)
			mutualWeight := weights.MutualExclusion
			totalDims++
			mutualMatched := mutualScore >= 0.5
			if mutualMatched {
				matchDims++
			}
			details = append(details, DimensionMatch{
				Dimension:   "mutual_exclusion",
				DisplayName: "互斥切换模式",
				Score:       mutualScore,
				Weight:      mutualWeight,
				ValueA:      fmt.Sprintf("u%d", userA),
				ValueB:      fmt.Sprintf("u%d", userB),
				Matched:     mutualMatched,
				Category:    "behavior",
			})
			totalWeight += mutualWeight
			weightedScore += mutualScore * mutualWeight
		}
	}

	if common.FingerprintEnableBehaviorAnalysis {
		if keystrokeA := model.GetLatestKeystrokeProfile(userA); keystrokeA != nil && keystrokeA.SampleCount >= getKeystrokeMinSamples() {
			if keystrokeB := model.GetLatestKeystrokeProfile(userB); keystrokeB != nil && keystrokeB.SampleCount >= getKeystrokeMinSamples() {
				keystrokeSim := CompareKeystrokeProfiles(*keystrokeA, *keystrokeB)
				keystrokeWeight := weights.KeystrokeSimilarity
				totalDims++
				keystrokeMatched := keystrokeSim > 0.65
				if keystrokeMatched {
					matchDims++
				}
				details = append(details, DimensionMatch{
					Dimension:   "keystroke_similarity",
					DisplayName: "打字节奏相似度",
					Score:       keystrokeSim,
					Weight:      keystrokeWeight,
					ValueA:      fmt.Sprintf("samples=%d", keystrokeA.SampleCount),
					ValueB:      fmt.Sprintf("samples=%d", keystrokeB.SampleCount),
					Matched:     keystrokeMatched,
					Category:    "behavior",
				})
				totalWeight += keystrokeWeight
				weightedScore += keystrokeSim * keystrokeWeight
			}
		}

		if mouseA := model.GetLatestMouseProfile(userA); mouseA != nil && mouseA.SampleCount >= getMouseMinSamples() {
			if mouseB := model.GetLatestMouseProfile(userB); mouseB != nil && mouseB.SampleCount >= getMouseMinSamples() {
				mouseSim := CompareMouseProfiles(*mouseA, *mouseB)
				mouseWeight := weights.MouseSimilarity
				totalDims++
				mouseMatched := mouseSim > 0.60
				if mouseMatched {
					matchDims++
				}
				details = append(details, DimensionMatch{
					Dimension:   "mouse_similarity",
					DisplayName: "鼠标行为相似度",
					Score:       mouseSim,
					Weight:      mouseWeight,
					ValueA:      fmt.Sprintf("samples=%d", mouseA.SampleCount),
					ValueB:      fmt.Sprintf("samples=%d", mouseB.SampleCount),
					Matched:     mouseMatched,
					Category:    "behavior",
				})
				totalWeight += mouseWeight
				weightedScore += mouseSim * mouseWeight
			}
		}
	}

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

func collectMatchedDimensions(details []DimensionMatch) []string {
	matched := make([]string, 0, len(details))
	for _, detail := range details {
		if detail.Matched {
			matched = append(matched, detail.Dimension)
		}
	}
	return matched
}

func getTierFromScore(score float64) string {
	switch {
	case score >= 0.95:
		return "tier1"
	case score >= 0.85:
		return "tier2"
	case score >= 0.70:
		return "tier3"
	case score >= 0.60:
		return "tier4"
	default:
		return "fallback"
	}
}

func CalculateSimilarity(a, b *model.Fingerprint, userA, userB int) SimilarityResult {
	weights := getFeatureWeights()
	if confidence, details, matched := evaluateStrongSignals(a, b, weights); matched {
		return SimilarityResult{
			Score:             confidence,
			Tier:              "tier1",
			MatchedDimensions: collectMatchedDimensions(details),
			Explanation:       "matched strong identity signal",
			Details:           details,
			MatchDimensions:   1,
			TotalDimensions:   1,
		}
	}

	fallbackScore, fallbackDetails, fallbackMatchDims, fallbackTotalDims := calculateFallbackSimilarity(a, b, userA, userB)

	deviceScore := 0.0
	networkScore := 0.0
	behaviorScore := 0.0
	totalDeviceWeight := 0.0
	totalNetworkWeight := 0.0
	totalBehaviorWeight := 0.0
	totalEnvironmentWeight := 0.0
	matchedDeviceWeight := 0.0
	matchedNetworkWeight := 0.0
	matchedBehaviorWeight := 0.0
	matchedEnvironmentWeight := 0.0

	for _, detail := range fallbackDetails {
		switch detail.Category {
		case "device":
			totalDeviceWeight += detail.Weight
			deviceScore += detail.Score * detail.Weight
			if detail.Matched {
				matchedDeviceWeight += detail.Weight
			}
		case "network":
			totalNetworkWeight += detail.Weight
			networkScore += detail.Score * detail.Weight
			if detail.Matched {
				matchedNetworkWeight += detail.Weight
			}
		case "behavior":
			totalBehaviorWeight += detail.Weight
			behaviorScore += detail.Score * detail.Weight
			if detail.Matched {
				matchedBehaviorWeight += detail.Weight
			}
		case "environment":
			totalEnvironmentWeight += detail.Weight
			if detail.Matched {
				matchedEnvironmentWeight += detail.Weight
			}
		}
	}

	if totalDeviceWeight > 0 {
		deviceScore /= totalDeviceWeight
	}
	if totalNetworkWeight > 0 {
		networkScore /= totalNetworkWeight
	}
	if totalBehaviorWeight > 0 {
		behaviorScore /= totalBehaviorWeight
	}

	matchedDimensions := collectMatchedDimensions(fallbackDetails)

	tier2EvidenceWeight := matchedDeviceWeight
	if tier2EvidenceWeight < 3.0 && matchedDeviceWeight >= 0.8 && matchedNetworkWeight > 0.6 && matchedEnvironmentWeight > 0.5 {
		tier2EvidenceWeight = matchedDeviceWeight + matchedNetworkWeight + matchedEnvironmentWeight*1.5
	}
	if tier2EvidenceWeight >= 3.0 {
		boost := clamp01((tier2EvidenceWeight - 3.0) / 2.0)
		finalScore := 0.85 + boost*0.14
		return SimilarityResult{
			Score:             clamp01(finalScore),
			Tier:              "tier2",
			MatchedDimensions: matchedDimensions,
			Explanation:       "tier2: strong device evidence with weighted boost",
			Details:           fallbackDetails,
			MatchDimensions:   fallbackMatchDims,
			TotalDimensions:   fallbackTotalDims,
		}
	}

	if matchedDeviceWeight >= 1.5 && matchedNetworkWeight > 0.6 {
		behaviorBoost := behaviorScore * 0.15
		environmentBoost := 0.0
		if totalEnvironmentWeight > 0 {
			environmentBoost = clamp01(matchedEnvironmentWeight/totalEnvironmentWeight) * 0.10
		}
		finalScore := 0.70 + behaviorBoost + environmentBoost
		return SimilarityResult{
			Score:             clamp01(finalScore),
			Tier:              "tier3",
			MatchedDimensions: matchedDimensions,
			Explanation:       "tier3: medium device evidence plus network correlation",
			Details:           fallbackDetails,
			MatchDimensions:   fallbackMatchDims,
			TotalDimensions:   fallbackTotalDims,
		}
	}

	if behaviorScore > 0.8 && networkScore > 0.5 {
		return SimilarityResult{
			Score:             0.60,
			Tier:              "tier4",
			MatchedDimensions: matchedDimensions,
			Explanation:       "tier4: behavior pattern with network support",
			Details:           fallbackDetails,
			MatchDimensions:   fallbackMatchDims,
			TotalDimensions:   fallbackTotalDims,
		}
	}

	return SimilarityResult{
		Score:             clamp01(fallbackScore),
		Tier:              getTierFromScore(clamp01(fallbackScore)),
		MatchedDimensions: matchedDimensions,
		Explanation:       "fallback weighted similarity",
		Details:           fallbackDetails,
		MatchDimensions:   fallbackMatchDims,
		TotalDimensions:   fallbackTotalDims,
	}
}

// CompareFingerprints 比较两条指纹记录，返回置信度、维度详情、匹配维度数、总维度数
func CompareFingerprints(a, b *model.Fingerprint, userA, userB int) (float64, []DimensionMatch, int, int) {
	similarity := CalculateSimilarity(a, b, userA, userB)
	return similarity.Score, similarity.Details, similarity.MatchDimensions, similarity.TotalDimensions
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

func serializeLinkDetails(userID, candidateUID int, details []DimensionMatch) []byte {
	raw, err := common.Marshal(details)
	if err == nil {
		return raw
	}

	common.SysLog(fmt.Sprintf("fingerprint link details marshal failed: user=%d candidate=%d err=%v", userID, candidateUID, err))

	fallback := []DimensionMatch{{
		Dimension:   "details_serialize_fallback",
		DisplayName: "详情序列化降级",
		Score:       0,
		Weight:      0,
		ValueA:      fmt.Sprintf("user=%d", userID),
		ValueB:      fmt.Sprintf("candidate=%d", candidateUID),
		Matched:     false,
		Category:    "system",
	}}

	rawFallback, fallbackErr := common.Marshal(fallback)
	if fallbackErr != nil {
		common.SysLog(fmt.Sprintf("fingerprint link fallback marshal failed: user=%d candidate=%d err=%v", userID, candidateUID, fallbackErr))
		return []byte(`[{"dimension":"details_serialize_fallback","display_name":"详情序列化降级","score":0,"weight":0,"value_a":"","value_b":"","matched":false,"category":"system"}]`)
	}
	return rawFallback
}

func parseIPJSONList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var ips []string
	if err := common.Unmarshal([]byte(raw), &ips); err == nil {
		return ips
	}
	// 兼容逗号分隔文本
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(strings.Trim(p, "\""))
		if v != "" {
			result = append(result, v)
		}
	}
	return result
}

func hasOverlap(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(a))
	for _, v := range a {
		set[v] = struct{}{}
	}
	for _, v := range b {
		if _, ok := set[v]; ok {
			return true
		}
	}
	return false
}

func compareWebRTC(a, b *model.Fingerprint, weights fingerprintWeights) (float64, []DimensionMatch, bool) {
	localA := parseIPJSONList(a.WebRTCLocalIPs)
	localB := parseIPJSONList(b.WebRTCLocalIPs)
	publicA := parseIPJSONList(a.WebRTCPublicIPs)
	publicB := parseIPJSONList(b.WebRTCPublicIPs)

	if len(localA) == 0 && len(localB) == 0 && len(publicA) == 0 && len(publicB) == 0 {
		return 0, nil, false
	}

	localMatched := hasOverlap(localA, localB)
	publicMatched := hasOverlap(publicA, publicB)

	score := 0.0
	display := ""
	detailWeight := weights.WebRTCBothIP
	switch {
	case localMatched && publicMatched:
		score = 1.0
		detailWeight = weights.WebRTCBothIP
		display = "WebRTC 本地+公网IP"
	case localMatched:
		score = 1.0
		detailWeight = weights.WebRTCLocalIP
		display = "WebRTC 本地IP"
	case publicMatched:
		score = 1.0
		detailWeight = weights.WebRTCPublicIP
		display = "WebRTC 公网IP"
	default:
		score = 0
		hasLocalData := len(localA) > 0 || len(localB) > 0
		hasPublicData := len(publicA) > 0 || len(publicB) > 0
		switch {
		case hasLocalData && hasPublicData:
			detailWeight = weights.WebRTCBothIP
			display = "WebRTC 本地+公网IP"
		case hasLocalData:
			detailWeight = weights.WebRTCLocalIP
			display = "WebRTC 本地IP"
		case hasPublicData:
			detailWeight = weights.WebRTCPublicIP
			display = "WebRTC 公网IP"
		default:
			detailWeight = weights.WebRTCBothIP
			display = "WebRTC IP"
		}
	}

	detail := DimensionMatch{
		Dimension:   "webrtc_ip",
		DisplayName: display,
		Score:       score,
		Weight:      detailWeight,
		ValueA:      truncateStr(fmt.Sprintf("local=%v public=%v", localA, publicA), 60),
		ValueB:      truncateStr(fmt.Sprintf("local=%v public=%v", localB, publicB), 60),
		Matched:     score > 0,
		Category:    "network",
	}

	return score, []DimensionMatch{detail}, score > 0
}

func evaluateStrongSignals(a, b *model.Fingerprint, weights fingerprintWeights) (float64, []DimensionMatch, bool) {
	if a == nil || b == nil {
		return 0, nil, false
	}

	if a.PersistentID != "" && b.PersistentID != "" && a.PersistentID == b.PersistentID {
		return 0.99, []DimensionMatch{{
			Dimension:   "persistent_id",
			DisplayName: "持久追踪ID",
			Score:       1,
			Weight:      weights.PersistentID,
			ValueA:      truncateStr(a.PersistentID, 60),
			ValueB:      truncateStr(b.PersistentID, 60),
			Matched:     true,
			Category:    "device",
		}}, true
	}

	if common.FingerprintEnableETag && a.ETagID != "" && b.ETagID != "" && a.ETagID == b.ETagID {
		return 0.95, []DimensionMatch{{
			Dimension:   "etag_id",
			DisplayName: "ETag追踪ID",
			Score:       1,
			Weight:      weights.ETagID,
			ValueA:      truncateStr(a.ETagID, 60),
			ValueB:      truncateStr(b.ETagID, 60),
			Matched:     true,
			Category:    "device",
		}}, true
	}

	if common.FingerprintEnableWebRTC {
		localA := parseIPJSONList(a.WebRTCLocalIPs)
		localB := parseIPJSONList(b.WebRTCLocalIPs)
		publicA := parseIPJSONList(a.WebRTCPublicIPs)
		publicB := parseIPJSONList(b.WebRTCPublicIPs)
		if len(localA) > 0 && len(localB) > 0 && len(publicA) > 0 && len(publicB) > 0 &&
			hasOverlap(localA, localB) && hasOverlap(publicA, publicB) {
			return 0.95, []DimensionMatch{{
				Dimension:   "webrtc_ip",
				DisplayName: "WebRTC 本地+公网IP",
				Score:       1,
				Weight:      weights.WebRTCBothIP,
				ValueA:      truncateStr(fmt.Sprintf("local=%v public=%v", localA, publicA), 60),
				ValueB:      truncateStr(fmt.Sprintf("local=%v public=%v", localB, publicB), 60),
				Matched:     true,
				Category:    "network",
			}}, true
		}
	}

	return 0, nil, false
}

func isShortCircuitStrongSignalResult(result *LinkResult) bool {
	if result == nil {
		return false
	}
	if len(result.Details) != 1 {
		return false
	}
	dim := result.Details[0].Dimension
	switch dim {
	case "persistent_id":
		return result.Confidence >= 0.99
	case "etag_id", "webrtc_ip":
		return result.Confidence >= 0.95
	default:
		return false
	}
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func intToDimensionValue(v int) string {
	if v <= 0 {
		return ""
	}
	return fmt.Sprint(v)
}

// ReviewLink 处理关联审核
func ReviewLink(linkID int64, action string, note string) error {
	link := model.GetLinkByID(linkID)
	if link == nil {
		return fmt.Errorf("link not found")
	}

	trimmedAction := strings.TrimSpace(action)
	if err := validateReviewActionForStatus(link.Status, trimmedAction); err != nil {
		return err
	}

	switch trimmedAction {
	case "confirm":
		if err := model.UpdateLinkStatus(linkID, model.AccountLinkStatusConfirmed, 0, note); err != nil {
			return err
		}
	case "reject":
		if err := model.UpdateLinkStatus(linkID, model.AccountLinkStatusRejected, 0, note); err != nil {
			return err
		}
	case "whitelist":
		if err := model.UpdateLinkStatus(linkID, model.AccountLinkStatusWhitelisted, 0, note); err != nil {
			return err
		}
		if err := model.AddToWhitelist(link.UserIDA, link.UserIDB, 0, note); err != nil {
			return err
		}
	case "ban_newer":
		if err := model.UpdateLinkStatus(linkID, model.AccountLinkStatusConfirmed, 0, note); err != nil {
			return err
		}
		if err := banNewerAccount(link.UserIDA, link.UserIDB); err != nil {
			return err
		}
		if err := model.UpdateLinkAction(linkID, "ban_newer_account"); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid review action: %s", trimmedAction)
	}

	return nil
}

func validateReviewActionForStatus(currentStatus, action string) error {
	status := strings.TrimSpace(currentStatus)
	if status == "" {
		status = model.AccountLinkStatusPending
	}

	action = strings.TrimSpace(action)
	switch action {
	case "confirm", "reject", "whitelist", "ban_newer":
	default:
		return fmt.Errorf("invalid review action: %s", action)
	}

	if status == model.AccountLinkStatusPending || status == model.AccountLinkStatusAutoConfirmed {
		return nil
	}
	return fmt.Errorf("review action %s not allowed for status %s", action, status)
}

func banNewerAccount(userA, userB int) error {
	if userA > userB {
		return banUserByID(userA)
	}
	return banUserByID(userB)
}

func banUserByID(userID int) error {
	return model.DB.Model(&model.User{}).Where("id = ?", userID).
		Update("status", common.UserStatusDisabled).Error
}

func hasASNEvidence(userA, userB int) bool {
	historyA := model.GetIPUAHistory(userA)
	historyB := model.GetIPUAHistory(userB)
	for _, h := range historyA {
		if h != nil && h.ASN > 0 && !shouldIgnoreASNHistory(h) {
			for _, other := range historyB {
				if other != nil && other.ASN > 0 && !shouldIgnoreASNHistory(other) {
					return true
				}
			}
			break
		}
	}
	return false
}

func shouldIgnoreASNHistory(h *model.IPUAHistory) bool {
	if h == nil {
		return true
	}
	if h.IsDatacenter {
		return true
	}
	ipType := strings.ToLower(strings.TrimSpace(h.IPType))
	switch ipType {
	case "datacenter", "vpn", "proxy", "tor":
		return true
	default:
		return false
	}
}

func ComputeASNOverlap(userA, userB int) float64 {
	historyA := model.GetIPUAHistory(userA)
	historyB := model.GetIPUAHistory(userB)
	if len(historyA) == 0 || len(historyB) == 0 {
		return 0
	}
	setA := make(map[int]struct{})
	for _, h := range historyA {
		if h == nil || h.ASN <= 0 || shouldIgnoreASNHistory(h) {
			continue
		}
		setA[h.ASN] = struct{}{}
	}
	if len(setA) == 0 {
		return 0
	}
	inter := 0
	setB := make(map[int]struct{})
	for _, h := range historyB {
		if h == nil || h.ASN <= 0 || shouldIgnoreASNHistory(h) {
			continue
		}
		setB[h.ASN] = struct{}{}
		if _, ok := setA[h.ASN]; ok {
			inter++
		}
	}
	if len(setB) == 0 {
		return 0
	}
	union := len(setA) + len(setB) - inter
	if union <= 0 {
		return 0
	}
	return float64(inter) / float64(union)
}
