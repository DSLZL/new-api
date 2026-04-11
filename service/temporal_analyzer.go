package service

import (
	"fmt"
	"math"
	"sort"
	"sync/atomic"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
)

const temporalDefaultBins = 48
const temporalMutualExclusionWindowDefault = 5 * time.Minute
const temporalMinSampleCount = 5
const temporalBurstDedupWindow = 90 * time.Second
const temporalSessionGapDefault = 30 * time.Minute

var temporalRefreshRunning int32

// TemporalResult 时间模式比较结果。
type TemporalResult struct {
	CosineSimilarity float64 `json:"cosine_similarity"`
	PeakOverlap      float64 `json:"peak_overlap"`
}

// GapResult 会话互斥分析结果。
type GapResult struct {
	SwitchCount     int     `json:"switch_count"`
	AvgGapMinutes   float64 `json:"avg_gap_minutes"`
	AToBCount       int     `json:"a_to_b_count"`
	BToACount       int     `json:"b_to_a_count"`
	NegativeGapRate float64 `json:"negative_gap_rate"`
}

// SessionWindow 用户会话窗口（最小化结构，后续可替换为持久会话模型）。
type SessionWindow struct {
	Start time.Time
	End   time.Time
}

// BuildActivityProfile 将时间戳构建为 48-bin（30分钟）概率分布。
func BuildActivityProfile(loginTimestamps []time.Time) []float64 {
	profile := make([]float64, temporalDefaultBins)
	if len(loginTimestamps) == 0 {
		return profile
	}

	for _, ts := range loginTimestamps {
		hour := ts.Hour()
		bucket := hour * 2
		if ts.Minute() >= 30 {
			bucket++
		}
		if bucket < 0 {
			bucket = 0
		}
		if bucket >= temporalDefaultBins {
			bucket = temporalDefaultBins - 1
		}
		profile[bucket] += 1
	}

	total := float64(len(loginTimestamps))
	for i := range profile {
		profile[i] = profile[i] / total
	}

	return profile
}

// CompareProfiles 返回余弦相似度（0~1）。
func CompareProfiles(profileA, profileB []float64) float64 {
	if len(profileA) == 0 || len(profileB) == 0 {
		return 0
	}
	n := len(profileA)
	if len(profileB) < n {
		n = len(profileB)
	}
	if n == 0 {
		return 0
	}

	dot := 0.0
	normA := 0.0
	normB := 0.0
	for i := 0; i < n; i++ {
		a := profileA[i]
		b := profileB[i]
		dot += a * b
		normA += a * a
		normB += b * b
	}
	if normA == 0 || normB == 0 {
		return 0
	}

	sim := dot / (math.Sqrt(normA) * math.Sqrt(normB))
	if sim < 0 {
		return 0
	}
	if sim > 1 {
		return 1
	}
	return sim
}

// CompareTemporalProfiles 返回时间相似结果（余弦 + 峰值重叠）。
func CompareTemporalProfiles(profileA, profileB []float64) TemporalResult {
	result := TemporalResult{CosineSimilarity: CompareProfiles(profileA, profileB)}
	if len(profileA) == 0 || len(profileB) == 0 {
		return result
	}
	overlap := topKPeakOverlap(profileA, profileB, 5)
	if overlap < 0 {
		overlap = 0
	}
	if overlap > 1 {
		overlap = 1
	}
	result.PeakOverlap = overlap
	return result
}

// CheckMutualExclusion 统计 A/B 登录时间序列在窗口内的快速切换次数。
func CheckMutualExclusion(timestampsA, timestampsB []time.Time, windowMinutes int) int {
	if windowMinutes <= 0 {
		windowMinutes = int(temporalMutualExclusionWindowDefault / time.Minute)
	}
	window := time.Duration(windowMinutes) * time.Minute
	if len(timestampsA) == 0 || len(timestampsB) == 0 {
		return 0
	}
	a := append([]time.Time(nil), timestampsA...)
	b := append([]time.Time(nil), timestampsB...)
	sort.Slice(a, func(i, j int) bool { return a[i].Before(a[j]) })
	sort.Slice(b, func(i, j int) bool { return b[i].Before(b[j]) })

	count := 0
	count += countForwardSwitches(a, b, window)
	count += countForwardSwitches(b, a, window)
	return count
}

// SessionGapAnalysis 分析会话互斥模式（你退我进）。
func SessionGapAnalysis(sessionsA, sessionsB []SessionWindow) GapResult {
	result := GapResult{}
	if len(sessionsA) == 0 || len(sessionsB) == 0 {
		return result
	}
	a := normalizeSessions(sessionsA)
	b := normalizeSessions(sessionsB)

	gaps := make([]float64, 0)
	negativeGaps := 0

	for _, sa := range a {
		for _, sb := range b {
			if sb.Start.Before(sa.End) {
				negativeGaps++
				continue
			}
			gap := sb.Start.Sub(sa.End)
			if gap <= 5*time.Minute {
				result.SwitchCount++
				result.AToBCount++
				gaps = append(gaps, gap.Minutes())
			}
		}
	}
	for _, sb := range b {
		for _, sa := range a {
			if sa.Start.Before(sb.End) {
				negativeGaps++
				continue
			}
			gap := sa.Start.Sub(sb.End)
			if gap <= 5*time.Minute {
				result.SwitchCount++
				result.BToACount++
				gaps = append(gaps, gap.Minutes())
			}
		}
	}

	if len(gaps) > 0 {
		total := 0.0
		for _, g := range gaps {
			total += g
		}
		result.AvgGapMinutes = total / float64(len(gaps))
	}
	totalPairs := float64(len(a) * len(b) * 2)
	if totalPairs > 0 {
		result.NegativeGapRate = float64(negativeGaps) / totalPairs
	}
	return result
}

// ComputeTimeSimilarity 基于最近指纹上报时间构建活跃模式相似度。
func ComputeTimeSimilarity(userA, userB int) float64 {
	if common.FingerprintEnableTemporalPrecomputeRead {
		profileA := model.GetLatestTemporalProfile(userA)
		profileB := model.GetLatestTemporalProfile(userB)
		binsA := parseTemporalBins(profileA)
		binsB := parseTemporalBins(profileB)
		if len(binsA) == temporalDefaultBins && len(binsB) == temporalDefaultBins &&
			profileA != nil && profileB != nil &&
			profileA.SampleCount >= temporalMinSampleCount && profileB.SampleCount >= temporalMinSampleCount {
			return CompareProfiles(binsA, binsB)
		}
	}

	tsA, tsB := getUserFingerprintTimestamps(userA, userB, 80)
	if len(tsA) < temporalMinSampleCount || len(tsB) < temporalMinSampleCount {
		return 0
	}

	profileA := BuildActivityProfile(tsA)
	profileB := BuildActivityProfile(tsB)
	return CompareProfiles(profileA, profileB)
}

// CheckMutualExclusionByUsers 基于最近指纹上报时间统计互斥切换。
func CheckMutualExclusionByUsers(userA, userB, windowMinutes int) int {
	if common.FingerprintEnableTemporalPrecomputeRead {
		sessionsA := toSessionWindows(model.GetLatestUserSessions(userA, 200))
		sessionsB := toSessionWindows(model.GetLatestUserSessions(userB, 200))
		if len(sessionsA) >= temporalMinSampleCount && len(sessionsB) >= temporalMinSampleCount {
			result := SessionGapAnalysis(sessionsA, sessionsB)
			if result.SwitchCount > 0 {
				return result.SwitchCount
			}
		}
	}

	tsA, tsB := getUserFingerprintTimestamps(userA, userB, 120)
	if len(tsA) < temporalMinSampleCount || len(tsB) < temporalMinSampleCount {
		return 0
	}
	return CheckMutualExclusion(tsA, tsB, windowMinutes)
}

func normalizeMutualExclusion(switchCount int) float64 {
	if switchCount <= 0 {
		return 0
	}
	if switchCount >= 5 {
		return 1
	}
	return float64(switchCount) / 5.0
}

func getUserFingerprintTimestamps(userA, userB, limit int) ([]time.Time, []time.Time) {
	fpsA := model.GetLatestFingerprints(userA, limit)
	fpsB := model.GetLatestFingerprints(userB, limit)
	if len(fpsA) == 0 || len(fpsB) == 0 {
		return nil, nil
	}

	tsA := make([]time.Time, 0, len(fpsA))
	for _, fp := range fpsA {
		if fp == nil || fp.CreatedAt.IsZero() {
			continue
		}
		tsA = append(tsA, fp.CreatedAt)
	}
	tsB := make([]time.Time, 0, len(fpsB))
	for _, fp := range fpsB {
		if fp == nil || fp.CreatedAt.IsZero() {
			continue
		}
		tsB = append(tsB, fp.CreatedAt)
	}

	sort.Slice(tsA, func(i, j int) bool { return tsA[i].Before(tsA[j]) })
	sort.Slice(tsB, func(i, j int) bool { return tsB[i].Before(tsB[j]) })
	return dedupBurstTimestamps(tsA, temporalBurstDedupWindow), dedupBurstTimestamps(tsB, temporalBurstDedupWindow)
}

func topKPeakOverlap(profileA, profileB []float64, k int) float64 {
	if k <= 0 {
		return 0
	}
	topA := topKIndices(profileA, k)
	topB := topKIndices(profileB, k)
	if len(topA) == 0 || len(topB) == 0 {
		return 0
	}
	setA := make(map[int]struct{}, len(topA))
	for _, idx := range topA {
		setA[idx] = struct{}{}
	}
	inter := 0
	for _, idx := range topB {
		if _, ok := setA[idx]; ok {
			inter++
		}
	}
	denom := len(topA)
	if len(topB) < denom {
		denom = len(topB)
	}
	if denom == 0 {
		return 0
	}
	return float64(inter) / float64(denom)
}

func topKIndices(values []float64, k int) []int {
	if len(values) == 0 || k <= 0 {
		return nil
	}
	type pair struct {
		idx int
		val float64
	}
	pairs := make([]pair, 0, len(values))
	for i, v := range values {
		pairs = append(pairs, pair{idx: i, val: v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].val == pairs[j].val {
			return pairs[i].idx < pairs[j].idx
		}
		return pairs[i].val > pairs[j].val
	})
	if k > len(pairs) {
		k = len(pairs)
	}
	out := make([]int, 0, k)
	for i := 0; i < k; i++ {
		out = append(out, pairs[i].idx)
	}
	return out
}

func countForwardSwitches(src, dst []time.Time, window time.Duration) int {
	if len(src) == 0 || len(dst) == 0 {
		return 0
	}
	count := 0
	j := 0
	for _, s := range src {
		for j < len(dst) && !dst[j].After(s) {
			j++
		}
		if j >= len(dst) {
			break
		}
		delta := dst[j].Sub(s)
		if delta > 0 && delta <= window {
			count++
			j++ // 命中后消费目标事件，避免同一事件被重复复用
		}
	}
	return count
}

func dedupBurstTimestamps(timestamps []time.Time, window time.Duration) []time.Time {
	if len(timestamps) == 0 {
		return nil
	}

	sorted := append([]time.Time(nil), timestamps...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Before(sorted[j])
	})

	result := make([]time.Time, 0, len(sorted))
	last := sorted[0]
	result = append(result, last)
	for i := 1; i < len(sorted); i++ {
		if !sorted[i].After(last) {
			continue
		}
		if sorted[i].Sub(last) <= window {
			continue
		}
		result = append(result, sorted[i])
		last = sorted[i]
	}
	return result
}

func normalizeSessions(sessions []SessionWindow) []SessionWindow {
	result := make([]SessionWindow, 0, len(sessions))
	for _, s := range sessions {
		if s.Start.IsZero() {
			continue
		}
		if s.End.IsZero() || s.End.Before(s.Start) {
			s.End = s.Start
		}
		result = append(result, s)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Start.Before(result[j].Start)
	})
	return result
}

func parseTemporalBins(profile *model.UserTemporalProfile) []float64 {
	if profile == nil || profile.ActivityBins == "" {
		return nil
	}
	var bins []float64
	if err := common.UnmarshalJsonStr(profile.ActivityBins, &bins); err != nil {
		return nil
	}
	if len(bins) != temporalDefaultBins {
		return nil
	}
	return bins
}

func toSessionWindows(sessions []model.UserSession) []SessionWindow {
	if len(sessions) == 0 {
		return nil
	}
	windows := make([]SessionWindow, 0, len(sessions))
	for _, s := range sessions {
		start := s.StartedAt
		end := s.EndedAt
		if start.IsZero() {
			continue
		}
		if end.IsZero() || end.Before(start) {
			end = start
		}
		windows = append(windows, SessionWindow{Start: start, End: end})
	}
	return windows
}

func BuildSessionsFromTimestamps(timestamps []time.Time, gap time.Duration) []SessionWindow {
	if len(timestamps) == 0 {
		return nil
	}
	if gap <= 0 {
		gap = temporalSessionGapDefault
	}

	sorted := append([]time.Time(nil), timestamps...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Before(sorted[j]) })

	sessions := make([]SessionWindow, 0)
	start := sorted[0]
	last := sorted[0]
	for i := 1; i < len(sorted); i++ {
		if sorted[i].Sub(last) > gap {
			sessions = append(sessions, SessionWindow{Start: start, End: last})
			start = sorted[i]
		}
		last = sorted[i]
	}
	sessions = append(sessions, SessionWindow{Start: start, End: last})
	return sessions
}

func RefreshTemporalProfilesCron(limit int) {
	if !common.FingerprintEnabled || !common.FingerprintEnableTemporalAnalysis || !common.FingerprintEnableTemporalPrecomputeWrite {
		return
	}
	if limit <= 0 {
		limit = 120
	}
	if !atomic.CompareAndSwapInt32(&temporalRefreshRunning, 0, 1) {
		return
	}
	defer atomic.StoreInt32(&temporalRefreshRunning, 0)

	userIDs := model.GetAllUserIDsWithFingerprints()
	for _, userID := range userIDs {
		if err := RefreshTemporalProfileForUser(userID, limit); err != nil {
			common.SysLog(fmt.Sprintf("refresh temporal profile failed: user=%d err=%v", userID, err))
		}
	}
}

func RefreshTemporalProfileForUser(userID, limit int) error {
	if userID <= 0 || limit <= 0 {
		return nil
	}

	fps := model.GetLatestFingerprints(userID, limit)
	timestamps := make([]time.Time, 0, len(fps))
	for _, fp := range fps {
		if fp == nil || fp.CreatedAt.IsZero() {
			continue
		}
		timestamps = append(timestamps, fp.CreatedAt)
	}
	timestamps = dedupBurstTimestamps(timestamps, temporalBurstDedupWindow)
	if len(timestamps) == 0 {
		return nil
	}

	profile := BuildActivityProfile(timestamps)
	profileRaw, err := common.Marshal(profile)
	if err != nil {
		return err
	}
	lastActivity := timestamps[len(timestamps)-1]
	peakBin := topKIndices(profile, 1)
	peak := 0
	if len(peakBin) > 0 {
		peak = peakBin[0]
	}
	day := lastActivity.UTC().Format("2006-01-02")

	if err := model.UpsertTemporalProfile(&model.UserTemporalProfile{
		UserID:         userID,
		ProfileDate:    day,
		Timezone:       "UTC",
		ActivityBins:   string(profileRaw),
		PeakBin:        peak,
		SampleCount:    len(timestamps),
		LastActivityAt: lastActivity,
	}); err != nil {
		return err
	}

	sessionWindows := BuildSessionsFromTimestamps(timestamps, temporalSessionGapDefault)
	sessions := make([]model.UserSession, 0, len(sessionWindows))
	for idx, w := range sessionWindows {
		sessions = append(sessions, model.UserSession{
			UserID:          userID,
			SessionID:       buildPrecomputeSessionID(userID, w),
			DeviceKey:       "",
			IPAddress:       "",
			StartedAt:       w.Start,
			EndedAt:         w.End,
			DurationSeconds: int(w.End.Sub(w.Start).Seconds()),
			EventCount:      estimateSessionEventCount(timestamps, w),
			IsBurst:         idx == 0 && len(sessionWindows) == 1 && len(timestamps) < temporalMinSampleCount,
			Source:          "precompute",
		})
	}
	if err := model.ReplaceUserSessionsBySource(userID, "precompute", sessions); err != nil {
		return err
	}
	return nil
}

func buildPrecomputeSessionID(userID int, window SessionWindow) string {
	return fmt.Sprintf("%s%d:%d:%d", model.UserSessionReservedPrefixPrecompute, userID, window.Start.UTC().Unix(), window.End.UTC().Unix())
}

func estimateSessionEventCount(timestamps []time.Time, window SessionWindow) int {
	if len(timestamps) == 0 {
		return 0
	}
	count := 0
	for _, ts := range timestamps {
		if (ts.Equal(window.Start) || ts.After(window.Start)) && (ts.Equal(window.End) || ts.Before(window.End)) {
			count++
		}
	}
	if count <= 0 {
		return 1
	}
	return count
}
