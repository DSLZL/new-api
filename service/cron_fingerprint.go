package service

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
)

// InitFingerprintCron 初始化指纹系统定时任务
func InitFingerprintCron() {
	if !common.FingerprintEnabled {
		return
	}

	common.SysLog("initializing fingerprint cron jobs...")

	// 每6小时: 全量关联扫描
	go func() {
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			FullLinkScan()
		}
	}()

	// 每天: 更新所有风险评分
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			UpdateAllRiskScores()
		}
	}()

	// 每小时: 预计算时序画像（可配置开关）
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			RefreshTemporalProfilesCron(120)
		}
	}()

	common.SysLog("fingerprint cron jobs initialized")
}

// FullLinkScan 全量关联扫描
func FullLinkScan() {
	if !common.FingerprintEnabled {
		return
	}

	common.SysLog("starting full fingerprint link scan...")
	startTime := time.Now()

	// 在 precompute-read 模式下，扫描前先刷新时序画像，确保本轮评分消费最新时序特征
	if common.FingerprintEnableTemporalPrecomputeRead {
		RefreshTemporalProfilesCron(120)
	}
	CleanOldFingerprints()
	CleanOldBehaviorProfiles()
	CheckAndUpdateASNData()

	for _, pair := range collectFullScanPairs() {
		recomputePairSnapshot(pair.UserA, pair.UserB, nil, false)
	}

	common.SysLog("full link scan completed in " + time.Since(startTime).String())
}

// IncrementalLinkScan 增量关联扫描（仅重算指定用户涉及 pair）
func IncrementalLinkScan(userID int, latestFP *model.Fingerprint) {
	if !common.FingerprintEnabled || userID <= 0 {
		return
	}

	for _, pair := range collectIncrementalScanPairs(userID, latestFP) {
		recomputePairSnapshot(pair.UserA, pair.UserB, latestFP, true)
	}

	UpdateRiskScore(userID)
}

type accountPair struct {
	UserA int
	UserB int
}

func collectFullScanPairs() []accountPair {
	allUserIDs := collectAllRelatedUserIDs()
	pairSet := make(map[string]accountPair)
	for i := 0; i < len(allUserIDs); i++ {
		for j := i + 1; j < len(allUserIDs); j++ {
			addPair(pairSet, allUserIDs[i], allUserIDs[j])
		}
	}
	return flattenPairs(pairSet)
}

func collectIncrementalScanPairs(userID int, latestFP *model.Fingerprint) []accountPair {
	if userID <= 0 {
		return nil
	}

	pairSet := make(map[string]accountPair)
	addCandidatePairs := func(fp *model.Fingerprint) {
		if fp == nil {
			return
		}
		for _, candidateUID := range findCandidates(userID, fp) {
			addPair(pairSet, userID, candidateUID)
		}
	}

	if latestFP != nil && latestFP.UserID == userID {
		addCandidatePairs(latestFP)
	}
	for _, fp := range model.GetLatestFingerprints(userID, 5) {
		addCandidatePairs(fp)
	}
	for _, fp := range model.GetDeviceProfilesAsFingerprints(userID) {
		addCandidatePairs(fp)
	}
	for _, peerUserID := range model.GetLinkedPeerUserIDs(userID) {
		addPair(pairSet, userID, peerUserID)
	}
	return flattenPairs(pairSet)
}

func recomputePairSnapshot(userA, userB int, latestFP *model.Fingerprint, enableAutoConfirm bool) {
	a, b := model.NormalizePair(userA, userB)
	if a == b {
		return
	}
	if model.IsWhitelisted(a, b) {
		return
	}

	existing := model.FindExistingLink(a, b)
	result := computePairSnapshotScore(a, b, latestFP)
	if result.Confidence < 0.30 && existing == nil {
		return
	}

	detailsJSON := serializeLinkDetails(a, b, result.Details)
	if err := model.UpsertLinkSnapshot(a, b, result.Confidence, result.MatchDimensions, result.TotalDimensions, string(detailsJSON)); err != nil {
		common.SysError("failed to upsert fingerprint link snapshot: " + err.Error())
		return
	}

	if enableAutoConfirm && result.Confidence >= common.GetFingerprintAutoConfirmThreshold() && !isShortCircuitStrongSignalResult(result) {
		link := model.FindExistingLink(a, b)
		if link != nil {
			if _, err := model.UpdateLinkStatusIfCurrent(link.ID, model.AccountLinkStatusPending, model.AccountLinkStatusAutoConfirmed, 0, "auto confirmed by system"); err != nil {
				common.SysError("failed to auto confirm fingerprint link: " + err.Error())
			}
		}
	}
}

func computePairSnapshotScore(userA, userB int, latestFP *model.Fingerprint) *LinkResult {
	fpsA := loadUserFingerprintsForRecalc(userA, latestFP)
	fpsB := loadUserFingerprintsForRecalc(userB, latestFP)
	best := &LinkResult{UserA: userA, UserB: userB}
	if len(fpsA) == 0 || len(fpsB) == 0 {
		best.Details = []DimensionMatch{}
		return best
	}

	for _, fpA := range fpsA {
		candidate := computeBestLinkScore(userA, fpA, userB, fpsB)
		if candidate != nil && candidate.Confidence > best.Confidence {
			best = candidate
		}
	}
	if best.Details == nil {
		best.Details = []DimensionMatch{}
	}
	return best
}

func loadUserFingerprintsForRecalc(userID int, latestFP *model.Fingerprint) []*model.Fingerprint {
	result := make([]*model.Fingerprint, 0, 12)
	seen := make(map[string]struct{})

	appendUnique := func(fp *model.Fingerprint) {
		if fp == nil {
			return
		}
		key := buildFingerprintIdentityKey(fp)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		result = append(result, fp)
	}

	if latestFP != nil && latestFP.UserID == userID {
		appendUnique(latestFP)
	}

	for _, fp := range model.GetLatestFingerprints(userID, 5) {
		appendUnique(fp)
	}
	for _, fp := range model.GetDeviceProfilesAsFingerprints(userID) {
		appendUnique(fp)
	}
	return result
}

func buildFingerprintIdentityKey(fp *model.Fingerprint) string {
	if fp == nil {
		return ""
	}
	return strings.Join([]string{
		fmt.Sprint(fp.ID),
		fmt.Sprint(fp.UserID),
		fp.LocalDeviceID,
		fp.CompositeHash,
		fp.ETagID,
		fp.PersistentID,
		fp.JA4,
		fp.TLSJA3Hash,
		fp.HTTPHeaderHash,
		fp.DNSResolverIP,
		fp.WebRTCLocalIPs,
		fp.WebRTCPublicIPs,
		fp.IPAddress,
		fp.CanvasHash,
		fp.WebGLHash,
		fp.AudioHash,
		fp.FontsHash,
		fp.UABrowser,
		fp.UABrowserVer,
		fp.UAOS,
		fp.UAOSVer,
		fp.UADeviceType,
		fp.CreatedAt.UTC().Format(time.RFC3339Nano),
	}, "|")
}

func collectAllRelatedUserIDs() []int {
	userSet := make(map[int]struct{})
	addUsers := func(ids []int) {
		for _, id := range ids {
			if id > 0 {
				userSet[id] = struct{}{}
			}
		}
	}

	var fpUserIDs []int
	if err := model.DB.Model(&model.Fingerprint{}).
		Distinct("user_id").
		Pluck("user_id", &fpUserIDs).Error; err != nil {
		common.SysError("failed to load fingerprint users for full scan: " + err.Error())
	} else {
		addUsers(fpUserIDs)
	}

	var profileUserIDs []int
	if err := model.DB.Model(&model.UserDeviceProfile{}).
		Distinct("user_id").
		Pluck("user_id", &profileUserIDs).Error; err != nil {
		common.SysError("failed to load device profile users for full scan: " + err.Error())
	} else {
		addUsers(profileUserIDs)
	}

	for _, pair := range model.GetAllAccountLinkPairs() {
		if pair.UserIDA > 0 {
			userSet[pair.UserIDA] = struct{}{}
		}
		if pair.UserIDB > 0 {
			userSet[pair.UserIDB] = struct{}{}
		}
	}

	result := make([]int, 0, len(userSet))
	for userID := range userSet {
		result = append(result, userID)
	}
	return result
}

func addPair(pairSet map[string]accountPair, userA, userB int) {
	a, b := model.NormalizePair(userA, userB)
	if a == b {
		return
	}
	key := fmt.Sprintf("%d:%d", a, b)
	pairSet[key] = accountPair{UserA: a, UserB: b}
}

func flattenPairs(pairSet map[string]accountPair) []accountPair {
	pairs := make([]accountPair, 0, len(pairSet))
	for _, pair := range pairSet {
		pairs = append(pairs, pair)
	}
	return pairs
}

// CleanOldFingerprints 清理过期指纹数据
func CleanOldFingerprints() {
	days := common.GetFingerprintRetentionDays()
	cutoff := time.Now().AddDate(0, 0, -days)
	deleted := model.DeleteOldFingerprints(cutoff)
	if deleted > 0 {
		common.SysLog("cleaned " + fmt.Sprint(deleted) + " old fingerprint records")
	}
}

// CleanOldBehaviorProfiles 清理过期行为画像数据
func CleanOldBehaviorProfiles() {
	days := common.GetFingerprintBehaviorRetentionDays()
	if days <= 0 {
		days = common.GetFingerprintRetentionDays()
	}
	cutoff := time.Now().AddDate(0, 0, -days)

	deletedKeystroke, err := model.DeleteOldKeystrokeProfiles(cutoff)
	if err != nil {
		common.SysError("failed to clean old keystroke profiles: " + err.Error())
	}

	deletedMouse, err := model.DeleteOldMouseProfiles(cutoff)
	if err != nil {
		common.SysError("failed to clean old mouse profiles: " + err.Error())
	}

	if deletedKeystroke > 0 || deletedMouse > 0 {
		common.SysLog("cleaned old behavior profiles: keystroke=" + fmt.Sprint(deletedKeystroke) + " mouse=" + fmt.Sprint(deletedMouse))
	}
}

// CheckAndUpdateASNData 检查 ASN 数据更新（当前为安全 no-op）
func CheckAndUpdateASNData() {
	if !common.FingerprintEnableASNAnalysis {
		return
	}

	asnDataPath := strings.TrimSpace(os.Getenv("FINGERPRINT_ASN_DB_PATH"))
	if asnDataPath == "" {
		common.SysLog("asn data update check skipped: FINGERPRINT_ASN_DB_PATH is empty")
		return
	}

	info, err := os.Stat(asnDataPath)
	if err != nil {
		common.SysError("asn data update check failed: " + err.Error())
		return
	}

	maxAgeDays := common.GetFingerprintASNUpdateCheckIntervalDays()
	if maxAgeDays <= 0 {
		maxAgeDays = 7
	}
	if time.Since(info.ModTime()) > time.Duration(maxAgeDays)*24*time.Hour {
		common.SysLog("asn data appears stale; update hook is currently no-op: path=" + asnDataPath)
	}
}
