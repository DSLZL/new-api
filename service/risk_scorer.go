package service

import (
	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
)

// UpdateRiskScore 更新用户风险评分
func UpdateRiskScore(userID int) {
	if !common.FingerprintEnabled {
		return
	}

	score := &model.UserRiskScore{UserID: userID}

	// 1. 关联账号数
	linkedCount := model.CountLinkedAccounts(userID, 0.70)
	score.LinkedAccounts = int(linkedCount)

	// 2. IP分析
	ipHistory := model.GetIPUAHistory(userID)
	uniqueIPs := make(map[string]bool)
	var vpnCount, dcCount, torCount int
	for _, h := range ipHistory {
		uniqueIPs[h.IPAddress] = true
		switch h.IPType {
		case "vpn", "proxy":
			vpnCount++
		case "datacenter":
			dcCount++
		case "tor":
			torCount++
		}
	}
	score.UniqueIPsCount = len(uniqueIPs)
	if len(ipHistory) > 0 {
		score.VPNUsageRate = float32(vpnCount) / float32(len(ipHistory))
		score.DatacenterIPRate = float32(dcCount) / float32(len(ipHistory))
	}
	score.TorUsageCount = torCount

	// 3. UA分析
	score.UniqueUACount = model.CountUniqueUAs(userID)

	// 4. 指纹变化率
	fps := model.GetLatestFingerprints(userID, 20)
	if len(fps) >= 2 {
		changes := 0
		for i := 1; i < len(fps); i++ {
			if fps[i].CompositeHash != fps[i-1].CompositeHash {
				changes++
			}
		}
		score.FingerprintChangeRate = float32(changes) / float32(len(fps)-1)
		if score.FingerprintChangeRate > 0.5 {
			score.FingerprintAnomalies = changes
		}
	}

	// 5. 综合评分
	risk := 0.0
	risk += float64(linkedCount) * 20.0
	risk += float64(score.VPNUsageRate) * 15.0
	risk += float64(score.DatacenterIPRate) * 20.0
	risk += float64(torCount) * 25.0
	risk += float64(score.FingerprintAnomalies) * 5.0
	risk += float64(score.FingerprintChangeRate) * 10.0

	if score.UniqueIPsCount > 50 {
		risk += 10
	}
	if score.UniqueUACount > 10 {
		risk += 10
	}

	if risk > 100 {
		risk = 100
	}
	score.RiskScore = float32(risk)

	switch {
	case risk >= 80:
		score.RiskLevel = "critical"
	case risk >= 60:
		score.RiskLevel = "high"
	case risk >= 30:
		score.RiskLevel = "medium"
	default:
		score.RiskLevel = "low"
	}

	_ = model.UpsertRiskScore(score)
}

// UpdateAllRiskScores 更新所有用户的风险评分
func UpdateAllRiskScores() {
	if !common.FingerprintEnabled {
		return
	}

	userIDs := model.GetAllUserIDsWithFingerprints()
	for _, uid := range userIDs {
		UpdateRiskScore(uid)
	}
	common.SysLog("updated risk scores for all users with fingerprints")
}
