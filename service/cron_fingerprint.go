package service

import (
	"encoding/json"
	"fmt"
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

	// 每天: 清理过期数据
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			CleanOldFingerprints()
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

	// ─── 路径1: 设备档案跨账号扫描（高精度，直接 device_key 命中）───
	// 查找同一 device_key 被多个 user_id 使用的情况
	type deviceGroup struct {
		DeviceKey string
		UserID    int
	}
	var deviceRows []deviceGroup
	model.DB.Model(&model.UserDeviceProfile{}).
		Select("device_key, user_id").
		Find(&deviceRows)

	deviceUserMap := make(map[string][]int)
	for _, row := range deviceRows {
		deviceUserMap[row.DeviceKey] = append(deviceUserMap[row.DeviceKey], row.UserID)
	}
	for _, userIDs := range deviceUserMap {
		if len(userIDs) <= 1 {
			continue
		}
		for i := 0; i < len(userIDs); i++ {
			for j := i + 1; j < len(userIDs); j++ {
				if model.IsWhitelisted(userIDs[i], userIDs[j]) {
					continue
				}
				_ = model.UpsertLink(userIDs[i], userIDs[j], 0.95, 1, 1,
					`[{"dimension":"device_key","display_name":"设备档案(同设备多账号)","score":0.95,"weight":0.95,"matched":true,"category":"device"}]`)
			}
		}
	}

	// ─── 路径2: 浏览器特征 hash 扫描（使用流水表，覆盖无设备ID场景）───
	scanByField := func(fieldName string) {
		groups := model.GroupUsersByField(fieldName)
		for _, userIDs := range groups {
			if len(userIDs) <= 1 {
				continue
			}
			for i := 0; i < len(userIDs); i++ {
				for j := i + 1; j < len(userIDs); j++ {
					if model.IsWhitelisted(userIDs[i], userIDs[j]) {
						continue
					}
					// 优先使用设备档案，档案为空才回退到流水最新5条
					fpsA := model.GetDeviceProfilesAsFingerprints(userIDs[i])
					if len(fpsA) == 0 {
						fpsA = model.GetLatestFingerprints(userIDs[i], 5)
					}
					fpsB := model.GetDeviceProfilesAsFingerprints(userIDs[j])
					if len(fpsB) == 0 {
						fpsB = model.GetLatestFingerprints(userIDs[j], 5)
					}
					if len(fpsA) == 0 || len(fpsB) == 0 {
						continue
					}

					bestConf := 0.0
					var bestDetails []DimensionMatch
					bestMatch := 0
					bestTotal := 0

					for _, fpA := range fpsA {
						for _, fpB := range fpsB {
							conf, details, m, t := CompareFingerprints(fpA, fpB, userIDs[i], userIDs[j])
							if conf > bestConf {
								bestConf = conf
								bestDetails = details
								bestMatch = m
								bestTotal = t
							}
						}
					}

					if bestConf >= 0.30 {
						detailsJSON, _ := json.Marshal(bestDetails)
						_ = model.UpsertLink(userIDs[i], userIDs[j], bestConf, bestMatch, bestTotal, string(detailsJSON))
					}
				}
			}
		}
	}

	scanByField("canvas_hash")
	scanByField("webgl_hash")
	scanByField("audio_hash")
	scanByField("local_device_id")
	scanByField("fonts_hash")

	common.SysLog("full link scan completed in " + time.Since(startTime).String())
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
