package model

import (
	"fmt"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
)

const (
	fingerprintWebGLDeepHashColumn       = "webgl_deep_hash"
	userRiskScoreUAOSConsistencyColumn   = "ua_os_consistency"
	fingerprintLegacyWebGLDeepHashColumn = "web_gl_deep_hash"
	userRiskScoreLegacyUAOSColumn        = "uaos_consistency"
	userDeviceProfileUniqueIndexName     = "uk_udp_user_device_key"
)

var addColumnIfMissing = func(db *gorm.DB, model any, fieldName string) error {
	return db.Migrator().AddColumn(model, fieldName)
}

// RunFingerprintMigration 执行指纹相关表的自动迁移
func RunFingerprintMigration() error {
	if !common.FingerprintEnabled {
		return nil
	}

	common.SysLog("running fingerprint database migration...")

	if err := migrateFingerprintETagColumn(DB); err != nil {
		common.SysError("fingerprint etag column migration failed: " + err.Error())
		return err
	}
	if err := migrateFingerprintLegacyColumns(DB); err != nil {
		common.SysError("fingerprint legacy column migration failed: " + err.Error())
		return err
	}
	if err := ensureFingerprintRequiredColumns(DB); err != nil {
		common.SysError("fingerprint required columns migration failed: " + err.Error())
		return err
	}

	err := DB.AutoMigrate(
		&Fingerprint{},
		&UserDeviceProfile{},
		&UserTemporalProfile{},
		&KeystrokeProfile{},
		&MouseProfile{},
		&UserSession{},
		&AccountLink{},
		&UserRiskScore{},
		&IPUAHistory{},
		&LinkWhitelist{},
	)
	if err != nil {
		common.SysError("fingerprint migration failed: " + err.Error())
		return err
	}
	if err := EnsureUserDeviceProfileUniqueIndex(DB); err != nil {
		common.SysError("fingerprint device-profile unique index migration failed: " + err.Error())
		return err
	}
	if err := EnsureUserSessionUniqueIndex(DB); err != nil {
		common.SysError("fingerprint session unique index migration failed: " + err.Error())
		return err
	}
	if err := EnsureAccountLinkUniqueIndex(DB); err != nil {
		common.SysError("fingerprint account-link unique index migration failed: " + err.Error())
		return err
	}

	if common.UsingPostgreSQL {
		pgIndexes := []string{
			`CREATE INDEX IF NOT EXISTS idx_fp_canvas_partial ON user_fingerprints(canvas_hash) WHERE canvas_hash != ''`,
			`CREATE INDEX IF NOT EXISTS idx_fp_webgl_partial ON user_fingerprints(webgl_hash) WHERE webgl_hash != ''`,
			`CREATE INDEX IF NOT EXISTS idx_fp_webgl_deep_partial ON user_fingerprints(webgl_deep_hash) WHERE webgl_deep_hash != ''`,
			`CREATE INDEX IF NOT EXISTS idx_fp_client_rects_partial ON user_fingerprints(client_rects_hash) WHERE client_rects_hash != ''`,
			`CREATE INDEX IF NOT EXISTS idx_fp_media_devices_partial ON user_fingerprints(media_devices_hash) WHERE media_devices_hash != ''`,
			`CREATE INDEX IF NOT EXISTS idx_fp_media_device_group_partial ON user_fingerprints(media_device_group_hash) WHERE media_device_group_hash != ''`,
			`CREATE INDEX IF NOT EXISTS idx_fp_speech_voices_partial ON user_fingerprints(speech_voices_hash) WHERE speech_voices_hash != ''`,
			`CREATE INDEX IF NOT EXISTS idx_fp_audio_partial ON user_fingerprints(audio_hash) WHERE audio_hash != ''`,
			`CREATE INDEX IF NOT EXISTS idx_fp_device_partial ON user_fingerprints(local_device_id) WHERE local_device_id != ''`,
			`CREATE INDEX IF NOT EXISTS idx_fp_ja4_partial ON user_fingerprints(ja4) WHERE ja4 != ''`,
			`CREATE INDEX IF NOT EXISTS idx_fp_http_header_partial ON user_fingerprints(http_header_hash) WHERE http_header_hash != ''`,
			`CREATE INDEX IF NOT EXISTS idx_fp_dns_resolver_partial ON user_fingerprints(dns_resolver_ip) WHERE dns_resolver_ip != ''`,
			`CREATE INDEX IF NOT EXISTS idx_fp_etag_partial ON user_fingerprints(etag_id) WHERE etag_id != ''`,
			`CREATE INDEX IF NOT EXISTS idx_fp_persistent_partial ON user_fingerprints(persistent_id) WHERE persistent_id != ''`,
			`CREATE INDEX IF NOT EXISTS idx_udp_device_key ON user_device_profiles(device_key)`,
			`CREATE INDEX IF NOT EXISTS idx_udp_media_devices_partial ON user_device_profiles(media_devices_hash) WHERE media_devices_hash != ''`,
			`CREATE INDEX IF NOT EXISTS idx_udp_media_device_group_partial ON user_device_profiles(media_device_group_hash) WHERE media_device_group_hash != ''`,
			`CREATE INDEX IF NOT EXISTS idx_udp_speech_voices_partial ON user_device_profiles(speech_voices_hash) WHERE speech_voices_hash != ''`,
			`CREATE INDEX IF NOT EXISTS idx_udp_http_header_partial ON user_device_profiles(http_header_hash) WHERE http_header_hash != ''`,
			`CREATE INDEX IF NOT EXISTS idx_utp_user_date ON user_temporal_profiles(user_id, profile_date)`,
			`CREATE INDEX IF NOT EXISTS idx_utp_last_activity ON user_temporal_profiles(last_activity_at)`,
			`CREATE INDEX IF NOT EXISTS idx_keystroke_user_updated ON keystroke_profiles(user_id, updated_at)`,
			`CREATE INDEX IF NOT EXISTS idx_mouse_user_updated ON mouse_profiles(user_id, updated_at)`,
			`CREATE INDEX IF NOT EXISTS idx_us_user_started ON user_sessions(user_id, started_at)`,
			`CREATE INDEX IF NOT EXISTS idx_us_user_ended ON user_sessions(user_id, ended_at)`,
			`CREATE INDEX IF NOT EXISTS idx_us_session_id_partial ON user_sessions(session_id) WHERE session_id != ''`,
			`CREATE INDEX IF NOT EXISTS idx_us_device_key_partial ON user_sessions(device_key) WHERE device_key != ''`,
			`CREATE INDEX IF NOT EXISTS idx_fp_created_brin ON user_fingerprints USING BRIN(created_at)`,
			`CREATE INDEX IF NOT EXISTS idx_ipua_last_brin ON ip_ua_history USING BRIN(last_seen)`,
			`CREATE INDEX IF NOT EXISTS idx_ipua_asn ON ip_ua_history(asn)`,
			`CREATE UNIQUE INDEX IF NOT EXISTS uk_ipua_user_ip_ua ON ip_ua_history(user_id, ip_address, ua_browser, ua_os)`,
			`CREATE UNIQUE INDEX IF NOT EXISTS uk_whitelist_pair ON link_whitelist(user_id_a, user_id_b)`,
			`CREATE UNIQUE INDEX IF NOT EXISTS uk_link_pair ON account_links(user_id_a, user_id_b)`,
			`CREATE UNIQUE INDEX IF NOT EXISTS uk_utp_user_date ON user_temporal_profiles(user_id, profile_date)`,
		}
		for _, sql := range pgIndexes {
			if err := DB.Exec(sql).Error; err != nil {
				common.SysLog("fingerprint index creation note: " + err.Error())
			}
		}
	} else {
		mysqlIndexes := []string{
			`CREATE UNIQUE INDEX uk_ipua_user_ip_ua ON ip_ua_history(user_id, ip_address, ua_browser, ua_os)`,
			`CREATE INDEX idx_ipua_asn ON ip_ua_history(asn)`,
			`CREATE INDEX idx_fp_webgl_deep_hash ON user_fingerprints(webgl_deep_hash)`,
			`CREATE INDEX idx_fp_client_rects_hash ON user_fingerprints(client_rects_hash)`,
			`CREATE INDEX idx_fp_media_devices_hash ON user_fingerprints(media_devices_hash)`,
			`CREATE INDEX idx_fp_media_device_group_hash ON user_fingerprints(media_device_group_hash)`,
			`CREATE INDEX idx_fp_speech_voices_hash ON user_fingerprints(speech_voices_hash)`,
			`CREATE INDEX idx_fp_ja4 ON user_fingerprints(ja4)`,
			`CREATE INDEX idx_fp_http_header_hash ON user_fingerprints(http_header_hash)`,
			`CREATE INDEX idx_fp_dns_resolver_ip ON user_fingerprints(dns_resolver_ip)`,
			`CREATE INDEX idx_fp_etag_id ON user_fingerprints(etag_id)`,
			`CREATE INDEX idx_fp_persistent_id ON user_fingerprints(persistent_id)`,
			`CREATE INDEX idx_udp_device_key ON user_device_profiles(device_key)`,
			`CREATE INDEX idx_udp_media_devices_hash ON user_device_profiles(media_devices_hash)`,
			`CREATE INDEX idx_udp_media_device_group_hash ON user_device_profiles(media_device_group_hash)`,
			`CREATE INDEX idx_udp_speech_voices_hash ON user_device_profiles(speech_voices_hash)`,
			`CREATE INDEX idx_udp_http_header_hash ON user_device_profiles(http_header_hash)`,
			`CREATE INDEX idx_utp_user_date ON user_temporal_profiles(user_id, profile_date)`,
			`CREATE INDEX idx_utp_last_activity ON user_temporal_profiles(last_activity_at)`,
			`CREATE INDEX idx_keystroke_user_updated ON keystroke_profiles(user_id, updated_at)`,
			`CREATE INDEX idx_mouse_user_updated ON mouse_profiles(user_id, updated_at)`,
			`CREATE INDEX idx_us_user_started ON user_sessions(user_id, started_at)`,
			`CREATE INDEX idx_us_user_ended ON user_sessions(user_id, ended_at)`,
			`CREATE INDEX idx_us_session_id ON user_sessions(session_id)`,
			`CREATE INDEX idx_us_device_key ON user_sessions(device_key)`,
			`CREATE UNIQUE INDEX uk_whitelist_pair ON link_whitelist(user_id_a, user_id_b)`,
			`CREATE UNIQUE INDEX uk_link_pair ON account_links(user_id_a, user_id_b)`,
			`CREATE UNIQUE INDEX uk_utp_user_date ON user_temporal_profiles(user_id, profile_date)`,
		}
		for _, sql := range mysqlIndexes {
			if err := execCreateIndexIfMissing(DB, sql).Error; err != nil {
				common.SysLog("fingerprint index creation note: " + err.Error())
			}
		}
	}

	common.SysLog("fingerprint database migration completed")
	return nil
}

func migrateFingerprintETagColumn(db *gorm.DB) error {
	if db == nil {
		db = DB
	}
	if db == nil || !db.Migrator().HasTable(&Fingerprint{}) {
		return nil
	}

	hasLegacyColumn := db.Migrator().HasColumn(&Fingerprint{}, "e_tag_id")
	if !hasLegacyColumn {
		return nil
	}
	if !db.Migrator().HasColumn(&Fingerprint{}, "etag_id") {
		return db.Migrator().RenameColumn(&Fingerprint{}, "e_tag_id", "etag_id")
	}
	return db.Exec(`UPDATE user_fingerprints SET etag_id = e_tag_id WHERE (etag_id = '' OR etag_id IS NULL) AND e_tag_id != ''`).Error
}

func migrateFingerprintLegacyColumns(db *gorm.DB) error {
	if db == nil {
		db = DB
	}
	if db == nil {
		return nil
	}
	if err := migrateLegacyColumnIfNeeded(db, &Fingerprint{}, "user_fingerprints", fingerprintLegacyWebGLDeepHashColumn, fingerprintWebGLDeepHashColumn); err != nil {
		return err
	}
	if err := migrateLegacyColumnIfNeeded(db, &UserRiskScore{}, "user_risk_scores", userRiskScoreLegacyUAOSColumn, userRiskScoreUAOSConsistencyColumn); err != nil {
		return err
	}
	return nil
}

func migrateLegacyColumnIfNeeded(db *gorm.DB, model any, tableName string, legacyColumnName string, targetColumnName string) error {
	if db == nil || model == nil || tableName == "" || legacyColumnName == "" || targetColumnName == "" {
		return nil
	}
	if !db.Migrator().HasTable(model) || !db.Migrator().HasColumn(model, legacyColumnName) {
		return nil
	}
	if db.Migrator().HasColumn(model, targetColumnName) {
		return db.Exec(buildLegacyColumnBackfillSQL(tableName, legacyColumnName, targetColumnName)).Error
	}
	return db.Migrator().RenameColumn(model, legacyColumnName, targetColumnName)
}

func buildLegacyColumnBackfillSQL(tableName string, legacyColumnName string, targetColumnName string) string {
	targetTable := quoteIdentifier(tableName)
	targetColumn := quoteIdentifier(targetColumnName)
	legacyColumn := quoteIdentifier(legacyColumnName)
	if targetColumnName == userRiskScoreUAOSConsistencyColumn {
		return fmt.Sprintf("UPDATE %s SET %s = %s WHERE (%s = 0 OR %s IS NULL) AND %s != 0", targetTable, targetColumn, legacyColumn, targetColumn, targetColumn, legacyColumn)
	}
	return fmt.Sprintf("UPDATE %s SET %s = %s WHERE (%s = '' OR %s IS NULL) AND %s != ''", targetTable, targetColumn, legacyColumn, targetColumn, targetColumn, legacyColumn)
}

func quoteIdentifier(identifier string) string {
	if common.UsingPostgreSQL {
		return `"` + identifier + `"`
	}
	return "`" + identifier + "`"
}

func ensureFingerprintRequiredColumns(db *gorm.DB) error {
	if db == nil {
		db = DB
	}
	if db == nil {
		return nil
	}

	if err := ensureColumnIfMissing(db, &Fingerprint{}, "user_fingerprints", fingerprintWebGLDeepHashColumn, "WebGLDeepHash", []string{fingerprintLegacyWebGLDeepHashColumn}, "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := ensureColumnIfMissing(db, &UserRiskScore{}, "user_risk_scores", userRiskScoreUAOSConsistencyColumn, "UAOSConsistency", []string{userRiskScoreLegacyUAOSColumn}, "REAL NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	return nil
}

func ensureColumnIfMissing(db *gorm.DB, model any, tableName string, columnName string, fieldName string, legacyColumnNames []string, sqliteDDL string) error {
	if db == nil || model == nil || tableName == "" || columnName == "" || fieldName == "" {
		return nil
	}
	if !db.Migrator().HasTable(model) {
		return nil
	}
	if hasColumnByAnyName(db, model, append([]string{columnName}, legacyColumnNames...)...) {
		return nil
	}
	if common.UsingSQLite {
		sql := fmt.Sprintf("ALTER TABLE `%s` ADD COLUMN `%s` %s", tableName, columnName, sqliteDDL)
		if err := db.Exec(sql).Error; err != nil {
			return err
		}
		return nil
	}
	return addColumnIfMissing(db, model, fieldName)
}

func hasColumnByAnyName(db *gorm.DB, model any, columnNames ...string) bool {
	if db == nil || model == nil {
		return false
	}
	for _, name := range columnNames {
		if strings.TrimSpace(name) == "" {
			continue
		}
		if db.Migrator().HasColumn(model, name) {
			return true
		}
	}
	return false
}

func EnsureUserDeviceProfileUniqueIndex(db *gorm.DB) error {
	if db == nil {
		return nil
	}
	if db.Migrator().HasIndex(&UserDeviceProfile{}, userDeviceProfileUniqueIndexName) {
		return nil
	}
	if err := normalizeUserDeviceProfilesForUniqueIndex(db); err != nil {
		return err
	}
	return db.Exec("CREATE UNIQUE INDEX uk_udp_user_device_key ON user_device_profiles(user_id, device_key)").Error
}

func normalizeUserDeviceProfilesForUniqueIndex(db *gorm.DB) error {
	tx := db.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	var profiles []UserDeviceProfile
	if err := tx.Order("id ASC").Find(&profiles).Error; err != nil {
		tx.Rollback()
		return err
	}

	type userDeviceProfileGroup struct {
		merged UserDeviceProfile
		ids    []int64
	}
	groups := make(map[string]userDeviceProfileGroup, len(profiles))
	for _, profile := range profiles {
		key := fmt.Sprintf("%d:%s", profile.UserID, profile.DeviceKey)
		group, ok := groups[key]
		if !ok {
			groups[key] = userDeviceProfileGroup{merged: profile, ids: []int64{profile.ID}}
			continue
		}
		group.merged = mergeUserDeviceProfileRows(group.merged, profile)
		group.ids = append(group.ids, profile.ID)
		groups[key] = group
	}

	for _, group := range groups {
		deleteIDs := make([]int64, 0, len(group.ids)-1)
		for _, id := range group.ids {
			if id != group.merged.ID {
				deleteIDs = append(deleteIDs, id)
			}
		}
		if len(deleteIDs) > 0 {
			if err := tx.Where("id IN ?", deleteIDs).Delete(&UserDeviceProfile{}).Error; err != nil {
				tx.Rollback()
				return err
			}
		}
		mergedUpdate := UserDeviceProfile{
			CanvasHash:            group.merged.CanvasHash,
			WebGLHash:             group.merged.WebGLHash,
			WebGLDeepHash:         group.merged.WebGLDeepHash,
			ClientRectsHash:       group.merged.ClientRectsHash,
			MediaDevicesHash:      group.merged.MediaDevicesHash,
			MediaDeviceCount:      group.merged.MediaDeviceCount,
			MediaDeviceGroupHash:  group.merged.MediaDeviceGroupHash,
			MediaDeviceTotal:      group.merged.MediaDeviceTotal,
			SpeechVoicesHash:      group.merged.SpeechVoicesHash,
			SpeechVoiceCount:      group.merged.SpeechVoiceCount,
			SpeechLocalVoiceCount: group.merged.SpeechLocalVoiceCount,
			AudioHash:             group.merged.AudioHash,
			FontsHash:             group.merged.FontsHash,
			LocalDeviceID:         group.merged.LocalDeviceID,
			CompositeHash:         group.merged.CompositeHash,
			HTTPHeaderHash:        group.merged.HTTPHeaderHash,
			UABrowser:             group.merged.UABrowser,
			UAOS:                  group.merged.UAOS,
			UADeviceType:          group.merged.UADeviceType,
			LastSeenIP:            group.merged.LastSeenIP,
			FirstSeenAt:           group.merged.FirstSeenAt,
			LastSeenAt:            group.merged.LastSeenAt,
			SeenCount:             group.merged.SeenCount,
		}
		if err := tx.Model(&UserDeviceProfile{}).Where("id = ?", group.merged.ID).
			Select(
				"CanvasHash",
				"WebGLHash",
				"WebGLDeepHash",
				"ClientRectsHash",
				"MediaDevicesHash",
				"MediaDeviceCount",
				"MediaDeviceGroupHash",
				"MediaDeviceTotal",
				"SpeechVoicesHash",
				"SpeechVoiceCount",
				"SpeechLocalVoiceCount",
				"AudioHash",
				"FontsHash",
				"LocalDeviceID",
				"CompositeHash",
				"HTTPHeaderHash",
				"UABrowser",
				"UAOS",
				"UADeviceType",
				"LastSeenIP",
				"FirstSeenAt",
				"LastSeenAt",
				"SeenCount",
			).
			Updates(&mergedUpdate).Error; err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit().Error
}

func mergeUserDeviceProfileRows(base UserDeviceProfile, candidate UserDeviceProfile) UserDeviceProfile {
	merged := base
	if candidate.LastSeenAt.After(merged.LastSeenAt) {
		merged.LastSeenAt = candidate.LastSeenAt
	}
	if merged.FirstSeenAt.IsZero() || (!candidate.FirstSeenAt.IsZero() && candidate.FirstSeenAt.Before(merged.FirstSeenAt)) {
		merged.FirstSeenAt = candidate.FirstSeenAt
	}
	if candidate.SeenCount > 0 {
		merged.SeenCount += candidate.SeenCount
	} else {
		merged.SeenCount++
	}
	if candidate.CanvasHash != "" {
		merged.CanvasHash = candidate.CanvasHash
	}
	if candidate.WebGLHash != "" {
		merged.WebGLHash = candidate.WebGLHash
	}
	if candidate.WebGLDeepHash != "" {
		merged.WebGLDeepHash = candidate.WebGLDeepHash
	}
	if candidate.ClientRectsHash != "" {
		merged.ClientRectsHash = candidate.ClientRectsHash
	}
	if candidate.MediaDevicesHash != "" {
		merged.MediaDevicesHash = candidate.MediaDevicesHash
	}
	if candidate.MediaDeviceCount != "" {
		merged.MediaDeviceCount = candidate.MediaDeviceCount
	}
	if candidate.MediaDeviceGroupHash != "" {
		merged.MediaDeviceGroupHash = candidate.MediaDeviceGroupHash
	}
	if candidate.MediaDeviceTotal > 0 {
		merged.MediaDeviceTotal = candidate.MediaDeviceTotal
	}
	if candidate.SpeechVoicesHash != "" {
		merged.SpeechVoicesHash = candidate.SpeechVoicesHash
	}
	if candidate.SpeechVoiceCount > 0 {
		merged.SpeechVoiceCount = candidate.SpeechVoiceCount
	}
	if candidate.SpeechLocalVoiceCount > 0 {
		merged.SpeechLocalVoiceCount = candidate.SpeechLocalVoiceCount
	}
	if candidate.AudioHash != "" {
		merged.AudioHash = candidate.AudioHash
	}
	if candidate.FontsHash != "" {
		merged.FontsHash = candidate.FontsHash
	}
	if candidate.LocalDeviceID != "" {
		merged.LocalDeviceID = candidate.LocalDeviceID
	}
	if candidate.CompositeHash != "" {
		merged.CompositeHash = candidate.CompositeHash
	}
	if candidate.HTTPHeaderHash != "" {
		merged.HTTPHeaderHash = candidate.HTTPHeaderHash
	}
	if candidate.UABrowser != "" {
		merged.UABrowser = candidate.UABrowser
	}
	if candidate.UAOS != "" {
		merged.UAOS = candidate.UAOS
	}
	if candidate.UADeviceType != "" {
		merged.UADeviceType = candidate.UADeviceType
	}
	if candidate.LastSeenIP != "" {
		merged.LastSeenIP = candidate.LastSeenIP
	}
	return merged
}

func execCreateIndexIfMissing(db *gorm.DB, sql string) *gorm.DB {
	if db == nil {
		return DB.Exec(sql)
	}
	indexName := parseCreateIndexName(sql)
	if indexName == "" {
		return db.Exec(sql)
	}
	if hasAnyKnownFingerprintIndex(db, indexName) {
		return db
	}
	return db.Exec(sql)
}

func parseCreateIndexName(sql string) string {
	fields := strings.Fields(strings.TrimSpace(sql))
	for i := 0; i < len(fields)-1; i++ {
		if !strings.EqualFold(fields[i], "index") {
			continue
		}
		next := i + 1
		if next+2 < len(fields) && strings.EqualFold(fields[next], "if") && strings.EqualFold(fields[next+1], "not") && strings.EqualFold(fields[next+2], "exists") {
			next += 3
		}
		if next < len(fields) {
			return strings.TrimSpace(fields[next])
		}
		return ""
	}
	return ""
}

func hasAnyKnownFingerprintIndex(db *gorm.DB, indexName string) bool {
	if db == nil || indexName == "" {
		return false
	}
	models := []any{
		&Fingerprint{},
		&UserDeviceProfile{},
		&UserTemporalProfile{},
		&KeystrokeProfile{},
		&MouseProfile{},
		&UserSession{},
		&AccountLink{},
		&UserRiskScore{},
		&IPUAHistory{},
		&LinkWhitelist{},
	}
	for _, tableModel := range models {
		if db.Migrator().HasIndex(tableModel, indexName) {
			return true
		}
	}
	return false
}
