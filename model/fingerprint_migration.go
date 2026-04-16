package model

import (
	"fmt"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
)

const (
	fingerprintWebGLDeepHashColumn      = "webgl_deep_hash"
	userRiskScoreUAOSConsistencyColumn  = "ua_os_consistency"
	fingerprintLegacyWebGLDeepHashColumn = "web_gl_deep_hash"
	userRiskScoreLegacyUAOSColumn        = "uaos_consistency"
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
			`CREATE UNIQUE INDEX IF NOT EXISTS uk_udp_user_device_key ON user_device_profiles(user_id, device_key)`,
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
			`CREATE UNIQUE INDEX uk_udp_user_device_key ON user_device_profiles(user_id, device_key)`,
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
