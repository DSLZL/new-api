package model

import (
	"github.com/QuantumNous/new-api/common"
)

// RunFingerprintMigration 执行指纹相关表的自动迁移
func RunFingerprintMigration() {
	if !common.FingerprintEnabled {
		return
	}

	common.SysLog("running fingerprint database migration...")

	err := DB.AutoMigrate(
		&Fingerprint{},
		&UserDeviceProfile{},
		&AccountLink{},
		&UserRiskScore{},
		&IPUAHistory{},
		&LinkWhitelist{},
	)
	if err != nil {
		common.SysError("fingerprint migration failed: " + err.Error())
		return
	}

	// PostgreSQL 专有优化索引
	if common.UsingPostgreSQL {
		pgIndexes := []string{
			// 部分索引: 只索引非空值
			`CREATE INDEX IF NOT EXISTS idx_fp_canvas_partial ON user_fingerprints(canvas_hash) WHERE canvas_hash != ''`,
			`CREATE INDEX IF NOT EXISTS idx_fp_webgl_partial ON user_fingerprints(webgl_hash) WHERE webgl_hash != ''`,
			`CREATE INDEX IF NOT EXISTS idx_fp_audio_partial ON user_fingerprints(audio_hash) WHERE audio_hash != ''`,
			`CREATE INDEX IF NOT EXISTS idx_fp_device_partial ON user_fingerprints(local_device_id) WHERE local_device_id != ''`,
			`CREATE INDEX IF NOT EXISTS idx_fp_ja3_partial ON user_fingerprints(tls_ja3_hash) WHERE tls_ja3_hash != ''`,
			`CREATE INDEX IF NOT EXISTS idx_fp_fonts_partial ON user_fingerprints(fonts_hash) WHERE fonts_hash != ''`,
			// BRIN 索引 (适合时序数据)
			`CREATE INDEX IF NOT EXISTS idx_fp_created_brin ON user_fingerprints USING BRIN(created_at)`,
			`CREATE INDEX IF NOT EXISTS idx_ipua_last_brin ON ip_ua_history USING BRIN(last_seen)`,
			// ip_ua_history 唯一约束 (for ON CONFLICT)
			`CREATE UNIQUE INDEX IF NOT EXISTS uk_ipua_user_ip_ua ON ip_ua_history(user_id, ip_address, ua_browser, ua_os)`,
			// link_whitelist 唯一约束
			`CREATE UNIQUE INDEX IF NOT EXISTS uk_whitelist_pair ON link_whitelist(user_id_a, user_id_b)`,
			// account_links 唯一约束
			`CREATE UNIQUE INDEX IF NOT EXISTS uk_link_pair ON account_links(user_id_a, user_id_b)`,
		}
		for _, sql := range pgIndexes {
			if err := DB.Exec(sql).Error; err != nil {
				common.SysLog("fingerprint index creation note: " + err.Error())
			}
		}
	} else {
		// MySQL/SQLite: 创建唯一索引
		mysqlIndexes := []string{
			`CREATE UNIQUE INDEX IF NOT EXISTS uk_ipua_user_ip_ua ON ip_ua_history(user_id, ip_address, ua_browser, ua_os)`,
			`CREATE UNIQUE INDEX IF NOT EXISTS uk_whitelist_pair ON link_whitelist(user_id_a, user_id_b)`,
			`CREATE UNIQUE INDEX IF NOT EXISTS uk_link_pair ON account_links(user_id_a, user_id_b)`,
		}
		for _, sql := range mysqlIndexes {
			// 忽略已存在的索引错误
			_ = DB.Exec(sql).Error
		}
	}

	common.SysLog("fingerprint database migration completed")
}
