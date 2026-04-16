package model

import (
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestParseCreateIndexName(t *testing.T) {
	require.Equal(t, "idx_fp_http_header_hash", parseCreateIndexName(`CREATE INDEX idx_fp_http_header_hash ON user_fingerprints(http_header_hash)`))
	require.Equal(t, "uk_link_pair", parseCreateIndexName(`CREATE UNIQUE INDEX uk_link_pair ON account_links(user_id_a, user_id_b)`))
}

func TestParseCreateIndexName_IgnoresIfNotExistsSyntaxInMySQLVariant(t *testing.T) {
	require.Equal(t, "idx_fp_http_header_hash", parseCreateIndexName(`CREATE INDEX IF NOT EXISTS idx_fp_http_header_hash ON user_fingerprints(http_header_hash)`))
	require.Equal(t, "uk_link_pair", parseCreateIndexName(`CREATE UNIQUE INDEX IF NOT EXISTS uk_link_pair ON account_links(user_id_a, user_id_b)`))
}

func TestEnsureUserSessionUniqueIndex_CreatesIndexOnce(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&UserSession{}))
	require.NoError(t, EnsureUserSessionUniqueIndex(db))
	require.True(t, db.Migrator().HasIndex(&UserSession{}, "uk_us_user_session"))
	require.NoError(t, EnsureUserSessionUniqueIndex(db))
}

func TestEnsureUserDeviceProfileUniqueIndex_CreatesIndexOnce(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&UserDeviceProfile{}))
	require.NoError(t, EnsureUserDeviceProfileUniqueIndex(db))
	require.True(t, db.Migrator().HasIndex(&UserDeviceProfile{}, userDeviceProfileUniqueIndexName))
	require.NoError(t, EnsureUserDeviceProfileUniqueIndex(db))
}

func TestEnsureUserDeviceProfileUniqueIndex_NormalizesLegacyRows(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&UserDeviceProfile{}))

	oldest := time.Now().UTC().Add(-2 * time.Hour)
	middle := time.Now().UTC().Add(-1 * time.Hour)
	latest := time.Now().UTC()
	require.NoError(t, db.Create(&UserDeviceProfile{
		UserID:         7,
		DeviceKey:      "lid:dup-7",
		CanvasHash:     "canvas-old",
		FirstSeenAt:    oldest,
		LastSeenAt:     middle,
		SeenCount:      2,
		SpeechVoicesHash: "speech-old",
	}).Error)
	require.NoError(t, db.Create(&UserDeviceProfile{
		UserID:            7,
		DeviceKey:         "lid:dup-7",
		WebGLHash:         "webgl-new",
		WebGLDeepHash:     "webgl-deep-new",
		MediaDevicesHash:  "media-new",
		HTTPHeaderHash:    "hdr-new",
		LastSeenIP:        "9.9.9.9",
		FirstSeenAt:       middle,
		LastSeenAt:        latest,
		SeenCount:         5,
	}).Error)

	require.NoError(t, EnsureUserDeviceProfileUniqueIndex(db))
	require.True(t, db.Migrator().HasIndex(&UserDeviceProfile{}, userDeviceProfileUniqueIndexName))

	var profiles []UserDeviceProfile
	require.NoError(t, db.Where("user_id = ? AND device_key = ?", 7, "lid:dup-7").Order("id ASC").Find(&profiles).Error)
	require.Len(t, profiles, 1)
	require.Equal(t, "canvas-old", profiles[0].CanvasHash)
	require.Equal(t, "webgl-new", profiles[0].WebGLHash)
	require.Equal(t, "webgl-deep-new", profiles[0].WebGLDeepHash)
	require.Equal(t, "media-new", profiles[0].MediaDevicesHash)
	require.Equal(t, "hdr-new", profiles[0].HTTPHeaderHash)
	require.Equal(t, "9.9.9.9", profiles[0].LastSeenIP)
	require.Equal(t, oldest.Unix(), profiles[0].FirstSeenAt.UTC().Unix())
	require.Equal(t, latest.Unix(), profiles[0].LastSeenAt.UTC().Unix())
	require.Equal(t, 7, profiles[0].SeenCount)
}

func TestMigrateFingerprintLegacyColumns_RenamesLegacyColumns(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	oldSQLite := common.UsingSQLite
	oldMySQL := common.UsingMySQL
	oldPostgreSQL := common.UsingPostgreSQL
	common.UsingSQLite = true
	common.UsingMySQL = false
	common.UsingPostgreSQL = false
	defer func() {
		common.UsingSQLite = oldSQLite
		common.UsingMySQL = oldMySQL
		common.UsingPostgreSQL = oldPostgreSQL
	}()

	require.NoError(t, db.Exec(`CREATE TABLE user_fingerprints (
		id integer primary key autoincrement,
		user_id integer not null,
		composite_hash text not null default '',
		web_gl_deep_hash text not null default ''
	)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO user_fingerprints (user_id, composite_hash, web_gl_deep_hash) VALUES (1, 'fp-1', 'legacy-webgl')`).Error)

	require.NoError(t, db.Exec(`CREATE TABLE user_risk_scores (
		id integer primary key autoincrement,
		user_id integer not null,
		risk_score real not null default 0,
		uaos_consistency real not null default 0
	)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO user_risk_scores (user_id, risk_score, uaos_consistency) VALUES (1, 0.2, 0.75)`).Error)

	require.NoError(t, migrateFingerprintLegacyColumns(db))
	require.True(t, db.Migrator().HasColumn(&Fingerprint{}, fingerprintWebGLDeepHashColumn))
	require.False(t, db.Migrator().HasColumn(&Fingerprint{}, fingerprintLegacyWebGLDeepHashColumn))
	require.True(t, db.Migrator().HasColumn(&UserRiskScore{}, userRiskScoreUAOSConsistencyColumn))
	require.False(t, db.Migrator().HasColumn(&UserRiskScore{}, userRiskScoreLegacyUAOSColumn))

	var webglDeepHash string
	require.NoError(t, db.Raw(`SELECT webgl_deep_hash FROM user_fingerprints WHERE user_id = ?`, 1).Scan(&webglDeepHash).Error)
	require.Equal(t, "legacy-webgl", webglDeepHash)

	var uaOSConsistency float32
	require.NoError(t, db.Raw(`SELECT ua_os_consistency FROM user_risk_scores WHERE user_id = ?`, 1).Scan(&uaOSConsistency).Error)
	require.InDelta(t, 0.75, uaOSConsistency, 0.0001)
}

func TestMigrateFingerprintLegacyColumns_BackfillsWhenBothColumnsExist(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	oldSQLite := common.UsingSQLite
	oldMySQL := common.UsingMySQL
	oldPostgreSQL := common.UsingPostgreSQL
	common.UsingSQLite = true
	common.UsingMySQL = false
	common.UsingPostgreSQL = false
	defer func() {
		common.UsingSQLite = oldSQLite
		common.UsingMySQL = oldMySQL
		common.UsingPostgreSQL = oldPostgreSQL
	}()

	require.NoError(t, db.Exec(`CREATE TABLE user_fingerprints (
		id integer primary key autoincrement,
		user_id integer not null,
		composite_hash text not null default '',
		webgl_deep_hash text not null default '',
		web_gl_deep_hash text not null default ''
	)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO user_fingerprints (user_id, composite_hash, webgl_deep_hash, web_gl_deep_hash) VALUES
		(1, 'fp-1', '', 'legacy-fill'),
		(2, 'fp-2', 'new-webgl', 'legacy-old')`).Error)

	require.NoError(t, db.Exec(`CREATE TABLE user_risk_scores (
		id integer primary key autoincrement,
		user_id integer not null,
		risk_score real not null default 0,
		ua_os_consistency real not null default 0,
		uaos_consistency real not null default 0
	)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO user_risk_scores (user_id, risk_score, ua_os_consistency, uaos_consistency) VALUES
		(1, 0.3, 0, 0.66),
		(2, 0.4, 0.4, 0.8)`).Error)

	require.NoError(t, migrateFingerprintLegacyColumns(db))

	var webglUser1 string
	require.NoError(t, db.Raw(`SELECT webgl_deep_hash FROM user_fingerprints WHERE user_id = ?`, 1).Scan(&webglUser1).Error)
	require.Equal(t, "legacy-fill", webglUser1)

	var webglUser2 string
	require.NoError(t, db.Raw(`SELECT webgl_deep_hash FROM user_fingerprints WHERE user_id = ?`, 2).Scan(&webglUser2).Error)
	require.Equal(t, "new-webgl", webglUser2)

	var scoreUser1 float32
	require.NoError(t, db.Raw(`SELECT ua_os_consistency FROM user_risk_scores WHERE user_id = ?`, 1).Scan(&scoreUser1).Error)
	require.InDelta(t, 0.66, scoreUser1, 0.0001)

	var scoreUser2 float32
	require.NoError(t, db.Raw(`SELECT ua_os_consistency FROM user_risk_scores WHERE user_id = ?`, 2).Scan(&scoreUser2).Error)
	require.InDelta(t, 0.4, scoreUser2, 0.0001)
}

func TestMigrateFingerprintETagColumn_RenamesLegacyColumn(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE user_fingerprints (
		id integer primary key autoincrement,
		user_id integer not null,
		composite_hash text not null default '',
		e_tag_id text not null default ''
	)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO user_fingerprints (user_id, composite_hash, e_tag_id) VALUES (1, 'fp-1', 'legacy-etag')`).Error)

	require.NoError(t, migrateFingerprintETagColumn(db))
	require.True(t, db.Migrator().HasColumn(&Fingerprint{}, "etag_id"))
	require.False(t, db.Migrator().HasColumn(&Fingerprint{}, "e_tag_id"))

	var etag string
	require.NoError(t, db.Raw(`SELECT etag_id FROM user_fingerprints WHERE user_id = ?`, 1).Scan(&etag).Error)
	require.Equal(t, "legacy-etag", etag)
}

func TestMigrateFingerprintETagColumn_BackfillsWhenBothColumnsExist(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE user_fingerprints (
		id integer primary key autoincrement,
		user_id integer not null,
		composite_hash text not null default '',
		etag_id text not null default '',
		e_tag_id text not null default ''
	)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO user_fingerprints (user_id, composite_hash, etag_id, e_tag_id) VALUES
		(1, 'fp-1', '', 'legacy-fill'),
		(2, 'fp-2', 'etag-new', 'legacy-old')`).Error)

	require.NoError(t, migrateFingerprintETagColumn(db))
	require.True(t, db.Migrator().HasColumn(&Fingerprint{}, "etag_id"))
	require.True(t, db.Migrator().HasColumn(&Fingerprint{}, "e_tag_id"))

	var etagUser1 string
	require.NoError(t, db.Raw(`SELECT etag_id FROM user_fingerprints WHERE user_id = ?`, 1).Scan(&etagUser1).Error)
	require.Equal(t, "legacy-fill", etagUser1)

	var etagUser2 string
	require.NoError(t, db.Raw(`SELECT etag_id FROM user_fingerprints WHERE user_id = ?`, 2).Scan(&etagUser2).Error)
	require.Equal(t, "etag-new", etagUser2)
}

func TestEnsureFingerprintRequiredColumns_AddsMissingColumnsOnSQLite(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE user_fingerprints (
		id integer primary key autoincrement,
		user_id integer not null,
		composite_hash text not null default ''
	)`).Error)
	require.NoError(t, db.Exec(`CREATE TABLE user_risk_scores (
		id integer primary key autoincrement,
		user_id integer not null,
		risk_score real not null default 0
	)`).Error)

	oldSQLite := common.UsingSQLite
	oldMySQL := common.UsingMySQL
	oldPostgreSQL := common.UsingPostgreSQL
	common.UsingSQLite = true
	common.UsingMySQL = false
	common.UsingPostgreSQL = false
	defer func() {
		common.UsingSQLite = oldSQLite
		common.UsingMySQL = oldMySQL
		common.UsingPostgreSQL = oldPostgreSQL
	}()

	require.NoError(t, ensureFingerprintRequiredColumns(db))
	require.True(t, db.Migrator().HasColumn(&Fingerprint{}, "webgl_deep_hash"))
	require.True(t, db.Migrator().HasColumn(&UserRiskScore{}, "ua_os_consistency"))
}

func TestEnsureFingerprintRequiredColumns_UsesFieldNameOnNonSQLite(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE user_fingerprints (
		id integer primary key autoincrement,
		user_id integer not null,
		composite_hash text not null default ''
	)`).Error)
	require.NoError(t, db.Exec(`CREATE TABLE user_risk_scores (
		id integer primary key autoincrement,
		user_id integer not null,
		risk_score real not null default 0
	)`).Error)

	calls := make([]string, 0, 2)
	oldAddColumnIfMissing := addColumnIfMissing
	addColumnIfMissing = func(db *gorm.DB, model any, fieldName string) error {
		calls = append(calls, fieldName)
		return nil
	}
	defer func() {
		addColumnIfMissing = oldAddColumnIfMissing
	}()

	oldSQLite := common.UsingSQLite
	oldMySQL := common.UsingMySQL
	oldPostgreSQL := common.UsingPostgreSQL
	common.UsingSQLite = false
	common.UsingMySQL = false
	common.UsingPostgreSQL = true
	defer func() {
		common.UsingSQLite = oldSQLite
		common.UsingMySQL = oldMySQL
		common.UsingPostgreSQL = oldPostgreSQL
	}()

	require.NoError(t, ensureFingerprintRequiredColumns(db))
	require.Equal(t, []string{"WebGLDeepHash", "UAOSConsistency"}, calls)
	require.False(t, db.Migrator().HasColumn(&Fingerprint{}, fingerprintWebGLDeepHashColumn))
	require.False(t, db.Migrator().HasColumn(&Fingerprint{}, fingerprintLegacyWebGLDeepHashColumn))
	require.False(t, db.Migrator().HasColumn(&UserRiskScore{}, userRiskScoreUAOSConsistencyColumn))
	require.False(t, db.Migrator().HasColumn(&UserRiskScore{}, userRiskScoreLegacyUAOSColumn))
}

func TestEnsureFingerprintRequiredColumns_SkipsLegacyColumnsOnNonSQLite(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE user_fingerprints (
		id integer primary key autoincrement,
		user_id integer not null,
		composite_hash text not null default '',
		web_gl_deep_hash text not null default ''
	)`).Error)
	require.NoError(t, db.Exec(`CREATE TABLE user_risk_scores (
		id integer primary key autoincrement,
		user_id integer not null,
		risk_score real not null default 0,
		uaos_consistency real not null default 0
	)`).Error)

	called := false
	oldAddColumnIfMissing := addColumnIfMissing
	addColumnIfMissing = func(db *gorm.DB, model any, fieldName string) error {
		called = true
		return nil
	}
	defer func() {
		addColumnIfMissing = oldAddColumnIfMissing
	}()

	oldSQLite := common.UsingSQLite
	oldMySQL := common.UsingMySQL
	oldPostgreSQL := common.UsingPostgreSQL
	common.UsingSQLite = false
	common.UsingMySQL = false
	common.UsingPostgreSQL = true
	defer func() {
		common.UsingSQLite = oldSQLite
		common.UsingMySQL = oldMySQL
		common.UsingPostgreSQL = oldPostgreSQL
	}()

	require.NoError(t, ensureFingerprintRequiredColumns(db))
	require.False(t, called)
}
