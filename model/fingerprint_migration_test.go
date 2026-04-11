package model

import (
	"testing"

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

func TestMigrateFingerprintETagColumn_BackfillsCanonicalColumn(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE user_fingerprints (
		id integer primary key autoincrement,
		user_id integer not null,
		composite_hash text not null default '',
		etag_id text not null default '',
		e_tag_id text not null default ''
	)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO user_fingerprints (user_id, composite_hash, etag_id, e_tag_id) VALUES (1, 'fp-1', '', 'legacy-etag')`).Error)

	require.NoError(t, migrateFingerprintETagColumn(db))

	var etag string
	require.NoError(t, db.Raw(`SELECT etag_id FROM user_fingerprints WHERE user_id = ?`, 1).Scan(&etag).Error)
	require.Equal(t, "legacy-etag", etag)
}
