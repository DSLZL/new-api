package model

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func setInviteCodeTestOptions(t *testing.T, values map[string]string) {
	t.Helper()
	common.OptionMapRWMutex.Lock()
	defer common.OptionMapRWMutex.Unlock()
	for key, value := range values {
		common.OptionMap[key] = value
	}
}

func createInviteCodeOwnerForTest(t *testing.T, suffix string) *User {
	t.Helper()
	user := &User{
		Username:    fmt.Sprintf("invite_owner_%s_%d", suffix, time.Now().UnixNano()),
		Password:    "password123",
		DisplayName: "invite-owner",
		Role:        common.RoleCommonUser,
		Status:      common.UserStatusEnabled,
		Group:       "default",
	}
	require.NoError(t, DB.Create(user).Error)
	return user
}

func countRowsForInviteCodeModelTest(t *testing.T, model any, query string, args ...any) int64 {
	t.Helper()
	var count int64
	require.NoError(t, DB.Model(model).Where(query, args...).Count(&count).Error)
	return count
}

func initInviteCodeModelTestDB(t *testing.T) {
	initInviteCodeModelTestDBWithMaxOpenConns(t, 1)
}

func initInviteCodeModelTestDBWithMaxOpenConns(t *testing.T, maxOpenConns int) {
	t.Helper()

	oldDB := DB
	oldUsingSQLite := common.UsingSQLite
	oldUsingMySQL := common.UsingMySQL
	oldUsingPostgreSQL := common.UsingPostgreSQL

	dsn := fmt.Sprintf("file:invite_code_model_test_%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	if maxOpenConns <= 0 {
		maxOpenConns = 1
	}
	sqlDB.SetMaxOpenConns(maxOpenConns)

	DB = db
	common.UsingSQLite = true
	common.UsingMySQL = false
	common.UsingPostgreSQL = false

	t.Cleanup(func() {
		DB = oldDB
		common.UsingSQLite = oldUsingSQLite
		common.UsingMySQL = oldUsingMySQL
		common.UsingPostgreSQL = oldUsingPostgreSQL
		_ = sqlDB.Close()
	})
}

func TestInviteCodeOptionDefaultsAndMigration(t *testing.T) {
	initInviteCodeModelTestDB(t)

	require.NoError(t, migrateDB())

	requiredTables := []string{
		"invite_codes",
		"invite_code_usages",
		"invite_code_audit_logs",
	}
	for _, table := range requiredTables {
		require.True(t, DB.Migrator().HasTable(table), "expected table %s to exist after migration", table)
	}

	InitOptionMap()

	expectedDefaults := map[string]string{
		"invite_code_max_uses_limit":            "100",
		"invite_code_max_expire_days":           "365",
		"invite_code_default_max_uses":          "1",
		"invite_code_default_max_expire_days":   "30",
		"invite_code_preserve_history_enabled":  "true",
		"invite_code_audit_enabled":             "false",
	}
	for key, expected := range expectedDefaults {
		value, exists := common.OptionMap[key]
		require.True(t, exists, "expected option key %s to exist", key)
		require.Equal(t, expected, value, "unexpected default value for option key %s", key)
	}
}

func TestInviteCodeCreate_EmptyStatusSetsActiveAndActivatedAt(t *testing.T) {
	initInviteCodeModelTestDB(t)
	require.NoError(t, migrateDB())

	item := &InviteCode{
		UserId:  1001,
		Code:    "ABCD",
		Status:  "",
		MaxUses: 1,
	}
	require.NoError(t, DB.Create(item).Error)
	require.Equal(t, InviteCodeStatusActive, item.Status)
	require.NotZero(t, item.ActivatedAt)
}

func TestInviteCodeCreate_NormalizesCode(t *testing.T) {
	initInviteCodeModelTestDB(t)
	require.NoError(t, migrateDB())

	item := &InviteCode{
		UserId:  1002,
		Code:    "  abcd  ",
		Status:  InviteCodeStatusActive,
		MaxUses: 1,
	}
	require.NoError(t, DB.Create(item).Error)
	require.Equal(t, "ABCD", item.Code)
}

func TestInviteCodeCreate_RejectsEmptyCode(t *testing.T) {
	initInviteCodeModelTestDB(t)
	require.NoError(t, migrateDB())

	item := &InviteCode{
		UserId:  1003,
		Code:    "   ",
		Status:  InviteCodeStatusActive,
		MaxUses: 1,
	}
	err := DB.Create(item).Error
	require.Error(t, err)
	require.Contains(t, err.Error(), "invite code cannot be empty")
}

func TestInviteCodeUpdate_NormalizesCode(t *testing.T) {
	initInviteCodeModelTestDB(t)
	require.NoError(t, migrateDB())

	item := &InviteCode{
		UserId:  1101,
		Code:    "ABCD",
		Status:  InviteCodeStatusActive,
		MaxUses: 1,
	}
	require.NoError(t, DB.Create(item).Error)

	item.Code = "  efgh  "
	require.NoError(t, DB.Save(item).Error)

	var saved InviteCode
	require.NoError(t, DB.First(&saved, item.Id).Error)
	require.Equal(t, "EFGH", saved.Code)
}

func TestInviteCodeUpdate_RejectsEmptyCode(t *testing.T) {
	initInviteCodeModelTestDB(t)
	require.NoError(t, migrateDB())

	item := &InviteCode{
		UserId:  1102,
		Code:    "WXYZ",
		Status:  InviteCodeStatusActive,
		MaxUses: 1,
	}
	require.NoError(t, DB.Create(item).Error)

	item.Code = "   "
	err := DB.Save(item).Error
	require.Error(t, err)
	require.Contains(t, err.Error(), "invite code cannot be empty")
}

func TestInviteCodeUpdate_ActiveStatusStampsActivatedAt(t *testing.T) {
	initInviteCodeModelTestDB(t)
	require.NoError(t, migrateDB())

	item := &InviteCode{
		UserId:       1103,
		Code:         "MNOP",
		Status:       InviteCodeStatusInvalidated,
		ActivatedAt:  0,
		InvalidatedAt: common.GetTimestamp(),
		MaxUses:      1,
	}
	require.NoError(t, DB.Create(item).Error)

	item.Status = InviteCodeStatusActive
	item.ActivatedAt = 0
	require.NoError(t, DB.Save(item).Error)
	require.NotZero(t, item.ActivatedAt)

	var saved InviteCode
	require.NoError(t, DB.First(&saved, item.Id).Error)
	require.NotZero(t, saved.ActivatedAt)
	require.Equal(t, InviteCodeStatusActive, saved.Status)
}

func TestInviteCodeUpdate_NormalizedDuplicateRejected(t *testing.T) {
	initInviteCodeModelTestDB(t)
	require.NoError(t, migrateDB())

	first := &InviteCode{
		UserId:  1104,
		Code:    "ABCD",
		Status:  InviteCodeStatusActive,
		MaxUses: 1,
	}
	second := &InviteCode{
		UserId:  1105,
		Code:    "EFGH",
		Status:  InviteCodeStatusActive,
		MaxUses: 1,
	}
	require.NoError(t, DB.Create(first).Error)
	require.NoError(t, DB.Create(second).Error)

	second.Code = "  abcd  "
	err := DB.Save(second).Error
	require.Error(t, err)
}

func TestCreateInitialInviteCodeForUser(t *testing.T) {
	initInviteCodeModelTestDB(t)
	require.NoError(t, migrateDB())
	InitOptionMap()
	setInviteCodeTestOptions(t, map[string]string{
		"invite_code_default_max_uses":        "2",
		"invite_code_default_max_expire_days": "7",
	})

	user := createInviteCodeOwnerForTest(t, "create")
	now := common.GetTimestamp()
	var created *InviteCode
	err := DB.Transaction(func(tx *gorm.DB) error {
		var createErr error
		created, createErr = CreateInitialInviteCodeForUser(tx, user)
		return createErr
	})
	require.NoError(t, err)
	require.NotNil(t, created)
	require.Equal(t, user.Id, created.UserId)
	require.Equal(t, InviteCodeStatusActive, created.Status)
	require.Equal(t, 2, created.MaxUses)
	require.Equal(t, 0, created.UsedCount)
	require.NotEmpty(t, created.Code)
	require.Greater(t, created.ExpiresAt, now)

	active, err := GetActiveInviteCodeByUserID(user.Id)
	require.NoError(t, err)
	require.Equal(t, created.Id, active.Id)
	require.Equal(t, created.Code, active.Code)

	var savedUser User
	require.NoError(t, DB.First(&savedUser, "id = ?", user.Id).Error)
	require.Equal(t, created.Code, savedUser.AffCode)
}

func TestUpdateActiveInviteCodeRules(t *testing.T) {
	initInviteCodeModelTestDB(t)
	require.NoError(t, migrateDB())
	InitOptionMap()
	setInviteCodeTestOptions(t, map[string]string{
		"invite_code_max_uses_limit":  "5",
		"invite_code_max_expire_days": "30",
	})

	user := createInviteCodeOwnerForTest(t, "update")
	var created *InviteCode
	require.NoError(t, DB.Transaction(func(tx *gorm.DB) error {
		var err error
		created, err = CreateInitialInviteCodeForUser(tx, user)
		return err
	}))
	require.NotNil(t, created)

	targetExpireAt := common.GetTimestamp() + int64(3*24*3600)
	var updated *InviteCode
	err := DB.Transaction(func(tx *gorm.DB) error {
		var updateErr error
		updated, updateErr = UpdateActiveInviteCodeRules(tx, user.Id, 3, targetExpireAt)
		return updateErr
	})
	require.NoError(t, err)
	require.NotNil(t, updated)
	require.Equal(t, created.Id, updated.Id)
	require.Equal(t, 3, updated.MaxUses)
	require.Equal(t, targetExpireAt, updated.ExpiresAt)
	require.Equal(t, InviteCodeStatusActive, updated.Status)
}

func TestRefreshInviteCodePreserveHistory(t *testing.T) {
	initInviteCodeModelTestDB(t)
	require.NoError(t, migrateDB())
	InitOptionMap()

	user := createInviteCodeOwnerForTest(t, "refresh_keep")
	var oldActive *InviteCode
	require.NoError(t, DB.Transaction(func(tx *gorm.DB) error {
		var err error
		oldActive, err = CreateInitialInviteCodeForUser(tx, user)
		return err
	}))
	require.NotNil(t, oldActive)

	var oldCode, newCode *InviteCode
	err := DB.Transaction(func(tx *gorm.DB) error {
		var refreshErr error
		oldCode, newCode, refreshErr = RefreshInviteCode(tx, user.Id, true)
		return refreshErr
	})
	require.NoError(t, err)
	require.NotNil(t, oldCode)
	require.NotNil(t, newCode)
	require.Equal(t, oldActive.Id, oldCode.Id)
	require.NotEqual(t, oldCode.Code, newCode.Code)
	require.Equal(t, InviteCodeStatusInvalidated, oldCode.Status)
	require.NotZero(t, oldCode.InvalidatedAt)
	require.Equal(t, InviteCodeStatusActive, newCode.Status)
	require.Equal(t, user.Id, newCode.UserId)

	var invalidatedCount int64
	require.NoError(t, DB.Model(&InviteCode{}).
		Where("id = ? AND status = ?", oldCode.Id, InviteCodeStatusInvalidated).
		Count(&invalidatedCount).Error)
	require.Equal(t, int64(1), invalidatedCount)
}

func TestRefreshInviteCodeHideHistoryWhenDisabled(t *testing.T) {
	initInviteCodeModelTestDB(t)
	require.NoError(t, migrateDB())
	InitOptionMap()

	user := createInviteCodeOwnerForTest(t, "refresh_hide")
	var oldActive *InviteCode
	require.NoError(t, DB.Transaction(func(tx *gorm.DB) error {
		var err error
		oldActive, err = CreateInitialInviteCodeForUser(tx, user)
		return err
	}))
	require.NotNil(t, oldActive)

	var oldCode, newCode *InviteCode
	err := DB.Transaction(func(tx *gorm.DB) error {
		var refreshErr error
		oldCode, newCode, refreshErr = RefreshInviteCode(tx, user.Id, false)
		return refreshErr
	})
	require.NoError(t, err)
	require.NotNil(t, oldCode)
	require.NotNil(t, newCode)
	require.Equal(t, oldActive.Id, oldCode.Id)
	require.Equal(t, InviteCodeStatusInvalidated, oldCode.Status)
	require.Equal(t, "refresh_hidden", oldCode.InvalidatedReason)

	visibleHistoryCount := countRowsForInviteCodeModelTest(
		t,
		&InviteCode{},
		"user_id = ? AND status = ? AND (invalidated_reason = '' OR invalidated_reason != ?)",
		user.Id,
		InviteCodeStatusInvalidated,
		"refresh_hidden",
	)
	require.Equal(t, int64(0), visibleHistoryCount)

	active, err := GetActiveInviteCodeByUserID(user.Id)
	require.NoError(t, err)
	require.Equal(t, newCode.Id, active.Id)
}

func TestBackfillInviteCodesFromLegacyAffCode(t *testing.T) {
	initInviteCodeModelTestDB(t)
	require.NoError(t, migrateDB())
	InitOptionMap()
	setInviteCodeTestOptions(t, map[string]string{
		"invite_code_default_max_uses":        "4",
		"invite_code_default_max_expire_days": "7",
	})

	legacyUser := &User{
		Username:    fmt.Sprintf("legacy_invite_%d", time.Now().UnixNano()),
		Password:    "password123",
		DisplayName: "legacy-user",
		Role:        common.RoleCommonUser,
		Status:      common.UserStatusEnabled,
		Group:       "default",
		AffCode:     "ABCD",
	}
	require.NoError(t, DB.Create(legacyUser).Error)

	require.NoError(t, backfillInviteCodesFromLegacyUsers(DB))

	code, err := GetActiveInviteCodeByUserID(legacyUser.Id)
	require.NoError(t, err)
	require.Equal(t, "ABCD", code.Code)
	require.Equal(t, 4, code.MaxUses)
	require.Equal(t, 0, code.UsedCount)
	require.Equal(t, InviteCodeStatusActive, code.Status)

	var inviteCodeCount int64
	require.NoError(t, DB.Model(&InviteCode{}).Where("user_id = ?", legacyUser.Id).Count(&inviteCodeCount).Error)
	require.Equal(t, int64(1), inviteCodeCount)

	require.NoError(t, backfillInviteCodesFromLegacyUsers(DB))
	require.NoError(t, DB.Model(&InviteCode{}).Where("user_id = ?", legacyUser.Id).Count(&inviteCodeCount).Error)
	require.Equal(t, int64(1), inviteCodeCount)
}

func TestConsumeInviteCodeMarksExhaustedAtLimit(t *testing.T) {
	initInviteCodeModelTestDB(t)
	require.NoError(t, migrateDB())
	InitOptionMap()
	setInviteCodeTestOptions(t, map[string]string{
		"invite_code_audit_enabled": "true",
	})

	user := createInviteCodeOwnerForTest(t, "consume")
	var code *InviteCode
	require.NoError(t, DB.Transaction(func(tx *gorm.DB) error {
		var err error
		code, err = CreateInitialInviteCodeForUser(tx, user)
		return err
	}))
	require.NotNil(t, code)

	require.NoError(t, DB.Model(&InviteCode{}).
		Where("id = ?", code.Id).
		UpdateColumns(map[string]any{
			"max_uses":   1,
			"used_count": 0,
			"status":     InviteCodeStatusActive,
		}).Error)

	require.NoError(t, DB.Transaction(func(tx *gorm.DB) error {
		return ConsumeInviteCode(tx, code, 998001, "password")
	}))

	var refreshed InviteCode
	require.NoError(t, DB.First(&refreshed, "id = ?", code.Id).Error)
	require.Equal(t, 1, refreshed.UsedCount)
	require.Equal(t, 1, refreshed.MaxUses)
	require.Equal(t, InviteCodeStatusExhausted, refreshed.Status)

	usageCount := countRowsForInviteCodeModelTest(
		t,
		&InviteCodeUsage{},
		"invite_code_id = ? AND invitee_user_id = ?",
		code.Id,
		998001,
	)
	require.Equal(t, int64(1), usageCount)

	auditCount := countRowsForInviteCodeModelTest(
		t,
		&InviteCodeAuditLog{},
		"invite_code_id = ? AND event_type = ?",
		code.Id,
		InviteCodeAuditEventUse,
	)
	require.Equal(t, int64(1), auditCount)

	maxUsesLimit, err := strconv.Atoi(common.OptionMap["invite_code_max_uses_limit"])
	require.NoError(t, err)
	require.Greater(t, maxUsesLimit, 0)
}
