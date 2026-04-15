package model

import (
	"fmt"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func initTwoFAModelTestDB(t *testing.T) {
	t.Helper()
	oldDB := DB
	dsn := fmt.Sprintf("file:twofa_model_test_%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&User{}, &TwoFA{}, &TwoFABackupCode{}))
	DB = db
	t.Cleanup(func() {
		DB = oldDB
		_ = sqlDB.Close()
	})
}

func createTwoFATestUser(t *testing.T) *User {
	t.Helper()
	user := &User{
		Username:    fmt.Sprintf("twofa_user_%d", time.Now().UnixNano()),
		Password:    "password123",
		DisplayName: "twofa-user",
		Role:        common.RoleCommonUser,
		Status:      common.UserStatusEnabled,
		Group:       "default",
		AffCode:     fmt.Sprintf("aff_twofa_%d", time.Now().UnixNano()),
	}
	require.NoError(t, DB.Create(user).Error)
	return user
}

func TestValidateBackupCodeAndUpdateUsage_InvalidFormatIncrementsFailedAttempts(t *testing.T) {
	initTwoFAModelTestDB(t)
	user := createTwoFATestUser(t)

	twoFA := &TwoFA{UserId: user.Id, Secret: "secret", IsEnabled: true}
	require.NoError(t, DB.Create(twoFA).Error)

	valid, err := twoFA.ValidateBackupCodeAndUpdateUsage("ABCD_123")
	require.False(t, valid)
	require.Error(t, err)

	fresh, loadErr := GetTwoFAByUserId(user.Id)
	require.NoError(t, loadErr)
	require.NotNil(t, fresh)
	require.Equal(t, 1, fresh.FailedAttempts)
}
