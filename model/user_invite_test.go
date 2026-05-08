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

func initInviteModelTestDB(t *testing.T) {
	t.Helper()
	oldDB := DB
	dsn := fmt.Sprintf("file:invite_model_test_%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&User{}))
	DB = db
	t.Cleanup(func() {
		DB = oldDB
		_ = sqlDB.Close()
	})
}

func TestResolveInviterIDFromAffCode_CaseInsensitive(t *testing.T) {
	initInviteModelTestDB(t)

	inviter := &User{
		Username:    fmt.Sprintf("invite_owner_%d", time.Now().UnixNano()),
		Password:    "password123",
		DisplayName: "invite-owner",
		Role:        common.RoleCommonUser,
		Status:      common.UserStatusEnabled,
		Group:       "default",
		AffCode:     "BK0P",
	}
	require.NoError(t, DB.Create(inviter).Error)

	idUpper, err := ResolveInviterIDFromAffCode("BK0P")
	require.NoError(t, err)
	require.Equal(t, inviter.Id, idUpper)

	idLower, err := ResolveInviterIDFromAffCode("bk0p")
	require.NoError(t, err)
	require.Equal(t, inviter.Id, idLower)
}

func TestInsert_PersistsInviterID(t *testing.T) {
	initInviteModelTestDB(t)

	inviter := &User{
		Username:    fmt.Sprintf("insert_inviter_%d", time.Now().UnixNano()),
		Password:    "password123",
		DisplayName: "insert-inviter",
		Role:        common.RoleCommonUser,
		Status:      common.UserStatusEnabled,
		Group:       "default",
		AffCode:     "TTVE",
	}
	require.NoError(t, DB.Create(inviter).Error)

	invitee := &User{
		Username:    fmt.Sprintf("insert_invitee_%d", time.Now().UnixNano()),
		Password:    "password123",
		DisplayName: "insert-invitee",
		Role:        common.RoleCommonUser,
		Status:      common.UserStatusEnabled,
		Group:       "default",
	}
	require.NoError(t, invitee.Insert(inviter.Id))

	var saved User
	require.NoError(t, DB.First(&saved, "id = ?", invitee.Id).Error)
	require.Equal(t, inviter.Id, saved.InviterId)
}

func TestInsertWithTx_PersistsInviterID(t *testing.T) {
	initInviteModelTestDB(t)

	inviter := &User{
		Username:    fmt.Sprintf("tx_inviter_%d", time.Now().UnixNano()),
		Password:    "password123",
		DisplayName: "tx-inviter",
		Role:        common.RoleCommonUser,
		Status:      common.UserStatusEnabled,
		Group:       "default",
		AffCode:     "BK0P",
	}
	require.NoError(t, DB.Create(inviter).Error)

	invitee := &User{
		Username:    fmt.Sprintf("tx_invitee_%d", time.Now().UnixNano()),
		DisplayName: "tx-invitee",
		Role:        common.RoleCommonUser,
		Status:      common.UserStatusEnabled,
		Group:       "default",
	}
	require.NoError(t, DB.Transaction(func(tx *gorm.DB) error {
		return invitee.InsertWithTx(tx, inviter.Id)
	}))

	var saved User
	require.NoError(t, DB.First(&saved, "id = ?", invitee.Id).Error)
	require.Equal(t, inviter.Id, saved.InviterId)
}
