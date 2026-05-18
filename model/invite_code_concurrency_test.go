package model

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestConsumeInviteCode_ConcurrentLastSlot(t *testing.T) {
	initInviteCodeModelTestDBWithMaxOpenConns(t, 8)
	require.NoError(t, migrateDB())
	InitOptionMap()
	common.OptionMapRWMutex.Lock()
	common.OptionMap["invite_code_audit_enabled"] = "false"
	common.OptionMapRWMutex.Unlock()

	user := createInviteCodeOwnerForTest(t, "concurrent")
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

	var successCount int32
	var exhaustedCount int32
	var otherErrorCount int32

	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		inviteeID := 900100 + i
		go func(id int) {
			defer wg.Done()
			err := DB.Transaction(func(tx *gorm.DB) error {
				localCode := *code
				return ConsumeInviteCode(tx, &localCode, id, "password")
			})
			if err == nil {
				atomic.AddInt32(&successCount, 1)
				return
			}
			if errors.Is(err, ErrInviteCodeExhausted) {
				atomic.AddInt32(&exhaustedCount, 1)
				return
			}
			atomic.AddInt32(&otherErrorCount, 1)
		}(inviteeID)
	}
	wg.Wait()

	require.Equal(t, int32(1), successCount)
	require.Equal(t, int32(1), exhaustedCount)
	require.Equal(t, int32(0), otherErrorCount)

	var refreshed InviteCode
	require.NoError(t, DB.First(&refreshed, "id = ?", code.Id).Error)
	require.Equal(t, 1, refreshed.UsedCount)
	require.Equal(t, 1, refreshed.MaxUses)
	require.Equal(t, InviteCodeStatusExhausted, refreshed.Status)

	var usageCount int64
	require.NoError(t, DB.Model(&InviteCodeUsage{}).Where("invite_code_id = ?", code.Id).Count(&usageCount).Error)
	require.Equal(t, int64(1), usageCount)
}

func TestRefreshInviteCode_ConcurrentSingleActiveInvariant(t *testing.T) {
	initInviteCodeModelTestDBWithMaxOpenConns(t, 8)
	require.NoError(t, migrateDB())
	InitOptionMap()

	user := createInviteCodeOwnerForTest(t, "refresh_concurrent")
	var initial *InviteCode
	require.NoError(t, DB.Transaction(func(tx *gorm.DB) error {
		var err error
		initial, err = CreateInitialInviteCodeForUser(tx, user)
		return err
	}))
	require.NotNil(t, initial)

	var successCount int32
	var failCount int32
	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			err := DB.Transaction(func(tx *gorm.DB) error {
				_, _, refreshErr := RefreshInviteCode(tx, user.Id, true)
				return refreshErr
			})
			if err == nil {
				atomic.AddInt32(&successCount, 1)
			} else {
				atomic.AddInt32(&failCount, 1)
			}
		}()
	}
	wg.Wait()

	require.Equal(t, int32(1), successCount)
	require.Equal(t, int32(1), failCount)

	var activeCount int64
	require.NoError(t, DB.Model(&InviteCode{}).
		Where("user_id = ? AND status = ?", user.Id, InviteCodeStatusActive).
		Count(&activeCount).Error)
	require.Equal(t, int64(1), activeCount)
}

func TestRefreshInviteCode_NilTxPath(t *testing.T) {
	initInviteCodeModelTestDBWithMaxOpenConns(t, 8)
	require.NoError(t, migrateDB())
	InitOptionMap()

	user := createInviteCodeOwnerForTest(t, "refresh_niltx")
	var initial *InviteCode
	require.NoError(t, DB.Transaction(func(tx *gorm.DB) error {
		var err error
		initial, err = CreateInitialInviteCodeForUser(tx, user)
		return err
	}))
	require.NotNil(t, initial)

	oldCode, newCode, err := RefreshInviteCode(nil, user.Id, true)
	require.NoError(t, err)
	require.NotNil(t, oldCode)
	require.NotNil(t, newCode)
	require.Equal(t, initial.Id, oldCode.Id)
	require.Equal(t, InviteCodeStatusInvalidated, oldCode.Status)
	require.Equal(t, InviteCodeStatusActive, newCode.Status)

	var activeCount int64
	require.NoError(t, DB.Model(&InviteCode{}).
		Where("user_id = ? AND status = ?", user.Id, InviteCodeStatusActive).
		Count(&activeCount).Error)
	require.Equal(t, int64(1), activeCount)
}

func TestRefreshInviteCode_ConcurrentSingleActiveInvariant_NilTx(t *testing.T) {
	initInviteCodeModelTestDBWithMaxOpenConns(t, 8)
	require.NoError(t, migrateDB())
	InitOptionMap()

	user := createInviteCodeOwnerForTest(t, "refresh_niltx_concurrent")
	var initial *InviteCode
	require.NoError(t, DB.Transaction(func(tx *gorm.DB) error {
		var err error
		initial, err = CreateInitialInviteCodeForUser(tx, user)
		return err
	}))
	require.NotNil(t, initial)

	var successCount int32
	var failCount int32
	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			_, _, err := RefreshInviteCode(nil, user.Id, true)
			if err == nil {
				atomic.AddInt32(&successCount, 1)
			} else {
				atomic.AddInt32(&failCount, 1)
			}
		}()
	}
	wg.Wait()

	require.Equal(t, int32(1), successCount)
	require.Equal(t, int32(1), failCount)

	var activeCount int64
	require.NoError(t, DB.Model(&InviteCode{}).
		Where("user_id = ? AND status = ?", user.Id, InviteCodeStatusActive).
		Count(&activeCount).Error)
	require.Equal(t, int64(1), activeCount)
}

func TestUpdateActiveInviteCodeRules_DoesNotOverwriteUsedCountUnderRace(t *testing.T) {
	initInviteCodeModelTestDBWithMaxOpenConns(t, 8)
	require.NoError(t, migrateDB())
	InitOptionMap()
	setInviteCodeTestOptions(t, map[string]string{
		"invite_code_max_uses_limit":  "10",
		"invite_code_max_expire_days": "365",
	})

	user := createInviteCodeOwnerForTest(t, "update_race")
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
			"max_uses":   3,
			"used_count": 0,
			"status":     InviteCodeStatusActive,
		}).Error)

	var updateErr error
	var consumeErr error
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		time.Sleep(5 * time.Millisecond)
		updateErr = DB.Transaction(func(tx *gorm.DB) error {
			_, err := UpdateActiveInviteCodeRules(tx, user.Id, 2, common.GetTimestamp()+int64(24*3600))
			return err
		})
	}()

	go func() {
		defer wg.Done()
		consumeErr = DB.Transaction(func(tx *gorm.DB) error {
			local := *code
			return ConsumeInviteCode(tx, &local, 930001, "password")
		})
	}()

	wg.Wait()
	require.NoError(t, consumeErr)
	require.NoError(t, updateErr)

	var refreshed InviteCode
	require.NoError(t, DB.First(&refreshed, "id = ?", code.Id).Error)
	require.Equal(t, 1, refreshed.UsedCount)
	require.Equal(t, 2, refreshed.MaxUses)
	require.Equal(t, InviteCodeStatusActive, refreshed.Status)

	require.NoError(t, DB.Model(&InviteCode{}).
		Where("id = ?", code.Id).
		UpdateColumns(map[string]any{
			"max_uses":   1,
			"used_count": 0,
			"status":     InviteCodeStatusActive,
		}).Error)

	var secondUpdateErr error
	var secondConsumeErr error
	wg = sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		time.Sleep(5 * time.Millisecond)
		secondUpdateErr = DB.Transaction(func(tx *gorm.DB) error {
			_, err := UpdateActiveInviteCodeRules(tx, user.Id, 1, common.GetTimestamp()+int64(24*3600))
			return err
		})
	}()
	go func() {
		defer wg.Done()
		secondConsumeErr = DB.Transaction(func(tx *gorm.DB) error {
			local := *code
			return ConsumeInviteCode(tx, &local, 930002, "password")
		})
	}()
	wg.Wait()
	require.NoError(t, secondConsumeErr)
	if secondUpdateErr != nil {
		require.True(
			t,
			errors.Is(secondUpdateErr, gorm.ErrRecordNotFound) || errors.Is(secondUpdateErr, ErrInviteCodeRuleInvalid),
			"unexpected update error: %v",
			secondUpdateErr,
		)
	}

	var exhausted InviteCode
	require.NoError(t, DB.First(&exhausted, "id = ?", code.Id).Error)
	require.Equal(t, 1, exhausted.UsedCount)
	require.Equal(t, 1, exhausted.MaxUses)
	require.Equal(t, InviteCodeStatusExhausted, exhausted.Status)
}
