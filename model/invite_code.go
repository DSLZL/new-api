package model

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	InviteCodeStatusActive      = "active"
	InviteCodeStatusInvalidated = "invalidated"
	InviteCodeStatusExhausted   = "exhausted"
	InviteCodeStatusExpired     = "expired"

	inviteCodeSecondsPerDay        = int64(86400)
	inviteCodeRefreshHiddenReason  = "refresh_hidden"
	inviteCodeDefaultMaxUsesLimit  = 100
	inviteCodeDefaultMaxExpireDays = 365
	inviteCodeGenerateMaxAttempts  = 24
	inviteCodeDefaultLength        = 8
	inviteCodeMinLength            = 4
	inviteCodeMaxLength            = 10
)

type InviteCode struct {
	Id int `json:"id"`

	UserId int    `json:"user_id" gorm:"type:int;not null;index:idx_invite_codes_user_status,priority:1"`
	Code   string `json:"code" gorm:"type:varchar(32);not null;uniqueIndex"`

	Status string `json:"status" gorm:"type:varchar(16);not null;default:'active';index:idx_invite_codes_user_status,priority:2"`

	MaxUses   int `json:"max_uses" gorm:"type:int;not null;default:1"`
	UsedCount int `json:"used_count" gorm:"type:int;not null;default:0"`

	ExpiresAt int64 `json:"expires_at" gorm:"type:bigint;not null;default:0"`

	ActivatedAt      int64  `json:"activated_at" gorm:"type:bigint;not null;default:0"`
	InvalidatedAt    int64  `json:"invalidated_at" gorm:"type:bigint;not null;default:0"`
	InvalidatedReason string `json:"invalidated_reason" gorm:"type:varchar(64);not null;default:''"`

	CreatedAt int64 `json:"created_at" gorm:"type:bigint"`
	UpdatedAt int64 `json:"updated_at" gorm:"type:bigint"`
}

func (InviteCode) TableName() string {
	return "invite_codes"
}

func (code *InviteCode) normalizeAndValidateForWrite() error {
	code.Code = strings.ToUpper(strings.TrimSpace(code.Code))
	if code.Code == "" {
		return errors.New("invite code cannot be empty")
	}

	code.Status = strings.TrimSpace(code.Status)
	if code.Status == "" {
		code.Status = InviteCodeStatusActive
	}
	return nil
}

func (code *InviteCode) stampActiveActivatedAt(now int64) {
	if code.ActivatedAt == 0 && code.Status == InviteCodeStatusActive {
		code.ActivatedAt = now
	}
}

func (code *InviteCode) BeforeCreate(tx *gorm.DB) error {
	if err := code.normalizeAndValidateForWrite(); err != nil {
		return err
	}
	now := common.GetTimestamp()
	code.CreatedAt = now
	code.UpdatedAt = now
	code.stampActiveActivatedAt(now)
	return nil
}

func (code *InviteCode) BeforeUpdate(tx *gorm.DB) error {
	if err := code.normalizeAndValidateForWrite(); err != nil {
		return err
	}
	now := common.GetTimestamp()
	code.UpdatedAt = now
	code.stampActiveActivatedAt(now)
	return nil
}

var (
	ErrInviteCodeRuleInvalid = errors.New("invite code rule invalid")
	ErrInviteCodeExpired     = errors.New("invite code expired")
	ErrInviteCodeExhausted   = errors.New("invite code exhausted")
	inviteCodeUserLocks      sync.Map
)

func normalizeInviteCodeLength(length int) (int, error) {
	if length == 0 {
		return inviteCodeDefaultLength, nil
	}
	if length < inviteCodeMinLength || length > inviteCodeMaxLength {
		return 0, ErrInviteCodeRuleInvalid
	}
	return length, nil
}

type inviteCodeAuditPayload struct {
	ID               int    `json:"id"`
	Code             string `json:"code"`
	Status           string `json:"status"`
	MaxUses          int    `json:"max_uses"`
	UsedCount        int    `json:"used_count"`
	ExpiresAt        int64  `json:"expires_at"`
	ActivatedAt      int64  `json:"activated_at"`
	InvalidatedAt    int64  `json:"invalidated_at"`
	InvalidatedReason string `json:"invalidated_reason"`
}

func getInviteCodeDB(tx *gorm.DB) *gorm.DB {
	if tx != nil {
		return tx
	}
	return DB
}

func getInviteCodeOptionString(key, fallback string) string {
	common.OptionMapRWMutex.RLock()
	defer common.OptionMapRWMutex.RUnlock()
	if common.OptionMap == nil {
		return fallback
	}
	value, ok := common.OptionMap[key]
	if !ok {
		return fallback
	}
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fallback
	}
	return trimmed
}

func getInviteCodeOptionInt(key string, fallback int) int {
	return getInviteCodeOptionIntWithMap(key, fallback, nil)
}

func getInviteCodeOptionIntWithMap(key string, fallback int, optionMap map[string]string) int {
	if optionMap != nil {
		value, ok := optionMap[key]
		if !ok {
			return fallback
		}
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return fallback
		}
		parsed, err := strconv.Atoi(trimmed)
		if err != nil {
			return fallback
		}
		return parsed
	}

	value := getInviteCodeOptionString(key, "")
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func getInviteCodeOptionBool(key string, fallback bool) bool {
	value := strings.ToLower(getInviteCodeOptionString(key, ""))
	switch value {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	default:
		return fallback
	}
}

func getInviteCodeMaxUsesLimit() int {
	limit := getInviteCodeOptionInt("invite_code_max_uses_limit", inviteCodeDefaultMaxUsesLimit)
	if limit <= 0 {
		return inviteCodeDefaultMaxUsesLimit
	}
	return limit
}

func getInviteCodeMaxExpireDays() int {
	days := getInviteCodeOptionInt("invite_code_max_expire_days", inviteCodeDefaultMaxExpireDays)
	if days <= 0 {
		return inviteCodeDefaultMaxExpireDays
	}
	return days
}

func getInviteCodeDefaultMaxUses() int {
	maxUses := getInviteCodeOptionInt("invite_code_default_max_uses", 1)
	if maxUses <= 0 {
		maxUses = 1
	}
	limit := getInviteCodeMaxUsesLimit()
	if maxUses > limit {
		maxUses = limit
	}
	return maxUses
}

func getInviteCodeDefaultMaxExpireDays() int {
	expireDays := getInviteCodeOptionInt("invite_code_default_max_expire_days", 30)
	if expireDays < 0 {
		expireDays = 0
	}
	maxDays := getInviteCodeMaxExpireDays()
	if expireDays > maxDays {
		expireDays = maxDays
	}
	return expireDays
}

func getInviteCodeAuditEnabled() bool {
	return getInviteCodeOptionBool("invite_code_audit_enabled", false)
}

func normalizeInviteCode(raw string) string {
	return strings.ToUpper(strings.TrimSpace(raw))
}

func toInviteCodeAuditPayload(code *InviteCode) *inviteCodeAuditPayload {
	if code == nil {
		return nil
	}
	return &inviteCodeAuditPayload{
		ID:                code.Id,
		Code:              code.Code,
		Status:            code.Status,
		MaxUses:           code.MaxUses,
		UsedCount:         code.UsedCount,
		ExpiresAt:         code.ExpiresAt,
		ActivatedAt:       code.ActivatedAt,
		InvalidatedAt:     code.InvalidatedAt,
		InvalidatedReason: code.InvalidatedReason,
	}
}

func appendInviteCodeAudit(tx *gorm.DB, inviteCodeID, userID, operatorUserID int, eventType string, before, after any) error {
	if !getInviteCodeAuditEnabled() {
		return nil
	}

	beforeBytes, err := common.Marshal(before)
	if err != nil {
		return err
	}
	afterBytes, err := common.Marshal(after)
	if err != nil {
		return err
	}

	return tx.Create(&InviteCodeAuditLog{
		InviteCodeId:   inviteCodeID,
		UserId:         userID,
		OperatorUserId: operatorUserID,
		EventType:      eventType,
		BeforePayload:  string(beforeBytes),
		AfterPayload:   string(afterBytes),
	}).Error
}

func appendInviteCodeUsage(tx *gorm.DB, code *InviteCode, inviteeUserID int, registerType string) error {
	normalizedRegisterType := strings.TrimSpace(registerType)
	if normalizedRegisterType == "" {
		normalizedRegisterType = "password"
	}
	return tx.Create(&InviteCodeUsage{
		InviteCodeId:  code.Id,
		InviterUserId: code.UserId,
		InviteeUserId: inviteeUserID,
		RegisterType:  normalizedRegisterType,
	}).Error
}

func isInviteCodeDuplicateError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "duplicate") {
		return true
	}
	if strings.Contains(message, "unique constraint") {
		return true
	}
	if strings.Contains(message, "unique failed") {
		return true
	}
	return false
}

func getExpireAtByDays(days int, now int64) int64 {
	if days <= 0 {
		return 0
	}
	return now + int64(days)*inviteCodeSecondsPerDay
}

func updateUserAffCode(tx *gorm.DB, userID int, code string) error {
	return tx.Model(&User{}).Where("id = ?", userID).Update("aff_code", code).Error
}

func tryLockInviteCodeUser(userID int) (func(), bool) {
	locker, _ := inviteCodeUserLocks.LoadOrStore(userID, &sync.Mutex{})
	mutex := locker.(*sync.Mutex)
	if !mutex.TryLock() {
		return nil, false
	}
	return mutex.Unlock, true
}

func getInviteCodeBackfillDefaults() (int, int64) {
	defaultMaxUses := getInviteCodeDefaultMaxUses()
	if defaultMaxUses <= 0 {
		defaultMaxUses = 1
	}
	expiresAt := getExpireAtByDays(getInviteCodeDefaultMaxExpireDays(), common.GetTimestamp())
	return defaultMaxUses, expiresAt
}

func ensureNoActiveInviteCodeExists(tx *gorm.DB, userID int) error {
	var count int64
	if err := tx.Model(&InviteCode{}).
		Where("user_id = ? AND status = ?", userID, InviteCodeStatusActive).
		Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return fmt.Errorf("active invite code already exists")
	}
	return nil
}

func lockInviteCodeOwnerForUpdate(tx *gorm.DB, userID int) error {
	var owner User
	return tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Select("id", "aff_code").
		First(&owner, "id = ?", userID).Error
}

func createInitialInviteCodeForUserTx(tx *gorm.DB, user *User) (*InviteCode, error) {
	return createInitialInviteCodeForUserTxLocked(tx, user, inviteCodeDefaultLength)
}

func createInitialInviteCodeForUserTxLocked(tx *gorm.DB, user *User, length int) (*InviteCode, error) {
	if err := ensureNoActiveInviteCodeExists(tx, user.Id); err != nil {
		return nil, err
	}
	normalizedLength, err := normalizeInviteCodeLength(length)
	if err != nil {
		return nil, err
	}

	maxUses := getInviteCodeDefaultMaxUses()
	maxExpireDays := getInviteCodeMaxExpireDays()
	expireDays := getInviteCodeDefaultMaxExpireDays()
	if maxUses <= 0 || maxUses > getInviteCodeMaxUsesLimit() {
		return nil, ErrInviteCodeRuleInvalid
	}
	if expireDays < 0 || expireDays > maxExpireDays {
		return nil, ErrInviteCodeRuleInvalid
	}

	now := common.GetTimestamp()
	expiresAt := getExpireAtByDays(expireDays, now)
	for i := 0; i < inviteCodeGenerateMaxAttempts; i++ {
		candidate := normalizeInviteCode(common.GetRandomString(normalizedLength))
		item := &InviteCode{
			UserId:    user.Id,
			Code:      candidate,
			Status:    InviteCodeStatusActive,
			MaxUses:   maxUses,
			UsedCount: 0,
			ExpiresAt: expiresAt,
		}
		if err := tx.Create(item).Error; err != nil {
			if isInviteCodeDuplicateError(err) {
				continue
			}
			return nil, err
		}
		if err := updateUserAffCode(tx, user.Id, item.Code); err != nil {
			return nil, err
		}
		if err := appendInviteCodeAudit(tx, item.Id, item.UserId, item.UserId, InviteCodeAuditEventCreate, nil, toInviteCodeAuditPayload(item)); err != nil {
			return nil, err
		}
		return item, nil
	}
	return nil, ErrInviteCodeInvalid
}

func CreateInitialInviteCodeForUser(tx *gorm.DB, user *User) (*InviteCode, error) {
	if user == nil || user.Id <= 0 {
		return nil, ErrInviteCodeInvalid
	}

	db := getInviteCodeDB(tx)
	if tx != nil {
		if err := lockInviteCodeOwnerForUpdate(db, user.Id); err != nil {
			return nil, err
		}
		return createInitialInviteCodeForUserTxLocked(db, user, inviteCodeDefaultLength)
	}
	var created *InviteCode
	err := db.Transaction(func(inner *gorm.DB) error {
		if err := lockInviteCodeOwnerForUpdate(inner, user.Id); err != nil {
			return err
		}
		var innerErr error
		created, innerErr = createInitialInviteCodeForUserTxLocked(inner, user, inviteCodeDefaultLength)
		return innerErr
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

func createInviteCodeWithExplicitCode(tx *gorm.DB, userID int, explicitCode string) (*InviteCode, error) {
	code := normalizeInviteCode(explicitCode)
	if userID <= 0 || code == "" {
		return nil, ErrInviteCodeInvalid
	}

	defaultMaxUses, expiresAt := getInviteCodeBackfillDefaults()
	item := &InviteCode{
		UserId:    userID,
		Code:      code,
		Status:    InviteCodeStatusActive,
		MaxUses:   defaultMaxUses,
		UsedCount: 0,
		ExpiresAt: expiresAt,
	}
	if err := tx.Create(item).Error; err != nil {
		return nil, err
	}
	if err := updateUserAffCode(tx, userID, item.Code); err != nil {
		return nil, err
	}
	if err := appendInviteCodeAudit(tx, item.Id, item.UserId, item.UserId, InviteCodeAuditEventCreate, nil, toInviteCodeAuditPayload(item)); err != nil {
		return nil, err
	}
	return item, nil
}

func BackfillInviteCodeFromLegacyAffCode(tx *gorm.DB, userID int) (*InviteCode, error) {
	if userID <= 0 {
		return nil, ErrInviteCodeInvalid
	}
	db := getInviteCodeDB(tx)
	if tx == nil {
		var ensured *InviteCode
		err := db.Transaction(func(inner *gorm.DB) error {
			var innerErr error
			ensured, innerErr = BackfillInviteCodeFromLegacyAffCode(inner, userID)
			return innerErr
		})
		if err != nil {
			return nil, err
		}
		return ensured, nil
	}

	if err := lockInviteCodeOwnerForUpdate(db, userID); err != nil {
		return nil, err
	}

	var active InviteCode
	if err := db.Where("user_id = ? AND status = ?", userID, InviteCodeStatusActive).
		Order("id DESC").
		First(&active).Error; err == nil {
		return &active, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	var owner User
	if err := db.Select("id", "aff_code").First(&owner, "id = ?", userID).Error; err != nil {
		return nil, err
	}

	legacyCode := NormalizeAffCode(owner.AffCode)
	if legacyCode != "" {
		return createInviteCodeWithExplicitCode(db, owner.Id, legacyCode)
	}
	return CreateInitialInviteCodeForUser(db, &owner)
}

func backfillInviteCodesFromLegacyUsers(db *gorm.DB) error {
	if db == nil {
		db = DB
	}

	var users []User
	if err := db.Select("id", "aff_code").Where("aff_code <> ''").Find(&users).Error; err != nil {
		return err
	}
	for _, user := range users {
		if _, err := BackfillInviteCodeFromLegacyAffCode(db, user.Id); err != nil {
			return err
		}
	}
	return nil
}

func GetActiveInviteCodeByUserID(userID int) (*InviteCode, error) {
	if userID <= 0 {
		return nil, ErrInviteCodeInvalid
	}
	var code InviteCode
	err := DB.Where("user_id = ? AND status = ?", userID, InviteCodeStatusActive).
		Order("id DESC").
		First(&code).Error
	if err != nil {
		return nil, err
	}
	return &code, nil
}

func UpdateActiveInviteCodeRules(tx *gorm.DB, userID, maxUses int, expiresAt int64) (*InviteCode, error) {
	if userID <= 0 {
		return nil, ErrInviteCodeInvalid
	}

	limit := getInviteCodeMaxUsesLimit()
	if maxUses <= 0 || maxUses > limit {
		return nil, ErrInviteCodeRuleInvalid
	}
	maxExpireAt := common.GetTimestamp() + int64(getInviteCodeMaxExpireDays())*inviteCodeSecondsPerDay
	if expiresAt > 0 && expiresAt > maxExpireAt {
		return nil, ErrInviteCodeRuleInvalid
	}

	db := getInviteCodeDB(tx)
	var code InviteCode
	if err := db.Where("user_id = ? AND status = ?", userID, InviteCodeStatusActive).Order("id DESC").First(&code).Error; err != nil {
		return nil, err
	}
	if maxUses < code.UsedCount {
		return nil, ErrInviteCodeRuleInvalid
	}

	before := toInviteCodeAuditPayload(&code)
	now := common.GetTimestamp()

	update := db.Session(&gorm.Session{SkipHooks: true}).
		Model(&InviteCode{}).
		Where("id = ? AND user_id = ? AND status = ?", code.Id, userID, InviteCodeStatusActive).
		Where("used_count <= ?", maxUses).
		Updates(map[string]any{
			"max_uses":   maxUses,
			"expires_at": expiresAt,
			"status": gorm.Expr(
				"CASE WHEN ? > 0 AND ? <= ? THEN ? WHEN used_count >= ? THEN ? ELSE ? END",
				expiresAt, expiresAt, now, InviteCodeStatusExpired,
				maxUses, InviteCodeStatusExhausted,
				InviteCodeStatusActive,
			),
			"updated_at": now,
		})
	if update.Error != nil {
		return nil, update.Error
	}
	if update.RowsAffected == 0 {
		return nil, ErrInviteCodeRuleInvalid
	}

	var updated InviteCode
	if err := db.First(&updated, "id = ?", code.Id).Error; err != nil {
		return nil, err
	}
	if err := appendInviteCodeAudit(db, updated.Id, updated.UserId, userID, InviteCodeAuditEventUpdateRules, before, toInviteCodeAuditPayload(&updated)); err != nil {
		return nil, err
	}
	return &updated, nil
}

func refreshInviteCodeTx(tx *gorm.DB, userID int, preserveHistory bool, length int) (*InviteCode, *InviteCode, error) {
	if userID <= 0 {
		return nil, nil, ErrInviteCodeInvalid
	}
	normalizedLength, err := normalizeInviteCodeLength(length)
	if err != nil {
		return nil, nil, err
	}
	db := getInviteCodeDB(tx)
	if err := lockInviteCodeOwnerForUpdate(db, userID); err != nil {
		return nil, nil, err
	}

	var oldCode InviteCode
	if err := db.Where("user_id = ? AND status = ?", userID, InviteCodeStatusActive).Order("id DESC").First(&oldCode).Error; err != nil {
		return nil, nil, err
	}
	before := toInviteCodeAuditPayload(&oldCode)
	now := common.GetTimestamp()
	invalidatedReason := ""
	if !preserveHistory {
		invalidatedReason = inviteCodeRefreshHiddenReason
	}
	update := db.Session(&gorm.Session{SkipHooks: true}).
		Model(&InviteCode{}).
		Where("id = ? AND user_id = ? AND status = ?", oldCode.Id, userID, InviteCodeStatusActive).
		Updates(map[string]any{
			"status":             InviteCodeStatusInvalidated,
			"invalidated_at":     now,
			"invalidated_reason": invalidatedReason,
			"updated_at":         now,
		})
	if update.Error != nil {
		return nil, nil, update.Error
	}
	if update.RowsAffected == 0 {
		return nil, nil, ErrInviteCodeInvalid
	}
	if err := db.First(&oldCode, "id = ?", oldCode.Id).Error; err != nil {
		return nil, nil, err
	}

	newCode, err := createInitialInviteCodeForUserTxLocked(db, &User{Id: userID}, normalizedLength)
	if err != nil {
		return nil, nil, err
	}

	if err := appendInviteCodeAudit(db, oldCode.Id, oldCode.UserId, userID, InviteCodeAuditEventRefresh, before, toInviteCodeAuditPayload(&oldCode)); err != nil {
		return nil, nil, err
	}
	return &oldCode, newCode, nil
}

func RefreshInviteCode(tx *gorm.DB, userID int, preserveHistory bool, length int) (*InviteCode, *InviteCode, error) {
	if userID <= 0 {
		return nil, nil, ErrInviteCodeInvalid
	}
	unlock, locked := tryLockInviteCodeUser(userID)
	if !locked {
		return nil, nil, ErrInviteCodeInvalid
	}
	defer unlock()

	if tx == nil {
		var oldCode *InviteCode
		var newCode *InviteCode
		err := DB.Transaction(func(inner *gorm.DB) error {
			var innerErr error
			oldCode, newCode, innerErr = refreshInviteCodeTx(inner, userID, preserveHistory, length)
			return innerErr
		})
		if err != nil {
			return nil, nil, err
		}
		return oldCode, newCode, nil
	}
	return refreshInviteCodeTx(tx, userID, preserveHistory, length)
}

func resolveActiveInviteCodeWithDB(tx *gorm.DB, raw string) (*InviteCode, error) {
	code := normalizeInviteCode(raw)
	if code == "" {
		return nil, ErrInviteCodeRequired
	}

	db := getInviteCodeDB(tx)
	var item InviteCode
	err := db.Where("code = ? AND status = ?", code, InviteCodeStatusActive).First(&item).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInviteCodeInvalid
		}
		return nil, err
	}

	now := common.GetTimestamp()
	if item.ExpiresAt > 0 && item.ExpiresAt <= now {
		return nil, ErrInviteCodeExpired
	}
	if item.UsedCount >= item.MaxUses {
		return nil, ErrInviteCodeExhausted
	}
	return &item, nil
}

func ResolveActiveInviteCode(raw string) (*InviteCode, error) {
	return resolveActiveInviteCodeWithDB(nil, raw)
}

func ResolveActiveInviteCodeWithTx(tx *gorm.DB, raw string) (*InviteCode, error) {
	return resolveActiveInviteCodeWithDB(tx, raw)
}

func ConsumeInviteCode(tx *gorm.DB, code *InviteCode, inviteeUserID int, registerType string) error {
	if code == nil || code.Id <= 0 {
		return ErrInviteCodeInvalid
	}
	db := getInviteCodeDB(tx)
	now := common.GetTimestamp()

	before := toInviteCodeAuditPayload(code)
	update := db.Session(&gorm.Session{SkipHooks: true}).
		Model(&InviteCode{}).
		Where("id = ? AND status = ?", code.Id, InviteCodeStatusActive).
		Where("expires_at = 0 OR expires_at > ?", now).
		Where("used_count < max_uses").
		Updates(map[string]any{
			"used_count": gorm.Expr("used_count + 1"),
			"status":     gorm.Expr("CASE WHEN used_count + 1 >= max_uses THEN ? ELSE status END", InviteCodeStatusExhausted),
			"updated_at": now,
		})
	if update.Error != nil {
		return update.Error
	}
	if update.RowsAffected == 0 {
		var latest InviteCode
		if err := db.First(&latest, "id = ?", code.Id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrInviteCodeInvalid
			}
			return err
		}
		if latest.ExpiresAt > 0 && latest.ExpiresAt <= now {
			return ErrInviteCodeExpired
		}
		if latest.UsedCount >= latest.MaxUses || latest.Status == InviteCodeStatusExhausted {
			return ErrInviteCodeExhausted
		}
		return ErrInviteCodeInvalid
	}

	var updated InviteCode
	if err := db.First(&updated, "id = ?", code.Id).Error; err != nil {
		return err
	}
	if err := appendInviteCodeUsage(db, &updated, inviteeUserID, registerType); err != nil {
		return err
	}
	if err := appendInviteCodeAudit(db, updated.Id, updated.UserId, inviteeUserID, InviteCodeAuditEventUse, before, toInviteCodeAuditPayload(&updated)); err != nil {
		return err
	}
	*code = updated
	return nil
}
