package model

import (
	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
)

const (
	InviteCodeAuditEventCreate      = "create"
	InviteCodeAuditEventUpdateRules = "update_rules"
	InviteCodeAuditEventRefresh     = "refresh"
	InviteCodeAuditEventInvalidate  = "invalidate"
	InviteCodeAuditEventUse         = "use"
)

type InviteCodeAuditLog struct {
	Id int `json:"id"`

	InviteCodeId   int    `json:"invite_code_id" gorm:"type:int;not null;index"`
	UserId         int    `json:"user_id" gorm:"type:int;not null;index"`
	OperatorUserId int    `json:"operator_user_id" gorm:"type:int;not null;default:0;index"`
	EventType      string `json:"event_type" gorm:"type:varchar(32);not null;index"`

	BeforePayload string `json:"before_payload" gorm:"type:text"`
	AfterPayload  string `json:"after_payload" gorm:"type:text"`

	CreatedAt int64 `json:"created_at" gorm:"type:bigint"`
}

func (InviteCodeAuditLog) TableName() string {
	return "invite_code_audit_logs"
}

func (log *InviteCodeAuditLog) BeforeCreate(tx *gorm.DB) error {
	log.CreatedAt = common.GetTimestamp()
	return nil
}
