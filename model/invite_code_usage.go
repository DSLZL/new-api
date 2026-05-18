package model

import (
	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
)

type InviteCodeUsage struct {
	Id int `json:"id"`

	InviteCodeId  int    `json:"invite_code_id" gorm:"type:int;not null;index"`
	InviterUserId int    `json:"inviter_user_id" gorm:"type:int;not null;index"`
	InviteeUserId int    `json:"invitee_user_id" gorm:"type:int;not null;index"`
	RegisterType  string `json:"register_type" gorm:"type:varchar(16);not null;default:'password';index"`

	CreatedAt int64 `json:"created_at" gorm:"type:bigint"`
}

func (InviteCodeUsage) TableName() string {
	return "invite_code_usages"
}

func (usage *InviteCodeUsage) BeforeCreate(tx *gorm.DB) error {
	usage.CreatedAt = common.GetTimestamp()
	return nil
}
