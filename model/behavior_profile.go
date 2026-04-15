package model

import (
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// KeystrokeProfile 用户打字节奏画像（仅保存统计特征，不保存按键内容）。
type KeystrokeProfile struct {
	ID int64 `json:"id" gorm:"primaryKey;autoIncrement"`

	UserID int `json:"user_id" gorm:"not null;index:idx_keystroke_user_updated,priority:1;uniqueIndex:uk_keystroke_user"`

	AvgHoldTime   float64 `json:"avg_hold_time" gorm:"default:0"`
	StdHoldTime   float64 `json:"std_hold_time" gorm:"default:0"`
	AvgFlightTime float64 `json:"avg_flight_time" gorm:"default:0"`
	StdFlightTime float64 `json:"std_flight_time" gorm:"default:0"`
	TypingSpeed   float64 `json:"typing_speed" gorm:"default:0"`
	DigraphData   string  `json:"digraph_data" gorm:"type:text;default:'[]'"`
	SampleCount   int     `json:"sample_count" gorm:"default:0"`

	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time `json:"updated_at" gorm:"autoUpdateTime;index:idx_keystroke_user_updated,priority:2"`
}

func (KeystrokeProfile) TableName() string {
	return "keystroke_profiles"
}

func UpsertKeystrokeProfile(profile *KeystrokeProfile) error {
	return upsertKeystrokeProfileWithDB(DB, profile)
}

func upsertKeystrokeProfileWithDB(db *gorm.DB, profile *KeystrokeProfile) error {
	if profile == nil || profile.UserID <= 0 {
		return nil
	}

	normalizedDigraphData := profile.DigraphData
	if normalizedDigraphData == "" {
		normalizedDigraphData = "[]"
	}

	upsert := KeystrokeProfile{
		UserID:        profile.UserID,
		AvgHoldTime:   profile.AvgHoldTime,
		StdHoldTime:   profile.StdHoldTime,
		AvgFlightTime: profile.AvgFlightTime,
		StdFlightTime: profile.StdFlightTime,
		TypingSpeed:   profile.TypingSpeed,
		DigraphData:   normalizedDigraphData,
		SampleCount:   profile.SampleCount,
	}

	return db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "user_id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"avg_hold_time",
			"std_hold_time",
			"avg_flight_time",
			"std_flight_time",
			"typing_speed",
			"digraph_data",
			"sample_count",
			"updated_at",
		}),
	}).Create(&upsert).Error
}

func GetLatestKeystrokeProfile(userID int) *KeystrokeProfile {
	if userID <= 0 {
		return nil
	}
	var profile KeystrokeProfile
	result := DB.Where("user_id = ?", userID).
		Order("updated_at DESC").
		Limit(1).
		Find(&profile)
	if result.Error != nil || result.RowsAffected == 0 {
		return nil
	}
	return &profile
}

// MouseProfile 用户鼠标行为画像（仅保存统计特征，不保存原始坐标）。
type MouseProfile struct {
	ID int64 `json:"id" gorm:"primaryKey;autoIncrement"`

	UserID int `json:"user_id" gorm:"not null;index:idx_mouse_user_updated,priority:1;uniqueIndex:uk_mouse_user"`

	AvgSpeed            float64 `json:"avg_speed" gorm:"default:0"`
	MaxSpeed            float64 `json:"max_speed" gorm:"default:0"`
	SpeedStd            float64 `json:"speed_std" gorm:"default:0"`
	AvgAcceleration     float64 `json:"avg_acceleration" gorm:"default:0"`
	AccStd              float64 `json:"acc_std" gorm:"default:0"`
	DirectionChangeRate float64 `json:"direction_change_rate" gorm:"default:0"`
	AvgScrollDelta      float64 `json:"avg_scroll_delta" gorm:"default:0"`
	ScrollDeltaMode     int     `json:"scroll_delta_mode" gorm:"default:0"`
	ClickDistribution   string  `json:"click_distribution" gorm:"type:text;default:'{}'"`
	SampleCount         int     `json:"sample_count" gorm:"default:0"`

	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time `json:"updated_at" gorm:"autoUpdateTime;index:idx_mouse_user_updated,priority:2"`
}

func (MouseProfile) TableName() string {
	return "mouse_profiles"
}

func UpsertMouseProfile(profile *MouseProfile) error {
	return upsertMouseProfileWithDB(DB, profile)
}

func upsertMouseProfileWithDB(db *gorm.DB, profile *MouseProfile) error {
	if profile == nil || profile.UserID <= 0 {
		return nil
	}

	normalizedClickDistribution := profile.ClickDistribution
	if normalizedClickDistribution == "" {
		normalizedClickDistribution = "{}"
	}

	upsert := MouseProfile{
		UserID:              profile.UserID,
		AvgSpeed:            profile.AvgSpeed,
		MaxSpeed:            profile.MaxSpeed,
		SpeedStd:            profile.SpeedStd,
		AvgAcceleration:     profile.AvgAcceleration,
		AccStd:              profile.AccStd,
		DirectionChangeRate: profile.DirectionChangeRate,
		AvgScrollDelta:      profile.AvgScrollDelta,
		ScrollDeltaMode:     profile.ScrollDeltaMode,
		ClickDistribution:   normalizedClickDistribution,
		SampleCount:         profile.SampleCount,
	}

	return db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "user_id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"avg_speed",
			"max_speed",
			"speed_std",
			"avg_acceleration",
			"acc_std",
			"direction_change_rate",
			"avg_scroll_delta",
			"scroll_delta_mode",
			"click_distribution",
			"sample_count",
			"updated_at",
		}),
	}).Create(&upsert).Error
}

func UpsertBehaviorProfilesAtomic(keystroke *KeystrokeProfile, mouse *MouseProfile) error {
	return DB.Transaction(func(tx *gorm.DB) error {
		return upsertBehaviorProfilesAtomicWithDB(tx, keystroke, mouse)
	})
}

func upsertBehaviorProfilesAtomicWithDB(db *gorm.DB, keystroke *KeystrokeProfile, mouse *MouseProfile) error {
	if err := upsertKeystrokeProfileWithDB(db, keystroke); err != nil {
		return err
	}
	if err := upsertMouseProfileWithDB(db, mouse); err != nil {
		return err
	}
	return nil
}

func GetLatestMouseProfile(userID int) *MouseProfile {
	if userID <= 0 {
		return nil
	}
	var profile MouseProfile
	result := DB.Where("user_id = ?", userID).
		Order("updated_at DESC").
		Limit(1).
		Find(&profile)
	if result.Error != nil || result.RowsAffected == 0 {
		return nil
	}
	return &profile
}

func DeleteOldKeystrokeProfiles(before time.Time) (int64, error) {
	result := DB.Where("updated_at < ?", before).Delete(&KeystrokeProfile{})
	if result.Error != nil {
		return 0, result.Error
	}
	return result.RowsAffected, nil
}

func DeleteOldMouseProfiles(before time.Time) (int64, error) {
	result := DB.Where("updated_at < ?", before).Delete(&MouseProfile{})
	if result.Error != nil {
		return 0, result.Error
	}
	return result.RowsAffected, nil
}
