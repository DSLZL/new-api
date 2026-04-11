package model

import (
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func UpsertTemporalProfile(profile *UserTemporalProfile) error {
	if profile == nil || profile.UserID <= 0 || profile.ProfileDate == "" {
		return nil
	}

	var existing UserTemporalProfile
	err := DB.Where("user_id = ? AND profile_date = ?", profile.UserID, profile.ProfileDate).
		First(&existing).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return DB.Create(profile).Error
		}
		return err
	}

	updates := UserTemporalProfile{
		Timezone:       profile.Timezone,
		ActivityBins:   profile.ActivityBins,
		PeakBin:        profile.PeakBin,
		SampleCount:    profile.SampleCount,
		LastActivityAt: profile.LastActivityAt,
	}

	return DB.Model(&existing).
		Select("Timezone", "ActivityBins", "PeakBin", "SampleCount", "LastActivityAt", "UpdatedAt").
		Updates(&updates).Error
}

func GetLatestTemporalProfile(userID int) *UserTemporalProfile {
	if userID <= 0 {
		return nil
	}
	var profile UserTemporalProfile
	if err := DB.Where("user_id = ?", userID).
		Order("profile_date DESC").
		Order("last_activity_at DESC").
		First(&profile).Error; err != nil {
		return nil
	}
	return &profile
}

func ReplaceUserSessions(userID int, sessions []UserSession) error {
	if userID <= 0 {
		return nil
	}

	tx := DB.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	if err := tx.Where("user_id = ?", userID).Delete(&UserSession{}).Error; err != nil {
		tx.Rollback()
		return err
	}
	if len(sessions) > 0 {
		if err := tx.Create(&sessions).Error; err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit().Error
}

func GetLatestUserSessions(userID int, limit int) []UserSession {
	if userID <= 0 {
		return nil
	}
	var sessions []UserSession
	query := DB.Where("user_id = ?", userID).Order("started_at DESC")
	if limit > 0 {
		query = query.Limit(limit)
	}
	query.Find(&sessions)
	return sessions
}

func EnsureUserSessionUniqueIndex(db *gorm.DB) error {
	if db == nil {
		return nil
	}
	const indexName = "uk_us_user_session"
	if db.Migrator().HasIndex(&UserSession{}, indexName) {
		return nil
	}
	if err := normalizeUserSessionIDsForUniqueIndex(db); err != nil {
		return err
	}
	return db.Exec("CREATE UNIQUE INDEX uk_us_user_session ON user_sessions(user_id, session_id)").Error
}

func normalizeUserSessionIDsForUniqueIndex(db *gorm.DB) error {
	tx := db.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	var sessions []UserSession
	if err := tx.Order("id ASC").Find(&sessions).Error; err != nil {
		tx.Rollback()
		return err
	}

	seen := make(map[string]struct{}, len(sessions))
	for _, session := range sessions {
		normalized := strings.TrimSpace(session.SessionID)
		if normalized == "" {
			normalized = fmt.Sprintf("legacy:%d:%d", session.UserID, session.ID)
		}
		key := fmt.Sprintf("%d:%s", session.UserID, normalized)
		if _, ok := seen[key]; ok {
			normalized = fmt.Sprintf("dup:%d:%d", session.UserID, session.ID)
			key = fmt.Sprintf("%d:%s", session.UserID, normalized)
		}
		if normalized != session.SessionID {
			if err := tx.Model(&UserSession{}).Where("id = ?", session.ID).Update("session_id", normalized).Error; err != nil {
				tx.Rollback()
				return err
			}
		}
		seen[key] = struct{}{}
	}

	return tx.Commit().Error
}

const UserSessionReservedPrefixPrecompute = "pc:"

func UpsertUserSession(session *UserSession) error {
	return upsertUserSessionWithDB(DB, session)
}

func upsertUserSessionWithDB(db *gorm.DB, session *UserSession) error {
	if session == nil || session.UserID <= 0 {
		return nil
	}

	session.Source = strings.TrimSpace(session.Source)
	if session.Source == "" {
		session.Source = "fingerprint"
	}

	session.SessionID = strings.TrimSpace(session.SessionID)
	if session.Source != "precompute" && strings.HasPrefix(session.SessionID, UserSessionReservedPrefixPrecompute) {
		session.SessionID = ""
	}
	if session.SessionID == "" {
		session.SessionID = fmt.Sprintf("adhoc:%d:%d:%d", session.UserID, session.StartedAt.UTC().UnixNano(), session.EndedAt.UTC().UnixNano())
	}

	upsert := *session
	return db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "user_id"}, {Name: "session_id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"device_key",
			"ip_address",
			"started_at",
			"ended_at",
			"duration_seconds",
			"event_count",
			"is_burst",
			"updated_at",
		}),
	}).Create(&upsert).Error
}

func ReplaceUserSessionsBySource(userID int, source string, sessions []UserSession) error {
	if userID <= 0 {
		return nil
	}
	trimmedSource := strings.TrimSpace(source)
	if trimmedSource == "" {
		return nil
	}

	tx := DB.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	if err := tx.Where("user_id = ? AND source = ?", userID, trimmedSource).Delete(&UserSession{}).Error; err != nil {
		tx.Rollback()
		return err
	}
	if len(sessions) > 0 {
		for i := range sessions {
			sessions[i].UserID = userID
			sessions[i].Source = trimmedSource
		}
		if err := tx.Create(&sessions).Error; err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit().Error
}
