package service

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func setupUserRankingServiceTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	oldDB := model.DB
	oldLOGDB := model.LOG_DB

	common.UsingSQLite = true
	common.UsingMySQL = false
	common.UsingPostgreSQL = false
	common.RedisEnabled = false

	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)

	model.DB = db
	model.LOG_DB = db
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.Log{}, &model.Option{}, &model.UserRankingSnapshot{}))

	t.Cleanup(func() {
		model.DB = oldDB
		model.LOG_DB = oldLOGDB
		sqlDB, err := db.DB()
		if err == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

func setUserRankingVisibility(t *testing.T, visibility UserRankingVisibility) {
	t.Helper()
	common.OptionMapRWMutex.Lock()
	if common.OptionMap == nil {
		common.OptionMap = map[string]string{}
	}
	common.OptionMap[userRankingVisibilityOptionKey] = string(visibility)
	common.OptionMapRWMutex.Unlock()
	InvalidateUserRankingCache()
}

func mustCreateUser(t *testing.T, db *gorm.DB, u model.User) model.User {
	t.Helper()
	if strings.TrimSpace(u.AffCode) == "" {
		u.AffCode = fmt.Sprintf("aff-%s-%s", strings.ReplaceAll(t.Name(), "/", "_"), u.Username)
	}
	require.NoError(t, db.Create(&u).Error)
	return u
}

func TestGetUserRankingsSnapshot_BalanceOrder(t *testing.T) {
	db := setupUserRankingServiceTestDB(t)
	setUserRankingVisibility(t, UserRankingVisibilityPublic)

	u1 := mustCreateUser(t, db, model.User{Username: "u1", DisplayName: "U1", Quota: 200, Status: common.UserStatusEnabled, Role: common.RoleCommonUser})
	u2 := mustCreateUser(t, db, model.User{Username: "u2", DisplayName: "U2", Quota: 500, Status: common.UserStatusEnabled, Role: common.RoleCommonUser})

	resp, err := GetUserRankingsSnapshot(string(UserRankingMetricBalance), string(UserRankingPeriodDaily), "")
	require.NoError(t, err)
	require.Equal(t, UserRankingPeriodTotal, resp.Period)
	require.Len(t, resp.Items, 2)
	require.Equal(t, u2.Id, resp.Items[0].UserId)
	require.Equal(t, int64(500), resp.Items[0].Value)
	require.Equal(t, u1.Id, resp.Items[1].UserId)
}

func TestGetUserRankingsSnapshot_InviteTotalAndDaily(t *testing.T) {
	db := setupUserRankingServiceTestDB(t)
	setUserRankingVisibility(t, UserRankingVisibilityPublic)

	inviter := mustCreateUser(t, db, model.User{
		Username:    "inviter",
		DisplayName: "Inviter",
		AffCount:    7,
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
	})
	other := mustCreateUser(t, db, model.User{
		Username:    "other",
		DisplayName: "Other",
		AffCount:    3,
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
	})

	now := time.Now()
	start, end := currentDayRange(now)
	require.NoError(t, db.Create(&model.User{
		Username:    "invitee1",
		DisplayName: "Invitee1",
		AffCode:     "aff-invitee1",
		InviterId:   inviter.Id,
		CreatedAt:   start + 10,
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
	}).Error)
	require.NoError(t, db.Create(&model.User{
		Username:    "invitee2",
		DisplayName: "Invitee2",
		AffCode:     "aff-invitee2",
		InviterId:   inviter.Id,
		CreatedAt:   start + 20,
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
	}).Error)
	require.NoError(t, db.Create(&model.User{
		Username:    "invitee3",
		DisplayName: "Invitee3",
		AffCode:     "aff-invitee3",
		InviterId:   other.Id,
		CreatedAt:   end - 1,
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
	}).Error)
	require.NoError(t, db.Create(&model.User{
		Username:    "invitee4",
		DisplayName: "Invitee4",
		AffCode:     "aff-invitee4",
		InviterId:   other.Id,
		CreatedAt:   end + 10,
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
	}).Error)

	totalResp, err := GetUserRankingsSnapshot(string(UserRankingMetricInvites), string(UserRankingPeriodTotal), "")
	require.NoError(t, err)
	require.Len(t, totalResp.Items, 2)
	require.Equal(t, inviter.Id, totalResp.Items[0].UserId)
	require.Equal(t, int64(7), totalResp.Items[0].Value)

	dailyResp, err := GetUserRankingsSnapshot(string(UserRankingMetricInvites), string(UserRankingPeriodDaily), "")
	require.NoError(t, err)
	require.Len(t, dailyResp.Items, 2)
	require.Equal(t, inviter.Id, dailyResp.Items[0].UserId)
	require.Equal(t, int64(2), dailyResp.Items[0].Value)
	require.Equal(t, other.Id, dailyResp.Items[1].UserId)
	require.Equal(t, int64(1), dailyResp.Items[1].Value)
}

func TestGetUserRankingsSnapshot_ConsumptionTotalAndDaily(t *testing.T) {
	db := setupUserRankingServiceTestDB(t)
	setUserRankingVisibility(t, UserRankingVisibilityPublic)

	u1 := mustCreateUser(t, db, model.User{Username: "u1", DisplayName: "U1", UsedQuota: 800, Status: common.UserStatusEnabled, Role: common.RoleCommonUser})
	u2 := mustCreateUser(t, db, model.User{Username: "u2", DisplayName: "U2", UsedQuota: 1200, Status: common.UserStatusEnabled, Role: common.RoleCommonUser})

	now := time.Now()
	start, end := currentDayRange(now)
	logs := []model.Log{
		{UserId: u1.Id, Username: u1.Username, Type: model.LogTypeConsume, Quota: 100, CreatedAt: start + 1},
		{UserId: u1.Id, Username: u1.Username, Type: model.LogTypeConsume, Quota: 150, CreatedAt: start + 2},
		{UserId: u2.Id, Username: u2.Username, Type: model.LogTypeConsume, Quota: 400, CreatedAt: start + 3},
		{UserId: u2.Id, Username: u2.Username, Type: model.LogTypeTopup, Quota: 999, CreatedAt: start + 4},
		{UserId: u2.Id, Username: u2.Username, Type: model.LogTypeConsume, Quota: 1000, CreatedAt: end + 5},
	}
	require.NoError(t, db.Create(&logs).Error)

	totalResp, err := GetUserRankingsSnapshot(string(UserRankingMetricConsumption), string(UserRankingPeriodTotal), "")
	require.NoError(t, err)
	require.Len(t, totalResp.Items, 2)
	require.Equal(t, u2.Id, totalResp.Items[0].UserId)
	require.Equal(t, int64(1200), totalResp.Items[0].Value)

	dailyResp, err := GetUserRankingsSnapshot(string(UserRankingMetricConsumption), string(UserRankingPeriodDaily), "")
	require.NoError(t, err)
	require.Len(t, dailyResp.Items, 2)
	require.Equal(t, u2.Id, dailyResp.Items[0].UserId)
	require.Equal(t, int64(400), dailyResp.Items[0].Value)
	require.Equal(t, u1.Id, dailyResp.Items[1].UserId)
	require.Equal(t, int64(250), dailyResp.Items[1].Value)
}

func TestGetUserRankingsSnapshot_InvalidMetricAndPeriod(t *testing.T) {
	setupUserRankingServiceTestDB(t)
	setUserRankingVisibility(t, UserRankingVisibilityPublic)

	_, err := GetUserRankingsSnapshot("bad-metric", "daily", "")
	require.Error(t, err)

	_, err = GetUserRankingsSnapshot(string(UserRankingMetricInvites), "bad-period", "")
	require.Error(t, err)

	_, err = GetUserRankingsSnapshot(string(UserRankingMetricInvites), string(UserRankingPeriodDaily), "2026-13-01")
	require.Error(t, err)
}

func TestGetUserRankingsSnapshot_CacheAndInvalidate(t *testing.T) {
	db := setupUserRankingServiceTestDB(t)
	setUserRankingVisibility(t, UserRankingVisibilityPublic)

	u := mustCreateUser(t, db, model.User{Username: "u1", DisplayName: "U1", Quota: 100, Status: common.UserStatusEnabled, Role: common.RoleCommonUser})

	resp1, err := GetUserRankingsSnapshot(string(UserRankingMetricBalance), string(UserRankingPeriodTotal), "")
	require.NoError(t, err)
	require.Len(t, resp1.Items, 1)
	require.Equal(t, int64(100), resp1.Items[0].Value)

	require.NoError(t, db.Model(&model.User{}).Where("id = ?", u.Id).Update("quota", 300).Error)

	resp2, err := GetUserRankingsSnapshot(string(UserRankingMetricBalance), string(UserRankingPeriodTotal), "")
	require.NoError(t, err)
	require.Len(t, resp2.Items, 1)
	require.Equal(t, int64(100), resp2.Items[0].Value)

	InvalidateUserRankingCache()
	resp3, err := GetUserRankingsSnapshot(string(UserRankingMetricBalance), string(UserRankingPeriodTotal), "")
	require.NoError(t, err)
	require.Equal(t, int64(300), resp3.Items[0].Value)
}

func TestGetUserRankingsSnapshot_HistoryDateSnapshotPersistAndReuse(t *testing.T) {
	db := setupUserRankingServiceTestDB(t)
	setUserRankingVisibility(t, UserRankingVisibilityPublic)

	u1 := mustCreateUser(t, db, model.User{Username: "u1", DisplayName: "U1", Quota: 200, Status: common.UserStatusEnabled, Role: common.RoleCommonUser})
	u2 := mustCreateUser(t, db, model.User{Username: "u2", DisplayName: "U2", Quota: 500, Status: common.UserStatusEnabled, Role: common.RoleCommonUser})

	date := "2024-01-02"
	require.NoError(t, model.SaveUserRankingSnapshot(date, string(UserRankingMetricBalance), string(UserRankingPeriodTotal), []model.UserRankingValueRow{
		{UserId: u2.Id, Username: u2.Username, DisplayName: u2.DisplayName, Value: 500},
		{UserId: u1.Id, Username: u1.Username, DisplayName: u1.DisplayName, Value: 200},
	}, 1704153600))

	resp1, err := GetUserRankingsSnapshot(string(UserRankingMetricBalance), string(UserRankingPeriodTotal), date)
	require.NoError(t, err)
	require.Equal(t, date, resp1.Date)
	require.Len(t, resp1.Items, 2)
	require.Equal(t, u2.Id, resp1.Items[0].UserId)
	require.Equal(t, int64(500), resp1.Items[0].Value)
	require.Equal(t, int64(1704153600), resp1.UpdatedAt)

	var count int64
	require.NoError(t, db.Model(&model.UserRankingSnapshot{}).
		Where("snapshot_date = ? AND metric = ? AND period = ?", date, string(UserRankingMetricBalance), string(UserRankingPeriodTotal)).
		Count(&count).Error)
	require.Equal(t, int64(2), count)

	require.NoError(t, db.Model(&model.User{}).Where("id = ?", u2.Id).Update("quota", 50).Error)
	resp2, err := GetUserRankingsSnapshot(string(UserRankingMetricBalance), string(UserRankingPeriodTotal), date)
	require.NoError(t, err)
	require.Equal(t, int64(500), resp2.Items[0].Value)
	require.Equal(t, resp1.UpdatedAt, resp2.UpdatedAt)

	InvalidateUserRankingCache()
	resp3, err := GetUserRankingsSnapshot(string(UserRankingMetricBalance), string(UserRankingPeriodTotal), date)
	require.NoError(t, err)
	require.Equal(t, int64(500), resp3.Items[0].Value)
	require.Equal(t, resp1.UpdatedAt, resp3.UpdatedAt)
	require.Equal(t, u1.Id, resp3.Items[1].UserId)
}

func TestGetUserRankingsSnapshot_HistoryDateWithoutSnapshotReturnsEmpty(t *testing.T) {
	db := setupUserRankingServiceTestDB(t)
	setUserRankingVisibility(t, UserRankingVisibilityPublic)

	_ = mustCreateUser(t, db, model.User{Username: "u1", DisplayName: "U1", Quota: 900, Status: common.UserStatusEnabled, Role: common.RoleCommonUser})

	resp, err := GetUserRankingsSnapshot(string(UserRankingMetricBalance), string(UserRankingPeriodTotal), "2023-01-02")
	require.NoError(t, err)
	require.Equal(t, "2023-01-02", resp.Date)
	require.Len(t, resp.Items, 0)

	var count int64
	require.NoError(t, db.Model(&model.UserRankingSnapshot{}).
		Where("snapshot_date = ? AND metric = ? AND period = ?", "2023-01-02", string(UserRankingMetricBalance), string(UserRankingPeriodTotal)).
		Count(&count).Error)
	require.Equal(t, int64(0), count)
}

func TestDurationUntilNextLocalMidnight(t *testing.T) {
	loc := time.FixedZone("UTC+8", 8*3600)
	now := time.Date(2026, 5, 10, 23, 59, 30, 0, loc)
	wait := durationUntilNextLocalMidnight(now)
	require.Equal(t, 30*time.Second, wait)

	now2 := time.Date(2026, 5, 10, 0, 0, 0, 0, loc)
	wait2 := durationUntilNextLocalMidnight(now2)
	require.Equal(t, 24*time.Hour, wait2)
}

func TestRunUserRankingDailySnapshotOnce_DailyMetricsPersisted(t *testing.T) {
	db := setupUserRankingServiceTestDB(t)
	setUserRankingVisibility(t, UserRankingVisibilityPublic)
	InvalidateUserRankingCache()

	u1 := mustCreateUser(t, db, model.User{
		Username:    "daily_u1",
		DisplayName: "Daily U1",
		Quota:       300,
		UsedQuota:   410,
		AffCount:    5,
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
	})
	u2 := mustCreateUser(t, db, model.User{
		Username:    "daily_u2",
		DisplayName: "Daily U2",
		Quota:       200,
		UsedQuota:   260,
		AffCount:    3,
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
	})

	base := time.Date(2026, 5, 11, 0, 0, 5, 0, beijingLocation())
	snapshotCtx := resolveUserRankingSnapshotContext(base)
	start, end := currentDayRange(snapshotCtx.snapshotDayRef)
	require.NoError(t, db.Create(&model.User{
		Username:    "d_invitee_1",
		DisplayName: "D Invitee 1",
		AffCode:     "d-invitee-1",
		InviterId:   u1.Id,
		CreatedAt:   start + 10,
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
	}).Error)
	require.NoError(t, db.Create(&model.User{
		Username:    "d_invitee_2",
		DisplayName: "D Invitee 2",
		AffCode:     "d-invitee-2",
		InviterId:   u1.Id,
		CreatedAt:   start + 20,
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
	}).Error)
	require.NoError(t, db.Create(&model.User{
		Username:    "d_invitee_3",
		DisplayName: "D Invitee 3",
		AffCode:     "d-invitee-3",
		InviterId:   u2.Id,
		CreatedAt:   start + 30,
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
	}).Error)
	require.NoError(t, db.Create(&model.User{
		Username:    "d_invitee_4",
		DisplayName: "D Invitee 4",
		AffCode:     "d-invitee-4",
		InviterId:   u2.Id,
		CreatedAt:   end + 10,
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
	}).Error)

	require.NoError(t, db.Create(&[]model.Log{
		{UserId: u1.Id, Username: u1.Username, Type: model.LogTypeConsume, Quota: 120, CreatedAt: start + 40},
		{UserId: u1.Id, Username: u1.Username, Type: model.LogTypeConsume, Quota: 80, CreatedAt: start + 50},
		{UserId: u2.Id, Username: u2.Username, Type: model.LogTypeConsume, Quota: 150, CreatedAt: start + 60},
		{UserId: u2.Id, Username: u2.Username, Type: model.LogTypeConsume, Quota: 999, CreatedAt: end + 61},
	}).Error)

	runUserRankingDailySnapshotOnce(base)
	snapshotDate := snapshotCtx.snapshotDate

	assertSnapshot := func(metric UserRankingMetric, period UserRankingPeriod, expectedCount int) []model.UserRankingValueRow {
		rows, snapshotAt, err := model.GetUserRankingSnapshot(snapshotDate, string(metric), string(period), rankingLeaderboardLimit)
		require.NoError(t, err)
		require.Equal(t, expectedCount, len(rows))
		require.Equal(t, snapshotCtx.snapshotAt.Unix(), snapshotAt)
		return rows
	}

	balanceRows := assertSnapshot(UserRankingMetricBalance, UserRankingPeriodTotal, 2)
	require.Equal(t, u1.Id, balanceRows[0].UserId)
	require.Equal(t, int64(300), balanceRows[0].Value)

	inviteRows := assertSnapshot(UserRankingMetricInvites, UserRankingPeriodDaily, 2)
	require.Equal(t, u1.Id, inviteRows[0].UserId)
	require.Equal(t, int64(2), inviteRows[0].Value)
	require.Equal(t, u2.Id, inviteRows[1].UserId)
	require.Equal(t, int64(1), inviteRows[1].Value)

	consumptionRows := assertSnapshot(UserRankingMetricConsumption, UserRankingPeriodDaily, 2)
	require.Equal(t, u1.Id, consumptionRows[0].UserId)
	require.Equal(t, int64(200), consumptionRows[0].Value)
	require.Equal(t, u2.Id, consumptionRows[1].UserId)
	require.Equal(t, int64(150), consumptionRows[1].Value)

	inviteTotalRows := assertSnapshot(UserRankingMetricInvites, UserRankingPeriodTotal, 2)
	require.Equal(t, u1.Id, inviteTotalRows[0].UserId)
	require.Equal(t, int64(5), inviteTotalRows[0].Value)
	require.Equal(t, u2.Id, inviteTotalRows[1].UserId)
	require.Equal(t, int64(3), inviteTotalRows[1].Value)

	consumptionTotalRows := assertSnapshot(UserRankingMetricConsumption, UserRankingPeriodTotal, 2)
	require.Equal(t, u1.Id, consumptionTotalRows[0].UserId)
	require.Equal(t, int64(410), consumptionTotalRows[0].Value)
	require.Equal(t, u2.Id, consumptionTotalRows[1].UserId)
	require.Equal(t, int64(260), consumptionTotalRows[1].Value)
}

func TestRunUserRankingDailySnapshotOnce_CrossDayTriggersOncePerBeijingDate(t *testing.T) {
	db := setupUserRankingServiceTestDB(t)
	setUserRankingVisibility(t, UserRankingVisibilityPublic)
	InvalidateUserRankingCache()
	userRankingSnapshotLastDateKey.Store(0)

	u1 := mustCreateUser(t, db, model.User{
		Username:    "cross_u1",
		DisplayName: "Cross U1",
		Quota:       800,
		AffCount:    9,
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
	})
	_ = u1

	first := time.Date(2026, 5, 10, 15, 59, 40, 0, time.UTC)
	runUserRankingDailySnapshotOnce(first)
	firstDate := resolveUserRankingSnapshotContext(first).snapshotDate

	var firstCount int64
	require.NoError(t, db.Model(&model.UserRankingSnapshot{}).
		Where("snapshot_date = ? AND metric = ? AND period = ?", firstDate, string(UserRankingMetricBalance), string(UserRankingPeriodTotal)).
		Count(&firstCount).Error)
	require.Greater(t, firstCount, int64(0))

	runUserRankingDailySnapshotOnce(first.Add(10 * time.Second))
	var firstCountAgain int64
	require.NoError(t, db.Model(&model.UserRankingSnapshot{}).
		Where("snapshot_date = ? AND metric = ? AND period = ?", firstDate, string(UserRankingMetricBalance), string(UserRankingPeriodTotal)).
		Count(&firstCountAgain).Error)
	require.Equal(t, firstCount, firstCountAgain)

	second := first.Add(10 * time.Second)
	runUserRankingDailySnapshotOnce(second)

	third := first.Add(26 * time.Hour)
	runUserRankingDailySnapshotOnce(third)
	secondDate := resolveUserRankingSnapshotContext(third).snapshotDate
	require.NotEqual(t, firstDate, secondDate)

	var secondCount int64
	require.NoError(t, db.Model(&model.UserRankingSnapshot{}).
		Where("snapshot_date = ? AND metric = ? AND period = ?", secondDate, string(UserRankingMetricBalance), string(UserRankingPeriodTotal)).
		Count(&secondCount).Error)
	require.Greater(t, secondCount, int64(0))

	lastDate := userRankingSnapshotLastDateKey.Load()
	require.Equal(t, beijingDateKey(resolveUserRankingSnapshotContext(third).snapshotDayRef), lastDate)
}

func TestResolveUserRankingSnapshotContext(t *testing.T) {
	now := time.Date(2026, 5, 11, 0, 0, 5, 0, beijingLocation())
	ctx := resolveUserRankingSnapshotContext(now)
	require.Equal(t, "2026-05-10", ctx.snapshotDate)
	require.Equal(t, int64(20260510), ctx.dateKey)
	dayStart := time.Date(2026, 5, 10, 0, 0, 0, 0, beijingLocation())
	require.Equal(t, dayStart.Add(12*time.Hour), ctx.snapshotDayRef)
	require.Equal(t, toBeijingTime(now), ctx.snapshotAt)
}

func TestRunUserRankingDailySnapshotTick_FallbackToLocalWhenNetworkTimeFails(t *testing.T) {
	setupUserRankingServiceTestDB(t)
	setUserRankingVisibility(t, UserRankingVisibilityPublic)
	InvalidateUserRankingCache()

	originalNowFn := userRankingSnapshotNetworkNowFn
	originalLastDate := userRankingSnapshotLastDateKey.Load()
	userRankingSnapshotLastDateKey.Store(0)
	userRankingSnapshotTaskRunning.Store(false)
	defer func() {
		userRankingSnapshotNetworkNowFn = originalNowFn
		userRankingSnapshotLastDateKey.Store(originalLastDate)
		userRankingSnapshotTaskRunning.Store(false)
	}()

	var called atomic.Int32
	userRankingSnapshotNetworkNowFn = func() (time.Time, error) {
		called.Add(1)
		return time.Time{}, fmt.Errorf("network down")
	}

	runUserRankingDailySnapshotTick()
	require.Equal(t, int32(1), called.Load())
	require.NotEqual(t, int64(0), userRankingSnapshotLastDateKey.Load())
}

func TestParseHTTPDateHeader(t *testing.T) {
	tm, err := parseHTTPDateHeader("Sun, 10 May 2026 16:00:00 GMT")
	require.NoError(t, err)
	require.Equal(t, time.Date(2026, 5, 10, 16, 0, 0, 0, time.UTC), tm.UTC())

	_, err = parseHTTPDateHeader("bad-date")
	require.Error(t, err)
}
