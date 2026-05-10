package controller

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func setupRankingsControllerTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	gin.SetMode(gin.TestMode)
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
		sqlDB, err := db.DB()
		if err == nil {
			_ = sqlDB.Close()
		}
	})

	return db
}

func decodeRankingJSON(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()

	var payload map[string]any
	require.NoError(t, common.Unmarshal(recorder.Body.Bytes(), &payload))
	return payload
}

func TestGetRankings_InvalidScope(t *testing.T) {
	setupRankingsControllerTestDB(t)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/rankings?scope=invalid", nil)

	GetRankings(ctx)

	require.Equal(t, http.StatusBadRequest, recorder.Code)
	body := decodeRankingJSON(t, recorder)
	require.Equal(t, false, body["success"])
}

func TestGetRankings_UsersInvalidMetric(t *testing.T) {
	setupRankingsControllerTestDB(t)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/rankings?scope=users&metric=bad", nil)

	GetRankings(ctx)

	require.Equal(t, http.StatusBadRequest, recorder.Code)
	body := decodeRankingJSON(t, recorder)
	require.Equal(t, false, body["success"])
}

func TestGetRankings_UsersBalancePeriodNormalization(t *testing.T) {
	db := setupRankingsControllerTestDB(t)
	require.NoError(t, db.Create(&model.User{
		Username:    "u1",
		DisplayName: "U1",
		Quota:       100,
		UsedQuota:   1,
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
		AccessToken: nil,
	}).Error)

	common.OptionMapRWMutex.Lock()
	if common.OptionMap == nil {
		common.OptionMap = map[string]string{}
	}
	common.OptionMap["ranking_setting.user_visibility"] = string(service.UserRankingVisibilityPublic)
	common.OptionMapRWMutex.Unlock()
	service.InvalidateUserRankingCache()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/rankings?scope=users&metric=balance&period=daily", nil)

	GetRankings(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)
	body := decodeRankingJSON(t, recorder)
	require.Equal(t, true, body["success"])
	data := body["data"].(map[string]any)
	require.Equal(t, "total", data["period"])
}

func TestGetRankings_UsersInvalidDate(t *testing.T) {
	setupRankingsControllerTestDB(t)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/rankings?scope=users&metric=balance&date=2026-99-10", nil)

	GetRankings(ctx)

	require.Equal(t, http.StatusBadRequest, recorder.Code)
	body := decodeRankingJSON(t, recorder)
	require.Equal(t, false, body["success"])
}

func TestGetRankings_UsersDateQueryAccepted(t *testing.T) {
	db := setupRankingsControllerTestDB(t)
	require.NoError(t, db.Create(&model.User{
		Username:    "u1",
		DisplayName: "U1",
		Quota:       100,
		UsedQuota:   1,
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
		AccessToken: nil,
	}).Error)

	common.OptionMapRWMutex.Lock()
	if common.OptionMap == nil {
		common.OptionMap = map[string]string{}
	}
	common.OptionMap["ranking_setting.user_visibility"] = string(service.UserRankingVisibilityPublic)
	common.OptionMapRWMutex.Unlock()
	service.InvalidateUserRankingCache()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/rankings?scope=users&metric=balance&period=total&date=2024-01-02", nil)

	GetRankings(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)
	body := decodeRankingJSON(t, recorder)
	require.Equal(t, true, body["success"])
	data := body["data"].(map[string]any)
	require.Equal(t, "2024-01-02", data["date"])
}

func TestGetRankings_UsersAuthOnlyRequiresLogin(t *testing.T) {
	setupRankingsControllerTestDB(t)

	common.OptionMapRWMutex.Lock()
	if common.OptionMap == nil {
		common.OptionMap = map[string]string{}
	}
	common.OptionMap["ranking_setting.user_visibility"] = string(service.UserRankingVisibilityAuthOnly)
	common.OptionMapRWMutex.Unlock()
	service.InvalidateUserRankingCache()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/rankings?scope=users&metric=balance", nil)

	GetRankings(ctx)

	require.Equal(t, http.StatusUnauthorized, recorder.Code)
	body := decodeRankingJSON(t, recorder)
	require.Equal(t, false, body["success"])
	require.Equal(t, "AUTH_NOT_LOGGED_IN", body["code"])
}

func TestGetRankings_UsersAuthOnlyWithLogin(t *testing.T) {
	db := setupRankingsControllerTestDB(t)
	require.NoError(t, db.Create(&model.User{
		Username:    "u2",
		DisplayName: "U2",
		Quota:       500,
		UsedQuota:   200,
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
	}).Error)

	common.OptionMapRWMutex.Lock()
	if common.OptionMap == nil {
		common.OptionMap = map[string]string{}
	}
	common.OptionMap["ranking_setting.user_visibility"] = string(service.UserRankingVisibilityAuthOnly)
	common.OptionMapRWMutex.Unlock()
	service.InvalidateUserRankingCache()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/rankings?scope=users&metric=balance", nil)
	ctx.Set("id", 1)

	GetRankings(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)
	body := decodeRankingJSON(t, recorder)
	require.Equal(t, true, body["success"])
}
