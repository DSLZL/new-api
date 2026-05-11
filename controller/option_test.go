package controller

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func setupOptionControllerTestDB(t *testing.T) *gorm.DB {
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
	require.NoError(t, db.AutoMigrate(&model.Option{}, &model.UserRankingSnapshot{}))

	common.OptionMapRWMutex.Lock()
	common.OptionMap = map[string]string{}
	common.OptionMapRWMutex.Unlock()
	service.InvalidateUserRankingCache()

	t.Cleanup(func() {
		service.InvalidateUserRankingCache()
		sqlDB, err := db.DB()
		if err == nil {
			_ = sqlDB.Close()
		}
	})

	return db
}

func performOptionUpdateRequest(t *testing.T, key string, value any) (int, map[string]any) {
	t.Helper()

	reqBody, err := common.Marshal(OptionUpdateRequest{
		Key:   key,
		Value: value,
	})
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/api/option", strings.NewReader(string(reqBody)))
	ctx.Request.Header.Set("Content-Type", "application/json")

	UpdateOption(ctx)

	resp := map[string]any{}
	require.NoError(t, common.Unmarshal(recorder.Body.Bytes(), &resp))
	return recorder.Code, resp
}

func saveUserRankingSnapshotForTest(t *testing.T, date string, value int64) {
	t.Helper()
	require.NoError(t, model.SaveUserRankingSnapshot(date, "balance", "total", []model.UserRankingValueRow{
		{
			UserId:      1,
			Username:    "u1",
			DisplayName: "U1",
			Value:       value,
		},
	}, time.Now().Unix()))
}

func TestRankingRewardOptionRejectsInvalidRulesJSON(t *testing.T) {
	setupOptionControllerTestDB(t)

	statusCode, resp := performOptionUpdateRequest(t, "ranking_reward_setting.rules", "{]")
	require.Equal(t, http.StatusOK, statusCode)
	require.Equal(t, false, resp["success"])
	require.NotEmpty(t, resp["message"])

	var option model.Option
	err := model.DB.First(&option, "key = ?", "ranking_reward_setting.rules").Error
	require.Error(t, err)
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)
}

func TestRankingRewardOptionAcceptsValidRulesAndPersists(t *testing.T) {
	setupOptionControllerTestDB(t)

	rulesJSON := `{"balance.daily":[{"rank":1,"quota":1000},{"rank":2,"quota":500}],"balance.total":[{"rank":1,"quota":2000}]}`

	statusCode, resp := performOptionUpdateRequest(t, "ranking_reward_setting.rules", rulesJSON)
	require.Equal(t, http.StatusOK, statusCode)
	require.Equal(t, true, resp["success"])

	var option model.Option
	require.NoError(t, model.DB.First(&option, "key = ?", "ranking_reward_setting.rules").Error)
	require.Equal(t, rulesJSON, option.Value)

	parsed, err := service.ParseRankingRewardRules(option.Value)
	require.NoError(t, err)
	require.Len(t, parsed["balance.daily"], 2)
	require.Equal(t, 1000, parsed["balance.daily"][0].Quota)

	setting := operation_setting.GetRankingRewardSetting()
	require.Len(t, setting.Rules["balance.daily"], 2)
	require.Equal(t, 500, setting.Rules["balance.daily"][1].Quota)
}

func TestRankingRewardOptionUpdateInvalidatesRankingCache(t *testing.T) {
	setupOptionControllerTestDB(t)

	common.OptionMapRWMutex.Lock()
	common.OptionMap["ranking_setting.user_visibility"] = string(service.UserRankingVisibilityPublic)
	common.OptionMapRWMutex.Unlock()

	snapshotDate := "2024-01-02"
	saveUserRankingSnapshotForTest(t, snapshotDate, 100)

	firstResp, err := service.GetUserRankingsSnapshot("balance", "total", snapshotDate)
	require.NoError(t, err)
	require.Len(t, firstResp.Items, 1)
	require.EqualValues(t, 100, firstResp.Items[0].Value)

	saveUserRankingSnapshotForTest(t, snapshotDate, 200)

	cachedResp, err := service.GetUserRankingsSnapshot("balance", "total", snapshotDate)
	require.NoError(t, err)
	require.Len(t, cachedResp.Items, 1)
	require.EqualValues(t, 100, cachedResp.Items[0].Value)

	statusCode, resp := performOptionUpdateRequest(t, "ranking_reward_setting.enabled", true)
	require.Equal(t, http.StatusOK, statusCode)
	require.Equal(t, true, resp["success"])

	afterUpdateResp, err := service.GetUserRankingsSnapshot("balance", "total", snapshotDate)
	require.NoError(t, err)
	require.Len(t, afterUpdateResp.Items, 1)
	require.EqualValues(t, 200, afterUpdateResp.Items[0].Value)
}
