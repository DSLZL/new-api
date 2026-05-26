package model

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func initLogModelTestDB(t *testing.T) {
	t.Helper()
	oldDB := DB
	oldLogDB := LOG_DB
	dsn := fmt.Sprintf("file:log_model_test_%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&User{}, &Log{}))
	DB = db
	LOG_DB = db
	t.Cleanup(func() {
		DB = oldDB
		LOG_DB = oldLogDB
		_ = sqlDB.Close()
	})
}

func TestRecordConsumeLog_IncludesRequestUserAgentInOther(t *testing.T) {
	initLogModelTestDB(t)

	oldConsumeEnabled := common.LogConsumeEnabled
	common.LogConsumeEnabled = true
	t.Cleanup(func() {
		common.LogConsumeEnabled = oldConsumeEnabled
	})

	require.NoError(t, DB.Create(&User{
		Id:       1,
		Username: "ua-log-user",
		Status:   common.UserStatusEnabled,
	}).Error)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest("POST", "/v1/chat/completions", nil)
	ctx.Request.Header.Set("User-Agent", "codex-test-agent/1.0")
	ctx.Set("username", "ua-log-user")
	ctx.Set(common.RequestIdKey, "req-ua-log-1")

	RecordConsumeLog(ctx, 1, RecordConsumeLogParams{
		ChannelId: 1,
		ModelName: "gpt-4o-mini",
		TokenName: "test-token",
		Quota:     128,
		Content:   "hello world",
		Other: map[string]interface{}{
			"request_path": "/v1/chat/completions",
		},
	})

	var log Log
	require.NoError(t, LOG_DB.First(&log).Error)
	assert.Equal(t, LogTypeConsume, log.Type)
	assert.Equal(t, "req-ua-log-1", log.RequestId)

	var other map[string]interface{}
	require.NoError(t, common.UnmarshalJsonStr(log.Other, &other))
	assert.Equal(t, "codex-test-agent/1.0", other["user_agent"])
	assert.Equal(t, "/v1/chat/completions", other["request_path"])
}
