package controller

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func setupInviteCodeControllerTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	gin.SetMode(gin.TestMode)
	common.UsingSQLite = true
	common.UsingMySQL = false
	common.UsingPostgreSQL = false
	common.RedisEnabled = false

	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)

	model.DB = db
	model.LOG_DB = db
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.InviteCode{}, &model.InviteCodeUsage{}, &model.InviteCodeAuditLog{}))
	require.NoError(t, i18n.Init())

	common.OptionMapRWMutex.Lock()
	if common.OptionMap == nil {
		common.OptionMap = map[string]string{}
	}
	originalAuditOption, hadAuditOption := common.OptionMap["invite_code_audit_enabled"]
	common.OptionMap["invite_code_audit_enabled"] = "false"
	common.OptionMapRWMutex.Unlock()

	t.Cleanup(func() {
		common.OptionMapRWMutex.Lock()
		if hadAuditOption {
			common.OptionMap["invite_code_audit_enabled"] = originalAuditOption
		} else {
			delete(common.OptionMap, "invite_code_audit_enabled")
		}
		common.OptionMapRWMutex.Unlock()
		_ = sqlDB.Close()
	})

	return db
}

func withInviteRegisterFlags(t *testing.T) {
	t.Helper()

	oldRegisterEnabled := common.RegisterEnabled
	oldPasswordRegisterEnabled := common.PasswordRegisterEnabled
	oldEmailVerificationEnabled := common.EmailVerificationEnabled
	oldInviteOnlyEnabled := common.InviteOnlyRegistrationEnabled
	oldFingerprintEnabled := common.FingerprintEnabled
	oldGenerateDefaultToken := constant.GenerateDefaultToken
	oldQuotaForNewUser := common.QuotaForNewUser
	oldQuotaForInvitee := common.QuotaForInvitee
	oldQuotaForInviter := common.QuotaForInviter
	oldGitHubOAuthEnabled := common.GitHubOAuthEnabled

	t.Cleanup(func() {
		common.RegisterEnabled = oldRegisterEnabled
		common.PasswordRegisterEnabled = oldPasswordRegisterEnabled
		common.EmailVerificationEnabled = oldEmailVerificationEnabled
		common.InviteOnlyRegistrationEnabled = oldInviteOnlyEnabled
		common.FingerprintEnabled = oldFingerprintEnabled
		constant.GenerateDefaultToken = oldGenerateDefaultToken
		common.QuotaForNewUser = oldQuotaForNewUser
		common.QuotaForInvitee = oldQuotaForInvitee
		common.QuotaForInviter = oldQuotaForInviter
		common.GitHubOAuthEnabled = oldGitHubOAuthEnabled
	})

	common.RegisterEnabled = true
	common.PasswordRegisterEnabled = true
	common.EmailVerificationEnabled = false
	common.InviteOnlyRegistrationEnabled = true
	common.FingerprintEnabled = false
	constant.GenerateDefaultToken = false
	common.QuotaForNewUser = 0
	common.QuotaForInvitee = 0
	common.QuotaForInviter = 0
	common.GitHubOAuthEnabled = true
}

func createInviteTestUser(t *testing.T, usernamePrefix, affCode string) *model.User {
	t.Helper()

	user := &model.User{
		Username:    fmt.Sprintf("%s_%d", usernamePrefix, time.Now().UnixNano()),
		Password:    "hashed-password",
		DisplayName: usernamePrefix,
		Role:        common.RoleCommonUser,
		Status:      common.UserStatusEnabled,
		Group:       "default",
		AffCode:     affCode,
	}
	require.NoError(t, model.DB.Create(user).Error)
	return user
}

func createInviteCodeRecord(t *testing.T, inviterID int, code string, maxUses, usedCount int, expiresAt int64) *model.InviteCode {
	t.Helper()

	item := &model.InviteCode{
		UserId:    inviterID,
		Code:      code,
		Status:    model.InviteCodeStatusActive,
		MaxUses:   maxUses,
		UsedCount: usedCount,
		ExpiresAt: expiresAt,
	}
	require.NoError(t, model.DB.Create(item).Error)
	return item
}

func decodeControllerResp(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	resp := map[string]any{}
	require.NoError(t, common.Unmarshal(recorder.Body.Bytes(), &resp))
	return resp
}

func extractBusinessCode(resp map[string]any) string {
	data, ok := resp["data"].(map[string]any)
	if !ok {
		return ""
	}
	code, _ := data["code"].(string)
	return code
}

func TestRegister_ConsumesActiveInviteCodeOnSuccess(t *testing.T) {
	setupInviteCodeControllerTestDB(t)
	withInviteRegisterFlags(t)

	inviter := createInviteTestUser(t, "register_active_inviter", "INVA")
	code := createInviteCodeRecord(t, inviter.Id, "ACTIVE-CODE-ONE", 1, 0, common.GetTimestamp()+3600)

	body := `{"username":"register_active_user","password":"12345678","aff_code":"ACTIVE-CODE-ONE"}`
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/user/register", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	Register(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)
	resp := decodeControllerResp(t, recorder)
	require.Equal(t, true, resp["success"])

	var inserted model.User
	require.NoError(t, model.DB.Where("username = ?", "register_active_user").First(&inserted).Error)
	require.Equal(t, inviter.Id, inserted.InviterId)

	var updatedCode model.InviteCode
	require.NoError(t, model.DB.First(&updatedCode, "id = ?", code.Id).Error)
	require.Equal(t, 1, updatedCode.UsedCount)

	var usage model.InviteCodeUsage
	require.NoError(t, model.DB.First(&usage, "invite_code_id = ? AND invitee_user_id = ?", code.Id, inserted.Id).Error)
	require.Equal(t, "password", usage.RegisterType)
}

func TestRegister_RollsBackUserWhenConsumeInviteCodeFailsAfterInsert(t *testing.T) {
	setupInviteCodeControllerTestDB(t)
	withInviteRegisterFlags(t)

	inviter := createInviteTestUser(t, "register_rollback_inviter", "RBK1")
	code := createInviteCodeRecord(t, inviter.Id, "ROLLBACK-CODE-ONE", 2, 0, common.GetTimestamp()+3600)
	require.NoError(t, model.DB.Exec("DROP TABLE invite_code_usages").Error)

	body := `{"username":"register_rollback_user","password":"12345678","aff_code":"ROLLBACK-CODE-ONE"}`
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/user/register", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	Register(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)
	resp := decodeControllerResp(t, recorder)
	require.Equal(t, false, resp["success"])

	var inserted model.User
	require.Error(t, model.DB.Where("username = ?", "register_rollback_user").First(&inserted).Error)

	var latestCode model.InviteCode
	require.NoError(t, model.DB.First(&latestCode, "id = ?", code.Id).Error)
	require.Equal(t, 0, latestCode.UsedCount)
}

func TestRegister_RejectsExpiredInviteCode(t *testing.T) {
	setupInviteCodeControllerTestDB(t)
	withInviteRegisterFlags(t)

	inviter := createInviteTestUser(t, "register_expired_inviter", "EXP1")
	createInviteCodeRecord(t, inviter.Id, "EXP1", 5, 0, common.GetTimestamp()-60)

	body := `{"username":"reg_expired_u","password":"12345678","aff_code":"EXP1"}`
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/user/register", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	Register(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)
	resp := decodeControllerResp(t, recorder)
	require.Equal(t, false, resp["success"])
	require.Equal(t, InviteCodeInvalidCode, extractBusinessCode(resp))

	var inserted model.User
	require.Error(t, model.DB.Where("username = ?", "reg_expired_u").First(&inserted).Error)
}

func TestRegister_RejectsExhaustedInviteCode(t *testing.T) {
	setupInviteCodeControllerTestDB(t)
	withInviteRegisterFlags(t)

	inviter := createInviteTestUser(t, "register_exhausted_inviter", "EXH1")
	createInviteCodeRecord(t, inviter.Id, "EXH1", 1, 1, common.GetTimestamp()+3600)

	body := `{"username":"reg_exhausted_u","password":"12345678","aff_code":"EXH1"}`
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/user/register", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	Register(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)
	resp := decodeControllerResp(t, recorder)
	require.Equal(t, false, resp["success"])
	require.Equal(t, InviteCodeInvalidCode, extractBusinessCode(resp))

	var inserted model.User
	require.Error(t, model.DB.Where("username = ?", "reg_exhausted_u").First(&inserted).Error)
}

func TestRegister_FinalizeRewardsAppliedOnceWithInvite(t *testing.T) {
	setupInviteCodeControllerTestDB(t)
	withInviteRegisterFlags(t)

	common.QuotaForNewUser = 11
	common.QuotaForInvitee = 13
	common.QuotaForInviter = 17

	inviter := createInviteTestUser(t, "register_reward_inviter", "RW11")
	code := createInviteCodeRecord(t, inviter.Id, "REWARD-CODE-ONE", 2, 0, common.GetTimestamp()+3600)

	body := `{"username":"register_reward_user","password":"12345678","aff_code":"REWARD-CODE-ONE"}`
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/user/register", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	Register(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)
	resp := decodeControllerResp(t, recorder)
	require.Equal(t, true, resp["success"])

	var inserted model.User
	require.NoError(t, model.DB.Where("username = ?", "register_reward_user").First(&inserted).Error)
	require.Equal(t, inviter.Id, inserted.InviterId)
	require.Equal(t, 24, inserted.Quota) // QuotaForNewUser + QuotaForInvitee

	var inviterAfter model.User
	require.NoError(t, model.DB.First(&inviterAfter, "id = ?", inviter.Id).Error)
	require.Equal(t, 1, inviterAfter.AffCount)
	require.Equal(t, 17, inviterAfter.AffQuota)
	require.Equal(t, 17, inviterAfter.AffHistoryQuota)

	var usageCount int64
	require.NoError(t, model.DB.Model(&model.InviteCodeUsage{}).Where("invite_code_id = ? AND invitee_user_id = ?", code.Id, inserted.Id).Count(&usageCount).Error)
	require.EqualValues(t, 1, usageCount)

	var latestCode model.InviteCode
	require.NoError(t, model.DB.First(&latestCode, "id = ?", code.Id).Error)
	require.Equal(t, 1, latestCode.UsedCount)
}

func TestContinueOAuthWithInvite_ConsumesActiveInviteCodeOnSuccess(t *testing.T) {
	setupInviteCodeControllerTestDB(t)
	withInviteRegisterFlags(t)

	inviter := createInviteTestUser(t, "oauth_active_inviter", "OINV")
	code := createInviteCodeRecord(t, inviter.Id, "OAUTH-CODE-ONE", 1, 0, common.GetTimestamp()+3600)

	router := gin.New()
	router.Use(sessions.Sessions("test-session", cookie.NewStore([]byte("test-secret"))))
	router.POST("/seed-oauth-pending", func(c *gin.Context) {
		session := sessions.Default(c)
		pending := pendingOAuthRegistration{
			Provider:       "GitHub",
			ProviderUserID: fmt.Sprintf("oauth_provider_uid_%d", time.Now().UnixNano()),
			Username:       "oauth_continue_user",
			DisplayName:    "OAuth Continue User",
			Email:          "",
			ExpiresAt:      time.Now().Add(5 * time.Minute).Unix(),
		}
		payload, err := common.Marshal(pending)
		require.NoError(t, err)
		session.Set(oauthPendingSessionKey, string(payload))
		require.NoError(t, session.Save())
		c.JSON(http.StatusOK, gin.H{"success": true})
	})
	router.POST("/api/oauth/invite/continue", ContinueOAuthWithInvite)

	seedRecorder := httptest.NewRecorder()
	seedReq := httptest.NewRequest(http.MethodPost, "/seed-oauth-pending", strings.NewReader(`{}`))
	seedReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(seedRecorder, seedReq)
	require.Equal(t, http.StatusOK, seedRecorder.Code)
	cookieHeader := seedRecorder.Header().Get("Set-Cookie")
	require.NotEmpty(t, cookieHeader)

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/oauth/invite/continue", strings.NewReader(`{"invite_code":"OAUTH-CODE-ONE"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", cookieHeader)
	router.ServeHTTP(recorder, req)

	require.Equal(t, http.StatusOK, recorder.Code)
	resp := decodeControllerResp(t, recorder)
	require.Equal(t, true, resp["success"])

	var inserted model.User
	require.NoError(t, model.DB.Where("username = ?", "oauth_continue_user").First(&inserted).Error)
	require.Equal(t, inviter.Id, inserted.InviterId)
	require.NotEmpty(t, inserted.GitHubId)

	var updatedCode model.InviteCode
	require.NoError(t, model.DB.First(&updatedCode, "id = ?", code.Id).Error)
	require.Equal(t, 1, updatedCode.UsedCount)

	var usage model.InviteCodeUsage
	require.NoError(t, model.DB.First(&usage, "invite_code_id = ? AND invitee_user_id = ?", code.Id, inserted.Id).Error)
	require.Equal(t, "oauth", usage.RegisterType)

	successCookie := recorder.Header().Get("Set-Cookie")
	if successCookie == "" {
		successCookie = cookieHeader
	}
	secondRecorder := httptest.NewRecorder()
	secondReq := httptest.NewRequest(http.MethodPost, "/api/oauth/invite/continue", strings.NewReader(`{"invite_code":"OAUTH-CODE-ONE"}`))
	secondReq.Header.Set("Content-Type", "application/json")
	secondReq.Header.Set("Cookie", successCookie)
	router.ServeHTTP(secondRecorder, secondReq)
	require.Equal(t, http.StatusOK, secondRecorder.Code)
	secondResp := decodeControllerResp(t, secondRecorder)
	require.Equal(t, false, secondResp["success"])
	require.Equal(t, OAuthCodePendingNotFound, extractBusinessCode(secondResp))
}
