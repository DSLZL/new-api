package controller

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestVerify2FALogin_InvalidNumericCodeConsumesOnlyOneAttempt(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)
	require.NoError(t, model.DB.AutoMigrate(&model.User{}, &model.TwoFA{}, &model.TwoFABackupCode{}))
	model.LOG_DB = model.DB
	require.NoError(t, i18n.Init())

	passwordHash, err := common.Password2Hash("12345678")
	require.NoError(t, err)
	user := &model.User{
		Username:    fmt.Sprintf("verify2fa_user_%d", time.Now().UnixNano()),
		Password:    passwordHash,
		DisplayName: "verify2fa_one_attempt_user",
		Role:        common.RoleCommonUser,
		Status:      common.UserStatusEnabled,
		Group:       "default",
		AffCode:     fmt.Sprintf("aff_verify2fa_%d", time.Now().UnixNano()),
	}
	require.NoError(t, model.DB.Create(user).Error)
	twoFA := &model.TwoFA{UserId: user.Id, Secret: "secret", IsEnabled: true}
	require.NoError(t, model.DB.Create(twoFA).Error)

	router := gin.New()
	router.Use(sessions.Sessions("test-session", cookie.NewStore([]byte("test-secret"))))
	router.POST("/seed-pending", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set("pending_user_id", user.Id)
		require.NoError(t, session.Save())
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	router.POST("/api/user/2fa/verify-login", Verify2FALogin)

	seedRecorder := httptest.NewRecorder()
	seedReq := httptest.NewRequest(http.MethodPost, "/seed-pending", strings.NewReader(`{}`))
	seedReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(seedRecorder, seedReq)
	require.Equal(t, http.StatusOK, seedRecorder.Code)

	cookieHeader := seedRecorder.Header().Get("Set-Cookie")
	require.NotEmpty(t, cookieHeader)

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/user/2fa/verify-login", strings.NewReader(`{"code":"123456"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", cookieHeader)
	router.ServeHTTP(recorder, req)

	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"success":false`)

	fresh, loadErr := model.GetTwoFAByUserId(user.Id)
	require.NoError(t, loadErr)
	require.NotNil(t, fresh)
	require.Equal(t, 1, fresh.FailedAttempts)
}

func TestVerify2FALogin_InvalidFormatCodeConsumesOnlyOneAttempt(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)
	require.NoError(t, model.DB.AutoMigrate(&model.User{}, &model.TwoFA{}, &model.TwoFABackupCode{}))
	model.LOG_DB = model.DB
	require.NoError(t, i18n.Init())

	passwordHash, err := common.Password2Hash("12345678")
	require.NoError(t, err)
	user := &model.User{
		Username:    fmt.Sprintf("verify2fa_invalidfmt_user_%d", time.Now().UnixNano()),
		Password:    passwordHash,
		DisplayName: "verify2fa_invalidfmt_user",
		Role:        common.RoleCommonUser,
		Status:      common.UserStatusEnabled,
		Group:       "default",
		AffCode:     fmt.Sprintf("aff_verify2fa_invalidfmt_%d", time.Now().UnixNano()),
	}
	require.NoError(t, model.DB.Create(user).Error)
	twoFA := &model.TwoFA{UserId: user.Id, Secret: "secret", IsEnabled: true}
	require.NoError(t, model.DB.Create(twoFA).Error)

	router := gin.New()
	router.Use(sessions.Sessions("test-session", cookie.NewStore([]byte("test-secret"))))
	router.POST("/seed-pending", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set("pending_user_id", user.Id)
		require.NoError(t, session.Save())
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	router.POST("/api/user/2fa/verify-login", Verify2FALogin)

	seedRecorder := httptest.NewRecorder()
	seedReq := httptest.NewRequest(http.MethodPost, "/seed-pending", strings.NewReader(`{}`))
	seedReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(seedRecorder, seedReq)
	require.Equal(t, http.StatusOK, seedRecorder.Code)

	cookieHeader := seedRecorder.Header().Get("Set-Cookie")
	require.NotEmpty(t, cookieHeader)

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/user/2fa/verify-login", strings.NewReader(`{"code":"bad_code"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", cookieHeader)
	router.ServeHTTP(recorder, req)

	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"success":false`)

	fresh, loadErr := model.GetTwoFAByUserId(user.Id)
	require.NoError(t, loadErr)
	require.NotNil(t, fresh)
	require.Equal(t, 1, fresh.FailedAttempts)
}

func TestDisable2FA_InvalidFormatCodeConsumesOnlyOneAttempt(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initFingerprintReportTestDB(t)
	require.NoError(t, model.DB.AutoMigrate(&model.User{}, &model.TwoFA{}, &model.TwoFABackupCode{}))
	model.LOG_DB = model.DB

	passwordHash, err := common.Password2Hash("12345678")
	require.NoError(t, err)
	user := &model.User{
		Username:    fmt.Sprintf("disable2fa_invalidfmt_user_%d", time.Now().UnixNano()),
		Password:    passwordHash,
		DisplayName: "disable2fa_invalidfmt_user",
		Role:        common.RoleCommonUser,
		Status:      common.UserStatusEnabled,
		Group:       "default",
		AffCode:     fmt.Sprintf("aff_disable2fa_invalidfmt_%d", time.Now().UnixNano()),
	}
	require.NoError(t, model.DB.Create(user).Error)
	twoFA := &model.TwoFA{UserId: user.Id, Secret: "secret", IsEnabled: true}
	require.NoError(t, model.DB.Create(twoFA).Error)

	router := gin.New()
	router.POST("/api/user/2fa/disable", func(c *gin.Context) {
		c.Set("id", user.Id)
		Disable2FA(c)
	})

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/user/2fa/disable", strings.NewReader(`{"code":"bad_code"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, req)

	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"success":false`)

	fresh, loadErr := model.GetTwoFAByUserId(user.Id)
	require.NoError(t, loadErr)
	require.NotNil(t, fresh)
	require.Equal(t, 1, fresh.FailedAttempts)
}

func TestUniversalVerify_2FAInvalidCodesConsumeOnlyOneAttempt(t *testing.T) {
	testCases := []struct {
		name string
		code string
	}{
		{name: "invalid_numeric_totp", code: "123456"},
		{name: "invalid_backup_code", code: "ABCD-EFGH"},
		{name: "malformed_code", code: "bad_code"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			initFingerprintReportTestDB(t)
			require.NoError(t, model.DB.AutoMigrate(&model.User{}, &model.TwoFA{}, &model.TwoFABackupCode{}))
			model.LOG_DB = model.DB

			passwordHash, err := common.Password2Hash("12345678")
			require.NoError(t, err)
			user := &model.User{
				Username:    fmt.Sprintf("universalverify2fa_%s_%d", tc.name, time.Now().UnixNano()),
				Password:    passwordHash,
				DisplayName: "universalverify2fa_user",
				Role:        common.RoleCommonUser,
				Status:      common.UserStatusEnabled,
				Group:       "default",
				AffCode:     fmt.Sprintf("aff_universalverify2fa_%s_%d", tc.name, time.Now().UnixNano()),
			}
			require.NoError(t, model.DB.Create(user).Error)
			twoFA := &model.TwoFA{UserId: user.Id, Secret: "secret", IsEnabled: true}
			require.NoError(t, model.DB.Create(twoFA).Error)

			router := gin.New()
			router.Use(sessions.Sessions("test-session", cookie.NewStore([]byte("test-secret"))))
			router.POST("/api/verify", func(c *gin.Context) {
				c.Set("id", user.Id)
				UniversalVerify(c)
			})

			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/verify", strings.NewReader(fmt.Sprintf(`{"method":"2fa","code":"%s"}`, tc.code)))
			req.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(recorder, req)

			require.Equal(t, http.StatusOK, recorder.Code)
			require.Contains(t, recorder.Body.String(), `"success":false`)

			fresh, loadErr := model.GetTwoFAByUserId(user.Id)
			require.NoError(t, loadErr)
			require.NotNil(t, fresh)
			require.Equal(t, 1, fresh.FailedAttempts)
		})
	}
}
