package controller

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func newInviteCodeAuthedContext(method, target, body string, userID int) (*gin.Context, *httptest.ResponseRecorder) {
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	if body == "" {
		ctx.Request = httptest.NewRequest(method, target, nil)
	} else {
		ctx.Request = httptest.NewRequest(method, target, strings.NewReader(body))
		ctx.Request.Header.Set("Content-Type", "application/json")
	}
	ctx.Set("id", userID)
	ctx.Set("role", common.RoleCommonUser)
	return ctx, recorder
}

func extractInviteCodeSetFromHistoryResp(t *testing.T, resp map[string]any) map[string]bool {
	t.Helper()
	items, ok := resp["data"].([]any)
	require.True(t, ok)
	codeSet := make(map[string]bool, len(items))
	for _, item := range items {
		record, ok := item.(map[string]any)
		require.True(t, ok)
		code, _ := record["code"].(string)
		if code != "" {
			codeSet[code] = true
		}
	}
	return codeSet
}

func TestGetUserInviteCodeDetail(t *testing.T) {
	setupInviteCodeControllerTestDB(t)

	user := createInviteTestUser(t, "invite_detail_user", "STALE-CODE")
	active := createInviteCodeRecord(t, user.Id, "ACTIVE-DETAIL-CODE", 6, 2, common.GetTimestamp()+7200)

	ctx, recorder := newInviteCodeAuthedContext(http.MethodGet, "/api/user/invite-code", "", user.Id)
	GetUserInviteCodeDetail(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)
	resp := decodeControllerResp(t, recorder)
	require.Equal(t, true, resp["success"])

	data, ok := resp["data"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, active.Code, data["code"])
	require.Equal(t, float64(active.MaxUses), data["max_uses"])
	require.Equal(t, float64(active.UsedCount), data["used_count"])
	require.Equal(t, model.InviteCodeStatusActive, data["status"])
}

func TestUpdateUserInviteCodeRules(t *testing.T) {
	setupInviteCodeControllerTestDB(t)

	user := createInviteTestUser(t, "invite_rules_user", "RULE-STALE")
	active := createInviteCodeRecord(t, user.Id, "RULE-CODE-ACTIVE", 1, 0, common.GetTimestamp()+3600)
	targetExpireAt := common.GetTimestamp() + 10*3600

	ctx, recorder := newInviteCodeAuthedContext(
		http.MethodPut,
		"/api/user/invite-code",
		`{"max_uses":7,"expires_at":`+strconv.FormatInt(targetExpireAt, 10)+`}`,
		user.Id,
	)
	UpdateUserInviteCodeRules(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)
	resp := decodeControllerResp(t, recorder)
	require.Equal(t, true, resp["success"])

	var updated model.InviteCode
	require.NoError(t, model.DB.First(&updated, "id = ?", active.Id).Error)
	require.Equal(t, 7, updated.MaxUses)
	require.Equal(t, targetExpireAt, updated.ExpiresAt)
}

func TestUpdateUserInviteCodeRules_BackfillsFromLegacyAffCodeWhenNoActiveRow(t *testing.T) {
	setupInviteCodeControllerTestDB(t)

	user := createInviteTestUser(t, "invite_rules_legacy_user", "LEGY")
	targetExpireAt := common.GetTimestamp() + 12*3600

	ctx, recorder := newInviteCodeAuthedContext(
		http.MethodPut,
		"/api/user/invite-code",
		`{"max_uses":9,"expires_at":`+strconv.FormatInt(targetExpireAt, 10)+`}`,
		user.Id,
	)
	UpdateUserInviteCodeRules(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)
	resp := decodeControllerResp(t, recorder)
	require.Equal(t, true, resp["success"])

	active, err := model.GetActiveInviteCodeByUserID(user.Id)
	require.NoError(t, err)
	require.Equal(t, "LEGY", active.Code)
	require.Equal(t, 9, active.MaxUses)
	require.Equal(t, targetExpireAt, active.ExpiresAt)
}

func TestUpdateUserInviteCodeRules_InvalidPayload(t *testing.T) {
	setupInviteCodeControllerTestDB(t)

	user := createInviteTestUser(t, "invite_rules_invalid_payload", "INVP")
	ctx, recorder := newInviteCodeAuthedContext(
		http.MethodPut,
		"/api/user/invite-code",
		`{"max_uses":"bad","expires_at":123}`,
		user.Id,
	)
	UpdateUserInviteCodeRules(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)
	resp := decodeControllerResp(t, recorder)
	require.Equal(t, false, resp["success"])
}

func TestInviteCodeRoutesRejectUnauthorizedByUserAuth(t *testing.T) {
	setupInviteCodeControllerTestDB(t)

	router := gin.New()
	router.Use(sessions.Sessions("test-session", cookie.NewStore([]byte("test-secret"))))
	userRoute := router.Group("/api/user")
	userRoute.Use(middleware.UserAuth())
	{
		userRoute.GET("/invite-code", GetUserInviteCodeDetail)
		userRoute.PUT("/invite-code", UpdateUserInviteCodeRules)
		userRoute.POST("/invite-code/refresh", RefreshUserInviteCode)
		userRoute.GET("/invite-codes/history", ListInviteCodeHistory)
	}

	cases := []struct {
		method string
		path   string
		body   string
	}{
		{method: http.MethodGet, path: "/api/user/invite-code"},
		{method: http.MethodPut, path: "/api/user/invite-code", body: `{"max_uses":2,"expires_at":0}`},
		{method: http.MethodPost, path: "/api/user/invite-code/refresh", body: `{}`},
		{method: http.MethodGet, path: "/api/user/invite-codes/history"},
	}

	for _, tc := range cases {
		recorder := httptest.NewRecorder()
		var req *http.Request
		if tc.body == "" {
			req = httptest.NewRequest(tc.method, tc.path, nil)
		} else {
			req = httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
		}
		router.ServeHTTP(recorder, req)

		require.Equal(t, http.StatusUnauthorized, recorder.Code, tc.method+" "+tc.path)
		resp := decodeControllerResp(t, recorder)
		require.Equal(t, false, resp["success"], tc.method+" "+tc.path)
	}
}

func TestRefreshUserInviteCode(t *testing.T) {
	setupInviteCodeControllerTestDB(t)

	common.OptionMapRWMutex.Lock()
	common.OptionMap["invite_code_preserve_history_enabled"] = "true"
	common.OptionMapRWMutex.Unlock()

	user := createInviteTestUser(t, "invite_refresh_user", "REFRESH-STALE")
	active := createInviteCodeRecord(t, user.Id, "REFRESH-CODE-OLD", 3, 0, common.GetTimestamp()+7200)

	ctx, recorder := newInviteCodeAuthedContext(http.MethodPost, "/api/user/invite-code/refresh", "{}", user.Id)
	RefreshUserInviteCode(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)
	resp := decodeControllerResp(t, recorder)
	require.Equal(t, true, resp["success"])

	data, ok := resp["data"].(map[string]any)
	require.True(t, ok)
	prev, ok := data["previous"].(map[string]any)
	require.True(t, ok)
	current, ok := data["current"].(map[string]any)
	require.True(t, ok)

	require.Equal(t, active.Code, prev["code"])
	require.NotEqual(t, prev["code"], current["code"])

	activeCode, err := model.GetActiveInviteCodeByUserID(user.Id)
	require.NoError(t, err)
	require.Equal(t, activeCode.Code, current["code"])

	require.NoError(t, model.DB.Model(&model.User{}).Where("id = ?", user.Id).Update("aff_code", "STALE-AFF-VALUE").Error)
	affCtx, affRecorder := newInviteCodeAuthedContext(http.MethodGet, "/api/user/aff", "", user.Id)
	GetAffCode(affCtx)
	affResp := decodeControllerResp(t, affRecorder)
	require.Equal(t, true, affResp["success"])
	require.Equal(t, activeCode.Code, affResp["data"])
}

func TestRefreshUserInviteCodeWithCustomLength(t *testing.T) {
	setupInviteCodeControllerTestDB(t)

	common.OptionMapRWMutex.Lock()
	common.OptionMap["invite_code_preserve_history_enabled"] = "true"
	common.OptionMapRWMutex.Unlock()

	user := createInviteTestUser(t, "invite_refresh_length_user", "REFRESH-LENGTH-STALE")
	createInviteCodeRecord(t, user.Id, "REFRESH-CODE-LEN", 3, 0, common.GetTimestamp()+7200)

	ctx, recorder := newInviteCodeAuthedContext(http.MethodPost, "/api/user/invite-code/refresh", `{"length":10}`, user.Id)
	RefreshUserInviteCode(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)
	resp := decodeControllerResp(t, recorder)
	require.Equal(t, true, resp["success"])

	data, ok := resp["data"].(map[string]any)
	require.True(t, ok)
	current, ok := data["current"].(map[string]any)
	require.True(t, ok)
	code, ok := current["code"].(string)
	require.True(t, ok)
	require.Len(t, code, 10)
}

func TestRefreshUserInviteCodeRejectsInvalidLength(t *testing.T) {
	setupInviteCodeControllerTestDB(t)

	common.OptionMapRWMutex.Lock()
	common.OptionMap["invite_code_preserve_history_enabled"] = "true"
	common.OptionMapRWMutex.Unlock()

	user := createInviteTestUser(t, "invite_refresh_invalid_length_user", "REFRESH-INVALID-STALE")
	createInviteCodeRecord(t, user.Id, "REFRESH-CODE-INVALID", 3, 0, common.GetTimestamp()+7200)

	ctx, recorder := newInviteCodeAuthedContext(http.MethodPost, "/api/user/invite-code/refresh", `{"length":3}`, user.Id)
	RefreshUserInviteCode(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)
	resp := decodeControllerResp(t, recorder)
	require.Equal(t, false, resp["success"])
}

func TestGetAffCode_PreservesLegacyAffCodeByBackfillWhenNoActiveRow(t *testing.T) {
	setupInviteCodeControllerTestDB(t)

	user := createInviteTestUser(t, "aff_legacy_backfill_user", "LGCY")
	ctx, recorder := newInviteCodeAuthedContext(http.MethodGet, "/api/user/aff", "", user.Id)
	GetAffCode(ctx)

	require.Equal(t, http.StatusOK, recorder.Code)
	resp := decodeControllerResp(t, recorder)
	require.Equal(t, true, resp["success"])
	require.Equal(t, "LGCY", resp["data"])

	active, err := model.GetActiveInviteCodeByUserID(user.Id)
	require.NoError(t, err)
	require.Equal(t, "LGCY", active.Code)
}

func TestListInviteCodeHistoryHonorsPreserveHistorySwitch(t *testing.T) {
	setupInviteCodeControllerTestDB(t)

	user := createInviteTestUser(t, "invite_history_user", "HISTORY-STALE")
	createInviteCodeRecord(t, user.Id, "HISTORY-CODE-INIT", 5, 0, common.GetTimestamp()+7200)

	visibleOld, _, err := model.RefreshInviteCode(nil, user.Id, true, 0)
	require.NoError(t, err)
	hiddenOld, _, err := model.RefreshInviteCode(nil, user.Id, false, 0)
	require.NoError(t, err)
	require.Equal(t, "", visibleOld.InvalidatedReason)
	require.Equal(t, "refresh_hidden", hiddenOld.InvalidatedReason)

	common.OptionMapRWMutex.Lock()
	common.OptionMap["invite_code_preserve_history_enabled"] = "true"
	common.OptionMapRWMutex.Unlock()
	ctxAll, recorderAll := newInviteCodeAuthedContext(http.MethodGet, "/api/user/invite-codes/history", "", user.Id)
	ListInviteCodeHistory(ctxAll)
	respAll := decodeControllerResp(t, recorderAll)
	require.Equal(t, true, respAll["success"])
	allCodes := extractInviteCodeSetFromHistoryResp(t, respAll)
	require.True(t, allCodes[visibleOld.Code])
	require.True(t, allCodes[hiddenOld.Code])

	common.OptionMapRWMutex.Lock()
	common.OptionMap["invite_code_preserve_history_enabled"] = "false"
	common.OptionMapRWMutex.Unlock()
	ctxFiltered, recorderFiltered := newInviteCodeAuthedContext(http.MethodGet, "/api/user/invite-codes/history", "", user.Id)
	ListInviteCodeHistory(ctxFiltered)
	respFiltered := decodeControllerResp(t, recorderFiltered)
	require.Equal(t, true, respFiltered["success"])
	filteredCodes := extractInviteCodeSetFromHistoryResp(t, respFiltered)
	require.True(t, filteredCodes[visibleOld.Code])
	require.False(t, filteredCodes[hiddenOld.Code])
}
