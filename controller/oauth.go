package controller

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/oauth"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const (
	OAuthCodeInviteRequired  = "INVITE_REQUIRED"
	OAuthCodePendingNotFound = "OAUTH_PENDING_NOT_FOUND"
	OAuthCodePendingExpired  = "OAUTH_PENDING_EXPIRED"
)

const oauthPendingSessionKey = "oauth_pending_registration"
const oauthPendingSessionTTL = 10 * time.Minute

type pendingOAuthRegistration struct {
	Provider       string `json:"provider"`
	ProviderUserID string `json:"provider_user_id"`
	Username       string `json:"username"`
	DisplayName    string `json:"display_name"`
	Email          string `json:"email"`
	ExpiresAt      int64  `json:"expires_at"`
}

type OAuthInviteRequiredError struct {
	Pending *pendingOAuthRegistration
}

func (e *OAuthInviteRequiredError) Error() string {
	return "invite code required for oauth registration"
}

func (e *OAuthInviteRequiredError) Code() string {
	return OAuthCodeInviteRequired
}

func buildPendingOAuthRegistration(provider oauth.Provider, oauthUser *oauth.OAuthUser) *pendingOAuthRegistration {
	username := provider.GetProviderPrefix() + strconv.Itoa(model.GetMaxUserId()+1)
	if oauthUser.Username != "" {
		if exists, err := model.CheckUserExistOrDeleted(oauthUser.Username, ""); err == nil && !exists {
			if len(oauthUser.Username) <= model.UserNameMaxLength {
				username = oauthUser.Username
			}
		}
	}

	displayName := provider.GetName() + " User"
	if oauthUser.DisplayName != "" {
		displayName = oauthUser.DisplayName
	} else if oauthUser.Username != "" {
		displayName = oauthUser.Username
	}

	email := strings.TrimSpace(oauthUser.Email)
	if email != "" {
		if exists, err := model.CheckUserExistOrDeleted("", email); err != nil || exists {
			email = ""
		}
	}

	return &pendingOAuthRegistration{
		Provider:       provider.GetName(),
		ProviderUserID: oauthUser.ProviderUserID,
		Username:       username,
		DisplayName:    displayName,
		Email:          email,
		ExpiresAt:      time.Now().Add(oauthPendingSessionTTL).Unix(),
	}
}

func persistPendingOAuthRegistration(session sessions.Session, pending *pendingOAuthRegistration) error {
	session.Set(oauthPendingSessionKey, pending)
	session.Delete("aff")
	return session.Save()
}

func clearPendingOAuthRegistration(session sessions.Session) error {
	session.Delete(oauthPendingSessionKey)
	return session.Save()
}

func readPendingOAuthRegistration(session sessions.Session) (*pendingOAuthRegistration, error) {
	raw := session.Get(oauthPendingSessionKey)
	if raw == nil {
		return nil, &OAuthPendingNotFoundError{}
	}

	var pending pendingOAuthRegistration
	switch v := raw.(type) {
	case pendingOAuthRegistration:
		pending = v
	case *pendingOAuthRegistration:
		if v == nil {
			return nil, &OAuthPendingNotFoundError{}
		}
		pending = *v
	case map[string]any:
		if provider, ok := v["provider"].(string); ok {
			pending.Provider = provider
		}
		if providerUserId, ok := v["provider_user_id"].(string); ok {
			pending.ProviderUserID = providerUserId
		}
		if username, ok := v["username"].(string); ok {
			pending.Username = username
		}
		if displayName, ok := v["display_name"].(string); ok {
			pending.DisplayName = displayName
		}
		if email, ok := v["email"].(string); ok {
			pending.Email = email
		}
		switch exp := v["expires_at"].(type) {
		case int64:
			pending.ExpiresAt = exp
		case int:
			pending.ExpiresAt = int64(exp)
		case float64:
			pending.ExpiresAt = int64(exp)
		}
	default:
		return nil, &OAuthPendingNotFoundError{}
	}

	if pending.Provider == "" || pending.ProviderUserID == "" || pending.Username == "" {
		return nil, &OAuthPendingNotFoundError{}
	}
	return &pending, nil
}

func jsonOAuthBusinessError(c *gin.Context, code string, message string) {
	c.JSON(http.StatusOK, gin.H{
		"success": false,
		"message": message,
		"data": gin.H{
			"code": code,
		},
	})
}

// providerParams returns map with Provider key for i18n templates
func providerParams(name string) map[string]any {
	return map[string]any{"Provider": name}
}

// GenerateOAuthCode generates a state code for OAuth CSRF protection
func GenerateOAuthCode(c *gin.Context) {
	session := sessions.Default(c)
	state := common.GetRandomString(12)
	affCode := c.Query("aff")
	if affCode != "" {
		session.Set("aff", affCode)
	}
	session.Set("oauth_state", state)
	err := session.Save()
	if err != nil {
		common.ApiError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data":    state,
	})
}

// HandleOAuth handles OAuth callback for all standard OAuth providers
func HandleOAuth(c *gin.Context) {
	providerName := c.Param("provider")
	provider := oauth.GetProvider(providerName)
	if provider == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": i18n.T(c, i18n.MsgOAuthUnknownProvider),
		})
		return
	}

	session := sessions.Default(c)

	// 1. Validate state (CSRF protection)
	state := c.Query("state")
	if state == "" || session.Get("oauth_state") == nil || state != session.Get("oauth_state").(string) {
		c.JSON(http.StatusForbidden, gin.H{
			"success": false,
			"message": i18n.T(c, i18n.MsgOAuthStateInvalid),
		})
		return
	}

	// 2. Check if user is already logged in (bind flow)
	username := session.Get("username")
	if username != nil {
		handleOAuthBind(c, provider)
		return
	}

	// 3. Check if provider is enabled
	if !provider.IsEnabled() {
		common.ApiErrorI18n(c, i18n.MsgOAuthNotEnabled, providerParams(provider.GetName()))
		return
	}

	// 4. Handle error from provider
	errorCode := c.Query("error")
	if errorCode != "" {
		errorDescription := c.Query("error_description")
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": errorDescription,
		})
		return
	}

	// 5. Exchange code for token
	code := c.Query("code")
	token, err := provider.ExchangeToken(c.Request.Context(), code, c)
	if err != nil {
		handleOAuthError(c, err)
		return
	}

	// 6. Get user info
	oauthUser, err := provider.GetUserInfo(c.Request.Context(), token)
	if err != nil {
		handleOAuthError(c, err)
		return
	}

	// 7. Find or create user
	user, err := findOrCreateOAuthUser(c, provider, oauthUser, session)
	if err != nil {
		switch e := err.(type) {
		case *OAuthInviteRequiredError:
			if saveErr := persistPendingOAuthRegistration(session, e.Pending); saveErr != nil {
				common.ApiError(c, saveErr)
				return
			}
			jsonOAuthBusinessError(c, e.Code(), i18n.T(c, i18n.MsgUserAffCodeEmpty))
		case *OAuthUserDeletedError:
			common.ApiErrorI18n(c, i18n.MsgOAuthUserDeleted)
		case *OAuthRegistrationDisabledError:
			common.ApiErrorI18n(c, i18n.MsgUserRegisterDisabled)
		default:
			common.ApiError(c, err)
		}
		return
	}

	// 8. Check user status
	if user.Status != common.UserStatusEnabled {
		common.ApiErrorI18n(c, i18n.MsgOAuthUserBanned)
		return
	}

	// 9. Setup login
	setupLogin(user, c)
}

// handleOAuthBind handles binding OAuth account to existing user
func handleOAuthBind(c *gin.Context, provider oauth.Provider) {
	if !provider.IsEnabled() {
		common.ApiErrorI18n(c, i18n.MsgOAuthNotEnabled, providerParams(provider.GetName()))
		return
	}

	// Exchange code for token
	code := c.Query("code")
	token, err := provider.ExchangeToken(c.Request.Context(), code, c)
	if err != nil {
		handleOAuthError(c, err)
		return
	}

	// Get user info
	oauthUser, err := provider.GetUserInfo(c.Request.Context(), token)
	if err != nil {
		handleOAuthError(c, err)
		return
	}

	// Check if this OAuth account is already bound (check both new ID and legacy ID)
	if provider.IsUserIDTaken(oauthUser.ProviderUserID) {
		common.ApiErrorI18n(c, i18n.MsgOAuthAlreadyBound, providerParams(provider.GetName()))
		return
	}
	// Also check legacy ID to prevent duplicate bindings during migration period
	if legacyID, ok := oauthUser.Extra["legacy_id"].(string); ok && legacyID != "" {
		if provider.IsUserIDTaken(legacyID) {
			common.ApiErrorI18n(c, i18n.MsgOAuthAlreadyBound, providerParams(provider.GetName()))
			return
		}
	}

	// Get current user from session
	session := sessions.Default(c)
	id := session.Get("id")
	user := model.User{Id: id.(int)}
	err = user.FillUserById()
	if err != nil {
		common.ApiError(c, err)
		return
	}

	// Handle binding based on provider type
	if genericProvider, ok := provider.(*oauth.GenericOAuthProvider); ok {
		// Custom provider: use user_oauth_bindings table
		err = model.UpdateUserOAuthBinding(user.Id, genericProvider.GetProviderId(), oauthUser.ProviderUserID)
		if err != nil {
			common.ApiError(c, err)
			return
		}
	} else {
		// Built-in provider: update user record directly
		provider.SetProviderUserID(&user, oauthUser.ProviderUserID)
		err = user.Update(false)
		if err != nil {
			common.ApiError(c, err)
			return
		}
	}

	common.ApiSuccessI18n(c, i18n.MsgOAuthBindSuccess, gin.H{
		"action": "bind",
	})
}

// findOrCreateOAuthUser finds existing user or creates new user
func findOrCreateOAuthUser(c *gin.Context, provider oauth.Provider, oauthUser *oauth.OAuthUser, session sessions.Session) (*model.User, error) {
	user := &model.User{}

	// Check if user already exists with new ID
	if provider.IsUserIDTaken(oauthUser.ProviderUserID) {
		err := provider.FillUserByProviderID(user, oauthUser.ProviderUserID)
		if err != nil {
			return nil, err
		}
		// Check if user has been deleted
		if user.Id == 0 {
			return nil, &OAuthUserDeletedError{}
		}
		return user, nil
	}

	// Try to find user with legacy ID (for GitHub migration from login to numeric ID)
	if legacyID, ok := oauthUser.Extra["legacy_id"].(string); ok && legacyID != "" {
		if provider.IsUserIDTaken(legacyID) {
			err := provider.FillUserByProviderID(user, legacyID)
			if err != nil {
				return nil, err
			}
			if user.Id != 0 {
				// Found user with legacy ID, migrate to new ID
				common.SysLog(fmt.Sprintf("[OAuth] Migrating user %d from legacy_id=%s to new_id=%s",
					user.Id, legacyID, oauthUser.ProviderUserID))
				if err := user.UpdateGitHubId(oauthUser.ProviderUserID); err != nil {
					common.SysError(fmt.Sprintf("[OAuth] Failed to migrate user %d: %s", user.Id, err.Error()))
					// Continue with login even if migration fails
				}
				return user, nil
			}
		}
	}

	// User doesn't exist, create new user if registration is enabled
	if !common.RegisterEnabled {
		return nil, &OAuthRegistrationDisabledError{}
	}

	pending := buildPendingOAuthRegistration(provider, oauthUser)

	// Handle affiliate code
	affCode := ""
	if rawAffCode := session.Get("aff"); rawAffCode != nil {
		if strAffCode, ok := rawAffCode.(string); ok {
			affCode = strAffCode
		}
	}

	inviterId := 0
	if common.InviteOnlyRegistrationEnabled {
		resolvedInviterId, resolveErr := model.ResolveInviterIDFromAffCode(affCode)
		if resolveErr != nil {
			if errors.Is(resolveErr, model.ErrInviteCodeRequired) || errors.Is(resolveErr, model.ErrInviteCodeInvalid) {
				return nil, &OAuthInviteRequiredError{Pending: pending}
			}
			return nil, resolveErr
		}
		inviterId = resolvedInviterId
	} else if normalizedAffCode := model.NormalizeAffCode(affCode); normalizedAffCode != "" {
		inviterId, _ = model.GetUserIdByAffCode(normalizedAffCode)
	}

	// Set up new user
	user.Username = pending.Username
	user.DisplayName = pending.DisplayName
	user.Email = pending.Email
	user.Role = common.RoleCommonUser
	user.Status = common.UserStatusEnabled

	// Use transaction to ensure user creation and OAuth binding are atomic
	if genericProvider, ok := provider.(*oauth.GenericOAuthProvider); ok {
		// Custom provider: create user and binding in a transaction
		err := model.DB.Transaction(func(tx *gorm.DB) error {
			// Create user
			if err := user.InsertWithTx(tx, inviterId); err != nil {
				return err
			}

			// Create OAuth binding
			binding := &model.UserOAuthBinding{
				UserId:         user.Id,
				ProviderId:     genericProvider.GetProviderId(),
				ProviderUserId: oauthUser.ProviderUserID,
			}
			if err := model.CreateUserOAuthBindingWithTx(tx, binding); err != nil {
				return err
			}

			return nil
		})
		if err != nil {
			return nil, err
		}

		// Perform post-transaction tasks (logs, sidebar config, inviter rewards)
		user.FinalizeOAuthUserCreation(inviterId)
	} else {
		// Built-in provider: create user and update provider ID in a transaction
		err := model.DB.Transaction(func(tx *gorm.DB) error {
			// Create user
			if err := user.InsertWithTx(tx, inviterId); err != nil {
				return err
			}

			// Set the provider user ID on the user model and update
			provider.SetProviderUserID(user, oauthUser.ProviderUserID)
			if err := tx.Model(user).Updates(map[string]interface{}{
				"github_id":   user.GitHubId,
				"discord_id":  user.DiscordId,
				"oidc_id":     user.OidcId,
				"linux_do_id": user.LinuxDOId,
				"wechat_id":   user.WeChatId,
				"telegram_id": user.TelegramId,
			}).Error; err != nil {
				return err
			}

			return nil
		})
		if err != nil {
			return nil, err
		}

		// Perform post-transaction tasks
		user.FinalizeOAuthUserCreation(inviterId)
	}

	return user, nil
}

func ContinueOAuthWithInvite(c *gin.Context) {
	if !common.RegisterEnabled {
		common.ApiErrorI18n(c, i18n.MsgUserRegisterDisabled)
		return
	}

	var req struct {
		InviteCode string `json:"invite_code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		common.ApiErrorI18n(c, i18n.MsgInvalidParams)
		return
	}

	session := sessions.Default(c)
	pending, pendingErr := readPendingOAuthRegistration(session)
	if pendingErr != nil {
		switch pendingErr.(type) {
		case *OAuthPendingNotFoundError:
			jsonOAuthBusinessError(c, OAuthCodePendingNotFound, i18n.T(c, i18n.MsgInvalidParams))
		default:
			common.ApiError(c, pendingErr)
		}
		return
	}
	if pending.ExpiresAt <= time.Now().Unix() {
		_ = clearPendingOAuthRegistration(session)
		jsonOAuthBusinessError(c, OAuthCodePendingExpired, i18n.T(c, i18n.MsgInvalidParams))
		return
	}

	inviterId, resolveErr := model.ResolveInviterIDFromAffCode(req.InviteCode)
	if resolveErr != nil {
		if errors.Is(resolveErr, model.ErrInviteCodeRequired) || errors.Is(resolveErr, model.ErrInviteCodeInvalid) {
			jsonOAuthBusinessError(c, InviteCodeInvalidCode, i18n.T(c, i18n.MsgInvalidParams))
			return
		}
		common.ApiError(c, resolveErr)
		return
	}

	provider := oauth.GetProvider(strings.ToLower(pending.Provider))
	if provider == nil {
		_ = clearPendingOAuthRegistration(session)
		common.ApiErrorI18n(c, i18n.MsgOAuthUnknownProvider)
		return
	}
	if !provider.IsEnabled() {
		_ = clearPendingOAuthRegistration(session)
		common.ApiErrorI18n(c, i18n.MsgOAuthNotEnabled, providerParams(provider.GetName()))
		return
	}
	if provider.IsUserIDTaken(pending.ProviderUserID) {
		// Another session may have completed registration first.
		user := &model.User{}
		if err := provider.FillUserByProviderID(user, pending.ProviderUserID); err != nil {
			common.ApiError(c, err)
			return
		}
		if user.Id == 0 {
			_ = clearPendingOAuthRegistration(session)
			common.ApiErrorI18n(c, i18n.MsgOAuthUserDeleted)
			return
		}
		_ = clearPendingOAuthRegistration(session)
		setupLogin(user, c)
		return
	}

	user := &model.User{
		Username:    pending.Username,
		DisplayName: pending.DisplayName,
		Email:       pending.Email,
		Role:        common.RoleCommonUser,
		Status:      common.UserStatusEnabled,
	}
	if err := model.DB.Transaction(func(tx *gorm.DB) error {
		if err := user.InsertWithTx(tx, inviterId); err != nil {
			return err
		}
		if genericProvider, ok := provider.(*oauth.GenericOAuthProvider); ok {
			binding := &model.UserOAuthBinding{
				UserId:         user.Id,
				ProviderId:     genericProvider.GetProviderId(),
				ProviderUserId: pending.ProviderUserID,
			}
			if err := model.CreateUserOAuthBindingWithTx(tx, binding); err != nil {
				return err
			}
			return nil
		}

		provider.SetProviderUserID(user, pending.ProviderUserID)
		return tx.Model(user).Updates(map[string]interface{}{
			"github_id":   user.GitHubId,
			"discord_id":  user.DiscordId,
			"oidc_id":     user.OidcId,
			"linux_do_id": user.LinuxDOId,
			"wechat_id":   user.WeChatId,
			"telegram_id": user.TelegramId,
		}).Error
	}); err != nil {
		common.ApiError(c, err)
		return
	}

	user.FinalizeOAuthUserCreation(inviterId)
	if err := clearPendingOAuthRegistration(session); err != nil {
		common.ApiError(c, err)
		return
	}
	setupLogin(user, c)
}

// Error types for OAuth
type OAuthUserDeletedError struct{}

func (e *OAuthUserDeletedError) Error() string {
	return "user has been deleted"
}

type OAuthRegistrationDisabledError struct{}

func (e *OAuthRegistrationDisabledError) Error() string {
	return "registration is disabled"
}

type OAuthPendingNotFoundError struct{}

func (e *OAuthPendingNotFoundError) Error() string {
	return "oauth pending registration not found"
}

// handleOAuthError handles OAuth errors and returns translated message
func handleOAuthError(c *gin.Context, err error) {
	switch e := err.(type) {
	case *oauth.OAuthError:
		if e.Params != nil {
			common.ApiErrorI18n(c, e.MsgKey, e.Params)
		} else {
			common.ApiErrorI18n(c, e.MsgKey)
		}
	case *oauth.AccessDeniedError:
		common.ApiErrorMsg(c, e.Message)
	case *oauth.TrustLevelError:
		common.ApiErrorI18n(c, i18n.MsgOAuthTrustLevelLow)
	default:
		common.ApiError(c, err)
	}
}
