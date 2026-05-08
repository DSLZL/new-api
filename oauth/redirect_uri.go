package oauth

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/gin-gonic/gin"
)

// buildOAuthRedirectURI builds redirect_uri for OAuth token exchange.
// Priority: Origin header -> forwarded/request host -> configured ServerAddress.
func buildOAuthRedirectURI(c *gin.Context, callbackPath string) string {
	return resolveOAuthRedirectURI(c, callbackPath, system_setting.ServerAddress)
}

func resolveOAuthRedirectURI(c *gin.Context, callbackPath string, serverAddress string) string {
	path := normalizeCallbackPath(callbackPath)
	fallback := normalizeOrigin(serverAddress)
	origin := requestOrigin(c)

	if origin != "" {
		if shouldPreferFallbackOverOrigin(fallback, origin) {
			return fallback + path
		}
		return origin + path
	}

	if fallback != "" {
		return fallback + path
	}

	return path
}

// Prevent proxy/header-induced HTTPS downgrade for OAuth redirect_uri.
// If configured ServerAddress is https on the same host while request-derived
// origin is http, prefer configured https value.
func shouldPreferFallbackOverOrigin(fallback string, origin string) bool {
	if fallback == "" || origin == "" {
		return false
	}
	fallbackURL, err := url.Parse(fallback)
	if err != nil {
		return false
	}
	originURL, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if strings.ToLower(strings.TrimSpace(fallbackURL.Scheme)) != "https" {
		return false
	}
	if strings.ToLower(strings.TrimSpace(originURL.Scheme)) != "http" {
		return false
	}
	fallbackHost := strings.ToLower(strings.TrimSpace(fallbackURL.Hostname()))
	originHost := strings.ToLower(strings.TrimSpace(originURL.Hostname()))
	if fallbackHost == "" || originHost == "" {
		return false
	}
	return fallbackHost == originHost
}

func requestOrigin(c *gin.Context) string {
	if c == nil || c.Request == nil {
		return ""
	}

	if origin := normalizeOrigin(c.GetHeader("Origin")); origin != "" {
		return origin
	}

	scheme := firstHeaderValue(c.GetHeader("X-Forwarded-Proto"))
	if scheme == "" {
		if c.Request.URL != nil && c.Request.URL.Scheme != "" {
			scheme = c.Request.URL.Scheme
		} else if c.Request.TLS != nil {
			scheme = "https"
		}
	}
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	if scheme != "http" && scheme != "https" {
		return ""
	}

	host := firstHeaderValue(c.GetHeader("X-Forwarded-Host"))
	if host == "" {
		host = strings.TrimSpace(c.Request.Host)
	}
	if host == "" {
		return ""
	}

	if strings.Contains(host, "://") {
		if parsed := normalizeOrigin(host); parsed != "" {
			return parsed
		}
		return ""
	}

	return fmt.Sprintf("%s://%s", scheme, host)
}

func normalizeOrigin(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.EqualFold(raw, "null") {
		return ""
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}

	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	host := strings.TrimSpace(parsed.Host)
	if scheme == "" || host == "" {
		return ""
	}
	if scheme != "http" && scheme != "https" {
		return ""
	}

	return fmt.Sprintf("%s://%s", scheme, host)
}

func normalizeCallbackPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}

func firstHeaderValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if before, _, found := strings.Cut(v, ","); found {
		return strings.TrimSpace(before)
	}
	return v
}
