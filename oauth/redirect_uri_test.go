package oauth

import (
	stdtls "crypto/tls"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func newTestContext(method, target string, headers map[string]string, host string, useTLS bool) *gin.Context {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(method, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if host != "" {
		req.Host = host
	}
	if useTLS {
		req.TLS = &stdtls.ConnectionState{}
	}
	c.Request = req
	return c
}

func TestResolveOAuthRedirectURI_OriginHeaderHasHighestPriority(t *testing.T) {
	c := newTestContext("GET", "/api/oauth/discord", map[string]string{
		"Origin": "http://127.0.0.1:3001",
	}, "api.example.com", false)

	got := resolveOAuthRedirectURI(c, "/oauth/discord", "https://configured.example.com")
	want := "http://127.0.0.1:3001/oauth/discord"
	if got != want {
		t.Fatalf("unexpected redirect URI: got %q, want %q", got, want)
	}
}

func TestResolveOAuthRedirectURI_UsesForwardedHeadersWhenOriginMissing(t *testing.T) {
	c := newTestContext("GET", "/api/oauth/oidc", map[string]string{
		"X-Forwarded-Proto": "https, http",
		"X-Forwarded-Host":  "gw.example.com, internal.example.com",
	}, "127.0.0.1:3001", false)

	got := resolveOAuthRedirectURI(c, "/oauth/oidc", "https://configured.example.com")
	want := "https://gw.example.com/oauth/oidc"
	if got != want {
		t.Fatalf("unexpected redirect URI: got %q, want %q", got, want)
	}
}

func TestResolveOAuthRedirectURI_FallbacksToServerAddress(t *testing.T) {
	got := resolveOAuthRedirectURI(nil, "oauth/discord", "https://configured.example.com/")
	want := "https://configured.example.com/oauth/discord"
	if got != want {
		t.Fatalf("unexpected redirect URI: got %q, want %q", got, want)
	}
}

func TestResolveOAuthRedirectURI_InvalidFallbackReturnsPath(t *testing.T) {
	got := resolveOAuthRedirectURI(nil, "/oauth/custom", "configured-without-scheme")
	want := "/oauth/custom"
	if got != want {
		t.Fatalf("unexpected redirect URI: got %q, want %q", got, want)
	}
}

func TestResolveOAuthRedirectURI_NullOriginUsesFallback(t *testing.T) {
	c := newTestContext("GET", "/api/oauth/discord", map[string]string{
		"Origin": "null",
	}, "127.0.0.1:3001", false)

	got := resolveOAuthRedirectURI(c, "/oauth/discord", "http://127.0.0.1:3001")
	want := "http://127.0.0.1:3001/oauth/discord"
	if got != want {
		t.Fatalf("unexpected redirect URI: got %q, want %q", got, want)
	}
}

func TestResolveOAuthRedirectURI_EmptyForwardedProtoFallsBackToServerAddress(t *testing.T) {
	c := newTestContext("GET", "/api/oauth/discord", map[string]string{
		"X-Forwarded-Host": "na.dslzl.top",
	}, "na.dslzl.top", false)

	got := resolveOAuthRedirectURI(c, "/oauth/discord", "https://na.dslzl.top")
	want := "https://na.dslzl.top/oauth/discord"
	if got != want {
		t.Fatalf("unexpected redirect URI: got %q, want %q", got, want)
	}
}

func TestResolveOAuthRedirectURI_PreferHttpsServerAddressWhenOriginDowngrades(t *testing.T) {
	c := newTestContext("GET", "/api/oauth/discord", map[string]string{
		"Origin": "http://na.dslzl.top",
	}, "na.dslzl.top", false)

	got := resolveOAuthRedirectURI(c, "/oauth/discord", "https://na.dslzl.top")
	want := "https://na.dslzl.top/oauth/discord"
	if got != want {
		t.Fatalf("unexpected redirect URI: got %q, want %q", got, want)
	}
}

func TestResolveOAuthRedirectURI_KeepOriginWhenDifferentHost(t *testing.T) {
	c := newTestContext("GET", "/api/oauth/discord", map[string]string{
		"Origin": "http://localhost:3000",
	}, "localhost:3000", false)

	got := resolveOAuthRedirectURI(c, "/oauth/discord", "https://na.dslzl.top")
	want := "http://localhost:3000/oauth/discord"
	if got != want {
		t.Fatalf("unexpected redirect URI: got %q, want %q", got, want)
	}
}
