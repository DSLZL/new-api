package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestFingerprintCollectMiddleware_PrefersCallbackCapturedJA4OverHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	oldEnabled := common.FingerprintEnabled
	common.FingerprintEnabled = true
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
	})

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("ja4_fingerprint", "ja4-callback")
		c.Next()
	})
	r.Use(FingerprintCollectMiddleware())
	r.GET("/t", func(c *gin.Context) {
		require.Equal(t, "ja4-callback", c.GetString("ja4_fingerprint"))
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	req.Header.Set("X-JA4-Fingerprint", "ja4-header")
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
}

func TestFingerprintCollectMiddleware_LeavesJA4EmptyWhenCallbackMissing(t *testing.T) {
	gin.SetMode(gin.TestMode)
	oldEnabled := common.FingerprintEnabled
	common.FingerprintEnabled = true
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
	})

	r := gin.New()
	r.Use(FingerprintCollectMiddleware())
	r.GET("/t", func(c *gin.Context) {
		require.Equal(t, "", c.GetString("ja4_fingerprint"))
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	req.Header.Set("X-JA4-Fingerprint", "ja4-header")
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
}

func TestExtractRealIP_DoesNotTrustForwardedHeadersFromPublicRemote(t *testing.T) {
	gin.SetMode(gin.TestMode)
	oldTrustedCIDRs := common.FingerprintTrustedProxyCIDRs
	common.FingerprintTrustedProxyCIDRs = []string{"127.0.0.1/8", "::1/128"}
	t.Cleanup(func() {
		common.FingerprintTrustedProxyCIDRs = oldTrustedCIDRs
	})

	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	req.RemoteAddr = "198.51.100.77:443"
	req.Header.Set("X-Real-IP", "1.2.3.4")
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = req

	ip := ExtractRealIP(ctx)
	require.Equal(t, "198.51.100.77", ip)
}

func TestExtractRealIP_TrustsForwardedHeadersFromPrivateProxy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	oldTrustedCIDRs := common.FingerprintTrustedProxyCIDRs
	common.FingerprintTrustedProxyCIDRs = []string{"127.0.0.1/8", "::1/128"}
	t.Cleanup(func() {
		common.FingerprintTrustedProxyCIDRs = oldTrustedCIDRs
	})

	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	req.RemoteAddr = "127.0.0.1:443"
	req.Header.Set("X-Real-IP", "1.2.3.4")

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = req

	ip := ExtractRealIP(ctx)
	require.Equal(t, "1.2.3.4", ip)
}

func TestExtractRealIP_DoesNotTrustPrivateButUnlistedProxy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	oldTrustedCIDRs := common.FingerprintTrustedProxyCIDRs
	common.FingerprintTrustedProxyCIDRs = []string{"127.0.0.1/8", "::1/128"}
	t.Cleanup(func() {
		common.FingerprintTrustedProxyCIDRs = oldTrustedCIDRs
	})

	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	req.RemoteAddr = "10.0.0.10:443"
	req.Header.Set("X-Real-IP", "1.2.3.4")

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = req

	ip := ExtractRealIP(ctx)
	require.Equal(t, "10.0.0.10", ip)
}

func TestExtractRealIP_IgnoresInvalidForwardedHeaderIP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	oldTrustedCIDRs := common.FingerprintTrustedProxyCIDRs
	common.FingerprintTrustedProxyCIDRs = []string{"127.0.0.1/8", "::1/128"}
	t.Cleanup(func() {
		common.FingerprintTrustedProxyCIDRs = oldTrustedCIDRs
	})

	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	req.RemoteAddr = "127.0.0.1:443"
	req.Header.Set("X-Real-IP", "not-an-ip")
	req.Header.Set("X-Forwarded-For", "also-bad, 8.8.8.8")

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = req

	ip := ExtractRealIP(ctx)
	require.Equal(t, "8.8.8.8", ip)
}

func TestExtractRealIP_TrustsConfiguredPrivateProxyCIDR(t *testing.T) {
	gin.SetMode(gin.TestMode)
	oldTrustedCIDRs := common.FingerprintTrustedProxyCIDRs
	common.FingerprintTrustedProxyCIDRs = []string{"10.0.0.0/8"}
	t.Cleanup(func() {
		common.FingerprintTrustedProxyCIDRs = oldTrustedCIDRs
	})

	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	req.RemoteAddr = "10.1.2.3:443"
	req.Header.Set("X-Real-IP", "8.8.4.4")

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = req

	ip := ExtractRealIP(ctx)
	require.Equal(t, "8.8.4.4", ip)
}

func TestExtractRealIP_XFFSkipsTrustedProxiesFromRight(t *testing.T) {
	gin.SetMode(gin.TestMode)
	oldTrustedCIDRs := common.FingerprintTrustedProxyCIDRs
	common.FingerprintTrustedProxyCIDRs = []string{"10.0.0.0/8"}
	t.Cleanup(func() {
		common.FingerprintTrustedProxyCIDRs = oldTrustedCIDRs
	})

	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	req.RemoteAddr = "10.1.2.3:443"
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 198.51.100.12, 10.1.2.3")

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = req

	ip := ExtractRealIP(ctx)
	require.Equal(t, "198.51.100.12", ip)
}

func TestFingerprintCollectMiddleware_ExtractsHTTPHeaderFingerprint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	oldEnabled := common.FingerprintEnabled
	common.FingerprintEnabled = true
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
	})

	r := gin.New()
	r.Use(FingerprintCollectMiddleware())
	r.GET("/t", func(c *gin.Context) {
		hash := c.GetString("http_header_fingerprint")
		require.Len(t, hash, 32)
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-CH-UA", "\"Chromium\";v=\"123\"")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
}

func TestExtractHeaderFingerprint_StableForSameHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctxA, _ := gin.CreateTestContext(httptest.NewRecorder())
	reqA := httptest.NewRequest(http.MethodGet, "/t", nil)
	reqA.Header.Set("Accept", "application/json")
	reqA.Header.Set("Accept-Encoding", "gzip")
	reqA.Header.Set("Accept-Language", "en-US")
	reqA.Header.Set("DNT", "1")
	reqA.Header.Set("Sec-Fetch-Mode", "cors")
	reqA.Header.Set("Sec-Fetch-Site", "same-origin")
	reqA.Header.Set("Sec-CH-UA", "\"Chromium\";v=\"123\"")
	reqA.Header.Set("Sec-CH-UA-Platform", "\"Windows\"")
	reqA.Header.Set("Sec-CH-UA-Mobile", "?0")
	ctxA.Request = reqA

	ctxB, _ := gin.CreateTestContext(httptest.NewRecorder())
	reqB := httptest.NewRequest(http.MethodGet, "/t", nil)
	reqB.Header.Set("Accept", "application/json")
	reqB.Header.Set("Accept-Encoding", "gzip")
	reqB.Header.Set("Accept-Language", "en-US")
	reqB.Header.Set("DNT", "1")
	reqB.Header.Set("Sec-Fetch-Mode", "cors")
	reqB.Header.Set("Sec-Fetch-Site", "same-origin")
	reqB.Header.Set("Sec-CH-UA", "\"Chromium\";v=\"123\"")
	reqB.Header.Set("Sec-CH-UA-Platform", "\"Windows\"")
	reqB.Header.Set("Sec-CH-UA-Mobile", "?0")
	ctxB.Request = reqB

	hashA := extractHeaderFingerprint(ctxA)
	hashB := extractHeaderFingerprint(ctxB)
	require.NotEmpty(t, hashA)
	require.Equal(t, hashA, hashB)
}
