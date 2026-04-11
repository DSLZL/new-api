package controller

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/gin-gonic/gin"
)

func newETagTestContext(method string, target string) (*gin.Context, *httptest.ResponseRecorder) {
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(method, target, nil)
	return ctx, recorder
}

func TestETagTracker_ReturnsNewETagWhenNoIfNoneMatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousEnabled := common.FingerprintEnabled
	common.FingerprintEnabled = true
	t.Cleanup(func() {
		common.FingerprintEnabled = previousEnabled
	})

	ctx, recorder := newETagTestContext(http.MethodGet, "/api/static/fp.js")
	ETagTracker(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}

	etag := recorder.Header().Get("ETag")
	if etag == "" {
		t.Fatalf("expected ETag header to be set")
	}
	if !strings.HasPrefix(etag, "\"") || !strings.HasSuffix(etag, "\"") {
		t.Fatalf("expected ETag to be quoted, got %q", etag)
	}

	cacheControl := recorder.Header().Get("Cache-Control")
	if cacheControl != "private, max-age=31536000" {
		t.Fatalf("unexpected Cache-Control: %q", cacheControl)
	}

	contentType := recorder.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/javascript") {
		t.Fatalf("expected javascript content type, got %q", contentType)
	}
}

func TestETagTracker_ReusesIfNoneMatchAndReturns304(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousEnabled := common.FingerprintEnabled
	common.FingerprintEnabled = true
	t.Cleanup(func() {
		common.FingerprintEnabled = previousEnabled
	})

	ctx, recorder := newETagTestContext(http.MethodGet, "/api/static/fp.js")
	ctx.Request.Header.Set("If-None-Match", "\"550e8400-e29b-41d4-a716-446655440000\"")
	if got := ctx.Request.Header.Get("If-None-Match"); got == "" {
		t.Fatalf("expected test request If-None-Match header to be set")
	}
	if got := ctx.GetHeader("If-None-Match"); got == "" {
		t.Fatalf("expected gin context to read If-None-Match header")
	}

	ETagTracker(ctx)

	if recorder.Code != http.StatusNotModified {
		t.Fatalf("expected status %d, got %d", http.StatusNotModified, recorder.Code)
	}

	etag := recorder.Header().Get("ETag")
	if etag != "\"550e8400-e29b-41d4-a716-446655440000\"" {
		t.Fatalf("expected echoed ETag %q, got %q", "\"550e8400-e29b-41d4-a716-446655440000\"", etag)
	}
}

func TestETagTracker_InvalidIfNoneMatchFallsBackTo200(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousEnabled := common.FingerprintEnabled
	common.FingerprintEnabled = true
	t.Cleanup(func() {
		common.FingerprintEnabled = previousEnabled
	})

	ctx, recorder := newETagTestContext(http.MethodGet, "/api/static/fp.js")
	ctx.Request.Header.Set("If-None-Match", "\"persist-123\"")

	ETagTracker(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}

	etag := recorder.Header().Get("ETag")
	if etag == "\"persist-123\"" {
		t.Fatalf("expected invalid If-None-Match to be rejected")
	}
}

func TestETagTracker_DisabledDoesNotReturnETagOr304(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousEnabled := common.FingerprintEnabled
	previousETagEnabled := common.FingerprintEnableETag
	common.FingerprintEnabled = true
	common.FingerprintEnableETag = false
	t.Cleanup(func() {
		common.FingerprintEnabled = previousEnabled
		common.FingerprintEnableETag = previousETagEnabled
	})

	ctx, recorder := newETagTestContext(http.MethodGet, "/api/static/fp.js")
	ctx.Request.Header.Set("If-None-Match", "\"550e8400-e29b-41d4-a716-446655440000\"")

	ETagTracker(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
	if etag := recorder.Header().Get("ETag"); etag != "" {
		t.Fatalf("expected ETag header to be empty when disabled, got %q", etag)
	}
}
