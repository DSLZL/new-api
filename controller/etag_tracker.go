package controller

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ETagTracker GET /api/static/fp.js
func ETagTracker(c *gin.Context) {
	if !common.FingerprintEnabled {
		c.Data(http.StatusOK, "application/javascript", []byte("/* fingerprint disabled */"))
		return
	}
	if !common.FingerprintEnableETag {
		c.Header("Cache-Control", "no-store")
		c.Header("Vary", "Cookie, Authorization")
		c.Data(http.StatusOK, "application/javascript", []byte("/* etag disabled */"))
		return
	}

	userID := c.GetInt("id")
	realIP := c.GetString("real_ip")
	if realIP == "" {
		realIP = middleware.ExtractRealIP(c)
	}
	userAgent := c.GetHeader("User-Agent")
	referer := c.Request.Referer()

	if trackingID, ok := parseValidTrackingID(c.GetHeader("If-None-Match")); ok {
		recordETagVisit(userID, realIP, userAgent, referer, trackingID)
		c.Header("ETag", fmt.Sprintf("\"%s\"", trackingID))
		c.Header("Cache-Control", "private, max-age=31536000")
		c.Header("Vary", "Cookie, Authorization")
		c.AbortWithStatus(http.StatusNotModified)
		return
	}

	trackingID := uuid.NewString()
	recordETagVisit(userID, realIP, userAgent, referer, trackingID)
	c.Header("ETag", fmt.Sprintf("\"%s\"", trackingID))
	c.Header("Cache-Control", "private, max-age=31536000")
	c.Header("Vary", "Cookie, Authorization")
	c.Data(http.StatusOK, "application/javascript", []byte("/* fp */"))
}

func parseValidTrackingID(raw string) (string, bool) {
	etag := strings.TrimSpace(raw)
	if etag == "" {
		return "", false
	}
	etag = strings.TrimPrefix(etag, "W/")
	etag = strings.Trim(etag, "\"")
	if etag == "" || len(etag) > 64 {
		return "", false
	}
	if _, err := uuid.Parse(etag); err != nil {
		return "", false
	}
	return etag, true
}

func recordETagVisit(userID int, realIP string, userAgent string, referer string, trackingID string) {
	if trackingID == "" || userID <= 0 {
		return
	}

	pageURL := sanitizePageURL(referer)
	go func(userID int, realIP string, userAgent string, trackingID string, pageURL string) {
		defer func() {
			if recover() != nil {
				return
			}
		}()

		parsedUA := common.ParseUserAgent(userAgent)
		ipInfo := service.LookupIP(realIP)
		fp := &model.Fingerprint{
			UserID:       userID,
			IPAddress:    realIP,
			IPCountry:    ipInfo.Country,
			IPRegion:     ipInfo.Region,
			IPCity:       ipInfo.City,
			IPISP:        ipInfo.ISP,
			IPType:       ipInfo.Type,
			UserAgent:    userAgent,
			UABrowser:    parsedUA.Browser,
			UABrowserVer: parsedUA.BrowserVer,
			UAOS:         parsedUA.OS,
			UAOSVer:      parsedUA.OSVer,
			UADeviceType: parsedUA.DeviceType,
			ETagID:       trackingID,
			PageURL:      pageURL,
		}
		if err := fp.Insert(); err != nil {
			return
		}
		service.IncrementalLinkScan(userID, fp)
	}(userID, realIP, userAgent, trackingID, pageURL)
}
