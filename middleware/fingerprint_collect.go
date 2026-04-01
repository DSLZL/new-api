package middleware

import (
	"net"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

// FingerprintCollectMiddleware IP/UA 采集中间件
func FingerprintCollectMiddleware() gin.HandlerFunc {
	if !common.FingerprintEnabled {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	return func(c *gin.Context) {
		// 1. 提取真实IP
		ip := ExtractRealIP(c)
		c.Set("real_ip", ip)

		// 2. 解析UA
		ua := c.GetHeader("User-Agent")
		parsedUA := common.ParseUserAgent(ua)
		c.Set("parsed_ua", parsedUA)

		c.Next()

		// 3. 确定用户 ID —— 两个来源
		userID := 0

		// 来源 A: auth 中间件注入的 id（已登录用户的常规请求）
		if idRaw, exists := c.Get("id"); exists {
			if uid, ok := idRaw.(int); ok && uid > 0 {
				userID = uid
			}
		}

		// ★ 来源 B: 注册 handler 注入的 new_user_id（注册请求无 token，但 handler 创建用户后可设置）
		if userID == 0 {
			if newIDRaw, exists := c.Get("new_user_id"); exists {
				if uid, ok := newIDRaw.(int); ok && uid > 0 {
					userID = uid
				}
			}
		}

		if userID > 0 {
			// 异步记录
			go func(uid int, ipAddr, rawUA string, pua *common.ParsedUA, endpoint string) {
				defer func() {
					if r := recover(); r != nil {
						// 静默处理panic
					}
				}()

				ipInfo := service.LookupIP(ipAddr)

				record := &model.IPUAHistory{
					UserID:       uid,
					IPAddress:    ipAddr,
					UserAgent:    rawUA,
					IPCountry:    ipInfo.Country,
					IPRegion:     ipInfo.Region,
					IPCity:       ipInfo.City,
					IPISP:        ipInfo.ISP,
					IPType:       ipInfo.Type,
					IPRiskScore:  float32(ipInfo.Risk),
					UABrowser:    pua.Browser,
					UABrowserVer: pua.BrowserVer,
					UAOS:         pua.OS,
					UAOSVer:      pua.OSVer,
					UADevice:     pua.DeviceType,
					Endpoint:     endpoint,
				}
				_ = model.UpsertIPUAHistory(record)
			}(userID, ip, ua, parsedUA, c.Request.URL.Path)
		}
	}
}

// ExtractRealIP 从请求中提取真实IP
func ExtractRealIP(c *gin.Context) string {
	// 优先级: CF-Connecting-IP > X-Real-IP > True-Client-IP > X-Forwarded-For > RemoteAddr
	headers := []string{
		"CF-Connecting-IP",
		"X-Real-IP",
		"True-Client-IP",
	}
	for _, h := range headers {
		ip := c.GetHeader(h)
		if ip != "" {
			return strings.TrimSpace(ip)
		}
	}

	// X-Forwarded-For: 取第一个非内网IP
	xff := c.GetHeader("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		for _, part := range parts {
			ip := strings.TrimSpace(part)
			if ip != "" && !isPrivateIP(ip) {
				return ip
			}
		}
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}

	// RemoteAddr
	ip, _, err := net.SplitHostPort(c.Request.RemoteAddr)
	if err != nil {
		return c.Request.RemoteAddr
	}
	return ip
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
	}
	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
