package middleware

import (
	"crypto/md5"
	"encoding/hex"
	"net"
	"sort"
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
		ja4 := c.GetString("ja4_fingerprint")
		if ja4 == "" {
			ja4 = service.GetTLSJA4FromRemoteAddr(c.Request.RemoteAddr)
		}
		httpHeaderFP := extractHeaderFingerprint(c)
		parsedUA := common.ParseUserAgent(ua)
		c.Set("parsed_ua", parsedUA)
		c.Set("ja4_fingerprint", ja4)
		c.Set("http_header_fingerprint", httpHeaderFP)

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
					ASN:          ipInfo.ASN,
					ASNOrg:       ipInfo.ASNOrg,
					IsDatacenter: ipInfo.IsDatacenter,
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
	remoteIP, _, err := net.SplitHostPort(c.Request.RemoteAddr)
	if err != nil {
		remoteIP = c.Request.RemoteAddr
	}
	remoteIP = strings.TrimSpace(remoteIP)

	if !shouldTrustForwardedHeaders(remoteIP) {
		return remoteIP
	}

	// 优先级: CF-Connecting-IP > X-Real-IP > True-Client-IP > X-Forwarded-For > RemoteAddr
	headers := []string{
		"CF-Connecting-IP",
		"X-Real-IP",
		"True-Client-IP",
	}
	for _, h := range headers {
		ip := strings.TrimSpace(c.GetHeader(h))
		if isValidForwardedIP(ip) {
			return ip
		}
	}

	// X-Forwarded-For: 从右向左剥离受信代理，取第一个不在受信代理列表中的合法IP
	xff := c.GetHeader("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(parts[i])
			if !isValidForwardedIP(ip) {
				continue
			}
			parsed := net.ParseIP(ip)
			if parsed == nil {
				continue
			}
			if isTrustedForwardedProxyIP(parsed) {
				continue
			}
			return ip
		}
	}

	return remoteIP
}

func shouldTrustForwardedHeaders(remoteIP string) bool {
	if remoteIP == "" {
		return false
	}
	ip := net.ParseIP(remoteIP)
	if ip == nil {
		return false
	}
	return isTrustedForwardedProxyIP(ip)
}

func isTrustedForwardedProxyIP(ip net.IP) bool {
	for _, cidr := range common.FingerprintTrustedProxyCIDRs {
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

func isValidForwardedIP(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() {
		return false
	}
	return true
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

func extractHeaderFingerprint(c *gin.Context) string {
	if c == nil || c.Request == nil {
		return ""
	}

	headerNames := make([]string, 0, len(c.Request.Header))
	for name := range c.Request.Header {
		headerNames = append(headerNames, strings.ToLower(name))
	}
	sort.Strings(headerNames)
	orderHash := md5Hex(strings.Join(headerNames, ","))

	acceptSeries := strings.Join([]string{
		strings.TrimSpace(c.GetHeader("Accept")),
		strings.TrimSpace(c.GetHeader("Accept-Encoding")),
		strings.TrimSpace(c.GetHeader("Accept-Language")),
	}, "|")
	acceptHash := md5Hex(acceptSeries)

	presenceBits := make([]string, 0, 5)
	presenceKeys := []string{"DNT", "Upgrade-Insecure-Requests", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-Dest"}
	for _, key := range presenceKeys {
		if strings.TrimSpace(c.GetHeader(key)) == "" {
			presenceBits = append(presenceBits, "0")
			continue
		}
		presenceBits = append(presenceBits, "1")
	}
	presenceBitmap := strings.Join(presenceBits, "")

	clientHints := strings.Join([]string{
		strings.TrimSpace(c.GetHeader("Sec-CH-UA")),
		strings.TrimSpace(c.GetHeader("Sec-CH-UA-Platform")),
		strings.TrimSpace(c.GetHeader("Sec-CH-UA-Mobile")),
	}, "|")

	finalRaw := strings.Join([]string{orderHash, acceptHash, presenceBitmap, clientHints}, "|")
	return md5Hex(finalRaw)
}

func md5Hex(raw string) string {
	sum := md5.Sum([]byte(raw))
	return hex.EncodeToString(sum[:])
}
