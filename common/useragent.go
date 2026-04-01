package common

import (
	"regexp"
	"strings"
)

// ParsedUA UA解析结果
type ParsedUA struct {
	Raw           string `json:"raw"`
	Browser       string `json:"browser"`
	BrowserVer    string `json:"browser_ver"`
	OS            string `json:"os"`
	OSVer         string `json:"os_ver"`
	DeviceType    string `json:"device_type"` // desktop, mobile, tablet, bot
	IsBot         bool   `json:"is_bot"`
	IsSuspicious  bool   `json:"is_suspicious"`
	SuspectReason string `json:"suspect_reason,omitempty"`
}

// ParseUserAgent 解析 User-Agent 字符串
func ParseUserAgent(raw string) *ParsedUA {
	ua := &ParsedUA{Raw: raw}

	if raw == "" {
		ua.IsSuspicious = true
		ua.SuspectReason = "empty UA"
		ua.DeviceType = "unknown"
		return ua
	}

	rawLower := strings.ToLower(raw)

	// 检测Bot
	botPatterns := []string{"bot", "crawler", "spider", "curl", "wget", "python-requests",
		"python-urllib", "go-http-client", "java/", "okhttp", "scrapy", "headless", "phantomjs"}
	for _, p := range botPatterns {
		if strings.Contains(rawLower, p) {
			ua.IsBot = true
			ua.DeviceType = "bot"
			break
		}
	}

	// 检测OS
	switch {
	case strings.Contains(raw, "Windows"):
		ua.OS = "Windows"
		ua.OSVer = extractVersion(raw, `Windows NT ([\d.]+)`)
	case strings.Contains(raw, "Mac OS X") || strings.Contains(raw, "macOS"):
		ua.OS = "macOS"
		ua.OSVer = strings.ReplaceAll(extractVersion(raw, `Mac OS X ([\d_.]+)`), "_", ".")
	case strings.Contains(raw, "CrOS"):
		ua.OS = "ChromeOS"
	case strings.Contains(raw, "Android"):
		ua.OS = "Android"
		ua.OSVer = extractVersion(raw, `Android ([\d.]+)`)
	case strings.Contains(raw, "iPhone") || strings.Contains(raw, "iPad") || strings.Contains(raw, "iPod"):
		ua.OS = "iOS"
		ua.OSVer = strings.ReplaceAll(extractVersion(raw, `OS ([\d_]+)`), "_", ".")
	case strings.Contains(raw, "Linux"):
		ua.OS = "Linux"
	case strings.Contains(raw, "FreeBSD"):
		ua.OS = "FreeBSD"
	}

	// 检测浏览器 (顺序重要: 先检测更具体的)
	switch {
	case strings.Contains(raw, "OPR/") || strings.Contains(raw, "Opera"):
		ua.Browser = "Opera"
		ua.BrowserVer = extractVersion(raw, `OPR/([\d.]+)`)
		if ua.BrowserVer == "" {
			ua.BrowserVer = extractVersion(raw, `Opera/([\d.]+)`)
		}
	case strings.Contains(raw, "Edg/"):
		ua.Browser = "Edge"
		ua.BrowserVer = extractVersion(raw, `Edg/([\d.]+)`)
	case strings.Contains(raw, "Brave"):
		ua.Browser = "Brave"
		ua.BrowserVer = extractVersion(raw, `Brave/([\d.]+)`)
	case strings.Contains(raw, "Vivaldi/"):
		ua.Browser = "Vivaldi"
		ua.BrowserVer = extractVersion(raw, `Vivaldi/([\d.]+)`)
	case strings.Contains(raw, "YaBrowser/"):
		ua.Browser = "Yandex"
		ua.BrowserVer = extractVersion(raw, `YaBrowser/([\d.]+)`)
	case strings.Contains(raw, "Chrome/") && !strings.Contains(raw, "Edg/") && !strings.Contains(raw, "OPR/"):
		ua.Browser = "Chrome"
		ua.BrowserVer = extractVersion(raw, `Chrome/([\d.]+)`)
	case strings.Contains(raw, "Firefox/"):
		ua.Browser = "Firefox"
		ua.BrowserVer = extractVersion(raw, `Firefox/([\d.]+)`)
	case strings.Contains(raw, "Safari/") && !strings.Contains(raw, "Chrome/"):
		ua.Browser = "Safari"
		ua.BrowserVer = extractVersion(raw, `Version/([\d.]+)`)
	case strings.Contains(rawLower, "msie") || strings.Contains(raw, "Trident/"):
		ua.Browser = "IE"
		ua.BrowserVer = extractVersion(raw, `MSIE ([\d.]+)`)
		if ua.BrowserVer == "" {
			ua.BrowserVer = extractVersion(raw, `rv:([\d.]+)`)
		}
	}

	// 检测设备类型
	if !ua.IsBot {
		switch {
		case strings.Contains(raw, "iPad") || strings.Contains(rawLower, "tablet"):
			ua.DeviceType = "tablet"
		case strings.Contains(raw, "Mobile") || strings.Contains(raw, "iPhone") ||
			strings.Contains(raw, "iPod") ||
			(strings.Contains(raw, "Android") && !strings.Contains(raw, "Tablet")):
			ua.DeviceType = "mobile"
		default:
			ua.DeviceType = "desktop"
		}
	}

	// 可疑性检查
	detectSuspiciousUA(ua)

	return ua
}

func detectSuspiciousUA(ua *ParsedUA) {
	if ua.IsBot {
		return
	}

	// 1. UA 过短 (正常浏览器 UA 通常 80+ 字符)
	if len(ua.Raw) > 0 && len(ua.Raw) < 30 {
		ua.IsSuspicious = true
		ua.SuspectReason = "UA too short"
		return
	}

	// 2. 不合理的组合
	if ua.OS == "iOS" && (ua.Browser == "IE" || ua.Browser == "Edge") {
		ua.IsSuspicious = true
		ua.SuspectReason = "impossible OS+Browser combination"
		return
	}

	// 3. Chrome 版本号异常 (当前稳定版约130+, 不可能到999)
	if ua.Browser == "Chrome" && ua.BrowserVer != "" {
		parts := strings.Split(ua.BrowserVer, ".")
		if len(parts) > 0 && len(parts[0]) >= 4 {
			ua.IsSuspicious = true
			ua.SuspectReason = "abnormal Chrome version"
			return
		}
	}

	// 4. 声称是桌面浏览器但包含明显的自动化工具标识
	autoKeywords := []string{"selenium", "webdriver", "puppeteer", "playwright"}
	rawLower := strings.ToLower(ua.Raw)
	for _, kw := range autoKeywords {
		if strings.Contains(rawLower, kw) {
			ua.IsSuspicious = true
			ua.SuspectReason = "automation tool detected: " + kw
			return
		}
	}
}

func extractVersion(ua string, pattern string) string {
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(ua)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
