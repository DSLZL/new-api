package service

import (
	"strings"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
)

// IPInfo IP情报信息
type IPInfo struct {
	IP           string  `json:"ip"`
	Country      string  `json:"country"`
	Region       string  `json:"region"`
	City         string  `json:"city"`
	ISP          string  `json:"isp"`
	Type         string  `json:"type"` // residential/datacenter/vpn/proxy/tor
	Risk         float64 `json:"risk"`
	ASN          int     `json:"asn"`
	ASNOrg       string  `json:"asn_org"`
	IsDatacenter bool    `json:"is_datacenter"`
}

// 简单的内存缓存 (如果 Redis 不可用时的降级方案)
var ipCacheMu sync.RWMutex
var ipCache = make(map[string]*ipCacheEntry)

type ipCacheEntry struct {
	info      *IPInfo
	expiresAt time.Time
}

// LookupIP 查询IP情报
func LookupIP(ip string) *IPInfo {
	if ip == "" {
		return &IPInfo{IP: ip, Type: "unknown"}
	}

	// 1. 查内存缓存
	ipCacheMu.RLock()
	if entry, ok := ipCache[ip]; ok && time.Now().Before(entry.expiresAt) {
		ipCacheMu.RUnlock()
		return entry.info
	}
	ipCacheMu.RUnlock()

	// 2. 查Redis缓存
	if common.RedisEnabled {
		cacheKey := "fp:ip:" + ip
		cached, err := common.RedisGet(cacheKey)
		if err == nil && cached != "" {
			var info IPInfo
			if common.Unmarshal([]byte(cached), &info) == nil {
				setIPCache(ip, &info)
				return &info
			}
		}
	}

	// 3. 基础信息 (无外部数据库时的最小化实现)
	info := &IPInfo{IP: ip}
	info.ASN, info.ASNOrg = deriveASNFromISP(info.ISP)
	info.IsDatacenter = detectDatacenterByASN(info.ASN, info.ASNOrg)
	info.Type = detectIPType(ip, info)
	if info.Type == "datacenter" {
		info.IsDatacenter = true
	}

	// 4. 风险评分
	switch info.Type {
	case "tor":
		info.Risk = 90
	case "datacenter":
		info.Risk = 60
	case "vpn", "proxy":
		info.Risk = 50
	default:
		info.Risk = 10
	}

	// 5. 缓存
	setIPCache(ip, info)
	if common.RedisEnabled {
		if data, err := common.Marshal(info); err == nil {
			cacheKey := "fp:ip:" + ip
			common.RedisSet(cacheKey, string(data), 24*time.Hour)
		}
	}

	return info
}

func setIPCache(ip string, info *IPInfo) {
	ipCacheMu.Lock()
	ipCache[ip] = &ipCacheEntry{
		info:      info,
		expiresAt: time.Now().Add(24 * time.Hour),
	}
	ipCacheMu.Unlock()
}

func detectIPType(ip string, info *IPInfo) string {
	ispLower := strings.ToLower(info.ISP)

	if info.IsDatacenter {
		return "datacenter"
	}

	// 数据中心关键词检测
	dcKeywords := []string{
		"amazon", "aws", "google cloud", "gce", "microsoft", "azure",
		"digitalocean", "linode", "vultr", "hetzner",
		"ovh", "alibaba", "aliyun", "tencent", "huawei",
		"data center", "datacenter", "hosting",
		"cloudflare", "fastly", "akamai",
		"oracle cloud", "ibm cloud",
	}
	for _, kw := range dcKeywords {
		if strings.Contains(ispLower, kw) {
			return "datacenter"
		}
	}

	// 常见IP段检测 (简单规则)
	knownRanges := map[string]string{
		"10.":     "private",
		"172.16":  "private",
		"192.168": "private",
		"127.":    "loopback",
	}
	for prefix, t := range knownRanges {
		if strings.HasPrefix(ip, prefix) {
			return t
		}
	}

	return "residential"
}

func deriveASNFromISP(isp string) (int, string) {
	isp = strings.TrimSpace(isp)
	if isp == "" {
		return 0, ""
	}
	return 0, isp
}

func detectDatacenterByASN(asn int, asnOrg string) bool {
	if asn > 0 {
		knownDatacenterASN := map[int]struct{}{
			13335: {}, // Cloudflare
			16509: {}, // AWS
			15169: {}, // Google
			8075:  {}, // Microsoft
			14061: {}, // DigitalOcean
			63949: {}, // Linode/Akamai
			20473: {}, // Vultr
			16276: {}, // OVH
			45102: {}, // Alibaba
			132203: {}, // Tencent
		}
		if _, ok := knownDatacenterASN[asn]; ok {
			return true
		}
	}

	orgLower := strings.ToLower(strings.TrimSpace(asnOrg))
	if orgLower == "" {
		return false
	}
	keywords := []string{
		"cloud", "hosting", "data center", "datacenter",
		"amazon", "aws", "google", "microsoft", "azure",
		"digitalocean", "linode", "vultr", "hetzner", "ovh", "cloudflare", "akamai",
		"alibaba", "aliyun", "tencent", "huawei", "oracle",
	}
	for _, kw := range keywords {
		if strings.Contains(orgLower, kw) {
			return true
		}
	}
	return false
}

// GetSubnet24 获取 /24 子网前缀
func GetSubnet24(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) >= 3 {
		return parts[0] + "." + parts[1] + "." + parts[2]
	}
	// IPv6 或无效地址，返回前半部分
	if idx := strings.LastIndex(ip, ":"); idx > 0 {
		return ip[:idx]
	}
	return ip
}
