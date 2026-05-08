package service

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
)

const dnsCloudflareAPIBase = "https://api.cloudflare.com/client/v4"

func ResolveDNSResolverIP(ctx context.Context, fallback string, probeID string) string {
	if !common.EnableDNSLeakDetection() {
		return sanitizeDNSResolverIP(fallback)
	}

	if common.EnableDNSCloudflare() {
		resolver := resolveDNSResolverFromCloudflare(ctx, probeID)
		if resolver != "" {
			return resolver
		}
	}

	return sanitizeDNSResolverIP(fallback)
}

func resolveDNSResolverFromCloudflare(ctx context.Context, probeID string) string {
	zoneID := common.GetDNSCloudflareZoneID()
	token := common.GetDNSCloudflareAPIToken()
	if zoneID == "" || token == "" {
		return ""
	}

	if ctx == nil {
		ctx = context.Background()
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	query := url.Values{}
	query.Set("per_page", "10")
	if probeID != "" {
		query.Set("name", probeID)
	}

	endpoint := fmt.Sprintf("%s/zones/%s/dns_analytics/report/bytime?%s", dnsCloudflareAPIBase, zoneID, query.Encode())
	req, err := http.NewRequestWithContext(timeoutCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		common.SysLog("dns leak cloudflare request build failed: " + err.Error())
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := GetHttpClient()
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		common.SysLog("dns leak cloudflare request failed: " + err.Error())
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		common.SysLog(fmt.Sprintf("dns leak cloudflare request non-2xx: %d", resp.StatusCode))
		return ""
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		common.SysLog("dns leak cloudflare read body failed: " + err.Error())
		return ""
	}

	return extractResolverIPFromCloudflareBody(string(body))
}

func extractResolverIPFromCloudflareBody(body string) string {
	candidate := strings.TrimSpace(body)
	if candidate == "" {
		return ""
	}

	if direct := sanitizeDNSResolverIP(candidate); direct != "" {
		return direct
	}

	type cloudflareAnalyticsResponse struct {
		Success bool `json:"success"`
		Result  []struct {
			Dimensions map[string]string `json:"dimensions"`
		} `json:"result"`
	}
	var parsed cloudflareAnalyticsResponse
	if err := common.UnmarshalJsonStr(candidate, &parsed); err != nil {
		return ""
	}
	for _, row := range parsed.Result {
		for _, key := range []string{"querySourceIP", "clientIP", "srcIP", "resolver_ip", "resolverIP"} {
			if resolver := sanitizeDNSResolverIP(row.Dimensions[key]); resolver != "" {
				return resolver
			}
		}
	}
	return ""
}

func sanitizeDNSResolverIP(value string) string {
	value = strings.Trim(strings.TrimSpace(value), `"`)
	if value == "" {
		return ""
	}
	addr, err := netip.ParseAddr(value)
	if err != nil || !addr.IsValid() {
		return ""
	}
	return addr.String()
}
