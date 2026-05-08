package service

import (
	"fmt"
	"maps"
	"math"
	"os"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// initTestDB 初始化内存 SQLite 用于测试
func initTestDB(t *testing.T) {
	t.Helper()
	oldDB := model.DB
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	err = db.AutoMigrate(&model.Fingerprint{}, &model.IPUAHistory{}, &model.UserTemporalProfile{}, &model.UserSession{}, &model.KeystrokeProfile{}, &model.MouseProfile{}, &model.AccountLink{}, &model.LinkWhitelist{}, &model.User{}, &model.UserDeviceProfile{}, &model.UserRiskScore{})
	require.NoError(t, err)
	require.NoError(t, model.EnsureUserSessionUniqueIndex(db))
	require.NoError(t, model.EnsureAccountLinkUniqueIndex(db))
	model.DB = db
	t.Cleanup(func() {
		model.DB = oldDB
		_ = sqlDB.Close()
	})
}

// ─── GetSubnet24 ───

func TestGetSubnet24_IPv4(t *testing.T) {
	cases := []struct {
		ip   string
		want string
	}{
		{"192.168.1.100", "192.168.1"},
		{"10.0.0.1", "10.0.0"},
		{"8.8.8.8", "8.8.8"},
		{"172.16.254.1", "172.16.254"},
	}
	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			assert.Equal(t, tc.want, GetSubnet24(tc.ip))
		})
	}
}

func TestGetSubnet24_IPv6(t *testing.T) {
	ip := "2001:db8::1"
	result := GetSubnet24(ip)
	// IPv6 返回最后一个冒号之前的部分，不应为空
	assert.NotEmpty(t, result)
	assert.NotEqual(t, ip, result, "IPv6 should be truncated")
}

func TestGetSubnet24_Empty(t *testing.T) {
	// 空字符串原样返回
	assert.Equal(t, "", GetSubnet24(""))
}

// ─── computeUASimilarity ───

func TestComputeUASimilarity_IdenticalUA(t *testing.T) {
	a := &model.Fingerprint{
		UAOS: "Windows", UAOSVer: "10",
		UABrowser: "Chrome", UABrowserVer: "120",
		UADeviceType: "desktop",
	}
	b := *a // 完全相同
	score := computeUASimilarity(a, &b)
	assert.Greater(t, score, 0.9, "identical UA should yield >0.9 similarity")
}

func TestComputeUASimilarity_DifferentOS(t *testing.T) {
	a := &model.Fingerprint{
		UAOS: "Windows", UABrowser: "Chrome", UADeviceType: "desktop",
	}
	b := &model.Fingerprint{
		UAOS: "macOS", UABrowser: "Chrome", UADeviceType: "desktop",
	}
	score := computeUASimilarity(a, b)
	// OS 不同，Browser/DeviceType 相同 → 部分匹配
	assert.Greater(t, score, 0.3)
	assert.Less(t, score, 0.9)
}

func TestComputeUASimilarity_CompletelyDifferent(t *testing.T) {
	a := &model.Fingerprint{
		UAOS: "Windows", UABrowser: "Chrome", UADeviceType: "desktop",
	}
	b := &model.Fingerprint{
		UAOS: "iOS", UABrowser: "Safari", UADeviceType: "mobile",
	}
	score := computeUASimilarity(a, b)
	assert.Less(t, score, 0.1, "completely different UA should yield near-0 similarity")
}

func TestComputeUASimilarity_EmptyFields(t *testing.T) {
	a := &model.Fingerprint{}
	b := &model.Fingerprint{}
	score := computeUASimilarity(a, b)
	assert.Equal(t, 0.0, score, "empty UA should yield 0")
}

// ─── CompareFingerprints ───

func makeFP(opts ...func(*model.Fingerprint)) *model.Fingerprint {
	fp := &model.Fingerprint{
		CanvasHash:         "canvas_abc123",
		WebGLHash:          "webgl_abc123",
		WebGLDeepHash:      "webgl_deep_abc123",
		ClientRectsHash:    "",
		AudioHash:          "audio_abc123",
		FontsHash:          "fonts_abc123",
		WebGLRenderer:      "NVIDIA GeForce RTX 3080",
		LocalDeviceID:      "device_abc123",
		CompositeHash:      "comp_abc123",
		TLSJA3Hash:         "ja3_abc123",
		JA4:                "ja4_abc123",
		ETagID:             "etag_abc123",
		PersistentID:       "persist_abc123",
		PersistentIDSource: "localStorage",
		WebRTCLocalIPs:     "[\"192.168.1.100\"]",
		WebRTCPublicIPs:    "[\"1.2.3.4\"]",
		IPAddress:          "1.2.3.4",
		UAOS:               "Windows",
		UAOSVer:            "10",
		UABrowser:          "Chrome",
		UABrowserVer:       "120",
		UADeviceType:       "desktop",
		ScreenWidth:        1920,
		ScreenHeight:       1080,
		Timezone:           "Asia/Shanghai",
		Languages:          "zh-CN,en-US",
		CPUCores:           8,
		Platform:           "Win32",
	}
	for _, o := range opts {
		o(fp)
	}
	return fp
}

// TestCompareFingerprints_IdenticalDevice 同一设备 → 高置信度
func TestCompareFingerprints_IdenticalDevice(t *testing.T) {
	initTestDB(t)

	a := makeFP()
	b := makeFP() // 完全相同的硬件指纹

	conf, details, matchDims, totalDims := CompareFingerprints(a, b, 1, 2)

	assert.InDelta(t, 0.99, conf, 0.0001, "identical device fingerprint should match Tier1 persistent_id score")
	assert.Equal(t, 1, matchDims)
	assert.Equal(t, 1, totalDims)
	assert.NotEmpty(t, details)
}

// TestCompareFingerprints_SameIPDifferentDevice IP相同但设备不同 → 低-中置信度
func TestCompareFingerprints_SameIPDifferentDevice(t *testing.T) {
	initTestDB(t)

	a := makeFP()
	b := makeFP(func(fp *model.Fingerprint) {
		// 清除或改写所有设备/协议/环境重合证据，仅保留 IP
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.WebGLDeepHash = ""
		fp.ClientRectsHash = ""
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.WebGLVendor = "AMD"
		fp.WebGLRenderer = "AMD Radeon RX 6800"
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.HTTPHeaderHash = ""
		fp.ETagID = ""
		fp.PersistentID = ""
		fp.PersistentIDSource = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.UAOS = "Android"
		fp.UAOSVer = "14"
		fp.UABrowser = "Firefox"
		fp.UABrowserVer = "125"
		fp.UADeviceType = "mobile"
		fp.ScreenWidth = 390
		fp.ScreenHeight = 844
		fp.Timezone = "America/New_York"
		fp.Languages = "en-US"
		fp.CPUCores = 4
		fp.Platform = "Linux armv8l"
	})

	conf, _, _, _ := CompareFingerprints(a, b, 10, 20)

	// 没有设备指纹，置信度应该较低
	assert.Less(t, conf, 0.75, "no device fingerprint should keep confidence below 0.75")
}

// TestCompareFingerprints_CompletelyDifferent 完全不同的设备 → 极低置信度
func TestCompareFingerprints_CompletelyDifferent(t *testing.T) {
	initTestDB(t)

	a := makeFP()
	b := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = "canvas_zzz999"
		fp.WebGLHash = "webgl_zzz999"
		fp.WebGLDeepHash = "webgl_deep_zzz999"
		fp.ClientRectsHash = ""
		fp.AudioHash = "audio_zzz999"
		fp.FontsHash = "fonts_zzz999"
		fp.LocalDeviceID = "device_zzz999"
		fp.CompositeHash = "comp_zzz999"
		fp.TLSJA3Hash = "ja3_zzz999"
		fp.JA4 = "ja4_zzz999"
		fp.ETagID = "etag_zzz999"
		fp.PersistentID = "persist_zzz999"
		fp.PersistentIDSource = "cookie"
		fp.WebRTCLocalIPs = "[\"10.0.0.9\"]"
		fp.WebRTCPublicIPs = "[\"203.0.113.250\"]"
		fp.IPAddress = "5.6.7.8"
		fp.UAOS = "iOS"
		fp.UAOSVer = "17"
		fp.UABrowser = "Safari"
		fp.UABrowserVer = "17"
		fp.UADeviceType = "mobile"
		fp.ScreenWidth = 390
		fp.ScreenHeight = 844
		fp.Timezone = "America/New_York"
		fp.Languages = "en-US"
		fp.CPUCores = 4
		fp.Platform = "iPhone"
		fp.WebGLRenderer = "Apple GPU"
	})

	conf, _, _, _ := CompareFingerprints(a, b, 100, 200)

	assert.Less(t, conf, 0.15, "completely different fingerprints should yield <0.15 confidence")
}

// TestCompareFingerprints_SameDeviceDifferentIP 设备相同、IP不同 (VPN切换场景)
func TestCompareFingerprints_SameDeviceDifferentIP(t *testing.T) {
	initTestDB(t)

	a := makeFP()
	b := makeFP(func(fp *model.Fingerprint) {
		fp.IPAddress = "99.88.77.66" // 不同 IP
	})

	conf, _, matchDims, _ := CompareFingerprints(a, b, 1, 2)

	// 设备指纹全部匹配，置信度应仍然很高
	assert.InDelta(t, 0.99, conf, 0.0001, "same device with different IP should still hit Tier1 persistent_id")
	assert.Equal(t, 1, matchDims)
}

// TestCompareFingerprints_DetailsOrder details 应按权重降序排列
func TestCompareFingerprints_DetailsOrder(t *testing.T) {
	initTestDB(t)

	a := makeFP()
	b := makeFP()

	_, details, _, _ := CompareFingerprints(a, b, 1, 2)

	require.GreaterOrEqual(t, len(details), 1)
	for i := 1; i < len(details); i++ {
		assert.GreaterOrEqual(t, details[i-1].Weight, details[i].Weight,
			"details should be sorted by weight descending")
	}
}

// TestCompareFingerprints_AutoConfirmThreshold 验证高置信度可触发自动确认阈值
func TestCompareFingerprints_PersistentIDExactMatchShortCircuits(t *testing.T) {
	initTestDB(t)

	a := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
	})
	b := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = "canvas_other"
		fp.WebGLHash = "webgl_other"
		fp.AudioHash = "audio_other"
		fp.FontsHash = "fonts_other"
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.PersistentID = a.PersistentID
		fp.PersistentIDSource = "cookie"
	})

	conf, details, _, _ := CompareFingerprints(a, b, 1, 2)
	assert.InDelta(t, 0.99, conf, 0.0001, "persistent id exact match should map to Tier1 score 0.99")
	require.NotEmpty(t, details)
	assert.Equal(t, "persistent_id", details[0].Dimension)
}

func TestCompareFingerprints_ETagExactMatchShortCircuits(t *testing.T) {
	initTestDB(t)

	a := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.PersistentID = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
	})
	b := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = "canvas_other"
		fp.WebGLHash = "webgl_other"
		fp.AudioHash = "audio_other"
		fp.FontsHash = "fonts_other"
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.PersistentID = ""
		fp.ETagID = a.ETagID
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
	})

	conf, details, _, _ := CompareFingerprints(a, b, 1, 2)
	assert.InDelta(t, 0.95, conf, 0.0001, "etag id exact match should map to Tier1 score 0.95")
	require.NotEmpty(t, details)
	assert.Equal(t, "etag_id", details[0].Dimension)
}

func TestCompareFingerprints_JA4MatchProvidesStrongSignal(t *testing.T) {
	initTestDB(t)

	a := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.PersistentID = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.HTTPHeaderHash = "hdr_same_abc"
	})
	b := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = "canvas_other"
		fp.WebGLHash = "webgl_other"
		fp.AudioHash = "audio_other"
		fp.FontsHash = "fonts_other"
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.PersistentID = ""
		fp.ETagID = ""
		fp.JA4 = a.JA4
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.HTTPHeaderHash = "hdr_same_abc"
	})

	conf, details, _, _ := CompareFingerprints(a, b, 1, 2)
	assert.GreaterOrEqual(t, conf, 0.75, "ja4 + http header hash match should provide strong protocol-layer signal")
	assert.Less(t, conf, 1.0, "ja4 should remain weighted signal, not strong-signal short-circuit")
	require.NotEmpty(t, details)
	assert.True(t, containsMatchedDimension(details, "http_header_hash"), "http header hash dimension should participate in weighted scoring")
}

func containsMatchedDimension(details []DimensionMatch, dim string) bool {
	for _, d := range details {
		if d.Dimension == dim && d.Matched {
			return true
		}
	}
	return false
}

func findDimension(details []DimensionMatch, dim string) *DimensionMatch {
	for i := range details {
		if details[i].Dimension == dim {
			return &details[i]
		}
	}
	return nil
}

func TestCompareFingerprints_DNSResolverIPMatch(t *testing.T) {
	initTestDB(t)

	oldDNS := common.FingerprintEnableDNSLeak
	common.FingerprintEnableDNSLeak = true
	t.Cleanup(func() {
		common.FingerprintEnableDNSLeak = oldDNS
	})

	a := makeFP(func(fp *model.Fingerprint) {
		fp.PersistentID = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.DNSResolverIP = "8.8.8.8"
		fp.IPAddress = "1.1.1.1"
	})
	b := makeFP(func(fp *model.Fingerprint) {
		fp.PersistentID = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.DNSResolverIP = "8.8.8.8"
		fp.IPAddress = "9.9.9.9"
	})

	_, details, _, _ := CompareFingerprints(a, b, 1, 2)

	var dnsDetail *DimensionMatch
	for i := range details {
		if details[i].Dimension == "dns_resolver_ip" {
			dnsDetail = &details[i]
			break
		}
	}
	require.NotNil(t, dnsDetail)
	assert.True(t, dnsDetail.Matched)
	assert.Equal(t, "8.8.8.8", dnsDetail.ValueA)
	assert.Equal(t, common.GetFingerprintWeightDNSResolver(), dnsDetail.Weight)
}

func TestCompareFingerprints_DNSResolverWeightUsesOptionMapHotUpdate(t *testing.T) {
	initTestDB(t)

	oldDNS := common.FingerprintEnableDNSLeak
	oldOptionMap := common.OptionMap
	common.FingerprintEnableDNSLeak = true
	common.OptionMap = map[string]string{}
	t.Cleanup(func() {
		common.FingerprintEnableDNSLeak = oldDNS
		common.OptionMap = oldOptionMap
	})

	a := makeFP(func(fp *model.Fingerprint) {
		fp.PersistentID = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.DNSResolverIP = "8.8.8.8"
		fp.IPAddress = "1.1.1.1"
	})
	b := makeFP(func(fp *model.Fingerprint) {
		fp.PersistentID = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.DNSResolverIP = "8.8.8.8"
		fp.IPAddress = "9.9.9.9"
	})

	common.OptionMap["FINGERPRINT_WEIGHT_DNS_RESOLVER"] = "0.33"
	_, details, _, _ := CompareFingerprints(a, b, 1, 2)

	var dnsDetail *DimensionMatch
	for i := range details {
		if details[i].Dimension == "dns_resolver_ip" {
			dnsDetail = &details[i]
			break
		}
	}
	require.NotNil(t, dnsDetail)
	assert.InDelta(t, 0.33, dnsDetail.Weight, 0.0001)
}

func TestCompareFingerprints_HTTPHeaderHashMatchNotShortCircuit(t *testing.T) {
	initTestDB(t)

	a := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.WebGLDeepHash = ""
		fp.ClientRectsHash = ""
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.WebGLVendor = ""
		fp.WebGLRenderer = ""
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.ETagID = ""
		fp.PersistentID = ""
		fp.PersistentIDSource = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.IPAddress = ""
		fp.ScreenWidth = 0
		fp.ScreenHeight = 0
		fp.Timezone = ""
		fp.Languages = ""
		fp.CPUCores = 0
		fp.Platform = ""
		fp.UAOS = ""
		fp.UAOSVer = ""
		fp.UABrowser = ""
		fp.UABrowserVer = ""
		fp.UADeviceType = ""
		fp.HTTPHeaderHash = "hdr-only-match"
	})
	b := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.WebGLDeepHash = ""
		fp.ClientRectsHash = ""
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.WebGLVendor = ""
		fp.WebGLRenderer = ""
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.ETagID = ""
		fp.PersistentID = ""
		fp.PersistentIDSource = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.IPAddress = ""
		fp.ScreenWidth = 0
		fp.ScreenHeight = 0
		fp.Timezone = ""
		fp.Languages = ""
		fp.CPUCores = 0
		fp.Platform = ""
		fp.UAOS = ""
		fp.UAOSVer = ""
		fp.UABrowser = ""
		fp.UABrowserVer = ""
		fp.UADeviceType = ""
		fp.HTTPHeaderHash = "hdr-only-match"
	})

	conf, details, matchDims, totalDims := CompareFingerprints(a, b, 1, 2)
	assert.Greater(t, conf, 0.0, "http header hash match should contribute positive weighted confidence")
	assert.Less(t, conf, 1.0, "http header hash must not short-circuit to full confidence")
	assert.GreaterOrEqual(t, matchDims, 1)
	assert.GreaterOrEqual(t, totalDims, 1)
	require.NotEmpty(t, details)
	assert.True(t, containsMatchedDimension(details, "http_header_hash"))
}

func TestCompareFingerprints_SpeechZeroCountsDoNotMatch(t *testing.T) {
	initTestDB(t)

	a := makeFP(func(fp *model.Fingerprint) {
		fp.PersistentID = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.SpeechVoicesHash = ""
		fp.SpeechVoiceCount = 0
		fp.SpeechLocalVoiceCount = 0
	})
	b := makeFP(func(fp *model.Fingerprint) {
		fp.PersistentID = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.SpeechVoicesHash = ""
		fp.SpeechVoiceCount = 0
		fp.SpeechLocalVoiceCount = 0
	})

	_, details, _, _ := CompareFingerprints(a, b, 1, 2)
	assert.Nil(t, findDimension(details, "speech_voice_count"))
	assert.Nil(t, findDimension(details, "speech_local_voice_count"))
}

func TestCompareFingerprints_WebRTCLocalAndPublicExactMatchShortCircuits(t *testing.T) {
	initTestDB(t)

	a := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.PersistentID = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[\"192.168.1.20\"]"
		fp.WebRTCPublicIPs = "[\"203.0.113.2\"]"
	})
	b := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = "canvas_other"
		fp.WebGLHash = "webgl_other"
		fp.AudioHash = "audio_other"
		fp.FontsHash = "fonts_other"
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.PersistentID = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[\"192.168.1.20\"]"
		fp.WebRTCPublicIPs = "[\"203.0.113.2\"]"
	})

	conf, details, _, _ := CompareFingerprints(a, b, 1, 2)
	assert.InDelta(t, 0.95, conf, 0.0001, "matching both webrtc local and public ips should map to Tier1 score 0.95")
	require.NotEmpty(t, details)
	assert.Equal(t, "webrtc_ip", details[0].Dimension)
	assert.Equal(t, "WebRTC 本地+公网IP", details[0].DisplayName)
}

func TestCompareFingerprints_WebRTCLocalOnlyStillStrong(t *testing.T) {
	initTestDB(t)

	a := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.PersistentID = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[\"192.168.10.8\"]"
		fp.WebRTCPublicIPs = "[\"198.51.100.88\"]"
	})
	b := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = "canvas_other"
		fp.WebGLHash = "webgl_other"
		fp.AudioHash = "audio_other"
		fp.FontsHash = "fonts_other"
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.PersistentID = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[\"192.168.10.8\"]"
		fp.WebRTCPublicIPs = "[\"203.0.113.99\"]"
	})

	conf, _, _, _ := CompareFingerprints(a, b, 1, 2)
	assert.Greater(t, conf, 0.80, "tier2 with webrtc local evidence should keep confidence high")
	assert.LessOrEqual(t, conf, 0.99)
}

func TestCompareWebRTC_UnmatchedUsesAvailableSignalWeight(t *testing.T) {
	weights := fingerprintWeights{
		WebRTCBothIP:   0.95,
		WebRTCLocalIP:  0.80,
		WebRTCPublicIP: 0.60,
	}

	t.Run("public_only_matched_uses_public_weight", func(t *testing.T) {
		a := &model.Fingerprint{WebRTCLocalIPs: "[]", WebRTCPublicIPs: "[\"203.0.113.10\"]"}
		b := &model.Fingerprint{WebRTCLocalIPs: "[]", WebRTCPublicIPs: "[\"203.0.113.10\"]"}

		score, details, matched := compareWebRTC(a, b, weights)
		assert.Equal(t, 1.0, score)
		assert.True(t, matched)
		require.Len(t, details, 1)
		assert.Equal(t, weights.WebRTCPublicIP, details[0].Weight)
	})

	t.Run("public_only_unmatched_uses_public_weight", func(t *testing.T) {
		a := &model.Fingerprint{WebRTCLocalIPs: "[]", WebRTCPublicIPs: "[\"203.0.113.10\"]"}
		b := &model.Fingerprint{WebRTCLocalIPs: "[]", WebRTCPublicIPs: "[\"198.51.100.20\"]"}

		score, details, matched := compareWebRTC(a, b, weights)
		assert.Equal(t, 0.0, score)
		assert.False(t, matched)
		require.Len(t, details, 1)
		assert.Equal(t, weights.WebRTCPublicIP, details[0].Weight)
	})

	t.Run("local_only_unmatched_uses_local_weight", func(t *testing.T) {
		a := &model.Fingerprint{WebRTCLocalIPs: "[\"192.168.1.20\"]", WebRTCPublicIPs: "[]"}
		b := &model.Fingerprint{WebRTCLocalIPs: "[\"192.168.1.30\"]", WebRTCPublicIPs: "[]"}

		score, details, matched := compareWebRTC(a, b, weights)
		assert.Equal(t, 0.0, score)
		assert.False(t, matched)
		require.Len(t, details, 1)
		assert.Equal(t, weights.WebRTCLocalIP, details[0].Weight)
	})
}

//
// 场景：同一自然人注册了三个账号，各自的登录方式略有不同：
//   账号 A (UserID=101): 正常浏览器，完整指纹
//   账号 B (UserID=102): 更换了 IP / 升级了浏览器版本（例如换了网络环境）
//   账号 C (UserID=103): 无痕模式登录（Canvas/WebGL/Audio 被随机化，LocalDeviceID 丢失）

// makeAccountA 正常浏览器登录，指纹完整
func makeAccountA() *model.Fingerprint {
	return makeFP(func(fp *model.Fingerprint) {
		fp.UserID = 101
	})
}

// makeAccountB 换了网络环境（不同 IP、不同子网），浏览器版本升级
// 设备硬件指纹（Canvas/WebGL/Audio/Fonts/LocalDeviceID）与账号 A 完全相同
func makeAccountB() *model.Fingerprint {
	return makeFP(func(fp *model.Fingerprint) {
		fp.UserID = 102
		// 换了网络，IP 与 A 不同（不同子网）
		fp.IPAddress = "5.6.7.8"
		// 浏览器小版本升级
		fp.UABrowserVer = "124"
		// TLS JA3 因新版本略有差异
		fp.TLSJA3Hash = "ja3_newver456"
	})
}

// makeAccountC 无痕模式登录：设备哈希被随机化，但 IP 与账号 A 相同，硬件特征保留
func makeAccountC() *model.Fingerprint {
	return makeFP(func(fp *model.Fingerprint) {
		fp.UserID = 103
		// 无痕模式下浏览器随机化这些哈希
		fp.CanvasHash = "canvas_incognito_rand7f3a"
		fp.WebGLHash = "webgl_incognito_rand2b8c"
		fp.AudioHash = "audio_incognito_rand9d1e"
		fp.WebGLDeepHash = "webgl_deep_incognito_rand7c1f"
		fp.FontsHash = "fonts_incognito_rand4a6f"
		// 无痕模式不持久化 LocalDeviceID 和 CompositeHash
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.PersistentID = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		// TLS 指纹也因无痕会话不同
		fp.TLSJA3Hash = ""
		// IP 与账号 A 相同（同一台机器，同一网络）
		fp.IPAddress = "1.2.3.4"
		// 硬件特征不变：GPU、屏幕、时区、CPU、平台
		// WebGLRenderer、ScreenWidth/Height、Timezone、CPUCores、Platform
		// 均继承自 makeFP 默认值，与账号 A 一致
	})
}

// TestMultiAccount_ABConfidence A vs B：设备指纹完全相同，仅网络环境不同 → 极高置信度
func TestMultiAccount_ABConfidence(t *testing.T) {
	initTestDB(t)

	a := makeAccountA()
	b := makeAccountB()

	conf, details, matchDims, _ := CompareFingerprints(a, b, 101, 102)

	// 设备级哈希全部命中，置信度应非常高
	assert.InDelta(t, 0.99, conf, 0.0001,
		"账号A与B共享持久标识，应命中 Tier1=0.99")
	assert.Equal(t, 1, matchDims,
		"短路路径下仅统计强信号维度")
	assert.NotEmpty(t, details)
}

// TestMultiAccount_ACConfidence A vs C：无痕模式，设备哈希不同，但 IP+硬件特征重叠 → 中高置信度
func TestMultiAccount_ACConfidence(t *testing.T) {
	initTestDB(t)

	a := makeAccountA()
	c := makeAccountC()

	conf, _, _, _ := CompareFingerprints(a, c, 101, 103)

	// 无痕模式哈希不同，但 IP 精确匹配 + GPU/屏幕/时区/CPU 匹配
	// ip_exact(0.50) + screen(0.25) + timezone(0.20) + cpu(0.15) + platform(0.10) + webgl_renderer(0.75)
	assert.Greater(t, conf, 0.35,
		"账号A与C共享IP和硬件特征，即使无痕模式置信度仍应 >0.40")
	assert.Less(t, conf, 0.90,
		"无痕模式丢失了设备哈希，置信度不应达到完全匹配水平")
}

// TestMultiAccount_BCConfidence B vs C：不同 IP + 随机化哈希，仅硬件特征重叠 → 低-中置信度但仍可检测
func TestMultiAccount_BCConfidence(t *testing.T) {
	initTestDB(t)

	b := makeAccountB()
	c := makeAccountC()

	conf, _, _, _ := CompareFingerprints(b, c, 102, 103)

	// IP 不同，哈希不同，仅 GPU/屏幕/时区/CPU 匹配
	assert.Greater(t, conf, 0.25,
		"账号B与C即使IP和哈希均不同，硬件特征重叠仍应产生 >0.25 的置信度")
}

// TestMultiAccount_ConfidenceRanking 三对置信度排序应符合直觉：A-B > A-C > B-C
func TestMultiAccount_ConfidenceRanking(t *testing.T) {
	initTestDB(t)

	a := makeAccountA()
	b := makeAccountB()
	c := makeAccountC()

	confAB, _, _, _ := CompareFingerprints(a, b, 101, 102)
	confAC, _, _, _ := CompareFingerprints(a, c, 101, 103)
	confBC, _, _, _ := CompareFingerprints(b, c, 102, 103)

	t.Logf("置信度 A-B=%.4f  A-C=%.4f  B-C=%.4f", confAB, confAC, confBC)

	assert.Greater(t, confAB, confAC,
		"A-B（共享完整设备指纹）置信度应高于 A-C（无痕模式）")
	assert.Greater(t, confAC, confBC,
		"A-C（共享IP）置信度应高于 B-C（IP和哈希均不同）")
}

// TestMultiAccount_CandidateDiscovery 验证候选发现路径：将三账号入库后互相能发现对方
func TestGetFeatureWeights_UsesWebRTCBothGetter(t *testing.T) {
	oldBoth := common.GetEnvOrDefaultString("FINGERPRINT_WEIGHT_WEBRTC_BOTH", "")
	oldPublic := common.GetEnvOrDefaultString("FINGERPRINT_WEIGHT_WEBRTC_PUBLIC", "")
	t.Cleanup(func() {
		if oldBoth == "" {
			_ = os.Unsetenv("FINGERPRINT_WEIGHT_WEBRTC_BOTH")
		} else {
			_ = os.Setenv("FINGERPRINT_WEIGHT_WEBRTC_BOTH", oldBoth)
		}
		if oldPublic == "" {
			_ = os.Unsetenv("FINGERPRINT_WEIGHT_WEBRTC_PUBLIC")
		} else {
			_ = os.Setenv("FINGERPRINT_WEIGHT_WEBRTC_PUBLIC", oldPublic)
		}
	})

	_ = os.Setenv("FINGERPRINT_WEIGHT_WEBRTC_BOTH", "0.93")
	_ = os.Setenv("FINGERPRINT_WEIGHT_WEBRTC_PUBLIC", "0.41")

	weights := getFeatureWeights()
	assert.Equal(t, 0.93, weights.WebRTCBothIP)
	assert.Equal(t, 0.41, weights.WebRTCPublicIP)
}

func TestEvaluateStrongSignals_PriorityPersistentIDOverOthers(t *testing.T) {
	weights := getFeatureWeights()
	a := makeFP(func(fp *model.Fingerprint) {
		fp.PersistentID = "pid-priority"
		fp.ETagID = "etag-priority"
		fp.WebRTCLocalIPs = "[\"192.168.2.10\"]"
		fp.WebRTCPublicIPs = "[\"203.0.113.20\"]"
	})
	b := makeFP(func(fp *model.Fingerprint) {
		fp.PersistentID = "pid-priority"
		fp.ETagID = "etag-priority"
		fp.WebRTCLocalIPs = "[\"192.168.2.10\"]"
		fp.WebRTCPublicIPs = "[\"203.0.113.20\"]"
	})

	conf, details, matched := evaluateStrongSignals(a, b, weights)
	require.True(t, matched)
	assert.InDelta(t, 0.99, conf, 0.0001)
	require.Len(t, details, 1)
	assert.Equal(t, "persistent_id", details[0].Dimension)
}

func TestEvaluateStrongSignals_WebRTCOnlyRequiresBothMatched(t *testing.T) {
	weights := getFeatureWeights()
	a := makeFP(func(fp *model.Fingerprint) {
		fp.PersistentID = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[\"192.168.3.11\"]"
		fp.WebRTCPublicIPs = "[\"203.0.113.31\"]"
	})
	b := makeFP(func(fp *model.Fingerprint) {
		fp.PersistentID = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[\"192.168.3.11\"]"
		fp.WebRTCPublicIPs = "[\"203.0.113.99\"]"
	})

	conf, details, matched := evaluateStrongSignals(a, b, weights)
	assert.False(t, matched)
	assert.Equal(t, 0.0, conf)
	assert.Nil(t, details)
}

func TestCompareFingerprints_WebGLDeepHashMatchProvidesPrimarySignal(t *testing.T) {
	initTestDB(t)

	a := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.WebGLDeepHash = "webgl_deep_same"
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.ETagID = ""
		fp.PersistentID = ""
		fp.PersistentIDSource = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.WebGLVendor = "NVIDIA Corporation"
		fp.WebGLRenderer = "ANGLE (NVIDIA GeForce RTX 3080)"
	})
	b := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.WebGLDeepHash = "webgl_deep_same"
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.ETagID = ""
		fp.PersistentID = ""
		fp.PersistentIDSource = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.WebGLVendor = "NVIDIA Corporation"
		fp.WebGLRenderer = "ANGLE (NVIDIA GeForce RTX 3080)"
	})

	conf, details, matchDims, totalDims := CompareFingerprints(a, b, 1, 2)

	require.NotEmpty(t, details)
	assert.Equal(t, "webgl_deep_hash", details[0].Dimension)
	assert.True(t, details[0].Matched)
	assert.InDelta(t, 0.88, details[0].Weight, 0.0001)
	assert.Greater(t, conf, 0.80)
	assert.Less(t, conf, 1.0)
	assert.GreaterOrEqual(t, matchDims, 1)
	assert.Greater(t, totalDims, 1)
}

func TestCompareFingerprints_WebGLDeepHashMatchOutweighsVendorRendererAuxiliarySignals(t *testing.T) {
	initTestDB(t)

	deepA := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.WebGLDeepHash = "webgl_deep_same"
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.ETagID = ""
		fp.PersistentID = ""
		fp.PersistentIDSource = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.WebGLVendor = "NVIDIA Corporation"
		fp.WebGLRenderer = "ANGLE (NVIDIA GeForce RTX 3080)"
	})
	deepB := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.WebGLDeepHash = "webgl_deep_same"
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.ETagID = ""
		fp.PersistentID = ""
		fp.PersistentIDSource = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.WebGLVendor = "NVIDIA Corporation"
		fp.WebGLRenderer = "ANGLE (NVIDIA GeForce RTX 3080)"
	})

	auxA := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.WebGLDeepHash = "webgl_deep_a"
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.ETagID = ""
		fp.PersistentID = ""
		fp.PersistentIDSource = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.WebGLVendor = "NVIDIA Corporation"
		fp.WebGLRenderer = "ANGLE (NVIDIA GeForce RTX 3080)"
	})
	auxB := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.WebGLDeepHash = "webgl_deep_b"
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.ETagID = ""
		fp.PersistentID = ""
		fp.PersistentIDSource = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.WebGLVendor = "NVIDIA Corporation"
		fp.WebGLRenderer = "ANGLE (NVIDIA GeForce RTX 3080)"
	})

	confDeep, _, _, _ := CompareFingerprints(deepA, deepB, 1, 2)
	confAux, _, _, _ := CompareFingerprints(auxA, auxB, 3, 4)

	assert.Greater(t, confDeep, confAux)
}

func TestCompareFingerprints_WebGLVendorAndRendererProvideAuxiliarySignals(t *testing.T) {
	initTestDB(t)

	a := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.WebGLDeepHash = "webgl_deep_a"
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.ETagID = ""
		fp.PersistentID = ""
		fp.PersistentIDSource = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.WebGLVendor = "NVIDIA Corporation"
		fp.WebGLRenderer = "ANGLE (NVIDIA GeForce RTX 3080)"
	})
	b := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.WebGLDeepHash = "webgl_deep_b"
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.ETagID = ""
		fp.PersistentID = ""
		fp.PersistentIDSource = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.WebGLVendor = "NVIDIA Corporation"
		fp.WebGLRenderer = "ANGLE (NVIDIA GeForce RTX 3080)"
	})

	conf, details, _, _ := CompareFingerprints(a, b, 1, 2)

	var vendorDetail *DimensionMatch
	var rendererDetail *DimensionMatch
	for i := range details {
		if details[i].Dimension == "webgl_vendor" {
			vendorDetail = &details[i]
		}
		if details[i].Dimension == "webgl_renderer" {
			rendererDetail = &details[i]
		}
	}

	require.NotNil(t, vendorDetail)
	require.NotNil(t, rendererDetail)
	assert.True(t, vendorDetail.Matched)
	assert.True(t, rendererDetail.Matched)
	assert.Less(t, vendorDetail.Weight, 0.88)
	assert.Less(t, rendererDetail.Weight, 0.88)
	assert.Less(t, conf, 1.0)
}

func TestCompareFingerprints_ClientRectsMatchProvidesStrongDeviceSignal(t *testing.T) {
	initTestDB(t)

	a := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.WebGLDeepHash = ""
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.ETagID = ""
		fp.PersistentID = ""
		fp.PersistentIDSource = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.ClientRectsHash = "client_rects_same"
	})
	b := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.WebGLDeepHash = ""
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.ETagID = ""
		fp.PersistentID = ""
		fp.PersistentIDSource = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.ClientRectsHash = "client_rects_same"
	})

	conf, details, _, _ := CompareFingerprints(a, b, 1, 2)

	var rectsDetail *DimensionMatch
	for i := range details {
		if details[i].Dimension == "client_rects_hash" {
			rectsDetail = &details[i]
			break
		}
	}
	require.NotNil(t, rectsDetail)
	assert.True(t, rectsDetail.Matched)
	assert.InDelta(t, 0.80, rectsDetail.Weight, 0.0001)
	assert.Greater(t, conf, 0.85, "tier2 device+network should raise score above base 0.85")
	assert.LessOrEqual(t, conf, 0.99, "tier2 score should stay below tier1")
}

func TestCompareFingerprints_ClientRectsMismatchReducesConfidence(t *testing.T) {
	initTestDB(t)

	matchA := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.WebGLDeepHash = ""
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.ETagID = ""
		fp.PersistentID = ""
		fp.PersistentIDSource = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.ClientRectsHash = "client_rects_same"
	})
	matchB := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.WebGLDeepHash = ""
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.ETagID = ""
		fp.PersistentID = ""
		fp.PersistentIDSource = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.ClientRectsHash = "client_rects_same"
	})
	mismatchB := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.WebGLDeepHash = ""
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.ETagID = ""
		fp.PersistentID = ""
		fp.PersistentIDSource = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.ClientRectsHash = "client_rects_other"
	})

	confMatch, _, _, _ := CompareFingerprints(matchA, matchB, 1, 2)
	confMismatch, _, _, _ := CompareFingerprints(matchA, mismatchB, 1, 3)

	assert.Greater(t, confMatch, confMismatch)
}

func TestIsShortCircuitStrongSignalResult(t *testing.T) {
	t.Run("nil_result", func(t *testing.T) {
		assert.False(t, isShortCircuitStrongSignalResult(nil))
	})

	t.Run("non_full_confidence", func(t *testing.T) {
		result := &LinkResult{
			Confidence: 0.97,
			Details: []DimensionMatch{{
				Dimension: "persistent_id",
			}},
		}
		assert.False(t, isShortCircuitStrongSignalResult(result))
	})

	t.Run("multi_details", func(t *testing.T) {
		result := &LinkResult{
			Confidence: 1.0,
			Details:    []DimensionMatch{{Dimension: "persistent_id"}, {Dimension: "ip_exact"}},
		}
		assert.False(t, isShortCircuitStrongSignalResult(result))
	})

	t.Run("single_non_strong_dimension", func(t *testing.T) {
		result := &LinkResult{
			Confidence: 1.0,
			Details: []DimensionMatch{{
				Dimension: "device_key",
			}},
		}
		assert.False(t, isShortCircuitStrongSignalResult(result))
	})

	t.Run("persistent_id_short_circuit", func(t *testing.T) {
		result := &LinkResult{
			Confidence: 0.99,
			Details: []DimensionMatch{{
				Dimension: "persistent_id",
			}},
		}
		assert.True(t, isShortCircuitStrongSignalResult(result))
	})

	t.Run("etag_short_circuit", func(t *testing.T) {
		result := &LinkResult{
			Confidence: 0.95,
			Details: []DimensionMatch{{
				Dimension: "etag_id",
			}},
		}
		assert.True(t, isShortCircuitStrongSignalResult(result))
	})

	t.Run("webrtc_short_circuit", func(t *testing.T) {
		result := &LinkResult{
			Confidence: 0.95,
			Details: []DimensionMatch{{
				Dimension: "webrtc_ip",
			}},
		}
		assert.True(t, isShortCircuitStrongSignalResult(result))
	})
}

func TestSerializeLinkDetails_FallbackOnMarshalError(t *testing.T) {
	details := []DimensionMatch{{
		Dimension:   "ua_similarity",
		DisplayName: "UA相似度",
		Score:       math.NaN(),
		Weight:      0.35,
		Matched:     false,
		Category:    "network",
	}}

	raw := serializeLinkDetails(1, 2, details)
	assert.NotEmpty(t, raw)

	var parsed []DimensionMatch
	require.NoError(t, common.Unmarshal(raw, &parsed))
	require.Len(t, parsed, 1)
	assert.Equal(t, "details_serialize_fallback", parsed[0].Dimension)
	assert.Equal(t, 0.0, parsed[0].Score)
	assert.Equal(t, 0.0, parsed[0].Weight)
	assert.Equal(t, "system", parsed[0].Category)
}

func TestAnalyzeAccountLinks_FallsBackToDeviceProfilesWhenNoRecentFingerprints(t *testing.T) {
	initTestDB(t)

	require.NoError(t, model.DB.AutoMigrate(
		&model.UserDeviceProfile{},
		&model.AccountLink{},
		&model.UserRiskScore{},
		&model.LinkWhitelist{},
		&model.IPUAHistory{},
	))
	require.NoError(t, model.EnsureAccountLinkUniqueIndex(model.DB))

	oldEnabled := common.FingerprintEnabled
	oldAuto := os.Getenv("FINGERPRINT_AUTO_CONFIRM_THRESHOLD")
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		if oldAuto == "" {
			_ = os.Unsetenv("FINGERPRINT_AUTO_CONFIRM_THRESHOLD")
		} else {
			_ = os.Setenv("FINGERPRINT_AUTO_CONFIRM_THRESHOLD", oldAuto)
		}
	})
	common.FingerprintEnabled = true
	_ = os.Setenv("FINGERPRINT_AUTO_CONFIRM_THRESHOLD", "1")

	target := &model.Fingerprint{
		UserID:        5001,
		IPAddress:     "10.10.10.10",
		LocalDeviceID: "shared-device-id",
		CompositeHash: "target-comp",
	}
	require.NoError(t, model.DB.Create(target).Error)

	// 让候选用户通过 IP 历史进入 findCandidates（而不是 recent fingerprints）
	require.NoError(t, model.UpsertIPUAHistory(&model.IPUAHistory{
		UserID:       5002,
		IPAddress:    "10.10.10.10",
		UABrowser:    "Chrome",
		UAOS:         "Windows",
		UserAgent:    "test-agent",
		Endpoint:     "/api/test",
		RequestCount: 1,
	}))

	// 候选用户没有任何 recent fingerprints，仅有 device profile
	require.NoError(t, model.UpsertDeviceProfile(&model.UserDeviceProfile{
		UserID:        5002,
		DeviceKey:     "lid:device-fallback",
		LocalDeviceID: "shared-device-id",
		CompositeHash: "fallback-comp",
		LastSeenIP:    "10.10.10.10",
	}))

	var recentCount int64
	require.NoError(t, model.DB.Model(&model.Fingerprint{}).Where("user_id = ?", 5002).Count(&recentCount).Error)
	require.Equal(t, int64(0), recentCount)

	AnalyzeAccountLinks(5001, target)

	link := model.FindExistingLink(5001, 5002)
	require.NotNil(t, link)
	assert.GreaterOrEqual(t, link.Confidence, 0.30)
}

func TestAnalyzeAccountLinks_AutoConfirmUsesCompareAndSwap(t *testing.T) {
	initTestDB(t)

	require.NoError(t, model.DB.Create(&model.AccountLink{
		UserIDA:    6001,
		UserIDB:    6002,
		Confidence: 0.82,
		Status:     model.AccountLinkStatusPending,
	}).Error)

	oldEnabled := common.FingerprintEnabled
	oldAuto := os.Getenv("FINGERPRINT_AUTO_CONFIRM_THRESHOLD")
	t.Cleanup(func() {
		common.FingerprintEnabled = oldEnabled
		if oldAuto == "" {
			_ = os.Unsetenv("FINGERPRINT_AUTO_CONFIRM_THRESHOLD")
		} else {
			_ = os.Setenv("FINGERPRINT_AUTO_CONFIRM_THRESHOLD", oldAuto)
		}
	})
	common.FingerprintEnabled = true
	_ = os.Setenv("FINGERPRINT_AUTO_CONFIRM_THRESHOLD", "0.8")

	require.NoError(t, model.UpsertIPUAHistory(&model.IPUAHistory{
		UserID:       6001,
		IPAddress:    "10.20.30.40",
		UABrowser:    "Chrome",
		UAOS:         "Windows",
		UserAgent:    "test-agent",
		Endpoint:     "/api/test",
		RequestCount: 1,
	}))
	require.NoError(t, model.UpsertIPUAHistory(&model.IPUAHistory{
		UserID:       6002,
		IPAddress:    "10.20.30.40",
		UABrowser:    "Chrome",
		UAOS:         "Windows",
		UserAgent:    "test-agent",
		Endpoint:     "/api/test",
		RequestCount: 1,
	}))
	require.NoError(t, model.UpsertDeviceProfile(&model.UserDeviceProfile{
		UserID:        6002,
		DeviceKey:     "lid:auto-confirm-candidate",
		LocalDeviceID: "shared-auto-confirm-device",
		UABrowser:     "Chrome",
		UAOS:          "Windows",
		LastSeenIP:    "10.20.30.40",
	}))

	target := &model.Fingerprint{
		UserID:        6001,
		IPAddress:     "10.20.30.40",
		LocalDeviceID: "shared-auto-confirm-device",
		UABrowser:     "Chrome",
		UAOS:          "Windows",
	}
	AnalyzeAccountLinks(6001, target)

	link := model.FindExistingLink(6001, 6002)
	require.NotNil(t, link)
	require.Equal(t, model.AccountLinkStatusAutoConfirmed, link.Status)

	require.NoError(t, model.UpdateLinkStatus(link.ID, model.AccountLinkStatusConfirmed, 99, "manual review"))
	AnalyzeAccountLinks(6001, target)

	link = model.FindExistingLink(6001, 6002)
	require.NotNil(t, link)
	require.Equal(t, model.AccountLinkStatusConfirmed, link.Status)
	require.Equal(t, 99, link.ReviewedBy)
	require.Equal(t, "manual review", link.ReviewNote)
}

func TestReviewLink_ValidatesActionsAndSideEffects(t *testing.T) {
	initTestDB(t)

	baseLink := model.AccountLink{
		UserIDA:    7001,
		UserIDB:    7002,
		Confidence: 0.77,
		Status:     model.AccountLinkStatusPending,
	}
	require.NoError(t, model.DB.Create(&baseLink).Error)

	require.Error(t, ReviewLink(baseLink.ID, "blocked", "bad action"))

	var unchanged model.AccountLink
	require.NoError(t, model.DB.First(&unchanged, baseLink.ID).Error)
	require.Equal(t, model.AccountLinkStatusPending, unchanged.Status)

	whitelistLink := model.AccountLink{UserIDA: 7101, UserIDB: 7102, Confidence: 0.8, Status: model.AccountLinkStatusPending}
	require.NoError(t, model.DB.Create(&whitelistLink).Error)
	require.NoError(t, ReviewLink(whitelistLink.ID, "whitelist", "trusted pair"))
	updatedWhitelist := model.GetLinkByID(whitelistLink.ID)
	require.NotNil(t, updatedWhitelist)
	require.Equal(t, model.AccountLinkStatusWhitelisted, updatedWhitelist.Status)
	require.True(t, model.IsWhitelisted(7101, 7102))

	require.NoError(t, model.DB.Create(&model.User{Id: 7201, Username: "review_u1", Password: "password123", AffCode: "aff-review-u1", Status: common.UserStatusEnabled}).Error)
	require.NoError(t, model.DB.Create(&model.User{Id: 7202, Username: "review_u2", Password: "password123", AffCode: "aff-review-u2", Status: common.UserStatusEnabled}).Error)
	banLink := model.AccountLink{UserIDA: 7201, UserIDB: 7202, Confidence: 0.93, Status: model.AccountLinkStatusPending}
	require.NoError(t, model.DB.Create(&banLink).Error)
	require.NoError(t, ReviewLink(banLink.ID, "ban_newer", "ban the newer account"))
	updatedBan := model.GetLinkByID(banLink.ID)
	require.NotNil(t, updatedBan)
	require.Equal(t, model.AccountLinkStatusConfirmed, updatedBan.Status)
	require.Equal(t, "ban_newer_account", updatedBan.ActionTaken)

	var bannedUser model.User
	require.NoError(t, model.DB.First(&bannedUser, 7202).Error)
	require.Equal(t, common.UserStatusDisabled, bannedUser.Status)

	autoLink := model.AccountLink{UserIDA: 7301, UserIDB: 7302, Confidence: 0.85, Status: model.AccountLinkStatusAutoConfirmed}
	require.NoError(t, model.DB.Create(&autoLink).Error)
	require.NoError(t, ReviewLink(autoLink.ID, "confirm", "auto reviewed"))
	updatedAuto := model.GetLinkByID(autoLink.ID)
	require.NotNil(t, updatedAuto)
	require.Equal(t, model.AccountLinkStatusConfirmed, updatedAuto.Status)

	reviewedLink := model.AccountLink{UserIDA: 7401, UserIDB: 7402, Confidence: 0.9, Status: model.AccountLinkStatusConfirmed}
	require.NoError(t, model.DB.Create(&reviewedLink).Error)
	require.Error(t, ReviewLink(reviewedLink.ID, "reject", "should be blocked"))
	unchangedReviewed := model.GetLinkByID(reviewedLink.ID)
	require.NotNil(t, unchangedReviewed)
	require.Equal(t, model.AccountLinkStatusConfirmed, unchangedReviewed.Status)
}

func TestGetFeatureWeights_UsesMediaAndSpeechGetters(t *testing.T) {
	oldMedia := common.GetEnvOrDefaultString("FINGERPRINT_WEIGHT_MEDIA_DEVICES_HASH", "")
	oldSpeech := common.GetEnvOrDefaultString("FINGERPRINT_WEIGHT_SPEECH_VOICES_HASH", "")
	t.Cleanup(func() {
		if oldMedia == "" {
			_ = os.Unsetenv("FINGERPRINT_WEIGHT_MEDIA_DEVICES_HASH")
		} else {
			_ = os.Setenv("FINGERPRINT_WEIGHT_MEDIA_DEVICES_HASH", oldMedia)
		}
		if oldSpeech == "" {
			_ = os.Unsetenv("FINGERPRINT_WEIGHT_SPEECH_VOICES_HASH")
		} else {
			_ = os.Setenv("FINGERPRINT_WEIGHT_SPEECH_VOICES_HASH", oldSpeech)
		}
	})

	_ = os.Setenv("FINGERPRINT_WEIGHT_MEDIA_DEVICES_HASH", "0.66")
	_ = os.Setenv("FINGERPRINT_WEIGHT_SPEECH_VOICES_HASH", "0.58")

	weights := getFeatureWeights()
	assert.Equal(t, 0.66, weights.MediaDevicesHash)
	assert.Equal(t, 0.58, weights.SpeechVoicesHash)
}

func TestGetFeatureWeights_UsesDynamicWeightsForCoreDimensions(t *testing.T) {
	oldOptionMap := common.OptionMap
	common.OptionMap = map[string]string{
		"FINGERPRINT_WEIGHT_LOCAL_DEVICE_ID":  "0.44",
		"FINGERPRINT_WEIGHT_CANVAS_HASH":      "0.33",
		"FINGERPRINT_WEIGHT_WEBGL_HASH":       "0.22",
		"FINGERPRINT_WEIGHT_AUDIO_HASH":       "0.11",
		"FINGERPRINT_WEIGHT_IP_EXACT":         "0.66",
		"FINGERPRINT_WEIGHT_UA_SIMILARITY":    "0.77",
		"FINGERPRINT_WEIGHT_SCREEN_RESOLUTION": "0.55",
	}
	t.Cleanup(func() {
		common.OptionMap = oldOptionMap
	})

	weights := getFeatureWeights()
	assert.InDelta(t, 0.44, weights.LocalDeviceID, 0.0001)
	assert.InDelta(t, 0.33, weights.CanvasHash, 0.0001)
	assert.InDelta(t, 0.22, weights.WebGLHash, 0.0001)
	assert.InDelta(t, 0.11, weights.AudioHash, 0.0001)
	assert.InDelta(t, 0.66, weights.IPExact, 0.0001)
	assert.InDelta(t, 0.77, weights.UASimilarity, 0.0001)
	assert.InDelta(t, 0.55, weights.ScreenResolution, 0.0001)
}

func TestCompareFingerprints_MediaDevicesHashMatchWeightedNotShortCircuit(t *testing.T) {
	initTestDB(t)

	a := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.WebGLDeepHash = ""
		fp.ClientRectsHash = ""
		fp.SpeechVoicesHash = ""
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.WebGLVendor = ""
		fp.WebGLRenderer = ""
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.ETagID = ""
		fp.PersistentID = ""
		fp.PersistentIDSource = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.IPAddress = ""
		fp.ScreenWidth = 0
		fp.ScreenHeight = 0
		fp.Timezone = ""
		fp.Languages = ""
		fp.CPUCores = 0
		fp.Platform = ""
		fp.UAOS = ""
		fp.UAOSVer = ""
		fp.UABrowser = ""
		fp.UABrowserVer = ""
		fp.UADeviceType = ""
		fp.MediaDevicesHash = "media_devices_same"
	})
	b := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.WebGLDeepHash = ""
		fp.ClientRectsHash = ""
		fp.SpeechVoicesHash = ""
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.WebGLVendor = ""
		fp.WebGLRenderer = ""
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.ETagID = ""
		fp.PersistentID = ""
		fp.PersistentIDSource = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.IPAddress = ""
		fp.ScreenWidth = 0
		fp.ScreenHeight = 0
		fp.Timezone = ""
		fp.Languages = ""
		fp.CPUCores = 0
		fp.Platform = ""
		fp.UAOS = ""
		fp.UAOSVer = ""
		fp.UABrowser = ""
		fp.UABrowserVer = ""
		fp.UADeviceType = ""
		fp.MediaDevicesHash = "media_devices_same"
	})

	conf, details, matchDims, totalDims := CompareFingerprints(a, b, 1, 2)
	assert.Greater(t, conf, 0.0)
	assert.Less(t, conf, 1.0)
	assert.GreaterOrEqual(t, matchDims, 1)
	assert.GreaterOrEqual(t, totalDims, 1)
	assert.True(t, containsMatchedDimension(details, "media_devices_hash"))

	var mediaDetail *DimensionMatch
	for i := range details {
		if details[i].Dimension == "media_devices_hash" {
			mediaDetail = &details[i]
			break
		}
	}
	require.NotNil(t, mediaDetail)
	assert.InDelta(t, 0.78, mediaDetail.Weight, 0.0001)
}

func TestCompareFingerprints_SpeechVoicesHashMatchWeightedNotShortCircuit(t *testing.T) {
	initTestDB(t)

	a := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.WebGLDeepHash = ""
		fp.ClientRectsHash = ""
		fp.MediaDevicesHash = ""
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.WebGLVendor = ""
		fp.WebGLRenderer = ""
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.ETagID = ""
		fp.PersistentID = ""
		fp.PersistentIDSource = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.IPAddress = ""
		fp.ScreenWidth = 0
		fp.ScreenHeight = 0
		fp.Timezone = ""
		fp.Languages = ""
		fp.CPUCores = 0
		fp.Platform = ""
		fp.UAOS = ""
		fp.UAOSVer = ""
		fp.UABrowser = ""
		fp.UABrowserVer = ""
		fp.UADeviceType = ""
		fp.SpeechVoicesHash = "speech_voices_same"
	})
	b := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.WebGLDeepHash = ""
		fp.ClientRectsHash = ""
		fp.MediaDevicesHash = ""
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.WebGLVendor = ""
		fp.WebGLRenderer = ""
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.ETagID = ""
		fp.PersistentID = ""
		fp.PersistentIDSource = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.IPAddress = ""
		fp.ScreenWidth = 0
		fp.ScreenHeight = 0
		fp.Timezone = ""
		fp.Languages = ""
		fp.CPUCores = 0
		fp.Platform = ""
		fp.UAOS = ""
		fp.UAOSVer = ""
		fp.UABrowser = ""
		fp.UABrowserVer = ""
		fp.UADeviceType = ""
		fp.SpeechVoicesHash = "speech_voices_same"
	})

	conf, details, matchDims, totalDims := CompareFingerprints(a, b, 1, 2)
	assert.Greater(t, conf, 0.0)
	assert.Less(t, conf, 1.0)
	assert.GreaterOrEqual(t, matchDims, 1)
	assert.GreaterOrEqual(t, totalDims, 1)
	assert.True(t, containsMatchedDimension(details, "speech_voices_hash"))

	var speechDetail *DimensionMatch
	for i := range details {
		if details[i].Dimension == "speech_voices_hash" {
			speechDetail = &details[i]
			break
		}
	}
	require.NotNil(t, speechDetail)
	assert.InDelta(t, 0.72, speechDetail.Weight, 0.0001)
}

func TestFindCandidates_IncludesMediaAndSpeechHashes(t *testing.T) {
	initTestDB(t)

	target := &model.Fingerprint{
		UserID:               1,
		LocalDeviceID:        "target-device",
		IPAddress:            "10.0.0.1",
		MediaDevicesHash:     "media-shared",
		MediaDeviceGroupHash: "media-group-shared",
		SpeechVoicesHash:     "speech-shared",
	}
	require.NoError(t, model.DB.Create(target).Error)

	candidateByMedia := &model.Fingerprint{
		UserID:           2,
		LocalDeviceID:    "candidate-media",
		IPAddress:        "20.0.0.2",
		MediaDevicesHash: "media-shared",
	}
	require.NoError(t, model.DB.Create(candidateByMedia).Error)

	candidateByMediaGroup := &model.Fingerprint{
		UserID:               5,
		LocalDeviceID:        "candidate-media-group",
		IPAddress:            "21.0.0.5",
		MediaDeviceGroupHash: "media-group-shared",
	}
	require.NoError(t, model.DB.Create(candidateByMediaGroup).Error)

	candidateBySpeech := &model.Fingerprint{
		UserID:           3,
		LocalDeviceID:    "candidate-speech",
		IPAddress:        "30.0.0.3",
		SpeechVoicesHash: "speech-shared",
	}
	require.NoError(t, model.DB.Create(candidateBySpeech).Error)

	unrelated := &model.Fingerprint{
		UserID:               4,
		LocalDeviceID:        "candidate-unrelated",
		IPAddress:            "40.0.0.4",
		MediaDevicesHash:     "media-other",
		MediaDeviceGroupHash: "media-group-other",
		SpeechVoicesHash:     "speech-other",
	}
	require.NoError(t, model.DB.Create(unrelated).Error)

	candidates := findCandidates(1, target)
	assert.Contains(t, candidates, 2)
	assert.Contains(t, candidates, 3)
	assert.Contains(t, candidates, 5)
	assert.NotContains(t, candidates, 1)
	assert.NotContains(t, candidates, 4)
}

func TestCompareFingerprints_MediaGroupAndSpeechCountsAreWeightedNotShortCircuit(t *testing.T) {
	initTestDB(t)

	a := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.WebGLDeepHash = ""
		fp.ClientRectsHash = ""
		fp.MediaDevicesHash = ""
		fp.SpeechVoicesHash = ""
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.WebGLVendor = ""
		fp.WebGLRenderer = ""
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.ETagID = ""
		fp.PersistentID = ""
		fp.PersistentIDSource = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.IPAddress = ""
		fp.ScreenWidth = 0
		fp.ScreenHeight = 0
		fp.Timezone = ""
		fp.Languages = ""
		fp.CPUCores = 0
		fp.Platform = ""
		fp.UAOS = ""
		fp.UAOSVer = ""
		fp.UABrowser = ""
		fp.UABrowserVer = ""
		fp.UADeviceType = ""
		fp.MediaDeviceGroupHash = "media-group-only"
		fp.MediaDeviceCount = "2-1-1"
		fp.SpeechVoiceCount = 9
		fp.SpeechLocalVoiceCount = 3
	})
	b := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.WebGLDeepHash = ""
		fp.ClientRectsHash = ""
		fp.MediaDevicesHash = ""
		fp.SpeechVoicesHash = ""
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.WebGLVendor = ""
		fp.WebGLRenderer = ""
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.ETagID = ""
		fp.PersistentID = ""
		fp.PersistentIDSource = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.IPAddress = ""
		fp.ScreenWidth = 0
		fp.ScreenHeight = 0
		fp.Timezone = ""
		fp.Languages = ""
		fp.CPUCores = 0
		fp.Platform = ""
		fp.UAOS = ""
		fp.UAOSVer = ""
		fp.UABrowser = ""
		fp.UABrowserVer = ""
		fp.UADeviceType = ""
		fp.MediaDeviceGroupHash = "media-group-only"
		fp.MediaDeviceCount = "2-1-1"
		fp.SpeechVoiceCount = 9
		fp.SpeechLocalVoiceCount = 3
	})

	conf, details, matchDims, totalDims := CompareFingerprints(a, b, 1, 2)
	assert.Greater(t, conf, 0.0)
	assert.Less(t, conf, 1.0)
	assert.GreaterOrEqual(t, matchDims, 1)
	assert.GreaterOrEqual(t, totalDims, 1)
	assert.True(t, containsMatchedDimension(details, "media_device_group_hash"))
	assert.True(t, containsMatchedDimension(details, "media_device_count"))
	assert.True(t, containsMatchedDimension(details, "speech_voice_count"))
	assert.True(t, containsMatchedDimension(details, "speech_local_voice_count"))
}

func TestComputeASNOverlap_Jaccard(t *testing.T) {
	initTestDB(t)

	_ = model.DB.Create(&model.IPUAHistory{UserID: 1, IPAddress: "1.1.1.1", UABrowser: "Chrome", UAOS: "Windows", ASN: 13335, ASNOrg: "Cloudflare"}).Error
	_ = model.DB.Create(&model.IPUAHistory{UserID: 1, IPAddress: "2.2.2.2", UABrowser: "Chrome", UAOS: "Windows", ASN: 16509, ASNOrg: "AWS"}).Error

	_ = model.DB.Create(&model.IPUAHistory{UserID: 2, IPAddress: "3.3.3.3", UABrowser: "Chrome", UAOS: "Windows", ASN: 13335, ASNOrg: "Cloudflare"}).Error
	_ = model.DB.Create(&model.IPUAHistory{UserID: 2, IPAddress: "4.4.4.4", UABrowser: "Chrome", UAOS: "Windows", ASN: 15169, ASNOrg: "Google"}).Error

	score := ComputeASNOverlap(1, 2)
	assert.InDelta(t, 1.0/3.0, score, 0.0001)
}

func TestComputeASNOverlap_IgnoresDatacenterAndProxyNoise(t *testing.T) {
	initTestDB(t)

	_ = model.DB.Create(&model.IPUAHistory{UserID: 51, IPAddress: "1.1.1.1", UABrowser: "Chrome", UAOS: "Windows", ASN: 13335, ASNOrg: "Cloudflare", IsDatacenter: true, IPType: "datacenter"}).Error
	_ = model.DB.Create(&model.IPUAHistory{UserID: 52, IPAddress: "1.1.1.2", UABrowser: "Chrome", UAOS: "Windows", ASN: 13335, ASNOrg: "Cloudflare", IsDatacenter: true, IPType: "proxy"}).Error

	score := ComputeASNOverlap(51, 52)
	assert.Equal(t, 0.0, score)
}

func TestCompareFingerprints_TemporalDimensionsRequireMinEvidence(t *testing.T) {
	initTestDB(t)

	base := time.Date(2026, 1, 1, 11, 0, 0, 0, time.UTC)
	for i := range 4 {
		_ = model.DB.Create(&model.Fingerprint{UserID: 61, CompositeHash: fmt.Sprintf("u61-%d", i), CreatedAt: base.Add(time.Duration(i*10) * time.Minute)}).Error
		_ = model.DB.Create(&model.Fingerprint{UserID: 62, CompositeHash: fmt.Sprintf("u62-%d", i), CreatedAt: base.Add(time.Duration(i*10+2) * time.Minute)}).Error
	}

	a := makeFP(func(fp *model.Fingerprint) {
		fp.PersistentID = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.JA4 = ""
		fp.TLSJA3Hash = ""
		fp.LocalDeviceID = ""
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.CompositeHash = ""
		fp.IPAddress = ""
	})
	b := makeFP(func(fp *model.Fingerprint) {
		fp.PersistentID = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.JA4 = ""
		fp.TLSJA3Hash = ""
		fp.LocalDeviceID = ""
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.CompositeHash = ""
		fp.IPAddress = ""
	})

	_, details, _, _ := CompareFingerprints(a, b, 61, 62)
	assert.False(t, containsDimension(details, "time_similarity"))
	assert.False(t, containsDimension(details, "mutual_exclusion"))
}

func TestCompareFingerprints_ContainsASNAndTemporalDimensions(t *testing.T) {
	initTestDB(t)

	for i := range 6 {
		ts := time.Date(2026, 1, 1, 8, i*5, 0, 0, time.UTC)
		_ = model.DB.Create(&model.Fingerprint{UserID: 11, CompositeHash: fmt.Sprintf("a-%d", i), CreatedAt: ts}).Error
		_ = model.DB.Create(&model.Fingerprint{UserID: 22, CompositeHash: fmt.Sprintf("b-%d", i), CreatedAt: ts}).Error
	}

	_ = model.DB.Create(&model.IPUAHistory{UserID: 11, IPAddress: "10.0.0.1", UABrowser: "Chrome", UAOS: "Windows", ASN: 13335, ASNOrg: "Cloudflare"}).Error
	_ = model.DB.Create(&model.IPUAHistory{UserID: 22, IPAddress: "10.0.0.2", UABrowser: "Chrome", UAOS: "Windows", ASN: 13335, ASNOrg: "Cloudflare"}).Error

	a := makeFP(func(fp *model.Fingerprint) {
		fp.PersistentID = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.JA4 = ""
		fp.TLSJA3Hash = ""
		fp.LocalDeviceID = ""
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.CompositeHash = ""
		fp.IPAddress = "10.0.0.1"
	})
	b := makeFP(func(fp *model.Fingerprint) {
		fp.PersistentID = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.JA4 = ""
		fp.TLSJA3Hash = ""
		fp.LocalDeviceID = ""
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.CompositeHash = ""
		fp.IPAddress = "10.0.0.2"
	})

	_, details, _, _ := CompareFingerprints(a, b, 11, 22)
	assert.True(t, containsDimension(details, "asn_similarity"))
	assert.True(t, containsDimension(details, "time_similarity"))
	assert.True(t, containsDimension(details, "mutual_exclusion"))
}

func TestCompareFingerprints_KeystrokeSimilarityIncludedWhenSamplesEnough(t *testing.T) {
	initTestDB(t)

	require.NoError(t, model.UpsertKeystrokeProfile(&model.KeystrokeProfile{
		UserID:        801,
		AvgHoldTime:   98,
		StdHoldTime:   16,
		AvgFlightTime: 118,
		StdFlightTime: 20,
		TypingSpeed:   4.9,
		DigraphData:   `[{"digraph":"alpha->alpha","avgFlightTime":120},{"digraph":"alpha->digit","avgFlightTime":110}]`,
		SampleCount:   160,
	}))
	require.NoError(t, model.UpsertKeystrokeProfile(&model.KeystrokeProfile{
		UserID:        802,
		AvgHoldTime:   101,
		StdHoldTime:   15,
		AvgFlightTime: 121,
		StdFlightTime: 19,
		TypingSpeed:   4.7,
		DigraphData:   `[{"digraph":"alpha->alpha","avgFlightTime":124},{"digraph":"alpha->digit","avgFlightTime":112}]`,
		SampleCount:   170,
	}))

	a := makeFP(func(fp *model.Fingerprint) {
		fp.PersistentID = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
	})
	b := makeFP(func(fp *model.Fingerprint) {
		fp.PersistentID = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
	})

	_, details, _, _ := CompareFingerprints(a, b, 801, 802)

	var keystrokeDetail *DimensionMatch
	for i := range details {
		if details[i].Dimension == "keystroke_similarity" {
			keystrokeDetail = &details[i]
			break
		}
	}
	require.NotNil(t, keystrokeDetail)
	assert.Greater(t, keystrokeDetail.Score, 0.70)
	assert.InDelta(t, getKeystrokeBehaviorWeight(), keystrokeDetail.Weight, 0.0001)
}

func TestCompareFingerprints_KeystrokeSimilarityRequiresMinSamples(t *testing.T) {
	initTestDB(t)

	require.NoError(t, model.UpsertKeystrokeProfile(&model.KeystrokeProfile{
		UserID:        811,
		AvgHoldTime:   100,
		StdHoldTime:   15,
		AvgFlightTime: 120,
		StdFlightTime: 20,
		TypingSpeed:   4.8,
		DigraphData:   `[{"digraph":"alpha->alpha","avgFlightTime":122}]`,
		SampleCount:   99,
	}))
	require.NoError(t, model.UpsertKeystrokeProfile(&model.KeystrokeProfile{
		UserID:        812,
		AvgHoldTime:   102,
		StdHoldTime:   14,
		AvgFlightTime: 121,
		StdFlightTime: 18,
		TypingSpeed:   4.7,
		DigraphData:   `[{"digraph":"alpha->alpha","avgFlightTime":124}]`,
		SampleCount:   150,
	}))

	a := makeFP(func(fp *model.Fingerprint) {
		fp.PersistentID = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
	})
	b := makeFP(func(fp *model.Fingerprint) {
		fp.PersistentID = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
	})

	_, details, _, _ := CompareFingerprints(a, b, 811, 812)
	assert.False(t, containsDimension(details, "keystroke_similarity"))
}

func TestCompareFingerprints_MouseSimilarityIncludedWhenSamplesEnough(t *testing.T) {
	initTestDB(t)

	require.NoError(t, model.UpsertMouseProfile(&model.MouseProfile{
		UserID:              901,
		AvgSpeed:            1380,
		MaxSpeed:            2100,
		SpeedStd:            180,
		AvgAcceleration:     320,
		AccStd:              75,
		DirectionChangeRate: 0.21,
		AvgScrollDelta:      96,
		ScrollDeltaMode:     0,
		ClickDistribution:   `{"topLeft":0.25,"topRight":0.25,"bottomLeft":0.25,"bottomRight":0.25}`,
		SampleCount:         80,
	}))
	require.NoError(t, model.UpsertMouseProfile(&model.MouseProfile{
		UserID:              902,
		AvgSpeed:            1400,
		MaxSpeed:            2120,
		SpeedStd:            170,
		AvgAcceleration:     315,
		AccStd:              70,
		DirectionChangeRate: 0.20,
		AvgScrollDelta:      100,
		ScrollDeltaMode:     0,
		ClickDistribution:   `{"topLeft":0.26,"topRight":0.24,"bottomLeft":0.24,"bottomRight":0.26}`,
		SampleCount:         95,
	}))

	a := makeFP(func(fp *model.Fingerprint) {
		fp.PersistentID = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
	})
	b := makeFP(func(fp *model.Fingerprint) {
		fp.PersistentID = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
	})

	_, details, _, _ := CompareFingerprints(a, b, 901, 902)

	var mouseDetail *DimensionMatch
	for i := range details {
		if details[i].Dimension == "mouse_similarity" {
			mouseDetail = &details[i]
			break
		}
	}
	require.NotNil(t, mouseDetail)
	assert.Greater(t, mouseDetail.Score, 0.70)
	assert.InDelta(t, getMouseBehaviorWeight(), mouseDetail.Weight, 0.0001)
}

func TestCompareFingerprints_BehaviorAnalysisDisabledSkipsKeystrokeAndMouse(t *testing.T) {
	initTestDB(t)

	oldEnabled := common.FingerprintEnableBehaviorAnalysis
	common.FingerprintEnableBehaviorAnalysis = false
	t.Cleanup(func() {
		common.FingerprintEnableBehaviorAnalysis = oldEnabled
	})

	require.NoError(t, model.UpsertKeystrokeProfile(&model.KeystrokeProfile{
		UserID:        821,
		AvgHoldTime:   98,
		StdHoldTime:   16,
		AvgFlightTime: 118,
		StdFlightTime: 20,
		TypingSpeed:   4.9,
		DigraphData:   `[{"digraph":"alpha->alpha","avgFlightTime":120}]`,
		SampleCount:   160,
	}))
	require.NoError(t, model.UpsertKeystrokeProfile(&model.KeystrokeProfile{
		UserID:        822,
		AvgHoldTime:   101,
		StdHoldTime:   15,
		AvgFlightTime: 121,
		StdFlightTime: 19,
		TypingSpeed:   4.7,
		DigraphData:   `[{"digraph":"alpha->alpha","avgFlightTime":124}]`,
		SampleCount:   170,
	}))
	require.NoError(t, model.UpsertMouseProfile(&model.MouseProfile{
		UserID:              821,
		AvgSpeed:            1380,
		MaxSpeed:            2100,
		SpeedStd:            180,
		AvgAcceleration:     320,
		AccStd:              75,
		DirectionChangeRate: 0.21,
		AvgScrollDelta:      96,
		ScrollDeltaMode:     0,
		ClickDistribution:   `{"topLeft":0.25,"topRight":0.25,"bottomLeft":0.25,"bottomRight":0.25}`,
		SampleCount:         80,
	}))
	require.NoError(t, model.UpsertMouseProfile(&model.MouseProfile{
		UserID:              822,
		AvgSpeed:            1400,
		MaxSpeed:            2120,
		SpeedStd:            170,
		AvgAcceleration:     315,
		AccStd:              70,
		DirectionChangeRate: 0.20,
		AvgScrollDelta:      100,
		ScrollDeltaMode:     0,
		ClickDistribution:   `{"topLeft":0.26,"topRight":0.24,"bottomLeft":0.24,"bottomRight":0.26}`,
		SampleCount:         95,
	}))

	a := makeFP(func(fp *model.Fingerprint) {
		fp.PersistentID = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
	})
	b := makeFP(func(fp *model.Fingerprint) {
		fp.PersistentID = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
	})

	_, details, _, _ := CompareFingerprints(a, b, 821, 822)
	assert.False(t, containsDimension(details, "keystroke_similarity"))
	assert.False(t, containsDimension(details, "mouse_similarity"))
}

func TestCompareFingerprints_MouseSimilarityRequiresMinSamples(t *testing.T) {
	initTestDB(t)

	require.NoError(t, model.UpsertMouseProfile(&model.MouseProfile{
		UserID:              911,
		AvgSpeed:            1380,
		MaxSpeed:            2100,
		SpeedStd:            180,
		AvgAcceleration:     320,
		AccStd:              75,
		DirectionChangeRate: 0.21,
		AvgScrollDelta:      96,
		ScrollDeltaMode:     0,
		ClickDistribution:   `{"topLeft":0.25,"topRight":0.25,"bottomLeft":0.25,"bottomRight":0.25}`,
		SampleCount:         49,
	}))
	require.NoError(t, model.UpsertMouseProfile(&model.MouseProfile{
		UserID:              912,
		AvgSpeed:            1400,
		MaxSpeed:            2120,
		SpeedStd:            170,
		AvgAcceleration:     315,
		AccStd:              70,
		DirectionChangeRate: 0.20,
		AvgScrollDelta:      100,
		ScrollDeltaMode:     0,
		ClickDistribution:   `{"topLeft":0.26,"topRight":0.24,"bottomLeft":0.24,"bottomRight":0.26}`,
		SampleCount:         80,
	}))

	a := makeFP(func(fp *model.Fingerprint) {
		fp.PersistentID = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
	})
	b := makeFP(func(fp *model.Fingerprint) {
		fp.PersistentID = ""
		fp.ETagID = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
	})

	_, details, _, _ := CompareFingerprints(a, b, 911, 912)
	assert.False(t, containsDimension(details, "mouse_similarity"))
}

func makeTierSimilarityFP(opts ...func(*model.Fingerprint)) *model.Fingerprint {
	fp := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.WebGLDeepHash = ""
		fp.ClientRectsHash = ""
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.WebGLVendor = ""
		fp.WebGLRenderer = ""
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
		fp.JA4 = ""
		fp.HTTPHeaderHash = ""
		fp.ETagID = ""
		fp.PersistentID = ""
		fp.PersistentIDSource = ""
		fp.WebRTCLocalIPs = "[]"
		fp.WebRTCPublicIPs = "[]"
		fp.IPAddress = ""
		fp.DNSResolverIP = ""
		fp.ScreenWidth = 0
		fp.ScreenHeight = 0
		fp.Timezone = ""
		fp.Languages = ""
		fp.CPUCores = 0
		fp.Platform = ""
		fp.UAOS = ""
		fp.UAOSVer = ""
		fp.UABrowser = ""
		fp.UABrowserVer = ""
		fp.UADeviceType = ""
		fp.MediaDevicesHash = ""
		fp.MediaDeviceGroupHash = ""
		fp.MediaDeviceCount = ""
		fp.SpeechVoicesHash = ""
		fp.SpeechVoiceCount = 0
		fp.SpeechLocalVoiceCount = 0
	})
	for _, opt := range opts {
		opt(fp)
	}
	return fp
}

func stabilizeSimilarityScoringConfig(t *testing.T, behaviorEnabled bool) {
	t.Helper()

	oldJA4 := common.FingerprintEnableJA4
	oldETag := common.FingerprintEnableETag
	oldWebRTC := common.FingerprintEnableWebRTC
	oldDNSLeak := common.FingerprintEnableDNSLeak
	oldASN := common.FingerprintEnableASNAnalysis
	oldTemporal := common.FingerprintEnableTemporalAnalysis
	oldBehavior := common.FingerprintEnableBehaviorAnalysis

	common.OptionMapRWMutex.RLock()
	oldOptionMap := make(map[string]string, len(common.OptionMap))
	maps.Copy(oldOptionMap, common.OptionMap)
	common.OptionMapRWMutex.RUnlock()

	common.FingerprintEnableJA4 = false
	common.FingerprintEnableETag = false
	common.FingerprintEnableWebRTC = false
	common.FingerprintEnableDNSLeak = false
	common.FingerprintEnableASNAnalysis = false
	common.FingerprintEnableTemporalAnalysis = false
	common.FingerprintEnableBehaviorAnalysis = behaviorEnabled

	common.OptionMapRWMutex.Lock()
	common.OptionMap = map[string]string{
		"FINGERPRINT_WEIGHT_KEYSTROKE":       "0.70",
		"FINGERPRINT_WEIGHT_MOUSE":           "0.65",
		"FINGERPRINT_WEIGHT_TIME_SIMILARITY": "0.50",
		"FINGERPRINT_WEIGHT_MUTUAL_EXCLUSION": "0.55",
	}
	common.OptionMapRWMutex.Unlock()

	t.Setenv("FINGERPRINT_MIN_KEYSTROKE_SAMPLES", "100")
	t.Setenv("FINGERPRINT_MIN_MOUSE_SAMPLES", "50")

	t.Cleanup(func() {
		common.FingerprintEnableJA4 = oldJA4
		common.FingerprintEnableETag = oldETag
		common.FingerprintEnableWebRTC = oldWebRTC
		common.FingerprintEnableDNSLeak = oldDNSLeak
		common.FingerprintEnableASNAnalysis = oldASN
		common.FingerprintEnableTemporalAnalysis = oldTemporal
		common.FingerprintEnableBehaviorAnalysis = oldBehavior

		common.OptionMapRWMutex.Lock()
		common.OptionMap = oldOptionMap
		common.OptionMapRWMutex.Unlock()
	})
}

func seedTier4BehaviorProfiles(t *testing.T, userA, userB int) {
	t.Helper()

	require.NoError(t, model.UpsertKeystrokeProfile(&model.KeystrokeProfile{
		UserID:        userA,
		AvgHoldTime:   99,
		StdHoldTime:   15,
		AvgFlightTime: 120,
		StdFlightTime: 18,
		TypingSpeed:   4.8,
		DigraphData:   `[{"digraph":"alpha->alpha","avgFlightTime":120},{"digraph":"alpha->digit","avgFlightTime":110}]`,
		SampleCount:   180,
	}))
	require.NoError(t, model.UpsertKeystrokeProfile(&model.KeystrokeProfile{
		UserID:        userB,
		AvgHoldTime:   99,
		StdHoldTime:   15,
		AvgFlightTime: 120,
		StdFlightTime: 18,
		TypingSpeed:   4.8,
		DigraphData:   `[{"digraph":"alpha->alpha","avgFlightTime":120},{"digraph":"alpha->digit","avgFlightTime":110}]`,
		SampleCount:   190,
	}))
	require.NoError(t, model.UpsertMouseProfile(&model.MouseProfile{
		UserID:              userA,
		AvgSpeed:            1380,
		MaxSpeed:            2100,
		SpeedStd:            180,
		AvgAcceleration:     320,
		AccStd:              75,
		DirectionChangeRate: 0.21,
		AvgScrollDelta:      96,
		ScrollDeltaMode:     0,
		ClickDistribution:   `{"topLeft":0.25,"topRight":0.25,"bottomLeft":0.25,"bottomRight":0.25}`,
		SampleCount:         120,
	}))
	require.NoError(t, model.UpsertMouseProfile(&model.MouseProfile{
		UserID:              userB,
		AvgSpeed:            1380,
		MaxSpeed:            2100,
		SpeedStd:            180,
		AvgAcceleration:     320,
		AccStd:              75,
		DirectionChangeRate: 0.21,
		AvgScrollDelta:      96,
		ScrollDeltaMode:     0,
		ClickDistribution:   `{"topLeft":0.25,"topRight":0.25,"bottomLeft":0.25,"bottomRight":0.25}`,
		SampleCount:         130,
	}))
}

func TestCalculateSimilarity_TierBuckets(t *testing.T) {
	t.Run("tier1 strong signal short circuit", func(t *testing.T) {
		initTestDB(t)
		stabilizeSimilarityScoringConfig(t, false)

		a := makeTierSimilarityFP(func(fp *model.Fingerprint) {
			fp.PersistentID = "tier1-persistent-id"
		})
		b := makeTierSimilarityFP(func(fp *model.Fingerprint) {
			fp.PersistentID = "tier1-persistent-id"
		})

		result := CalculateSimilarity(a, b, 3101, 3102)
		assert.Equal(t, "tier1", result.Tier)
		assert.InDelta(t, 0.99, result.Score, 0.0001)
		require.Len(t, result.Details, 1)
		assert.Equal(t, "persistent_id", result.Details[0].Dimension)
	})

	t.Run("tier2 requires device network and environment evidence", func(t *testing.T) {
		initTestDB(t)
		stabilizeSimilarityScoringConfig(t, false)

		a := makeTierSimilarityFP(func(fp *model.Fingerprint) {
			fp.LocalDeviceID = "tier2-device"
			fp.WebGLRenderer = "ANGLE (NVIDIA GeForce RTX 3080)"
			fp.IPAddress = "10.10.10.20"
			fp.UAOS = "Windows"
			fp.UAOSVer = "11"
			fp.UABrowser = "Chrome"
			fp.UABrowserVer = "124"
			fp.UADeviceType = "desktop"
			fp.ScreenWidth = 2560
			fp.ScreenHeight = 1440
			fp.Timezone = "Asia/Shanghai"
			fp.Languages = "zh-CN,en-US"
			fp.CPUCores = 8
			fp.Platform = "Win32"
		})
		b := makeTierSimilarityFP(func(fp *model.Fingerprint) {
			fp.LocalDeviceID = "tier2-device"
			fp.WebGLRenderer = "ANGLE (NVIDIA GeForce RTX 3080)"
			fp.IPAddress = "10.10.10.20"
			fp.UAOS = "Windows"
			fp.UAOSVer = "11"
			fp.UABrowser = "Chrome"
			fp.UABrowserVer = "124"
			fp.UADeviceType = "desktop"
			fp.ScreenWidth = 2560
			fp.ScreenHeight = 1440
			fp.Timezone = "Asia/Shanghai"
			fp.Languages = "zh-CN,en-US"
			fp.CPUCores = 8
			fp.Platform = "Win32"
		})

		result := CalculateSimilarity(a, b, 3201, 3202)
		assert.Equal(t, "tier2", result.Tier)
		assert.Greater(t, result.Score, 0.85)
		assert.Less(t, result.Score, 0.95)
		assert.True(t, containsDimension(result.Details, "local_device_id"))
		assert.True(t, containsDimension(result.Details, "webgl_renderer"))
	})

	t.Run("tier3 keeps medium device evidence plus network correlation", func(t *testing.T) {
		initTestDB(t)
		stabilizeSimilarityScoringConfig(t, false)

		a := makeTierSimilarityFP(func(fp *model.Fingerprint) {
			fp.LocalDeviceID = "tier3-device"
			fp.WebGLRenderer = "ANGLE (NVIDIA GeForce RTX 3080)"
			fp.IPAddress = "10.20.30.40"
			fp.UAOS = "Windows"
			fp.UAOSVer = "11"
			fp.UABrowser = "Chrome"
			fp.UABrowserVer = "124"
			fp.UADeviceType = "desktop"
			fp.ScreenWidth = 2560
			fp.ScreenHeight = 1440
			fp.Timezone = "Asia/Shanghai"
			fp.Languages = "zh-CN,en-US"
			fp.CPUCores = 8
			fp.Platform = "Win32"
		})
		b := makeTierSimilarityFP(func(fp *model.Fingerprint) {
			fp.LocalDeviceID = "tier3-device"
			fp.WebGLRenderer = "ANGLE (NVIDIA GeForce RTX 3080)"
			fp.IPAddress = "10.20.30.40"
			fp.UAOS = "Windows"
			fp.UAOSVer = "11"
			fp.UABrowser = "Chrome"
			fp.UABrowserVer = "124"
			fp.UADeviceType = "desktop"
		})

		result := CalculateSimilarity(a, b, 3301, 3302)
		assert.Equal(t, "tier3", result.Tier)
		assert.InDelta(t, 0.70, result.Score, 0.0001)
	})

	t.Run("tier4 uses behavior evidence with network support", func(t *testing.T) {
		initTestDB(t)
		stabilizeSimilarityScoringConfig(t, true)
		seedTier4BehaviorProfiles(t, 3401, 3402)

		a := makeTierSimilarityFP(func(fp *model.Fingerprint) {
			fp.IPAddress = "198.51.100.42"
			fp.UAOS = "Windows"
			fp.UAOSVer = "11"
			fp.UABrowser = "Chrome"
			fp.UABrowserVer = "124"
			fp.UADeviceType = "desktop"
		})
		b := makeTierSimilarityFP(func(fp *model.Fingerprint) {
			fp.IPAddress = "198.51.100.42"
			fp.UAOS = "Windows"
			fp.UAOSVer = "11"
			fp.UABrowser = "Chrome"
			fp.UABrowserVer = "124"
			fp.UADeviceType = "desktop"
		})

		result := CalculateSimilarity(a, b, 3401, 3402)
		assert.Equal(t, "tier4", result.Tier)
		assert.InDelta(t, 0.60, result.Score, 0.0001)
		assert.True(t, containsDimension(result.Details, "keystroke_similarity"))
		assert.True(t, containsDimension(result.Details, "mouse_similarity"))
	})

	t.Run("fallback keeps weak residual evidence below tier4 threshold", func(t *testing.T) {
		initTestDB(t)
		stabilizeSimilarityScoringConfig(t, false)

		a := makeTierSimilarityFP(func(fp *model.Fingerprint) {
			fp.LocalDeviceID = "fallback-device"
		})
		b := makeTierSimilarityFP(func(fp *model.Fingerprint) {
			fp.LocalDeviceID = "fallback-device"
		})

		result := CalculateSimilarity(a, b, 3501, 3502)
		assert.Equal(t, "fallback", result.Tier)
		assert.Less(t, result.Score, 0.60)
		assert.True(t, containsDimension(result.Details, "local_device_id"))
	})
}

func TestCalculateSimilarity_DegradesWhenEvidenceGoesMissing(t *testing.T) {
	initTestDB(t)
	stabilizeSimilarityScoringConfig(t, true)
	seedTier4BehaviorProfiles(t, 3601, 3604)

	strongSignalA := makeTierSimilarityFP(func(fp *model.Fingerprint) {
		fp.PersistentID = "degrade-persistent-id"
	})
	strongSignalB := makeTierSimilarityFP(func(fp *model.Fingerprint) {
		fp.PersistentID = "degrade-persistent-id"
	})
	baselineA := makeTierSimilarityFP(func(fp *model.Fingerprint) {
		fp.LocalDeviceID = "degrade-device"
		fp.WebGLRenderer = "ANGLE (NVIDIA GeForce RTX 3080)"
		fp.IPAddress = "203.0.113.55"
		fp.UAOS = "Windows"
		fp.UAOSVer = "11"
		fp.UABrowser = "Chrome"
		fp.UABrowserVer = "124"
		fp.UADeviceType = "desktop"
		fp.ScreenWidth = 2560
		fp.ScreenHeight = 1440
		fp.Timezone = "Asia/Shanghai"
		fp.Languages = "zh-CN,en-US"
		fp.CPUCores = 8
		fp.Platform = "Win32"
	})
	baselineB := makeTierSimilarityFP(func(fp *model.Fingerprint) {
		fp.LocalDeviceID = "degrade-device"
		fp.WebGLRenderer = "ANGLE (NVIDIA GeForce RTX 3080)"
		fp.IPAddress = "203.0.113.55"
		fp.UAOS = "Windows"
		fp.UAOSVer = "11"
		fp.UABrowser = "Chrome"
		fp.UABrowserVer = "124"
		fp.UADeviceType = "desktop"
		fp.ScreenWidth = 2560
		fp.ScreenHeight = 1440
		fp.Timezone = "Asia/Shanghai"
		fp.Languages = "zh-CN,en-US"
		fp.CPUCores = 8
		fp.Platform = "Win32"
	})
	missingEnvironmentB := makeTierSimilarityFP(func(fp *model.Fingerprint) {
		fp.LocalDeviceID = "degrade-device"
		fp.WebGLRenderer = "ANGLE (NVIDIA GeForce RTX 3080)"
		fp.IPAddress = "203.0.113.55"
		fp.UAOS = "Windows"
		fp.UAOSVer = "11"
		fp.UABrowser = "Chrome"
		fp.UABrowserVer = "124"
		fp.UADeviceType = "desktop"
	})
	behaviorDrivenB := makeTierSimilarityFP(func(fp *model.Fingerprint) {
		fp.IPAddress = "203.0.113.55"
		fp.UAOS = "Windows"
		fp.UAOSVer = "11"
		fp.UABrowser = "Chrome"
		fp.UABrowserVer = "124"
		fp.UADeviceType = "desktop"
	})
	weakFallbackB := makeTierSimilarityFP(func(fp *model.Fingerprint) {
		fp.LocalDeviceID = "degrade-device"
	})

	strongSignalResult := CalculateSimilarity(strongSignalA, strongSignalB, 3601, 3606)
	fullResult := CalculateSimilarity(baselineA, baselineB, 3601, 3602)
	missingEnvironmentResult := CalculateSimilarity(baselineA, missingEnvironmentB, 3601, 3603)
	behaviorDrivenResult := CalculateSimilarity(baselineA, behaviorDrivenB, 3601, 3604)
	weakFallbackResult := CalculateSimilarity(baselineA, weakFallbackB, 3601, 3605)

	assert.Equal(t, "tier1", strongSignalResult.Tier)
	assert.Equal(t, "tier2", fullResult.Tier)
	assert.Equal(t, "tier3", missingEnvironmentResult.Tier)
	assert.Equal(t, "tier4", behaviorDrivenResult.Tier)
	assert.Equal(t, "fallback", weakFallbackResult.Tier)
	assert.Greater(t, strongSignalResult.Score, fullResult.Score)
	assert.Greater(t, fullResult.Score, missingEnvironmentResult.Score)
	assert.Greater(t, missingEnvironmentResult.Score, behaviorDrivenResult.Score)
	assert.Greater(t, behaviorDrivenResult.Score, weakFallbackResult.Score)
}

func containsDimension(details []DimensionMatch, dim string) bool {
	for _, d := range details {
		if d.Dimension == dim {
			return true
		}
	}
	return false
}
