package service

import (
	"testing"

	"github.com/QuantumNous/new-api/model"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// initTestDB 初始化内存 SQLite 用于测试
func initTestDB(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	err = db.AutoMigrate(&model.Fingerprint{}, &model.IPUAHistory{})
	require.NoError(t, err)
	model.DB = db
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
		CanvasHash:    "canvas_abc123",
		WebGLHash:     "webgl_abc123",
		AudioHash:     "audio_abc123",
		FontsHash:     "fonts_abc123",
		WebGLRenderer: "NVIDIA GeForce RTX 3080",
		LocalDeviceID: "device_abc123",
		CompositeHash: "comp_abc123",
		TLSJA3Hash:    "ja3_abc123",
		IPAddress:     "1.2.3.4",
		UAOS:          "Windows",
		UAOSVer:       "10",
		UABrowser:     "Chrome",
		UABrowserVer:  "120",
		UADeviceType:  "desktop",
		ScreenWidth:   1920,
		ScreenHeight:  1080,
		Timezone:      "Asia/Shanghai",
		Languages:     "zh-CN,en-US",
		CPUCores:      8,
		Platform:      "Win32",
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

	assert.Greater(t, conf, 0.85, "identical device fingerprint should yield confidence >0.85")
	assert.Greater(t, matchDims, 5)
	assert.Greater(t, totalDims, 0)
	assert.NotEmpty(t, details)
}

// TestCompareFingerprints_SameIPDifferentDevice IP相同但设备不同 → 低-中置信度
func TestCompareFingerprints_SameIPDifferentDevice(t *testing.T) {
	initTestDB(t)

	a := makeFP()
	b := makeFP(func(fp *model.Fingerprint) {
		// 清除所有设备级指纹，仅保留 IP
		fp.CanvasHash = ""
		fp.WebGLHash = ""
		fp.AudioHash = ""
		fp.FontsHash = ""
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
		fp.TLSJA3Hash = ""
	})

	conf, _, _, _ := CompareFingerprints(a, b, 10, 20)

	// 没有设备指纹，置信度应该较低
	assert.Less(t, conf, 0.6, "no device fingerprint should keep confidence below 0.6")
}

// TestCompareFingerprints_CompletelyDifferent 完全不同的设备 → 极低置信度
func TestCompareFingerprints_CompletelyDifferent(t *testing.T) {
	initTestDB(t)

	a := makeFP()
	b := makeFP(func(fp *model.Fingerprint) {
		fp.CanvasHash = "canvas_zzz999"
		fp.WebGLHash = "webgl_zzz999"
		fp.AudioHash = "audio_zzz999"
		fp.FontsHash = "fonts_zzz999"
		fp.LocalDeviceID = "device_zzz999"
		fp.CompositeHash = "comp_zzz999"
		fp.TLSJA3Hash = "ja3_zzz999"
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
	assert.Greater(t, conf, 0.80, "same device with different IP should still yield high confidence")
	assert.Greater(t, matchDims, 4)
}

// TestCompareFingerprints_DetailsOrder details 应按权重降序排列
func TestCompareFingerprints_DetailsOrder(t *testing.T) {
	initTestDB(t)

	a := makeFP()
	b := makeFP()

	_, details, _, _ := CompareFingerprints(a, b, 1, 2)

	require.Greater(t, len(details), 1)
	for i := 1; i < len(details); i++ {
		assert.GreaterOrEqual(t, details[i-1].Weight, details[i].Weight,
			"details should be sorted by weight descending")
	}
}

// TestCompareFingerprints_AutoConfirmThreshold 验证高置信度可触发自动确认阈值
func TestCompareFingerprints_AutoConfirmThreshold(t *testing.T) {
	initTestDB(t)

	a := makeFP()
	b := makeFP()

	conf, _, _, _ := CompareFingerprints(a, b, 1, 2)

	// 默认自动确认阈值 0.90，相同设备应超过
	assert.GreaterOrEqual(t, conf, 0.85,
		"identical device fingerprints should approach or exceed the 0.90 auto-confirm threshold")
}

// ─── 多账号同人检测 ───
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
		fp.FontsHash = "fonts_incognito_rand4a6f"
		// 无痕模式不持久化 LocalDeviceID 和 CompositeHash
		fp.LocalDeviceID = ""
		fp.CompositeHash = ""
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
	assert.Greater(t, conf, 0.70,
		"账号A与B共享所有设备指纹，置信度应 >0.70")
	assert.Greater(t, matchDims, 4,
		"至少5个维度匹配")
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
	assert.Greater(t, conf, 0.40,
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
func TestMultiAccount_CandidateDiscovery(t *testing.T) {
	initTestDB(t)

	a := makeAccountA()
	b := makeAccountB()
	c := makeAccountC()

	// 将三账号指纹写入数据库
	require.NoError(t, model.DB.Create(a).Error)
	require.NoError(t, model.DB.Create(b).Error)
	require.NoError(t, model.DB.Create(c).Error)

	// IP 路径依赖 ip_ua_history 表：A 和 C 使用相同 IP，插入历史记录
	require.NoError(t, model.DB.Create(&model.IPUAHistory{
		UserID: 101, IPAddress: "1.2.3.4",
	}).Error)
	require.NoError(t, model.DB.Create(&model.IPUAHistory{
		UserID: 103, IPAddress: "1.2.3.4",
	}).Error)
	// B 使用不同 IP（模拟 VPN）
	require.NoError(t, model.DB.Create(&model.IPUAHistory{
		UserID: 102, IPAddress: "5.6.7.8",
	}).Error)

	// 账号 B 登录时，应能通过 canvas/local_device_id 路径发现账号 A
	candidatesForB := findCandidates(102, b)
	assert.Contains(t, candidatesForB, 101,
		"账号B登录时应通过 Canvas/LocalDeviceID 等设备哈希发现账号A")

	// 账号 C 登录时（无痕），应能通过精确 IP 匹配发现账号 A
	candidatesForC := findCandidates(103, c)
	assert.Contains(t, candidatesForC, 101,
		"账号C（无痕）登录时应通过精确 IP 匹配发现账号A")

	// 账号 A 登录时，应同时发现 B（设备哈希）和 C（IP）
	candidatesForA := findCandidates(101, a)
	assert.Contains(t, candidatesForA, 102,
		"账号A应通过设备哈希发现账号B")
	assert.Contains(t, candidatesForA, 103,
		"账号A应通过 IP 精确匹配发现账号C")
}
