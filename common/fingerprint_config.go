package common

import (
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
)

var FingerprintEnabled bool
var FingerprintSuperAdminOnly bool
var FingerprintTestResetEnabled bool
var FingerprintTrustedProxyCIDRs = []string{"127.0.0.1/8", "::1/128"}
var FingerprintEnableJA4 = true
var FingerprintEnableETag = true
var FingerprintEnableWebRTC = true
var FingerprintEnableASNAnalysis = true
var FingerprintEnableDNSLeak = false
var FingerprintEnableTemporalAnalysis = true
var FingerprintEnableTemporalPrecomputeWrite = true
var FingerprintEnableTemporalPrecomputeRead = false
var FingerprintEnableBehaviorAnalysis = true

func InitFingerprintConfig() {
	FingerprintEnabled = GetEnvOrDefaultBool("FINGERPRINT_ENABLED", false)
	FingerprintSuperAdminOnly = GetEnvOrDefaultBool("FINGERPRINT_SUPER_ADMIN_ONLY", false)
	FingerprintTestResetEnabled = GetEnvOrDefaultBool("FINGERPRINT_TEST_RESET_ENABLED", false)
	FingerprintTrustedProxyCIDRs = getFingerprintTrustedProxyCIDRs()
	FingerprintEnableJA4 = GetEnvOrDefaultBool("FINGERPRINT_ENABLE_JA4", true)
	FingerprintEnableETag = GetEnvOrDefaultBool("FINGERPRINT_ENABLE_ETAG", true)
	FingerprintEnableWebRTC = GetEnvOrDefaultBool("FINGERPRINT_ENABLE_WEBRTC", true)
	FingerprintEnableASNAnalysis = GetEnvOrDefaultBool("FINGERPRINT_ENABLE_ASN_ANALYSIS", true)
	FingerprintEnableDNSLeak = GetEnvOrDefaultBool("FINGERPRINT_ENABLE_DNS_LEAK", false)
	FingerprintEnableTemporalAnalysis = GetEnvOrDefaultBool("FINGERPRINT_ENABLE_TEMPORAL_ANALYSIS", true)
	FingerprintEnableTemporalPrecomputeWrite = GetEnvOrDefaultBool("FINGERPRINT_ENABLE_TEMPORAL_PRECOMPUTE_WRITE", true)
	FingerprintEnableTemporalPrecomputeRead = GetEnvOrDefaultBool("FINGERPRINT_ENABLE_TEMPORAL_PRECOMPUTE_READ", false)
	FingerprintEnableBehaviorAnalysis = GetEnvOrDefaultBool("FINGERPRINT_ENABLE_BEHAVIOR_ANALYSIS", true)

	if FingerprintEnabled {
		SysLog("fingerprint system enabled")
		if FingerprintSuperAdminOnly {
			SysLog("fingerprint data visible to super admin only")
		} else {
			SysLog("fingerprint data visible to admin and super admin")
		}
		SysLog(fmt.Sprintf("fingerprint features: ja4=%t etag=%t webrtc=%t asn=%t dns_leak=%t temporal=%t temporal_precompute_write=%t temporal_precompute_read=%t",
			FingerprintEnableJA4, FingerprintEnableETag, FingerprintEnableWebRTC,
			FingerprintEnableASNAnalysis, FingerprintEnableDNSLeak, FingerprintEnableTemporalAnalysis,
			FingerprintEnableTemporalPrecomputeWrite, FingerprintEnableTemporalPrecomputeRead))
	}
}

func HasFingerprintAccess(role int) bool {
	if !FingerprintEnabled {
		return false
	}
	if FingerprintSuperAdminOnly {
		return role >= RoleRootUser
	}
	return role >= RoleAdminUser
}

func GetFingerprintRetentionDays() int {
	return GetEnvOrDefault("FINGERPRINT_RETENTION_DAYS", 90)
}

func GetFingerprintIPUAWriteSampleRate() int {
	rate := GetEnvOrDefault("FINGERPRINT_IPUA_WRITE_SAMPLE_RATE", 100)
	if rate < 1 {
		return 1
	}
	if rate > 100 {
		return 100
	}
	return rate
}

func GetFingerprintIPUAUserHistoryLimit() int {
	return parseFingerprintPositiveInt("FINGERPRINT_IPUA_USER_HISTORY_LIMIT", 200)
}

func GetFingerprintIPUAUserHistoryCleanupBatch() int {
	return parseFingerprintPositiveInt("FINGERPRINT_IPUA_USER_HISTORY_CLEANUP_BATCH", 50)
}

func GetFingerprintIPUAWriteMinIntervalSeconds() int {
	return parseFingerprintPositiveInt("FINGERPRINT_IPUA_WRITE_MIN_INTERVAL_SECONDS", 300)
}

func GetFingerprintIPUARetentionDays() int {
	return parseFingerprintPositiveInt("FINGERPRINT_IPUA_RETENTION_DAYS", GetFingerprintRetentionDays())
}

func GetFingerprintSessionRetentionDays() int {
	return parseFingerprintPositiveInt("FINGERPRINT_SESSION_RETENTION_DAYS", GetFingerprintRetentionDays())
}

func GetFingerprintActiveUserWindowHours() int {
	return parseFingerprintPositiveInt("FINGERPRINT_ACTIVE_USER_WINDOW_HOURS", 168)
}

func GetFingerprintFullScanMaxUsers() int {
	return parseFingerprintPositiveInt("FINGERPRINT_FULL_SCAN_MAX_USERS", 3000)
}

func GetFingerprintFullScanMaxPairs() int {
	return parseFingerprintPositiveInt("FINGERPRINT_FULL_SCAN_MAX_PAIRS", 200000)
}

func GetFingerprintFullScanMaxDurationSeconds() int {
	return parseFingerprintPositiveInt("FINGERPRINT_FULL_SCAN_MAX_DURATION_SECONDS", 600)
}

func GetFingerprintCandidateMaxPerSource() int {
	return parseFingerprintPositiveInt("FINGERPRINT_CANDIDATE_MAX_PER_SOURCE", 200)
}

func GetFingerprintCandidateLowSignalMaxPerSource() int {
	return parseFingerprintPositiveInt("FINGERPRINT_CANDIDATE_LOW_SIGNAL_MAX_PER_SOURCE", 40)
}

func GetFingerprintCandidateMaxTotal() int {
	return parseFingerprintPositiveInt("FINGERPRINT_CANDIDATE_MAX_TOTAL", 1200)
}

func GetFingerprintAssociationQueryTimeoutSeconds() int {
	return parseFingerprintPositiveInt("FINGERPRINT_ASSOC_QUERY_TIMEOUT_SECONDS", 8)
}

func GetFingerprintAssociationFastTargetLimit() int {
	return parseFingerprintPositiveInt("FINGERPRINT_ASSOC_FAST_TARGET_FP_LIMIT", 3)
}

func GetFingerprintAssociationFastCandidateLimit() int {
	return parseFingerprintPositiveInt("FINGERPRINT_ASSOC_FAST_CANDIDATE_FP_LIMIT", 3)
}

func GetFingerprintAssociationFullTargetLimit() int {
	return parseFingerprintPositiveInt("FINGERPRINT_ASSOC_FULL_TARGET_FP_LIMIT", 10)
}

func GetFingerprintAssociationFullCandidateLimit() int {
	return parseFingerprintPositiveInt("FINGERPRINT_ASSOC_FULL_CANDIDATE_FP_LIMIT", 10)
}

func GetFingerprintTemporalRefreshMaxUsers() int {
	return parseFingerprintPositiveInt("FINGERPRINT_TEMPORAL_REFRESH_MAX_USERS", 1000)
}

func GetFingerprintMaxUserAgentLength() int {
	return parseFingerprintPositiveInt("FINGERPRINT_MAX_USER_AGENT_LENGTH", 512)
}

func GetFingerprintMaxFontsListLength() int {
	return parseFingerprintPositiveInt("FINGERPRINT_MAX_FONTS_LIST_LENGTH", 1024)
}

func GetFingerprintMaxWebRTCIPsLength() int {
	return parseFingerprintPositiveInt("FINGERPRINT_MAX_WEBRTC_IPS_LENGTH", 256)
}

func GetFingerprintMaxPageURLLength() int {
	return parseFingerprintPositiveInt("FINGERPRINT_MAX_PAGE_URL_LENGTH", 256)
}

func parseValidFingerprintWeight(val string) (float64, bool) {
	f, err := strconv.ParseFloat(strings.TrimSpace(val), 64)
	if err != nil {
		return 0, false
	}
	if math.IsNaN(f) || math.IsInf(f, 0) || f <= 0 || f > 1 {
		return 0, false
	}
	return f, true
}

func parseFingerprintWeight(envKey string, defaultValue float64) float64 {
	val := strings.TrimSpace(os.Getenv(envKey))
	if val == "" {
		return defaultValue
	}
	f, ok := parseValidFingerprintWeight(val)
	if !ok {
		return defaultValue
	}
	return f
}

func parseFingerprintPositiveInt(envKey string, defaultValue int) int {
	val := strings.TrimSpace(os.Getenv(envKey))
	if val == "" {
		return defaultValue
	}
	parsed, err := strconv.Atoi(val)
	if err != nil || parsed <= 0 {
		return defaultValue
	}
	return parsed
}

func getFingerprintTrustedProxyCIDRs() []string {
	raw := strings.TrimSpace(os.Getenv("FINGERPRINT_TRUSTED_PROXY_CIDRS"))
	if raw == "" {
		return []string{"127.0.0.1/8", "::1/128"}
	}

	parts := strings.Split(raw, ",")
	cidrs := make([]string, 0, len(parts))
	for _, part := range parts {
		cidr := strings.TrimSpace(part)
		if cidr == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			continue
		}
		cidrs = append(cidrs, cidr)
	}
	if len(cidrs) == 0 {
		return []string{"127.0.0.1/8", "::1/128"}
	}
	return cidrs
}

func GetFingerprintAutoConfirmThreshold() float64 {
	return parseFingerprintWeight("FINGERPRINT_AUTO_CONFIRM_THRESHOLD", 0.90)
}

func GetFingerprintAlertThreshold() float64 {
	return parseFingerprintWeight("FINGERPRINT_ALERT_THRESHOLD", 0.70)
}

func getFingerprintWeightValue(alias string) float64 {
	return GetWeights()[alias]
}

func GetFingerprintWeightJA4() float64 {
	return getFingerprintWeightValue("ja4")
}

func GetFingerprintWeightWebGLDeepHash() float64 {
	return getFingerprintWeightValue("webgl_deep_hash")
}

func GetFingerprintWeightClientRectsHash() float64 {
	return getFingerprintWeightValue("client_rects_hash")
}

func GetFingerprintWeightMediaDevicesHash() float64 {
	return getFingerprintWeightValue("media_devices_hash")
}

func GetFingerprintWeightMediaDeviceGroupHash() float64 {
	return getFingerprintWeightValue("media_device_group_hash")
}

func GetFingerprintWeightMediaDeviceCount() float64 {
	return getFingerprintWeightValue("media_device_count")
}

func GetFingerprintWeightSpeechVoicesHash() float64 {
	return getFingerprintWeightValue("speech_voices_hash")
}

func GetFingerprintWeightSpeechVoiceCount() float64 {
	return getFingerprintWeightValue("speech_voice_count")
}

func GetFingerprintWeightSpeechLocalVoiceCount() float64 {
	return getFingerprintWeightValue("speech_local_voice_count")
}

func GetFingerprintWeightHTTPHeaderHash() float64 {
	return getFingerprintWeightValue("http_header_hash")
}

func GetFingerprintWeightETagID() float64 {
	return getFingerprintWeightValue("etag_id")
}

func GetFingerprintWeightPersistentID() float64 {
	return getFingerprintWeightValue("persistent_id")
}

func GetFingerprintWeightWebRTCBoth() float64 {
	return getFingerprintWeightValue("webrtc_both")
}

func GetFingerprintWeightWebRTCPublic() float64 {
	return getFingerprintWeightValue("webrtc_public")
}

func GetFingerprintWeightWebRTCLocal() float64 {
	return getFingerprintWeightValue("webrtc_local")
}

func GetFingerprintWeightASN() float64 {
	return getFingerprintWeightValue("asn")
}

func GetFingerprintWeightDNSResolver() float64 {
	return getFingerprintWeightValue("dns_resolver")
}

func GetFingerprintWeightTimeSimilarity() float64 {
	return getFingerprintWeightValue("time_similarity")
}

func GetFingerprintWeightMutualExclusion() float64 {
	return getFingerprintWeightValue("mutual_exclusion")
}

func GetFingerprintWeightKeystroke() float64 {
	return getFingerprintWeightValue("keystroke")
}

func GetFingerprintWeightMouseBehavior() float64 {
	return getFingerprintWeightValue("mouse")
}

type fingerprintWeightConfig struct {
	alias      string
	envKey     string
	defaultVal float64
}

var fingerprintWeightConfigs = []fingerprintWeightConfig{
	{alias: "persistent_id", envKey: "FINGERPRINT_WEIGHT_PERSISTENT_ID", defaultVal: 0.95},
	{alias: "etag_id", envKey: "FINGERPRINT_WEIGHT_ETAG_ID", defaultVal: 0.80},
	{alias: "webrtc_both", envKey: "FINGERPRINT_WEIGHT_WEBRTC_BOTH", defaultVal: 0.95},
	{alias: "webrtc_local", envKey: "FINGERPRINT_WEIGHT_WEBRTC_LOCAL", defaultVal: 0.80},
	{alias: "webrtc_public", envKey: "FINGERPRINT_WEIGHT_WEBRTC_PUBLIC", defaultVal: 0.60},
	{alias: "ja4", envKey: "FINGERPRINT_WEIGHT_JA4", defaultVal: 0.85},
	{alias: "http_header_hash", envKey: "FINGERPRINT_WEIGHT_HTTP_HEADER_HASH", defaultVal: 0.60},
	{alias: "local_device_id", envKey: "FINGERPRINT_WEIGHT_LOCAL_DEVICE_ID", defaultVal: 0.95},
	{alias: "canvas_hash", envKey: "FINGERPRINT_WEIGHT_CANVAS_HASH", defaultVal: 0.90},
	{alias: "webgl_hash", envKey: "FINGERPRINT_WEIGHT_WEBGL_HASH", defaultVal: 0.85},
	{alias: "webgl_deep_hash", envKey: "FINGERPRINT_WEIGHT_WEBGL_DEEP_HASH", defaultVal: 0.88},
	{alias: "client_rects_hash", envKey: "FINGERPRINT_WEIGHT_CLIENT_RECTS_HASH", defaultVal: 0.80},
	{alias: "media_devices_hash", envKey: "FINGERPRINT_WEIGHT_MEDIA_DEVICES_HASH", defaultVal: 0.78},
	{alias: "media_device_group_hash", envKey: "FINGERPRINT_WEIGHT_MEDIA_DEVICE_GROUP_HASH", defaultVal: 0.60},
	{alias: "media_device_count", envKey: "FINGERPRINT_WEIGHT_MEDIA_DEVICE_COUNT", defaultVal: 0.30},
	{alias: "speech_voices_hash", envKey: "FINGERPRINT_WEIGHT_SPEECH_VOICES_HASH", defaultVal: 0.72},
	{alias: "speech_voice_count", envKey: "FINGERPRINT_WEIGHT_SPEECH_VOICE_COUNT", defaultVal: 0.25},
	{alias: "speech_local_voice_count", envKey: "FINGERPRINT_WEIGHT_SPEECH_LOCAL_VOICE_COUNT", defaultVal: 0.20},
	{alias: "audio_hash", envKey: "FINGERPRINT_WEIGHT_AUDIO_HASH", defaultVal: 0.80},
	{alias: "webgl_vendor", envKey: "FINGERPRINT_WEIGHT_WEBGL_VENDOR", defaultVal: 0.72},
	{alias: "webgl_renderer", envKey: "FINGERPRINT_WEIGHT_WEBGL_RENDERER", defaultVal: 0.75},
	{alias: "tls_ja3_hash", envKey: "FINGERPRINT_WEIGHT_TLS_JA3_HASH", defaultVal: 0.75},
	{alias: "fonts_hash", envKey: "FINGERPRINT_WEIGHT_FONTS_HASH", defaultVal: 0.70},
	{alias: "ip_history_overlap", envKey: "FINGERPRINT_WEIGHT_IP_HISTORY_OVERLAP", defaultVal: 0.55},
	{alias: "ip_exact", envKey: "FINGERPRINT_WEIGHT_IP_EXACT", defaultVal: 0.50},
	{alias: "ip_subnet", envKey: "FINGERPRINT_WEIGHT_IP_SUBNET", defaultVal: 0.40},
	{alias: "dns_resolver", envKey: "FINGERPRINT_WEIGHT_DNS_RESOLVER", defaultVal: 0.50},
	{alias: "asn", envKey: "FINGERPRINT_WEIGHT_ASN", defaultVal: 0.45},
	{alias: "ua_similarity", envKey: "FINGERPRINT_WEIGHT_UA_SIMILARITY", defaultVal: 0.35},
	{alias: "time_similarity", envKey: "FINGERPRINT_WEIGHT_TIME_SIMILARITY", defaultVal: 0.50},
	{alias: "mutual_exclusion", envKey: "FINGERPRINT_WEIGHT_MUTUAL_EXCLUSION", defaultVal: 0.55},
	{alias: "keystroke", envKey: "FINGERPRINT_WEIGHT_KEYSTROKE", defaultVal: 0.70},
	{alias: "mouse", envKey: "FINGERPRINT_WEIGHT_MOUSE", defaultVal: 0.65},
	{alias: "screen_resolution", envKey: "FINGERPRINT_WEIGHT_SCREEN_RESOLUTION", defaultVal: 0.25},
	{alias: "timezone", envKey: "FINGERPRINT_WEIGHT_TIMEZONE", defaultVal: 0.20},
	{alias: "cpu_cores", envKey: "FINGERPRINT_WEIGHT_CPU_CORES", defaultVal: 0.15},
	{alias: "languages", envKey: "FINGERPRINT_WEIGHT_LANGUAGES", defaultVal: 0.15},
	{alias: "platform", envKey: "FINGERPRINT_WEIGHT_PLATFORM", defaultVal: 0.10},
}

var fingerprintWeightAliasToOptionKey = func() map[string]string {
	result := make(map[string]string, len(fingerprintWeightConfigs))
	for _, cfg := range fingerprintWeightConfigs {
		result[cfg.alias] = cfg.envKey
	}
	return result
}()

func FingerprintWeightAliasToOptionKey() map[string]string {
	result := make(map[string]string, len(fingerprintWeightAliasToOptionKey))
	for alias, key := range fingerprintWeightAliasToOptionKey {
		result[alias] = key
	}
	return result
}

func GetWeights() map[string]float64 {
	weights := make(map[string]float64, len(fingerprintWeightConfigs))
	OptionMapRWMutex.RLock()
	defer OptionMapRWMutex.RUnlock()

	for _, cfg := range fingerprintWeightConfigs {
		if val, ok := OptionMap[cfg.envKey]; ok {
			if parsed, valid := parseValidFingerprintWeight(val); valid {
				weights[cfg.alias] = parsed
				continue
			}
		}
		weights[cfg.alias] = parseFingerprintWeight(cfg.envKey, cfg.defaultVal)
	}

	return weights
}

func GetFingerprintMinKeystrokeSamples() int {
	return parseFingerprintPositiveInt("FINGERPRINT_MIN_KEYSTROKE_SAMPLES", 100)
}

func GetFingerprintMinMouseSamples() int {
	return parseFingerprintPositiveInt("FINGERPRINT_MIN_MOUSE_SAMPLES", 50)
}

func GetFingerprintBehaviorCollectDuration() int {
	return parseFingerprintPositiveInt("FINGERPRINT_BEHAVIOR_COLLECT_DURATION", 60)
}

func GetFingerprintBehaviorRetentionDays() int {
	return parseFingerprintPositiveInt("FINGERPRINT_BEHAVIOR_RETENTION_DAYS", GetFingerprintRetentionDays())
}

func GetFingerprintASNUpdateCheckIntervalDays() int {
	return parseFingerprintPositiveInt("FINGERPRINT_ASN_UPDATE_CHECK_INTERVAL_DAYS", 7)
}

func EnableDNSLeakDetection() bool {
	return GetEnvOrDefaultBool("FINGERPRINT_ENABLE_DNS_LEAK_DETECTION", false)
}

func EnableDNSCloudflare() bool {
	return GetEnvOrDefaultBool("FINGERPRINT_ENABLE_DNS_CLOUDFLARE", false)
}

func GetDNSCloudflareZoneID() string {
	return strings.TrimSpace(os.Getenv("FINGERPRINT_DNS_CLOUDFLARE_ZONE_ID"))
}

func GetDNSCloudflareAPIToken() string {
	return strings.TrimSpace(os.Getenv("FINGERPRINT_DNS_CLOUDFLARE_API_TOKEN"))
}

func GetDNSProbeDomainSuffix() string {
	return strings.TrimSpace(os.Getenv("FINGERPRINT_DNS_PROBE_DOMAIN_SUFFIX"))
}

func IsBlockTor() bool {
	return strings.ToLower(os.Getenv("FINGERPRINT_BLOCK_TOR")) == "true"
}

func IsBlockDatacenterIP() bool {
	return strings.ToLower(os.Getenv("FINGERPRINT_BLOCK_DATACENTER_IP")) == "true"
}

func GetMaxRegistrationsPerIP24h() int {
	return GetEnvOrDefault("FINGERPRINT_MAX_REG_PER_IP_24H", 3)
}
