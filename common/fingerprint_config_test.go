package common

import (
	"os"
	"reflect"
	"testing"
)

func TestFingerprintConfig_ReadsFeatureSwitches(t *testing.T) {
	oldEnabled := os.Getenv("FINGERPRINT_ENABLED")
	oldJA4 := os.Getenv("FINGERPRINT_ENABLE_JA4")
	oldETag := os.Getenv("FINGERPRINT_ENABLE_ETAG")
	oldWebRTC := os.Getenv("FINGERPRINT_ENABLE_WEBRTC")
	t.Cleanup(func() {
		_ = os.Setenv("FINGERPRINT_ENABLED", oldEnabled)
		_ = os.Setenv("FINGERPRINT_ENABLE_JA4", oldJA4)
		_ = os.Setenv("FINGERPRINT_ENABLE_ETAG", oldETag)
		_ = os.Setenv("FINGERPRINT_ENABLE_WEBRTC", oldWebRTC)
	})

	_ = os.Setenv("FINGERPRINT_ENABLED", "true")
	_ = os.Setenv("FINGERPRINT_ENABLE_JA4", "false")
	_ = os.Setenv("FINGERPRINT_ENABLE_ETAG", "true")
	_ = os.Setenv("FINGERPRINT_ENABLE_WEBRTC", "false")

	InitFingerprintConfig()

	if !FingerprintEnabled {
		t.Fatalf("expected FingerprintEnabled true")
	}
	if FingerprintEnableJA4 {
		t.Fatalf("expected FingerprintEnableJA4 false")
	}
	if !FingerprintEnableETag {
		t.Fatalf("expected FingerprintEnableETag true")
	}
	if FingerprintEnableWebRTC {
		t.Fatalf("expected FingerprintEnableWebRTC false")
	}
}

func TestFingerprintConfig_ReadsTrustedProxyCIDRs(t *testing.T) {
	old := os.Getenv("FINGERPRINT_TRUSTED_PROXY_CIDRS")
	t.Cleanup(func() {
		_ = os.Setenv("FINGERPRINT_TRUSTED_PROXY_CIDRS", old)
	})

	_ = os.Setenv("FINGERPRINT_TRUSTED_PROXY_CIDRS", "10.0.0.0/8, 192.168.0.0/16 ,invalid-cidr")
	InitFingerprintConfig()

	expected := []string{"10.0.0.0/8", "192.168.0.0/16"}
	if !reflect.DeepEqual(FingerprintTrustedProxyCIDRs, expected) {
		t.Fatalf("expected trusted proxy CIDRs %v, got %v", expected, FingerprintTrustedProxyCIDRs)
	}
}

func TestFingerprintConfig_TrustedProxyCIDRsFallbackToDefault(t *testing.T) {
	old := os.Getenv("FINGERPRINT_TRUSTED_PROXY_CIDRS")
	t.Cleanup(func() {
		_ = os.Setenv("FINGERPRINT_TRUSTED_PROXY_CIDRS", old)
	})

	_ = os.Setenv("FINGERPRINT_TRUSTED_PROXY_CIDRS", "invalid-cidr")
	InitFingerprintConfig()

	expected := []string{"127.0.0.1/8", "::1/128"}
	if !reflect.DeepEqual(FingerprintTrustedProxyCIDRs, expected) {
		t.Fatalf("expected default trusted proxy CIDRs %v, got %v", expected, FingerprintTrustedProxyCIDRs)
	}
}
func TestFingerprintConfig_ReadsWeightsAndFallbacks(t *testing.T) {
	oldJA4 := os.Getenv("FINGERPRINT_WEIGHT_JA4")
	oldETag := os.Getenv("FINGERPRINT_WEIGHT_ETAG_ID")
	oldPID := os.Getenv("FINGERPRINT_WEIGHT_PERSISTENT_ID")
	oldPub := os.Getenv("FINGERPRINT_WEIGHT_WEBRTC_PUBLIC")
	oldLocal := os.Getenv("FINGERPRINT_WEIGHT_WEBRTC_LOCAL")
	oldBoth := os.Getenv("FINGERPRINT_WEIGHT_WEBRTC_BOTH")
	t.Cleanup(func() {
		_ = os.Setenv("FINGERPRINT_WEIGHT_JA4", oldJA4)
		_ = os.Setenv("FINGERPRINT_WEIGHT_ETAG_ID", oldETag)
		_ = os.Setenv("FINGERPRINT_WEIGHT_PERSISTENT_ID", oldPID)
		_ = os.Setenv("FINGERPRINT_WEIGHT_WEBRTC_PUBLIC", oldPub)
		_ = os.Setenv("FINGERPRINT_WEIGHT_WEBRTC_LOCAL", oldLocal)
		_ = os.Setenv("FINGERPRINT_WEIGHT_WEBRTC_BOTH", oldBoth)
	})

	_ = os.Setenv("FINGERPRINT_WEIGHT_JA4", "0.77")
	_ = os.Setenv("FINGERPRINT_WEIGHT_ETAG_ID", "0.66")
	_ = os.Setenv("FINGERPRINT_WEIGHT_PERSISTENT_ID", "0.55")
	_ = os.Setenv("FINGERPRINT_WEIGHT_WEBRTC_PUBLIC", "0.44")
	_ = os.Setenv("FINGERPRINT_WEIGHT_WEBRTC_LOCAL", "0.33")
	_ = os.Setenv("FINGERPRINT_WEIGHT_WEBRTC_BOTH", "0.99")

	if got := GetFingerprintWeightJA4(); got != 0.77 {
		t.Fatalf("expected JA4 weight 0.77, got %v", got)
	}
	if got := GetFingerprintWeightETagID(); got != 0.66 {
		t.Fatalf("expected ETag weight 0.66, got %v", got)
	}
	if got := GetFingerprintWeightPersistentID(); got != 0.55 {
		t.Fatalf("expected PersistentID weight 0.55, got %v", got)
	}
	if got := GetFingerprintWeightWebRTCPublic(); got != 0.44 {
		t.Fatalf("expected WebRTC public weight 0.44, got %v", got)
	}
	if got := GetFingerprintWeightWebRTCLocal(); got != 0.33 {
		t.Fatalf("expected WebRTC local weight 0.33, got %v", got)
	}
	if got := GetFingerprintWeightWebRTCBoth(); got != 0.99 {
		t.Fatalf("expected WebRTC both weight 0.99, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_JA4", "1.20")
	if got := GetFingerprintWeightJA4(); got != 0.85 {
		t.Fatalf("expected fallback JA4 weight 0.85, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_WEBRTC_BOTH", "1.50")
	if got := GetFingerprintWeightWebRTCBoth(); got != 0.95 {
		t.Fatalf("expected fallback WebRTC both weight 0.95, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_WEBRTC_PUBLIC", "0.44oops")
	if got := GetFingerprintWeightWebRTCPublic(); got != 0.60 {
		t.Fatalf("expected invalid formatted WebRTC public fallback 0.60, got %v", got)
	}
}

func TestFingerprintConfig_ReadsWebGLDeepHashWeightAndFallbacks(t *testing.T) {
	oldWebGLDeep := os.Getenv("FINGERPRINT_WEIGHT_WEBGL_DEEP_HASH")
	oldClientRects := os.Getenv("FINGERPRINT_WEIGHT_CLIENT_RECTS_HASH")
	oldMediaDevices := os.Getenv("FINGERPRINT_WEIGHT_MEDIA_DEVICES_HASH")
	oldMediaDeviceGroup := os.Getenv("FINGERPRINT_WEIGHT_MEDIA_DEVICE_GROUP_HASH")
	oldMediaDeviceCount := os.Getenv("FINGERPRINT_WEIGHT_MEDIA_DEVICE_COUNT")
	oldSpeechVoices := os.Getenv("FINGERPRINT_WEIGHT_SPEECH_VOICES_HASH")
	oldSpeechVoiceCount := os.Getenv("FINGERPRINT_WEIGHT_SPEECH_VOICE_COUNT")
	oldSpeechLocalVoiceCount := os.Getenv("FINGERPRINT_WEIGHT_SPEECH_LOCAL_VOICE_COUNT")
	oldHTTPHeader := os.Getenv("FINGERPRINT_WEIGHT_HTTP_HEADER_HASH")
	t.Cleanup(func() {
		_ = os.Setenv("FINGERPRINT_WEIGHT_WEBGL_DEEP_HASH", oldWebGLDeep)
		_ = os.Setenv("FINGERPRINT_WEIGHT_CLIENT_RECTS_HASH", oldClientRects)
		_ = os.Setenv("FINGERPRINT_WEIGHT_MEDIA_DEVICES_HASH", oldMediaDevices)
		_ = os.Setenv("FINGERPRINT_WEIGHT_MEDIA_DEVICE_GROUP_HASH", oldMediaDeviceGroup)
		_ = os.Setenv("FINGERPRINT_WEIGHT_MEDIA_DEVICE_COUNT", oldMediaDeviceCount)
		_ = os.Setenv("FINGERPRINT_WEIGHT_SPEECH_VOICES_HASH", oldSpeechVoices)
		_ = os.Setenv("FINGERPRINT_WEIGHT_SPEECH_VOICE_COUNT", oldSpeechVoiceCount)
		_ = os.Setenv("FINGERPRINT_WEIGHT_SPEECH_LOCAL_VOICE_COUNT", oldSpeechLocalVoiceCount)
		_ = os.Setenv("FINGERPRINT_WEIGHT_HTTP_HEADER_HASH", oldHTTPHeader)
	})

	_ = os.Setenv("FINGERPRINT_WEIGHT_WEBGL_DEEP_HASH", "0.88")
	if got := GetFingerprintWeightWebGLDeepHash(); got != 0.88 {
		t.Fatalf("expected WebGL deep hash weight 0.88, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_WEBGL_DEEP_HASH", "1.20")
	if got := GetFingerprintWeightWebGLDeepHash(); got != 0.88 {
		t.Fatalf("expected fallback WebGL deep hash weight 0.88, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_WEBGL_DEEP_HASH", "oops")
	if got := GetFingerprintWeightWebGLDeepHash(); got != 0.88 {
		t.Fatalf("expected invalid formatted WebGL deep hash fallback 0.88, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_CLIENT_RECTS_HASH", "0.80")
	if got := GetFingerprintWeightClientRectsHash(); got != 0.80 {
		t.Fatalf("expected ClientRects weight 0.80, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_CLIENT_RECTS_HASH", "1.10")
	if got := GetFingerprintWeightClientRectsHash(); got != 0.80 {
		t.Fatalf("expected fallback ClientRects weight 0.80, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_CLIENT_RECTS_HASH", "bad")
	if got := GetFingerprintWeightClientRectsHash(); got != 0.80 {
		t.Fatalf("expected invalid formatted ClientRects fallback 0.80, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_MEDIA_DEVICES_HASH", "0.78")
	if got := GetFingerprintWeightMediaDevicesHash(); got != 0.78 {
		t.Fatalf("expected media devices hash weight 0.78, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_MEDIA_DEVICE_GROUP_HASH", "0.70")
	if got := GetFingerprintWeightMediaDeviceGroupHash(); got != 0.70 {
		t.Fatalf("expected media device group hash weight 0.70, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_MEDIA_DEVICE_COUNT", "0.35")
	if got := GetFingerprintWeightMediaDeviceCount(); got != 0.35 {
		t.Fatalf("expected media device count weight 0.35, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_MEDIA_DEVICES_HASH", "1.20")
	if got := GetFingerprintWeightMediaDevicesHash(); got != 0.78 {
		t.Fatalf("expected fallback media devices hash weight 0.78, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_MEDIA_DEVICE_GROUP_HASH", "1.20")
	if got := GetFingerprintWeightMediaDeviceGroupHash(); got != 0.60 {
		t.Fatalf("expected fallback media device group hash weight 0.60, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_MEDIA_DEVICE_COUNT", "1.20")
	if got := GetFingerprintWeightMediaDeviceCount(); got != 0.30 {
		t.Fatalf("expected fallback media device count weight 0.30, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_MEDIA_DEVICES_HASH", "bad")
	if got := GetFingerprintWeightMediaDevicesHash(); got != 0.78 {
		t.Fatalf("expected invalid formatted media devices hash fallback 0.78, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_MEDIA_DEVICE_GROUP_HASH", "bad")
	if got := GetFingerprintWeightMediaDeviceGroupHash(); got != 0.60 {
		t.Fatalf("expected invalid formatted media device group hash fallback 0.60, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_MEDIA_DEVICE_COUNT", "bad")
	if got := GetFingerprintWeightMediaDeviceCount(); got != 0.30 {
		t.Fatalf("expected invalid formatted media device count fallback 0.30, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_SPEECH_VOICES_HASH", "0.72")
	if got := GetFingerprintWeightSpeechVoicesHash(); got != 0.72 {
		t.Fatalf("expected speech voices hash weight 0.72, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_SPEECH_VOICE_COUNT", "0.33")
	if got := GetFingerprintWeightSpeechVoiceCount(); got != 0.33 {
		t.Fatalf("expected speech voice count weight 0.33, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_SPEECH_LOCAL_VOICE_COUNT", "0.22")
	if got := GetFingerprintWeightSpeechLocalVoiceCount(); got != 0.22 {
		t.Fatalf("expected speech local voice count weight 0.22, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_SPEECH_VOICES_HASH", "1.20")
	if got := GetFingerprintWeightSpeechVoicesHash(); got != 0.72 {
		t.Fatalf("expected fallback speech voices hash weight 0.72, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_SPEECH_VOICE_COUNT", "1.20")
	if got := GetFingerprintWeightSpeechVoiceCount(); got != 0.25 {
		t.Fatalf("expected fallback speech voice count weight 0.25, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_SPEECH_LOCAL_VOICE_COUNT", "1.20")
	if got := GetFingerprintWeightSpeechLocalVoiceCount(); got != 0.20 {
		t.Fatalf("expected fallback speech local voice count weight 0.20, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_SPEECH_VOICES_HASH", "bad")
	if got := GetFingerprintWeightSpeechVoicesHash(); got != 0.72 {
		t.Fatalf("expected invalid formatted speech voices hash fallback 0.72, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_SPEECH_VOICE_COUNT", "bad")
	if got := GetFingerprintWeightSpeechVoiceCount(); got != 0.25 {
		t.Fatalf("expected invalid formatted speech voice count fallback 0.25, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_SPEECH_LOCAL_VOICE_COUNT", "bad")
	if got := GetFingerprintWeightSpeechLocalVoiceCount(); got != 0.20 {
		t.Fatalf("expected invalid formatted speech local voice count fallback 0.20, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_HTTP_HEADER_HASH", "0.60")
	if got := GetFingerprintWeightHTTPHeaderHash(); got != 0.60 {
		t.Fatalf("expected HTTP Header hash weight 0.60, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_HTTP_HEADER_HASH", "1.20")
	if got := GetFingerprintWeightHTTPHeaderHash(); got != 0.60 {
		t.Fatalf("expected fallback HTTP Header hash weight 0.60, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_HTTP_HEADER_HASH", "bad")
	if got := GetFingerprintWeightHTTPHeaderHash(); got != 0.60 {
		t.Fatalf("expected invalid formatted HTTP Header hash fallback 0.60, got %v", got)
	}
}

func TestFingerprintConfig_ReadsP2WeightsAndSwitches(t *testing.T) {
	oldASNWeight := os.Getenv("FINGERPRINT_WEIGHT_ASN")
	oldDNSWeight := os.Getenv("FINGERPRINT_WEIGHT_DNS_RESOLVER")
	oldTimeWeight := os.Getenv("FINGERPRINT_WEIGHT_TIME_SIMILARITY")
	oldMutualWeight := os.Getenv("FINGERPRINT_WEIGHT_MUTUAL_EXCLUSION")
	oldASNEnable := os.Getenv("FINGERPRINT_ENABLE_ASN_ANALYSIS")
	oldDNSEnable := os.Getenv("FINGERPRINT_ENABLE_DNS_LEAK")
	oldTemporalEnable := os.Getenv("FINGERPRINT_ENABLE_TEMPORAL_ANALYSIS")
	oldTemporalPrecomputeWrite := os.Getenv("FINGERPRINT_ENABLE_TEMPORAL_PRECOMPUTE_WRITE")
	oldTemporalPrecomputeRead := os.Getenv("FINGERPRINT_ENABLE_TEMPORAL_PRECOMPUTE_READ")
	oldDNSLeakDetection := os.Getenv("FINGERPRINT_ENABLE_DNS_LEAK_DETECTION")
	oldDNSCloudflare := os.Getenv("FINGERPRINT_ENABLE_DNS_CLOUDFLARE")
	oldDNSZoneID := os.Getenv("FINGERPRINT_DNS_CLOUDFLARE_ZONE_ID")
	oldDNSAPIToken := os.Getenv("FINGERPRINT_DNS_CLOUDFLARE_API_TOKEN")
	oldDNSProbeSuffix := os.Getenv("FINGERPRINT_DNS_PROBE_DOMAIN_SUFFIX")
	t.Cleanup(func() {
		_ = os.Setenv("FINGERPRINT_WEIGHT_ASN", oldASNWeight)
		_ = os.Setenv("FINGERPRINT_WEIGHT_DNS_RESOLVER", oldDNSWeight)
		_ = os.Setenv("FINGERPRINT_WEIGHT_TIME_SIMILARITY", oldTimeWeight)
		_ = os.Setenv("FINGERPRINT_WEIGHT_MUTUAL_EXCLUSION", oldMutualWeight)
		_ = os.Setenv("FINGERPRINT_ENABLE_ASN_ANALYSIS", oldASNEnable)
		_ = os.Setenv("FINGERPRINT_ENABLE_DNS_LEAK", oldDNSEnable)
		_ = os.Setenv("FINGERPRINT_ENABLE_TEMPORAL_ANALYSIS", oldTemporalEnable)
		_ = os.Setenv("FINGERPRINT_ENABLE_TEMPORAL_PRECOMPUTE_WRITE", oldTemporalPrecomputeWrite)
		_ = os.Setenv("FINGERPRINT_ENABLE_TEMPORAL_PRECOMPUTE_READ", oldTemporalPrecomputeRead)
		_ = os.Setenv("FINGERPRINT_ENABLE_DNS_LEAK_DETECTION", oldDNSLeakDetection)
		_ = os.Setenv("FINGERPRINT_ENABLE_DNS_CLOUDFLARE", oldDNSCloudflare)
		_ = os.Setenv("FINGERPRINT_DNS_CLOUDFLARE_ZONE_ID", oldDNSZoneID)
		_ = os.Setenv("FINGERPRINT_DNS_CLOUDFLARE_API_TOKEN", oldDNSAPIToken)
		_ = os.Setenv("FINGERPRINT_DNS_PROBE_DOMAIN_SUFFIX", oldDNSProbeSuffix)
	})

	_ = os.Setenv("FINGERPRINT_WEIGHT_ASN", "0.41")
	_ = os.Setenv("FINGERPRINT_WEIGHT_DNS_RESOLVER", "0.52")
	_ = os.Setenv("FINGERPRINT_WEIGHT_TIME_SIMILARITY", "0.63")
	_ = os.Setenv("FINGERPRINT_WEIGHT_MUTUAL_EXCLUSION", "0.54")
	_ = os.Setenv("FINGERPRINT_ENABLE_ASN_ANALYSIS", "false")
	_ = os.Setenv("FINGERPRINT_ENABLE_DNS_LEAK", "true")
	_ = os.Setenv("FINGERPRINT_ENABLE_TEMPORAL_ANALYSIS", "false")
	_ = os.Setenv("FINGERPRINT_ENABLE_TEMPORAL_PRECOMPUTE_WRITE", "false")
	_ = os.Setenv("FINGERPRINT_ENABLE_TEMPORAL_PRECOMPUTE_READ", "true")
	_ = os.Setenv("FINGERPRINT_ENABLE_DNS_LEAK_DETECTION", "true")
	_ = os.Setenv("FINGERPRINT_ENABLE_DNS_CLOUDFLARE", "true")
	_ = os.Setenv("FINGERPRINT_DNS_CLOUDFLARE_ZONE_ID", "zone-1")
	_ = os.Setenv("FINGERPRINT_DNS_CLOUDFLARE_API_TOKEN", "token-1")
	_ = os.Setenv("FINGERPRINT_DNS_PROBE_DOMAIN_SUFFIX", "dnsprobe.example.com")

	InitFingerprintConfig()

	if got := GetFingerprintWeightASN(); got != 0.41 {
		t.Fatalf("expected ASN weight 0.41, got %v", got)
	}
	if got := GetFingerprintWeightDNSResolver(); got != 0.52 {
		t.Fatalf("expected DNS weight 0.52, got %v", got)
	}
	if got := GetFingerprintWeightTimeSimilarity(); got != 0.63 {
		t.Fatalf("expected time weight 0.63, got %v", got)
	}
	if got := GetFingerprintWeightMutualExclusion(); got != 0.54 {
		t.Fatalf("expected mutual exclusion weight 0.54, got %v", got)
	}
	if FingerprintEnableASNAnalysis {
		t.Fatalf("expected FingerprintEnableASNAnalysis false")
	}
	if !FingerprintEnableDNSLeak {
		t.Fatalf("expected FingerprintEnableDNSLeak true")
	}
	if FingerprintEnableTemporalAnalysis {
		t.Fatalf("expected FingerprintEnableTemporalAnalysis false")
	}
	if FingerprintEnableTemporalPrecomputeWrite {
		t.Fatalf("expected FingerprintEnableTemporalPrecomputeWrite false")
	}
	if !FingerprintEnableTemporalPrecomputeRead {
		t.Fatalf("expected FingerprintEnableTemporalPrecomputeRead true")
	}
	if !EnableDNSLeakDetection() {
		t.Fatalf("expected EnableDNSLeakDetection true")
	}
	if !EnableDNSCloudflare() {
		t.Fatalf("expected EnableDNSCloudflare true")
	}
	if got := GetDNSCloudflareZoneID(); got != "zone-1" {
		t.Fatalf("expected DNS cloudflare zone id zone-1, got %q", got)
	}
	if got := GetDNSCloudflareAPIToken(); got != "token-1" {
		t.Fatalf("expected DNS cloudflare api token token-1, got %q", got)
	}
	if got := GetDNSProbeDomainSuffix(); got != "dnsprobe.example.com" {
		t.Fatalf("expected DNS probe suffix dnsprobe.example.com, got %q", got)
	}
}

func TestFingerprintConfig_TemporalPrecomputeFallbackDefaults(t *testing.T) {
	oldTemporalPrecomputeWrite := os.Getenv("FINGERPRINT_ENABLE_TEMPORAL_PRECOMPUTE_WRITE")
	oldTemporalPrecomputeRead := os.Getenv("FINGERPRINT_ENABLE_TEMPORAL_PRECOMPUTE_READ")
	t.Cleanup(func() {
		_ = os.Setenv("FINGERPRINT_ENABLE_TEMPORAL_PRECOMPUTE_WRITE", oldTemporalPrecomputeWrite)
		_ = os.Setenv("FINGERPRINT_ENABLE_TEMPORAL_PRECOMPUTE_READ", oldTemporalPrecomputeRead)
	})

	_ = os.Setenv("FINGERPRINT_ENABLE_TEMPORAL_PRECOMPUTE_WRITE", "invalid")
	_ = os.Setenv("FINGERPRINT_ENABLE_TEMPORAL_PRECOMPUTE_READ", "invalid")

	InitFingerprintConfig()

	if !FingerprintEnableTemporalPrecomputeWrite {
		t.Fatalf("expected FingerprintEnableTemporalPrecomputeWrite fallback true")
	}
	if FingerprintEnableTemporalPrecomputeRead {
		t.Fatalf("expected FingerprintEnableTemporalPrecomputeRead fallback false")
	}
}

func TestFingerprintConfig_GetWeightsPrefersOptionMap(t *testing.T) {
	oldMap := OptionMap
	oldEnvJA4 := os.Getenv("FINGERPRINT_WEIGHT_JA4")
	oldEnvPersistent := os.Getenv("FINGERPRINT_WEIGHT_PERSISTENT_ID")
	t.Cleanup(func() {
		OptionMap = oldMap
		if oldEnvJA4 == "" {
			_ = os.Unsetenv("FINGERPRINT_WEIGHT_JA4")
		} else {
			_ = os.Setenv("FINGERPRINT_WEIGHT_JA4", oldEnvJA4)
		}
		if oldEnvPersistent == "" {
			_ = os.Unsetenv("FINGERPRINT_WEIGHT_PERSISTENT_ID")
		} else {
			_ = os.Setenv("FINGERPRINT_WEIGHT_PERSISTENT_ID", oldEnvPersistent)
		}
	})

	OptionMap = map[string]string{
		"FINGERPRINT_WEIGHT_JA4":           "0.66",
		"FINGERPRINT_WEIGHT_PERSISTENT_ID": "0.77",
	}
	_ = os.Setenv("FINGERPRINT_WEIGHT_JA4", "0.33")
	_ = os.Setenv("FINGERPRINT_WEIGHT_PERSISTENT_ID", "0.44")

	weights := GetWeights()
	if got := weights["ja4"]; got != 0.66 {
		t.Fatalf("expected option map JA4 weight 0.66, got %v", got)
	}
	if got := weights["persistent_id"]; got != 0.77 {
		t.Fatalf("expected option map persistent weight 0.77, got %v", got)
	}
}

func TestFingerprintConfig_ReadsIPUAWriteOptimizationConfig(t *testing.T) {
	oldSampleRate := os.Getenv("FINGERPRINT_IPUA_WRITE_SAMPLE_RATE")
	oldHistoryLimit := os.Getenv("FINGERPRINT_IPUA_USER_HISTORY_LIMIT")
	oldCleanupBatch := os.Getenv("FINGERPRINT_IPUA_USER_HISTORY_CLEANUP_BATCH")
	oldMinInterval := os.Getenv("FINGERPRINT_IPUA_WRITE_MIN_INTERVAL_SECONDS")
	oldIPUARetention := os.Getenv("FINGERPRINT_IPUA_RETENTION_DAYS")
	oldSessionRetention := os.Getenv("FINGERPRINT_SESSION_RETENTION_DAYS")
	oldMaxUserAgentLength := os.Getenv("FINGERPRINT_MAX_USER_AGENT_LENGTH")
	oldMaxFontsListLength := os.Getenv("FINGERPRINT_MAX_FONTS_LIST_LENGTH")
	oldMaxWebRTCIPsLength := os.Getenv("FINGERPRINT_MAX_WEBRTC_IPS_LENGTH")
	oldMaxPageURLLength := os.Getenv("FINGERPRINT_MAX_PAGE_URL_LENGTH")
	oldRetention := os.Getenv("FINGERPRINT_RETENTION_DAYS")
	t.Cleanup(func() {
		if oldSampleRate == "" {
			_ = os.Unsetenv("FINGERPRINT_IPUA_WRITE_SAMPLE_RATE")
		} else {
			_ = os.Setenv("FINGERPRINT_IPUA_WRITE_SAMPLE_RATE", oldSampleRate)
		}
		if oldHistoryLimit == "" {
			_ = os.Unsetenv("FINGERPRINT_IPUA_USER_HISTORY_LIMIT")
		} else {
			_ = os.Setenv("FINGERPRINT_IPUA_USER_HISTORY_LIMIT", oldHistoryLimit)
		}
		if oldCleanupBatch == "" {
			_ = os.Unsetenv("FINGERPRINT_IPUA_USER_HISTORY_CLEANUP_BATCH")
		} else {
			_ = os.Setenv("FINGERPRINT_IPUA_USER_HISTORY_CLEANUP_BATCH", oldCleanupBatch)
		}
		if oldMinInterval == "" {
			_ = os.Unsetenv("FINGERPRINT_IPUA_WRITE_MIN_INTERVAL_SECONDS")
		} else {
			_ = os.Setenv("FINGERPRINT_IPUA_WRITE_MIN_INTERVAL_SECONDS", oldMinInterval)
		}
		if oldIPUARetention == "" {
			_ = os.Unsetenv("FINGERPRINT_IPUA_RETENTION_DAYS")
		} else {
			_ = os.Setenv("FINGERPRINT_IPUA_RETENTION_DAYS", oldIPUARetention)
		}
		if oldSessionRetention == "" {
			_ = os.Unsetenv("FINGERPRINT_SESSION_RETENTION_DAYS")
		} else {
			_ = os.Setenv("FINGERPRINT_SESSION_RETENTION_DAYS", oldSessionRetention)
		}
		if oldMaxUserAgentLength == "" {
			_ = os.Unsetenv("FINGERPRINT_MAX_USER_AGENT_LENGTH")
		} else {
			_ = os.Setenv("FINGERPRINT_MAX_USER_AGENT_LENGTH", oldMaxUserAgentLength)
		}
		if oldMaxFontsListLength == "" {
			_ = os.Unsetenv("FINGERPRINT_MAX_FONTS_LIST_LENGTH")
		} else {
			_ = os.Setenv("FINGERPRINT_MAX_FONTS_LIST_LENGTH", oldMaxFontsListLength)
		}
		if oldMaxWebRTCIPsLength == "" {
			_ = os.Unsetenv("FINGERPRINT_MAX_WEBRTC_IPS_LENGTH")
		} else {
			_ = os.Setenv("FINGERPRINT_MAX_WEBRTC_IPS_LENGTH", oldMaxWebRTCIPsLength)
		}
		if oldMaxPageURLLength == "" {
			_ = os.Unsetenv("FINGERPRINT_MAX_PAGE_URL_LENGTH")
		} else {
			_ = os.Setenv("FINGERPRINT_MAX_PAGE_URL_LENGTH", oldMaxPageURLLength)
		}
		if oldRetention == "" {
			_ = os.Unsetenv("FINGERPRINT_RETENTION_DAYS")
		} else {
			_ = os.Setenv("FINGERPRINT_RETENTION_DAYS", oldRetention)
		}
	})

	_ = os.Setenv("FINGERPRINT_IPUA_WRITE_SAMPLE_RATE", "37")
	_ = os.Setenv("FINGERPRINT_IPUA_USER_HISTORY_LIMIT", "300")
	_ = os.Setenv("FINGERPRINT_IPUA_USER_HISTORY_CLEANUP_BATCH", "60")
	_ = os.Setenv("FINGERPRINT_IPUA_WRITE_MIN_INTERVAL_SECONDS", "120")
	_ = os.Setenv("FINGERPRINT_IPUA_RETENTION_DAYS", "21")
	_ = os.Setenv("FINGERPRINT_SESSION_RETENTION_DAYS", "14")
	_ = os.Setenv("FINGERPRINT_MAX_USER_AGENT_LENGTH", "128")
	_ = os.Setenv("FINGERPRINT_MAX_FONTS_LIST_LENGTH", "256")
	_ = os.Setenv("FINGERPRINT_MAX_WEBRTC_IPS_LENGTH", "80")
	_ = os.Setenv("FINGERPRINT_MAX_PAGE_URL_LENGTH", "120")
	_ = os.Setenv("FINGERPRINT_RETENTION_DAYS", "90")

	if got := GetFingerprintIPUAWriteSampleRate(); got != 37 {
		t.Fatalf("expected ipua sample rate 37, got %v", got)
	}
	if got := GetFingerprintIPUAUserHistoryLimit(); got != 300 {
		t.Fatalf("expected ipua history limit 300, got %v", got)
	}
	if got := GetFingerprintIPUAUserHistoryCleanupBatch(); got != 60 {
		t.Fatalf("expected ipua cleanup batch 60, got %v", got)
	}
	if got := GetFingerprintIPUAWriteMinIntervalSeconds(); got != 120 {
		t.Fatalf("expected ipua min interval 120, got %v", got)
	}
	if got := GetFingerprintIPUARetentionDays(); got != 21 {
		t.Fatalf("expected ipua retention days 21, got %v", got)
	}
	if got := GetFingerprintSessionRetentionDays(); got != 14 {
		t.Fatalf("expected session retention days 14, got %v", got)
	}
	if got := GetFingerprintMaxUserAgentLength(); got != 128 {
		t.Fatalf("expected max user agent length 128, got %v", got)
	}
	if got := GetFingerprintMaxFontsListLength(); got != 256 {
		t.Fatalf("expected max fonts list length 256, got %v", got)
	}
	if got := GetFingerprintMaxWebRTCIPsLength(); got != 80 {
		t.Fatalf("expected max webrtc ips length 80, got %v", got)
	}
	if got := GetFingerprintMaxPageURLLength(); got != 120 {
		t.Fatalf("expected max page_url length 120, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_IPUA_WRITE_SAMPLE_RATE", "0")
	if got := GetFingerprintIPUAWriteSampleRate(); got != 1 {
		t.Fatalf("expected ipua sample rate lower bound 1, got %v", got)
	}
	_ = os.Setenv("FINGERPRINT_IPUA_WRITE_SAMPLE_RATE", "999")
	if got := GetFingerprintIPUAWriteSampleRate(); got != 100 {
		t.Fatalf("expected ipua sample rate upper bound 100, got %v", got)
	}
	_ = os.Setenv("FINGERPRINT_IPUA_USER_HISTORY_LIMIT", "bad")
	if got := GetFingerprintIPUAUserHistoryLimit(); got != 200 {
		t.Fatalf("expected ipua history limit fallback 200, got %v", got)
	}
	_ = os.Setenv("FINGERPRINT_IPUA_USER_HISTORY_CLEANUP_BATCH", "bad")
	if got := GetFingerprintIPUAUserHistoryCleanupBatch(); got != 50 {
		t.Fatalf("expected ipua cleanup batch fallback 50, got %v", got)
	}
	_ = os.Setenv("FINGERPRINT_IPUA_WRITE_MIN_INTERVAL_SECONDS", "bad")
	if got := GetFingerprintIPUAWriteMinIntervalSeconds(); got != 300 {
		t.Fatalf("expected ipua min interval fallback 300, got %v", got)
	}
	_ = os.Setenv("FINGERPRINT_IPUA_RETENTION_DAYS", "bad")
	if got := GetFingerprintIPUARetentionDays(); got != 90 {
		t.Fatalf("expected ipua retention fallback to retention days 90, got %v", got)
	}
	_ = os.Setenv("FINGERPRINT_SESSION_RETENTION_DAYS", "bad")
	if got := GetFingerprintSessionRetentionDays(); got != 90 {
		t.Fatalf("expected session retention fallback to retention days 90, got %v", got)
	}
	_ = os.Setenv("FINGERPRINT_MAX_USER_AGENT_LENGTH", "bad")
	if got := GetFingerprintMaxUserAgentLength(); got != 512 {
		t.Fatalf("expected max user agent length fallback 512, got %v", got)
	}
	_ = os.Setenv("FINGERPRINT_MAX_FONTS_LIST_LENGTH", "bad")
	if got := GetFingerprintMaxFontsListLength(); got != 1024 {
		t.Fatalf("expected max fonts list length fallback 1024, got %v", got)
	}
	_ = os.Setenv("FINGERPRINT_MAX_WEBRTC_IPS_LENGTH", "bad")
	if got := GetFingerprintMaxWebRTCIPsLength(); got != 256 {
		t.Fatalf("expected max webrtc ips length fallback 256, got %v", got)
	}
	_ = os.Setenv("FINGERPRINT_MAX_PAGE_URL_LENGTH", "bad")
	if got := GetFingerprintMaxPageURLLength(); got != 256 {
		t.Fatalf("expected max page_url length fallback 256, got %v", got)
	}
}

func TestFingerprintConfig_ReadsScanAndCandidateBudgetConfig(t *testing.T) {
	oldActiveHours := os.Getenv("FINGERPRINT_ACTIVE_USER_WINDOW_HOURS")
	oldFullScanMaxUsers := os.Getenv("FINGERPRINT_FULL_SCAN_MAX_USERS")
	oldFullScanMaxPairs := os.Getenv("FINGERPRINT_FULL_SCAN_MAX_PAIRS")
	oldFullScanMaxDuration := os.Getenv("FINGERPRINT_FULL_SCAN_MAX_DURATION_SECONDS")
	oldCandidateMaxPerSource := os.Getenv("FINGERPRINT_CANDIDATE_MAX_PER_SOURCE")
	oldCandidateLowSignalPerSource := os.Getenv("FINGERPRINT_CANDIDATE_LOW_SIGNAL_MAX_PER_SOURCE")
	oldCandidateMaxTotal := os.Getenv("FINGERPRINT_CANDIDATE_MAX_TOTAL")
	oldTemporalRefreshMaxUsers := os.Getenv("FINGERPRINT_TEMPORAL_REFRESH_MAX_USERS")
	t.Cleanup(func() {
		_ = os.Setenv("FINGERPRINT_ACTIVE_USER_WINDOW_HOURS", oldActiveHours)
		_ = os.Setenv("FINGERPRINT_FULL_SCAN_MAX_USERS", oldFullScanMaxUsers)
		_ = os.Setenv("FINGERPRINT_FULL_SCAN_MAX_PAIRS", oldFullScanMaxPairs)
		_ = os.Setenv("FINGERPRINT_FULL_SCAN_MAX_DURATION_SECONDS", oldFullScanMaxDuration)
		_ = os.Setenv("FINGERPRINT_CANDIDATE_MAX_PER_SOURCE", oldCandidateMaxPerSource)
		_ = os.Setenv("FINGERPRINT_CANDIDATE_LOW_SIGNAL_MAX_PER_SOURCE", oldCandidateLowSignalPerSource)
		_ = os.Setenv("FINGERPRINT_CANDIDATE_MAX_TOTAL", oldCandidateMaxTotal)
		_ = os.Setenv("FINGERPRINT_TEMPORAL_REFRESH_MAX_USERS", oldTemporalRefreshMaxUsers)
	})

	_ = os.Setenv("FINGERPRINT_ACTIVE_USER_WINDOW_HOURS", "72")
	_ = os.Setenv("FINGERPRINT_FULL_SCAN_MAX_USERS", "666")
	_ = os.Setenv("FINGERPRINT_FULL_SCAN_MAX_PAIRS", "12345")
	_ = os.Setenv("FINGERPRINT_FULL_SCAN_MAX_DURATION_SECONDS", "333")
	_ = os.Setenv("FINGERPRINT_CANDIDATE_MAX_PER_SOURCE", "88")
	_ = os.Setenv("FINGERPRINT_CANDIDATE_LOW_SIGNAL_MAX_PER_SOURCE", "22")
	_ = os.Setenv("FINGERPRINT_CANDIDATE_MAX_TOTAL", "456")
	_ = os.Setenv("FINGERPRINT_TEMPORAL_REFRESH_MAX_USERS", "777")

	if got := GetFingerprintActiveUserWindowHours(); got != 72 {
		t.Fatalf("expected active user window hours 72, got %v", got)
	}
	if got := GetFingerprintFullScanMaxUsers(); got != 666 {
		t.Fatalf("expected full scan max users 666, got %v", got)
	}
	if got := GetFingerprintFullScanMaxPairs(); got != 12345 {
		t.Fatalf("expected full scan max pairs 12345, got %v", got)
	}
	if got := GetFingerprintFullScanMaxDurationSeconds(); got != 333 {
		t.Fatalf("expected full scan max duration seconds 333, got %v", got)
	}
	if got := GetFingerprintCandidateMaxPerSource(); got != 88 {
		t.Fatalf("expected candidate max per source 88, got %v", got)
	}
	if got := GetFingerprintCandidateLowSignalMaxPerSource(); got != 22 {
		t.Fatalf("expected candidate low signal max per source 22, got %v", got)
	}
	if got := GetFingerprintCandidateMaxTotal(); got != 456 {
		t.Fatalf("expected candidate max total 456, got %v", got)
	}
	if got := GetFingerprintTemporalRefreshMaxUsers(); got != 777 {
		t.Fatalf("expected temporal refresh max users 777, got %v", got)
	}

	_ = os.Setenv("FINGERPRINT_ACTIVE_USER_WINDOW_HOURS", "bad")
	_ = os.Setenv("FINGERPRINT_FULL_SCAN_MAX_USERS", "bad")
	_ = os.Setenv("FINGERPRINT_FULL_SCAN_MAX_PAIRS", "bad")
	_ = os.Setenv("FINGERPRINT_FULL_SCAN_MAX_DURATION_SECONDS", "bad")
	_ = os.Setenv("FINGERPRINT_CANDIDATE_MAX_PER_SOURCE", "bad")
	_ = os.Setenv("FINGERPRINT_CANDIDATE_LOW_SIGNAL_MAX_PER_SOURCE", "bad")
	_ = os.Setenv("FINGERPRINT_CANDIDATE_MAX_TOTAL", "bad")
	_ = os.Setenv("FINGERPRINT_TEMPORAL_REFRESH_MAX_USERS", "bad")

	if got := GetFingerprintActiveUserWindowHours(); got != 168 {
		t.Fatalf("expected active user window hours fallback 168, got %v", got)
	}
	if got := GetFingerprintFullScanMaxUsers(); got != 3000 {
		t.Fatalf("expected full scan max users fallback 3000, got %v", got)
	}
	if got := GetFingerprintFullScanMaxPairs(); got != 200000 {
		t.Fatalf("expected full scan max pairs fallback 200000, got %v", got)
	}
	if got := GetFingerprintFullScanMaxDurationSeconds(); got != 600 {
		t.Fatalf("expected full scan max duration seconds fallback 600, got %v", got)
	}
	if got := GetFingerprintCandidateMaxPerSource(); got != 200 {
		t.Fatalf("expected candidate max per source fallback 200, got %v", got)
	}
	if got := GetFingerprintCandidateLowSignalMaxPerSource(); got != 40 {
		t.Fatalf("expected candidate low signal max per source fallback 40, got %v", got)
	}
	if got := GetFingerprintCandidateMaxTotal(); got != 1200 {
		t.Fatalf("expected candidate max total fallback 1200, got %v", got)
	}
	if got := GetFingerprintTemporalRefreshMaxUsers(); got != 1000 {
		t.Fatalf("expected temporal refresh max users fallback 1000, got %v", got)
	}
}

func TestFingerprintConfig_ReadsBehaviorConfig(t *testing.T) {
	oldWeightKeystroke := os.Getenv("FINGERPRINT_WEIGHT_KEYSTROKE")
	oldWeightMouse := os.Getenv("FINGERPRINT_WEIGHT_MOUSE")
	oldMinKeystroke := os.Getenv("FINGERPRINT_MIN_KEYSTROKE_SAMPLES")
	oldMinMouse := os.Getenv("FINGERPRINT_MIN_MOUSE_SAMPLES")
	oldCollectDuration := os.Getenv("FINGERPRINT_BEHAVIOR_COLLECT_DURATION")
	oldBehaviorRetentionDays := os.Getenv("FINGERPRINT_BEHAVIOR_RETENTION_DAYS")
	oldASNUpdateIntervalDays := os.Getenv("FINGERPRINT_ASN_UPDATE_CHECK_INTERVAL_DAYS")
	oldBehaviorEnabled := os.Getenv("FINGERPRINT_ENABLE_BEHAVIOR_ANALYSIS")
	t.Cleanup(func() {
		_ = os.Setenv("FINGERPRINT_WEIGHT_KEYSTROKE", oldWeightKeystroke)
		_ = os.Setenv("FINGERPRINT_WEIGHT_MOUSE", oldWeightMouse)
		_ = os.Setenv("FINGERPRINT_MIN_KEYSTROKE_SAMPLES", oldMinKeystroke)
		_ = os.Setenv("FINGERPRINT_MIN_MOUSE_SAMPLES", oldMinMouse)
		_ = os.Setenv("FINGERPRINT_BEHAVIOR_COLLECT_DURATION", oldCollectDuration)
		_ = os.Setenv("FINGERPRINT_BEHAVIOR_RETENTION_DAYS", oldBehaviorRetentionDays)
		_ = os.Setenv("FINGERPRINT_ASN_UPDATE_CHECK_INTERVAL_DAYS", oldASNUpdateIntervalDays)
		_ = os.Setenv("FINGERPRINT_ENABLE_BEHAVIOR_ANALYSIS", oldBehaviorEnabled)
	})

	_ = os.Setenv("FINGERPRINT_WEIGHT_KEYSTROKE", "0.61")
	_ = os.Setenv("FINGERPRINT_WEIGHT_MOUSE", "0.57")
	_ = os.Setenv("FINGERPRINT_MIN_KEYSTROKE_SAMPLES", "123")
	_ = os.Setenv("FINGERPRINT_MIN_MOUSE_SAMPLES", "77")
	_ = os.Setenv("FINGERPRINT_BEHAVIOR_COLLECT_DURATION", "90")
	_ = os.Setenv("FINGERPRINT_BEHAVIOR_RETENTION_DAYS", "45")
	_ = os.Setenv("FINGERPRINT_ASN_UPDATE_CHECK_INTERVAL_DAYS", "14")
	_ = os.Setenv("FINGERPRINT_ENABLE_BEHAVIOR_ANALYSIS", "false")

	InitFingerprintConfig()

	if got := GetFingerprintWeightKeystroke(); got != 0.61 {
		t.Fatalf("expected keystroke weight 0.61, got %v", got)
	}
	if got := GetFingerprintWeightMouseBehavior(); got != 0.57 {
		t.Fatalf("expected mouse weight 0.57, got %v", got)
	}
	if got := GetFingerprintMinKeystrokeSamples(); got != 123 {
		t.Fatalf("expected min keystroke samples 123, got %v", got)
	}
	if got := GetFingerprintMinMouseSamples(); got != 77 {
		t.Fatalf("expected min mouse samples 77, got %v", got)
	}
	if got := GetFingerprintBehaviorCollectDuration(); got != 90 {
		t.Fatalf("expected behavior collect duration 90, got %v", got)
	}
	if got := GetFingerprintBehaviorRetentionDays(); got != 45 {
		t.Fatalf("expected behavior retention days 45, got %v", got)
	}
	if got := GetFingerprintASNUpdateCheckIntervalDays(); got != 14 {
		t.Fatalf("expected asn update check interval days 14, got %v", got)
	}
	if FingerprintEnableBehaviorAnalysis {
		t.Fatalf("expected FingerprintEnableBehaviorAnalysis false")
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_KEYSTROKE", "1.5")
	if got := GetFingerprintWeightKeystroke(); got != 0.70 {
		t.Fatalf("expected fallback keystroke weight 0.70, got %v", got)
	}
	_ = os.Setenv("FINGERPRINT_WEIGHT_MOUSE", "bad")
	if got := GetFingerprintWeightMouseBehavior(); got != 0.65 {
		t.Fatalf("expected fallback mouse weight 0.65, got %v", got)
	}
	_ = os.Setenv("FINGERPRINT_MIN_KEYSTROKE_SAMPLES", "bad")
	if got := GetFingerprintMinKeystrokeSamples(); got != 100 {
		t.Fatalf("expected fallback min keystroke samples 100, got %v", got)
	}
	_ = os.Setenv("FINGERPRINT_MIN_MOUSE_SAMPLES", "bad")
	if got := GetFingerprintMinMouseSamples(); got != 50 {
		t.Fatalf("expected fallback min mouse samples 50, got %v", got)
	}
	_ = os.Setenv("FINGERPRINT_BEHAVIOR_COLLECT_DURATION", "bad")
	if got := GetFingerprintBehaviorCollectDuration(); got != 60 {
		t.Fatalf("expected fallback behavior collect duration 60, got %v", got)
	}
	_ = os.Setenv("FINGERPRINT_BEHAVIOR_RETENTION_DAYS", "bad")
	_ = os.Setenv("FINGERPRINT_RETENTION_DAYS", "90")
	if got := GetFingerprintBehaviorRetentionDays(); got != 90 {
		t.Fatalf("expected fallback behavior retention days 90, got %v", got)
	}
	_ = os.Setenv("FINGERPRINT_ASN_UPDATE_CHECK_INTERVAL_DAYS", "bad")
	if got := GetFingerprintASNUpdateCheckIntervalDays(); got != 7 {
		t.Fatalf("expected fallback asn update check interval days 7, got %v", got)
	}
	_ = os.Setenv("FINGERPRINT_ENABLE_BEHAVIOR_ANALYSIS", "invalid")
	InitFingerprintConfig()
	if !FingerprintEnableBehaviorAnalysis {
		t.Fatalf("expected FingerprintEnableBehaviorAnalysis fallback true")
	}

	_ = os.Setenv("FINGERPRINT_WEIGHT_JA4", " 0.77 \n")
	if got := GetFingerprintWeightJA4(); got != 0.77 {
		t.Fatalf("expected trimmed JA4 weight 0.77, got %v", got)
	}
	_ = os.Setenv("FINGERPRINT_WEIGHT_KEYSTROKE", "NaN")
	if got := GetFingerprintWeightKeystroke(); got != 0.70 {
		t.Fatalf("expected NaN fallback keystroke weight 0.70, got %v", got)
	}
}
