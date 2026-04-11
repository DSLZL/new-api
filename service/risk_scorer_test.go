package service

import (
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
)

func TestHasWebRTCPublicMismatch(t *testing.T) {
	if hasWebRTCPublicMismatch(nil) {
		t.Fatalf("nil fingerprint should not mismatch")
	}

	fpSame := &model.Fingerprint{IPAddress: "1.2.3.4", WebRTCPublicIPs: `["1.2.3.4"]`}
	if hasWebRTCPublicMismatch(fpSame) {
		t.Fatalf("same public ip should not mismatch")
	}

	fpDiff := &model.Fingerprint{IPAddress: "1.2.3.4", WebRTCPublicIPs: `["8.8.8.8"]`}
	if !hasWebRTCPublicMismatch(fpDiff) {
		t.Fatalf("different public ip should mismatch")
	}
}

func TestCompareFingerprints_RespectsFeatureSwitches(t *testing.T) {
	oldJA4 := common.FingerprintEnableJA4
	oldETag := common.FingerprintEnableETag
	oldWebRTC := common.FingerprintEnableWebRTC
	t.Cleanup(func() {
		common.FingerprintEnableJA4 = oldJA4
		common.FingerprintEnableETag = oldETag
		common.FingerprintEnableWebRTC = oldWebRTC
	})

	a := &model.Fingerprint{
		JA4:             "ja4-x",
		ETagID:          "etag-x",
		WebRTCPublicIPs: `["8.8.8.8"]`,
		UABrowser:       "Chrome",
		UABrowserVer:    "120",
		UAOS:            "Windows",
		UADeviceType:    "desktop",
	}
	b := &model.Fingerprint{
		JA4:             "ja4-x",
		ETagID:          "etag-x",
		WebRTCPublicIPs: `["8.8.8.8"]`,
		UABrowser:       "Chrome",
		UABrowserVer:    "120",
		UAOS:            "Windows",
		UADeviceType:    "desktop",
	}

	common.FingerprintEnableJA4 = true
	common.FingerprintEnableETag = true
	common.FingerprintEnableWebRTC = true
	confOn, _, _, _ := CompareFingerprints(a, b, 1, 2)

	common.FingerprintEnableJA4 = false
	common.FingerprintEnableETag = false
	common.FingerprintEnableWebRTC = false
	confOff, _, _, _ := CompareFingerprints(a, b, 1, 2)

	if confOn <= confOff {
		t.Fatalf("expected confidence with features on > off, got on=%v off=%v", confOn, confOff)
	}
}
