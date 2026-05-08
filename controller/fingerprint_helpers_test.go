package controller

import (
	"fmt"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
)

func TestSanitizeWebRTCLocalIPList_OnlyPrivateAndDedup(t *testing.T) {
	input := []string{
		"192.168.1.10",
		"8.8.8.8",
		"192.168.1.10",
		"10.0.0.5",
		"not-an-ip",
	}

	got := sanitizeWebRTCLocalIPList(input)
	if len(got) != 2 {
		t.Fatalf("expected 2 private IPs, got %v", got)
	}
	if got[0] != "192.168.1.10" || got[1] != "10.0.0.5" {
		t.Fatalf("unexpected local IP list: %v", got)
	}
}

func TestSanitizeWebRTCPublicIPList_OnlyPublicAndDedup(t *testing.T) {
	input := []string{
		"192.168.1.10",
		"1.1.1.1",
		"1.1.1.1",
		"8.8.8.8",
		"127.0.0.1",
	}

	got := sanitizeWebRTCPublicIPList(input)
	if len(got) != 2 {
		t.Fatalf("expected 2 public IPs, got %v", got)
	}
	if got[0] != "1.1.1.1" || got[1] != "8.8.8.8" {
		t.Fatalf("unexpected public IP list: %v", got)
	}
}

func TestSanitizeWebRTCPublicIPList_LimitSize(t *testing.T) {
	input := make([]string, 0, 40)
	for i := 1; i <= 40; i++ {
		input = append(input, fmt.Sprintf("8.8.8.%d", i%255))
	}

	got := sanitizeWebRTCPublicIPList(input)
	if len(got) > 16 {
		t.Fatalf("expected at most 16 items, got %d", len(got))
	}
}

func TestStringifyStringSlice_EmptyAsArray(t *testing.T) {
	if got := stringifyStringSlice(nil); got != "[]" {
		t.Fatalf("expected [] for nil slice, got %q", got)
	}
	if got := stringifyStringSlice([]string{}); got != "[]" {
		t.Fatalf("expected [] for empty slice, got %q", got)
	}
}

func TestSanitizePageURL_StripsQueryAndFragment(t *testing.T) {
	raw := "https://example.com/path/to?a=1&token=secret#frag"
	got := sanitizePageURL(raw)
	if got != "https://example.com/path/to" {
		t.Fatalf("unexpected sanitized URL: %q", got)
	}
}

func TestApplyClientFingerprintData_CopiesMediaSpeechFields(t *testing.T) {
	fp := &model.Fingerprint{}
	clientFP := &ClientFingerprintData{
		MediaDevicesHash:      "media-devices-hash",
		MediaDeviceCount:      "1-1-1",
		MediaDeviceGroupHash:  "media-group-hash",
		MediaDeviceTotal:      3,
		SpeechVoicesHash:      "speech-voices-hash",
		SpeechVoiceCount:      12,
		SpeechLocalVoiceCount: 5,
	}

	applyClientFingerprintData(fp, clientFP)

	if fp.MediaDevicesHash != clientFP.MediaDevicesHash {
		t.Fatalf("expected media devices hash %q, got %q", clientFP.MediaDevicesHash, fp.MediaDevicesHash)
	}
	if fp.MediaDeviceCount != clientFP.MediaDeviceCount {
		t.Fatalf("expected media device count %q, got %q", clientFP.MediaDeviceCount, fp.MediaDeviceCount)
	}
	if fp.MediaDeviceGroupHash != clientFP.MediaDeviceGroupHash {
		t.Fatalf("expected media device group hash %q, got %q", clientFP.MediaDeviceGroupHash, fp.MediaDeviceGroupHash)
	}
	if fp.MediaDeviceTotal != clientFP.MediaDeviceTotal {
		t.Fatalf("expected media device total %d, got %d", clientFP.MediaDeviceTotal, fp.MediaDeviceTotal)
	}
	if fp.SpeechVoicesHash != clientFP.SpeechVoicesHash {
		t.Fatalf("expected speech voices hash %q, got %q", clientFP.SpeechVoicesHash, fp.SpeechVoicesHash)
	}
	if fp.SpeechVoiceCount != clientFP.SpeechVoiceCount {
		t.Fatalf("expected speech voice count %d, got %d", clientFP.SpeechVoiceCount, fp.SpeechVoiceCount)
	}
	if fp.SpeechLocalVoiceCount != clientFP.SpeechLocalVoiceCount {
		t.Fatalf("expected speech local voice count %d, got %d", clientFP.SpeechLocalVoiceCount, fp.SpeechLocalVoiceCount)
	}
}

func TestBuildUserDeviceProfileFromFingerprint_MapsMediaSpeechFields(t *testing.T) {
	parsedUA := &common.ParsedUA{
		Browser:    "Chrome",
		OS:         "macOS",
		DeviceType: "desktop",
	}
	fp := &model.Fingerprint{
		LocalDeviceID:         "lid-123",
		CanvasHash:            "canvas-hash",
		WebGLHash:             "webgl-hash",
		AudioHash:             "audio-hash",
		MediaDevicesHash:      "media-devices-hash",
		MediaDeviceCount:      "1-1-1",
		MediaDeviceGroupHash:  "media-group-hash",
		MediaDeviceTotal:      3,
		SpeechVoicesHash:      "speech-voices-hash",
		SpeechVoiceCount:      12,
		SpeechLocalVoiceCount: 5,
		CompositeHash:         "composite-hash",
		HTTPHeaderHash:        "http-header-hash",
	}

	profile := buildUserDeviceProfileFromFingerprint(7, "1.2.3.4", parsedUA, fp)
	if profile == nil {
		t.Fatal("expected profile to be built")
	}
	if profile.DeviceKey != "lid:lid-123" {
		t.Fatalf("expected device key from local device id, got %q", profile.DeviceKey)
	}
	if profile.MediaDevicesHash != fp.MediaDevicesHash {
		t.Fatalf("expected media devices hash %q, got %q", fp.MediaDevicesHash, profile.MediaDevicesHash)
	}
	if profile.MediaDeviceCount != fp.MediaDeviceCount {
		t.Fatalf("expected media device count %q, got %q", fp.MediaDeviceCount, profile.MediaDeviceCount)
	}
	if profile.MediaDeviceGroupHash != fp.MediaDeviceGroupHash {
		t.Fatalf("expected media device group hash %q, got %q", fp.MediaDeviceGroupHash, profile.MediaDeviceGroupHash)
	}
	if profile.MediaDeviceTotal != fp.MediaDeviceTotal {
		t.Fatalf("expected media device total %d, got %d", fp.MediaDeviceTotal, profile.MediaDeviceTotal)
	}
	if profile.SpeechVoicesHash != fp.SpeechVoicesHash {
		t.Fatalf("expected speech voices hash %q, got %q", fp.SpeechVoicesHash, profile.SpeechVoicesHash)
	}
	if profile.SpeechVoiceCount != fp.SpeechVoiceCount {
		t.Fatalf("expected speech voice count %d, got %d", fp.SpeechVoiceCount, profile.SpeechVoiceCount)
	}
	if profile.SpeechLocalVoiceCount != fp.SpeechLocalVoiceCount {
		t.Fatalf("expected speech local voice count %d, got %d", fp.SpeechLocalVoiceCount, profile.SpeechLocalVoiceCount)
	}
	if profile.HTTPHeaderHash != fp.HTTPHeaderHash {
		t.Fatalf("expected http header hash %q, got %q", fp.HTTPHeaderHash, profile.HTTPHeaderHash)
	}
	if profile.UABrowser != parsedUA.Browser || profile.UAOS != parsedUA.OS || profile.UADeviceType != parsedUA.DeviceType {
		t.Fatalf("expected parsed UA fields to be copied, got %#v", profile)
	}
}
