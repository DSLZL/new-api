package controller

import (
	"net"
	"net/netip"
	"net/url"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
)

const maxWebRTCIPs = 16

func sanitizeWebRTCLocalIPList(values []string) []string {
	return sanitizeIPList(values, true)
}

func sanitizeWebRTCPublicIPList(values []string) []string {
	return sanitizeIPList(values, false)
}

func sanitizeIPList(values []string, localOnly bool) []string {
	if len(values) == 0 {
		return nil
	}

	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		if len(result) >= maxWebRTCIPs {
			break
		}
		ip := net.ParseIP(raw)
		if ip == nil {
			continue
		}
		normalized := ip.String()
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}

		parsed, err := netip.ParseAddr(normalized)
		if err != nil {
			continue
		}
		if parsed.IsUnspecified() || parsed.IsLoopback() || parsed.IsMulticast() {
			continue
		}

		isPrivate := parsed.IsPrivate()
		if localOnly && !isPrivate {
			continue
		}
		if !localOnly && isPrivate {
			continue
		}

		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	return result
}

func stringifyStringSlice(values []string) string {
	if len(values) == 0 {
		return "[]"
	}
	payload, err := common.Marshal(values)
	if err != nil {
		return "[]"
	}
	return string(payload)
}

func sanitizePageURL(raw string) string {
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func applyClientFingerprintData(fp *model.Fingerprint, clientFP *ClientFingerprintData) {
	if fp == nil || clientFP == nil {
		return
	}

	fp.CanvasHash = clientFP.CanvasHash
	fp.WebGLHash = clientFP.WebGLHash
	fp.WebGLDeepHash = clientFP.WebGLDeepHash
	fp.ClientRectsHash = clientFP.ClientRectsHash
	fp.WebGLVendor = clientFP.WebGLVendor
	fp.WebGLRenderer = clientFP.WebGLRenderer
	fp.MediaDevicesHash = clientFP.MediaDevicesHash
	fp.MediaDeviceCount = clientFP.MediaDeviceCount
	fp.MediaDeviceGroupHash = clientFP.MediaDeviceGroupHash
	fp.MediaDeviceTotal = clientFP.MediaDeviceTotal
	fp.SpeechVoicesHash = clientFP.SpeechVoicesHash
	fp.SpeechVoiceCount = clientFP.SpeechVoiceCount
	fp.SpeechLocalVoiceCount = clientFP.SpeechLocalVoiceCount
	fp.AudioHash = clientFP.AudioHash
	fp.FontsHash = clientFP.FontsHash
	fp.FontsList = clientFP.FontsList
	fp.ScreenWidth = clientFP.ScreenWidth
	fp.ScreenHeight = clientFP.ScreenHeight
	fp.ColorDepth = clientFP.ColorDepth
	fp.PixelRatio = clientFP.PixelRatio
	fp.CPUCores = clientFP.CPUCores
	fp.DeviceMemory = clientFP.DeviceMemory
	fp.MaxTouch = clientFP.MaxTouch
	fp.Timezone = clientFP.Timezone
	fp.TZOffset = clientFP.TZOffset
	fp.Languages = clientFP.Languages
	fp.Platform = clientFP.Platform
	fp.DoNotTrack = clientFP.DoNotTrack
	fp.CookieEnabled = clientFP.CookieEnabled
	fp.LocalDeviceID = clientFP.LocalDeviceID
	fp.PersistentID = clientFP.PersistentID
	fp.PersistentIDSource = clientFP.PersistentIDSource
	fp.ETagID = clientFP.ETagID
	fp.WebRTCLocalIPs = stringifyStringSlice(sanitizeWebRTCLocalIPList(clientFP.WebRTCLocalIPs))
	fp.WebRTCPublicIPs = stringifyStringSlice(sanitizeWebRTCPublicIPList(clientFP.WebRTCPublicIPs))
	fp.CompositeHash = clientFP.CompositeHash
}

func buildUserDeviceProfileFromFingerprint(userID int, realIP string, parsedUA *common.ParsedUA, fp *model.Fingerprint) *model.UserDeviceProfile {
	if fp == nil {
		return nil
	}

	deviceKey := model.BuildDeviceKey(fp.LocalDeviceID, fp.CanvasHash, fp.WebGLHash, fp.AudioHash)
	if deviceKey == "" {
		return nil
	}

	profile := &model.UserDeviceProfile{
		UserID:                userID,
		DeviceKey:             deviceKey,
		CanvasHash:            fp.CanvasHash,
		WebGLHash:             fp.WebGLHash,
		WebGLDeepHash:         fp.WebGLDeepHash,
		ClientRectsHash:       fp.ClientRectsHash,
		MediaDevicesHash:      fp.MediaDevicesHash,
		MediaDeviceCount:      fp.MediaDeviceCount,
		MediaDeviceGroupHash:  fp.MediaDeviceGroupHash,
		MediaDeviceTotal:      fp.MediaDeviceTotal,
		SpeechVoicesHash:      fp.SpeechVoicesHash,
		SpeechVoiceCount:      fp.SpeechVoiceCount,
		SpeechLocalVoiceCount: fp.SpeechLocalVoiceCount,
		AudioHash:             fp.AudioHash,
		FontsHash:             fp.FontsHash,
		LocalDeviceID:         fp.LocalDeviceID,
		CompositeHash:         fp.CompositeHash,
		HTTPHeaderHash:        fp.HTTPHeaderHash,
		LastSeenIP:            realIP,
	}
	if parsedUA != nil {
		profile.UABrowser = parsedUA.Browser
		profile.UAOS = parsedUA.OS
		profile.UADeviceType = parsedUA.DeviceType
	}
	return profile
}
