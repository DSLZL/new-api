package service

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const tlsJA4CacheTTL = 2 * time.Minute

type tlsJA4CacheEntry struct {
	value     string
	expiresAt time.Time
}

var (
	tlsJA4Store      sync.Map
	tlsJA4WriteCount atomic.Uint64
)

// BuildJA4FromClientHello 生成稳定 JA4-like 指纹（方案C最小实现）
func BuildJA4FromClientHello(hello *tls.ClientHelloInfo) string {
	if hello == nil {
		return ""
	}

	cipherParts := make([]string, 0, len(hello.CipherSuites))
	for _, suite := range hello.CipherSuites {
		cipherParts = append(cipherParts, strconv.FormatUint(uint64(suite), 16))
	}

	versionParts := make([]string, 0, len(hello.SupportedVersions))
	for _, v := range hello.SupportedVersions {
		versionParts = append(versionParts, strconv.FormatUint(uint64(v), 16))
	}

	part := strings.Join([]string{
		hello.ServerName,
		strings.Join(cipherParts, ","),
		strings.Join(versionParts, ","),
	}, "|")

	sum := sha256.Sum256([]byte(part))
	return "ja4c_" + hex.EncodeToString(sum[:16])
}

func rememberTLSJA4(remoteAddr string, ja4 string) {
	if remoteAddr == "" || ja4 == "" {
		return
	}
	tlsJA4Store.Store(remoteAddr, tlsJA4CacheEntry{
		value:     ja4,
		expiresAt: time.Now().Add(tlsJA4CacheTTL),
	})

	if tlsJA4WriteCount.Add(1)%128 == 0 {
		cleanupExpiredTLSJA4(time.Now())
	}
}

func GetTLSJA4FromRemoteAddr(remoteAddr string) string {
	if remoteAddr == "" {
		return ""
	}
	v, ok := tlsJA4Store.Load(remoteAddr)
	if !ok {
		return ""
	}
	entry, ok := v.(tlsJA4CacheEntry)
	if !ok {
		tlsJA4Store.Delete(remoteAddr)
		return ""
	}
	if time.Now().After(entry.expiresAt) {
		tlsJA4Store.Delete(remoteAddr)
		return ""
	}
	return entry.value
}

func cleanupExpiredTLSJA4(now time.Time) {
	tlsJA4Store.Range(func(key, value any) bool {
		entry, ok := value.(tlsJA4CacheEntry)
		if !ok || now.After(entry.expiresAt) {
			tlsJA4Store.Delete(key)
		}
		return true
	})
}

func CaptureTLSJA4FromClientHello(hello *tls.ClientHelloInfo) {
	if hello == nil || hello.Conn == nil {
		return
	}
	ja4 := BuildJA4FromClientHello(hello)
	rememberTLSJA4(hello.Conn.RemoteAddr().String(), ja4)
}
