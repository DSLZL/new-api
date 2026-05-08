package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSanitizeDNSResolverIP(t *testing.T) {
	assert.Equal(t, "8.8.8.8", sanitizeDNSResolverIP(" 8.8.8.8 "))
	assert.Equal(t, "", sanitizeDNSResolverIP("not-an-ip"))
	assert.Equal(t, "", sanitizeDNSResolverIP(""))
}

func TestResolveDNSResolverIP_UsesFallbackSanitization(t *testing.T) {
	assert.Equal(t, "1.1.1.1", ResolveDNSResolverIP(context.TODO(), " \"1.1.1.1\" ", "probe-1"))
	assert.Equal(t, "", ResolveDNSResolverIP(context.TODO(), "bad-ip", "probe-2"))
}

func TestExtractResolverIPFromCloudflareBody(t *testing.T) {
	assert.Equal(t, "1.1.1.1", extractResolverIPFromCloudflareBody("1.1.1.1"))
	body := `{"success":true,"result":[{"dimensions":{"resolver_ip":"8.8.8.8"}}]}`
	assert.Equal(t, "8.8.8.8", extractResolverIPFromCloudflareBody(body))
	assert.Equal(t, "", extractResolverIPFromCloudflareBody(`{"success":true}`))
}
