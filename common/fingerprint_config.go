package common

import (
	"fmt"
	"os"
	"strings"
)

var FingerprintEnabled bool
var FingerprintSuperAdminOnly bool

func InitFingerprintConfig() {
	FingerprintEnabled = GetEnvOrDefaultBool("FINGERPRINT_ENABLED", false)
	FingerprintSuperAdminOnly = GetEnvOrDefaultBool("FINGERPRINT_SUPER_ADMIN_ONLY", false)

	if FingerprintEnabled {
		SysLog("fingerprint system enabled")
		if FingerprintSuperAdminOnly {
			SysLog("fingerprint data visible to super admin only")
		} else {
			SysLog("fingerprint data visible to admin and super admin")
		}
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

func GetFingerprintAutoConfirmThreshold() float64 {
	val := os.Getenv("FINGERPRINT_AUTO_CONFIRM_THRESHOLD")
	if val == "" {
		return 0.90
	}
	var f float64
	_, _ = fmt.Sscanf(val, "%f", &f)
	if f <= 0 || f > 1 {
		return 0.90
	}
	return f
}

func GetFingerprintAlertThreshold() float64 {
	val := os.Getenv("FINGERPRINT_ALERT_THRESHOLD")
	if val == "" {
		return 0.70
	}
	var f float64
	_, _ = fmt.Sscanf(val, "%f", &f)
	if f <= 0 || f > 1 {
		return 0.70
	}
	return f
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
