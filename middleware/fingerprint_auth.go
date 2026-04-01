package middleware

import (
	"net/http"

	"github.com/QuantumNous/new-api/common"
	"github.com/gin-gonic/gin"
)

// FingerprintAdminAuth 指纹管理权限中间件
// 根据环境变量 FINGERPRINT_SUPER_ADMIN_ONLY 决定最低权限级别
func FingerprintAdminAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"message": "未登录",
			})
			c.Abort()
			return
		}

		userRole, ok := role.(int)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"message": "用户信息无效",
			})
			c.Abort()
			return
		}

		if !common.HasFingerprintAccess(userRole) {
			msg := "仅管理员及以上可查看指纹与关联数据"
			if common.FingerprintSuperAdminOnly {
				msg = "仅超级管理员可查看指纹与关联数据"
			}
			c.JSON(http.StatusForbidden, gin.H{
				"success": false,
				"message": msg,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// SuperAdminOnly 仅超级管理员中间件 (不受环境变量控制)
func SuperAdminOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"message": "未登录",
			})
			c.Abort()
			return
		}

		userRole, ok := role.(int)
		if !ok || userRole < common.RoleRootUser {
			c.JSON(http.StatusForbidden, gin.H{
				"success": false,
				"message": "仅超级管理员可执行此操作",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
