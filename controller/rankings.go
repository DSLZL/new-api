package controller

import (
	"net/http"

	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

func GetRankings(c *gin.Context) {
	scope := c.DefaultQuery("scope", "models")
	if scope == "users" {
		handleUserRankings(c)
		return
	}

	if scope != "models" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "invalid ranking scope",
		})
		return
	}

	result, err := service.GetRankingsSnapshot(c.DefaultQuery("period", "week"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    result,
	})
}

func handleUserRankings(c *gin.Context) {
	visibility := service.GetUserRankingVisibility()
	if visibility == service.UserRankingVisibilityAuthOnly {
		if c.GetInt("id") == 0 {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"message": "Not logged in",
				"code":    "AUTH_NOT_LOGGED_IN",
			})
			return
		}
	}

	metric := c.DefaultQuery("metric", "balance")
	period := c.DefaultQuery("period", "total")
	date := c.Query("date")
	result, err := service.GetUserRankingsSnapshot(metric, period, date)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    result,
	})
}
