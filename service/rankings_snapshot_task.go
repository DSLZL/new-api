package service

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/logger"
	"github.com/QuantumNous/new-api/model"
	"github.com/bytedance/gopkg/util/gopool"
)

const (
	userRankingSnapshotTickInterval = 1 * time.Minute
	userRankingSnapshotHTTPTimeout  = 8 * time.Second
)

var (
	userRankingSnapshotTaskOnce     sync.Once
	userRankingSnapshotTaskRunning  atomic.Bool
	userRankingSnapshotLastDateKey  atomic.Int64
	userRankingSnapshotNetworkNowFn = fetchNetworkNow
)

func StartUserRankingDailySnapshotTask() {
	userRankingSnapshotTaskOnce.Do(func() {
		if !common.IsMasterNode {
			return
		}
		gopool.Go(func() {
			logger.LogInfo(context.Background(), fmt.Sprintf("user ranking snapshot task started: tick=%s zone=Asia/Shanghai network_time=true", userRankingSnapshotTickInterval))
			ticker := time.NewTicker(userRankingSnapshotTickInterval)
			defer ticker.Stop()

			runUserRankingDailySnapshotTick()
			for range ticker.C {
				runUserRankingDailySnapshotTick()
			}
		})
	})
}

func runUserRankingDailySnapshotTick() {
	if !userRankingSnapshotTaskRunning.CompareAndSwap(false, true) {
		return
	}
	defer userRankingSnapshotTaskRunning.Store(false)

	now, err := userRankingSnapshotNetworkNowFn()
	if err != nil {
		logger.LogWarn(context.Background(), fmt.Sprintf("user ranking snapshot task using local time fallback: %v", err))
		now = time.Now()
	}
	runUserRankingDailySnapshotOnce(now)
}

func runUserRankingDailySnapshotOnce(now time.Time) {
	snapshotCtx := resolveUserRankingSnapshotContext(now)
	lastDateKey := userRankingSnapshotLastDateKey.Load()
	if lastDateKey == snapshotCtx.dateKey {
		return
	}

	ctx := context.Background()
	if err := persistUserRankingDailySnapshots(snapshotCtx); err != nil {
		logger.LogWarn(ctx, fmt.Sprintf("user ranking snapshot task failed: date=%s err=%v", snapshotCtx.snapshotDate, err))
		return
	}
	userRankingSnapshotLastDateKey.Store(snapshotCtx.dateKey)
	InvalidateUserRankingCache()
	logger.LogInfo(ctx, fmt.Sprintf("user ranking snapshot task completed: date=%s ts=%d", snapshotCtx.snapshotDate, snapshotCtx.snapshotAt.Unix()))
}

type userRankingSnapshotContext struct {
	snapshotDate   string
	snapshotDayRef time.Time
	snapshotAt     time.Time
	dateKey        int64
}

func resolveUserRankingSnapshotContext(now time.Time) userRankingSnapshotContext {
	beijingNow := toBeijingTime(now)
	dayStart := time.Date(beijingNow.Year(), beijingNow.Month(), beijingNow.Day(), 0, 0, 0, 0, beijingNow.Location())
	targetDay := dayStart.AddDate(0, 0, -1)
	return userRankingSnapshotContext{
		snapshotDate:   formatUserRankingDate(targetDay),
		snapshotDayRef: targetDay.Add(12 * time.Hour),
		snapshotAt:     beijingNow,
		dateKey:        beijingDateKey(targetDay),
	}
}

func persistUserRankingDailySnapshots(snapshotCtx userRankingSnapshotContext) error {
	targets := userRankingSnapshotTargets()
	snapshotAt := snapshotCtx.snapshotAt.Unix()
	for _, target := range targets {
		refTime := snapshotCtx.snapshotAt
		if target.period == UserRankingPeriodDaily {
			refTime = snapshotCtx.snapshotDayRef
		}
		rows, err := buildUserRankingRows(target.metric, target.period, refTime)
		if err != nil {
			return err
		}
		if err = model.SaveUserRankingSnapshot(snapshotCtx.snapshotDate, string(target.metric), string(target.period), rows, snapshotAt); err != nil {
			return err
		}
	}
	return nil
}

type userRankingSnapshotTarget struct {
	metric UserRankingMetric
	period UserRankingPeriod
}

func userRankingSnapshotTargets() []userRankingSnapshotTarget {
	targets := []userRankingSnapshotTarget{
		{metric: UserRankingMetricBalance, period: UserRankingPeriodTotal},
		{metric: UserRankingMetricInvites, period: UserRankingPeriodDaily},
		{metric: UserRankingMetricInvites, period: UserRankingPeriodTotal},
		{metric: UserRankingMetricConsumption, period: UserRankingPeriodDaily},
		{metric: UserRankingMetricConsumption, period: UserRankingPeriodTotal},
	}
	return targets
}

func beijingDateKey(t time.Time) int64 {
	bj := toBeijingTime(t)
	return int64(bj.Year())*10000 + int64(bj.Month())*100 + int64(bj.Day())
}

func toBeijingTime(now time.Time) time.Time {
	return now.In(beijingLocation())
}

func beijingLocation() *time.Location {
	return time.FixedZone("CST-8", 8*3600)
}

func durationUntilNextLocalMidnight(now time.Time) time.Duration {
	loc := now.Location()
	next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, loc)
	return next.Sub(now)
}

func fetchNetworkNow() (time.Time, error) {
	urls := userRankingNetworkTimeURLs()
	var lastErr error
	for _, u := range urls {
		t, err := fetchNetworkNowFromURL(u, userRankingSnapshotHTTPTimeout)
		if err == nil {
			return t, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("empty network time sources")
	}
	return time.Time{}, lastErr
}

func userRankingNetworkTimeURLs() []string {
	raw := strings.TrimSpace(os.Getenv("RANKING_SNAPSHOT_TIME_URLS"))
	if raw == "" {
		return []string{
			"https://www.google.com",
			"https://www.cloudflare.com",
			"https://www.microsoft.com",
		}
	}
	parts := strings.Split(raw, ",")
	urls := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		urls = append(urls, item)
	}
	if len(urls) == 0 {
		return []string{
			"https://www.google.com",
			"https://www.cloudflare.com",
			"https://www.microsoft.com",
		}
	}
	return urls
}

func fetchNetworkNowFromURL(url string, timeout time.Duration) (time.Time, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return time.Time{}, err
	}

	client := &http.Client{
		Timeout: timeout,
	}
	resp, err := client.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	dateValue := strings.TrimSpace(resp.Header.Get("Date"))
	if dateValue == "" {
		return time.Time{}, fmt.Errorf("missing Date header from %s", url)
	}
	parsed, err := parseHTTPDateHeader(dateValue)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse Date header failed from %s: %w", url, err)
	}
	return parsed, nil
}

func parseHTTPDateHeader(value string) (time.Time, error) {
	layouts := []string{
		time.RFC1123,
		time.RFC1123Z,
		time.RFC850,
		time.ANSIC,
		"Mon, 2 Jan 2006 15:04:05 GMT",
		"Monday, 02-Jan-06 15:04:05 GMT",
		"Mon Jan _2 15:04:05 2006",
	}
	for _, layout := range layouts {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported HTTP date format: %s", value)
}
