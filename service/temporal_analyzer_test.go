package service

import (
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildActivityProfile_Normalized48Bins(t *testing.T) {
	ts := []time.Time{
		time.Date(2026, 1, 1, 8, 10, 0, 0, time.UTC),
		time.Date(2026, 1, 1, 8, 40, 0, 0, time.UTC),
		time.Date(2026, 1, 1, 20, 20, 0, 0, time.UTC),
	}
	profile := BuildActivityProfile(ts)
	assert.Len(t, profile, 48)
	sum := 0.0
	for _, v := range profile {
		sum += v
	}
	assert.InDelta(t, 1.0, sum, 0.000001)
	assert.Greater(t, profile[16], 0.0) // 08:00-08:29
	assert.Greater(t, profile[17], 0.0) // 08:30-08:59
	assert.Greater(t, profile[40], 0.0) // 20:00-20:29
}

func TestBuildActivityProfile_Empty(t *testing.T) {
	profile := BuildActivityProfile(nil)
	assert.Len(t, profile, 48)
	for _, v := range profile {
		assert.Equal(t, 0.0, v)
	}
}

func TestDedupBurstTimestamps_SortsDescendingInput(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	input := []time.Time{
		base.Add(6 * time.Minute),
		base.Add(4 * time.Minute),
		base.Add(2 * time.Minute),
		base,
	}

	got := dedupBurstTimestamps(input, temporalBurstDedupWindow)
	assert.Equal(t, []time.Time{
		base,
		base.Add(2 * time.Minute),
		base.Add(4 * time.Minute),
		base.Add(6 * time.Minute),
	}, got)
}

func TestDedupBurstTimestamps_RespectsWindowBoundary(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	input := []time.Time{
		base.Add(181 * time.Second),
		base.Add(90 * time.Second),
		base,
	}

	got := dedupBurstTimestamps(input, temporalBurstDedupWindow)
	assert.Equal(t, []time.Time{
		base,
		base.Add(181 * time.Second),
	}, got)
}

func TestCheckMutualExclusion_CountsBidirectionalSwitches(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	a := []time.Time{
		base,
		base.Add(10 * time.Minute),
		base.Add(20 * time.Minute),
	}
	b := []time.Time{
		base.Add(2 * time.Minute),
		base.Add(12 * time.Minute),
		base.Add(22 * time.Minute),
	}
	switches := CheckMutualExclusion(a, b, 5)
	assert.Equal(t, 3, switches)
}

func TestCheckMutualExclusion_DoesNotReuseSingleTargetEvent(t *testing.T) {
	base := time.Date(2026, 1, 1, 13, 0, 0, 0, time.UTC)
	a := []time.Time{base, base.Add(90 * time.Second)}
	b := []time.Time{base.Add(2 * time.Minute)}
	switches := CheckMutualExclusion(a, b, 5)
	assert.Equal(t, 1, switches)
}

func TestComputeTimeSimilarity_RequiresMinSamples(t *testing.T) {
	initTestDB(t)
	base := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 4; i++ {
		assert.NoError(t, model.DB.Create(&model.Fingerprint{UserID: 301, CompositeHash: "u301", CreatedAt: base.Add(time.Duration(i*30) * time.Minute)}).Error)
		assert.NoError(t, model.DB.Create(&model.Fingerprint{UserID: 302, CompositeHash: "u302", CreatedAt: base.Add(time.Duration(i*30) * time.Minute)}).Error)
	}
	sim := ComputeTimeSimilarity(301, 302)
	assert.Equal(t, 0.0, sim)
}

func TestComputeTimeSimilarity_UsesPrecomputedProfileWhenEnabled(t *testing.T) {
	initTestDB(t)

	oldRead := common.FingerprintEnableTemporalPrecomputeRead
	common.FingerprintEnableTemporalPrecomputeRead = true
	t.Cleanup(func() { common.FingerprintEnableTemporalPrecomputeRead = oldRead })

	bins := make([]float64, 48)
	bins[10] = 0.4
	bins[11] = 0.6
	raw, err := common.Marshal(bins)
	assert.NoError(t, err)

	now := time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC)
	assert.NoError(t, model.DB.Create(&model.UserTemporalProfile{
		UserID:         501,
		ProfileDate:    "2026-01-02",
		Timezone:       "UTC",
		ActivityBins:   string(raw),
		PeakBin:        11,
		SampleCount:    8,
		LastActivityAt: now,
	}).Error)
	assert.NoError(t, model.DB.Create(&model.UserTemporalProfile{
		UserID:         502,
		ProfileDate:    "2026-01-02",
		Timezone:       "UTC",
		ActivityBins:   string(raw),
		PeakBin:        11,
		SampleCount:    8,
		LastActivityAt: now,
	}).Error)

	sim := ComputeTimeSimilarity(501, 502)
	assert.InDelta(t, 1.0, sim, 0.000001)
}

func TestBuildPrecomputeSessionID_IsStableAndDistinct(t *testing.T) {
	window := SessionWindow{
		Start: time.Date(2026, 1, 3, 9, 0, 0, 0, time.UTC),
		End:   time.Date(2026, 1, 3, 9, 50, 0, 0, time.UTC),
	}

	first := buildPrecomputeSessionID(601, window)
	second := buildPrecomputeSessionID(601, window)
	otherUser := buildPrecomputeSessionID(602, window)
	otherWindow := buildPrecomputeSessionID(601, SessionWindow{Start: window.Start, End: window.End.Add(time.Minute)})

	require.NotEmpty(t, first)
	assert.Equal(t, first, second)
	assert.NotEqual(t, first, otherUser)
	assert.NotEqual(t, first, otherWindow)
}

func TestRefreshTemporalProfileForUser_PersistsProfileAndSessions(t *testing.T) {
	initTestDB(t)

	base := time.Date(2026, 1, 3, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 6; i++ {
		assert.NoError(t, model.DB.Create(&model.Fingerprint{
			UserID:        601,
			CompositeHash: "u601",
			CreatedAt:     base.Add(time.Duration(i*10) * time.Minute),
		}).Error)
	}

	assert.NoError(t, RefreshTemporalProfileForUser(601, 80))

	profile := model.GetLatestTemporalProfile(601)
	assert.NotNil(t, profile)
	assert.Equal(t, 6, profile.SampleCount)
	assert.Equal(t, base.Add(50*time.Minute), profile.LastActivityAt)
	assert.NotEmpty(t, profile.ActivityBins)

	sessions := model.GetLatestUserSessions(601, 10)
	assert.Len(t, sessions, 1)
	assert.Equal(t, "precompute", sessions[0].Source)
	assert.Equal(t, buildPrecomputeSessionID(601, SessionWindow{Start: base, End: base.Add(50 * time.Minute)}), sessions[0].SessionID)
	assert.Equal(t, base, sessions[0].StartedAt)
	assert.Equal(t, base.Add(50*time.Minute), sessions[0].EndedAt)
	assert.Equal(t, 6, sessions[0].EventCount)
}

func TestCheckMutualExclusionByUsers_UsesPrecomputedSessions(t *testing.T) {
	initTestDB(t)

	oldRead := common.FingerprintEnableTemporalPrecomputeRead
	common.FingerprintEnableTemporalPrecomputeRead = true
	t.Cleanup(func() { common.FingerprintEnableTemporalPrecomputeRead = oldRead })

	base := time.Date(2026, 1, 4, 12, 0, 0, 0, time.UTC)
	sessionsA := []model.UserSession{}
	sessionsB := []model.UserSession{}
	for i := 0; i < 5; i++ {
		startA := base.Add(time.Duration(i*15) * time.Minute)
		endA := startA.Add(2 * time.Minute)
		startB := endA.Add(1 * time.Minute)
		endB := startB.Add(2 * time.Minute)
		sessionsA = append(sessionsA, model.UserSession{
			UserID:     701,
			SessionID:  buildPrecomputeSessionID(701, SessionWindow{Start: startA, End: endA}),
			StartedAt:  startA,
			EndedAt:    endA,
			EventCount: 2,
			Source:     "precompute",
		})
		sessionsB = append(sessionsB, model.UserSession{
			UserID:     702,
			SessionID:  buildPrecomputeSessionID(702, SessionWindow{Start: startB, End: endB}),
			StartedAt:  startB,
			EndedAt:    endB,
			EventCount: 2,
			Source:     "precompute",
		})
	}
	assert.NoError(t, model.ReplaceUserSessions(701, sessionsA))
	assert.NoError(t, model.ReplaceUserSessions(702, sessionsB))

	switches := CheckMutualExclusionByUsers(701, 702, 5)
	assert.Equal(t, 5, switches)
}

func TestCheckMutualExclusionByUsers_FallsBackToFingerprintTimestamps(t *testing.T) {
	initTestDB(t)

	oldRead := common.FingerprintEnableTemporalPrecomputeRead
	common.FingerprintEnableTemporalPrecomputeRead = true
	t.Cleanup(func() { common.FingerprintEnableTemporalPrecomputeRead = oldRead })

	base := time.Date(2026, 1, 6, 0, 0, 0, 0, time.UTC)
	sessionsA := []model.UserSession{}
	sessionsB := []model.UserSession{}
	for i := 0; i < 5; i++ {
		startA := base.Add(time.Duration(i) * time.Hour)
		endA := startA.Add(time.Minute)
		startB := startA.Add(30 * time.Minute)
		endB := startB.Add(time.Minute)
		sessionsA = append(sessionsA, model.UserSession{
			UserID:     801,
			SessionID:  buildPrecomputeSessionID(801, SessionWindow{Start: startA, End: endA}),
			StartedAt:  startA,
			EndedAt:    endA,
			EventCount: 1,
			Source:     "precompute",
		})
		sessionsB = append(sessionsB, model.UserSession{
			UserID:     802,
			SessionID:  buildPrecomputeSessionID(802, SessionWindow{Start: startB, End: endB}),
			StartedAt:  startB,
			EndedAt:    endB,
			EventCount: 1,
			Source:     "precompute",
		})
	}
	assert.NoError(t, model.ReplaceUserSessions(801, sessionsA))
	assert.NoError(t, model.ReplaceUserSessions(802, sessionsB))

	fingerprintBase := time.Date(2026, 1, 6, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		assert.NoError(t, model.DB.Create(&model.Fingerprint{
			UserID:        801,
			CompositeHash: "u801",
			CreatedAt:     fingerprintBase.Add(time.Duration(i*10) * time.Minute),
		}).Error)
		assert.NoError(t, model.DB.Create(&model.Fingerprint{
			UserID:        802,
			CompositeHash: "u802",
			CreatedAt:     fingerprintBase.Add(2*time.Minute + time.Duration(i*10)*time.Minute),
		}).Error)
	}

	precomputeA := toSessionWindows(model.GetLatestUserSessions(801, 200))
	precomputeB := toSessionWindows(model.GetLatestUserSessions(802, 200))
	assert.Len(t, precomputeA, 5)
	assert.Len(t, precomputeB, 5)
	assert.Equal(t, 0, SessionGapAnalysis(precomputeA, precomputeB).SwitchCount)

	switches := CheckMutualExclusionByUsers(801, 802, 5)
	assert.Equal(t, 5, switches)
}

func TestRefreshTemporalProfileForUser_PreservesFingerprintSessions(t *testing.T) {
	initTestDB(t)

	base := time.Date(2026, 1, 5, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 6; i++ {
		assert.NoError(t, model.DB.Create(&model.Fingerprint{
			UserID:        611,
			CompositeHash: "u611",
			CreatedAt:     base.Add(time.Duration(i*10) * time.Minute),
		}).Error)
	}
	assert.NoError(t, model.UpsertUserSession(&model.UserSession{
		UserID:          611,
		SessionID:       "fp-session-611",
		DeviceKey:       "lid:fp-611",
		IPAddress:       "1.2.3.4",
		StartedAt:       base.Add(-30 * time.Minute),
		EndedAt:         base.Add(-20 * time.Minute),
		DurationSeconds: 600,
		EventCount:      2,
		Source:          "fingerprint",
	}))

	assert.NoError(t, RefreshTemporalProfileForUser(611, 80))

	sessions := model.GetLatestUserSessions(611, 20)
	assert.GreaterOrEqual(t, len(sessions), 2)

	hasFingerprint := false
	hasPrecompute := false
	for _, session := range sessions {
		if session.Source == "fingerprint" && session.SessionID == "fp-session-611" {
			hasFingerprint = true
		}
		if session.Source == "precompute" {
			hasPrecompute = true
		}
	}
	assert.True(t, hasFingerprint)
	assert.True(t, hasPrecompute)
}
