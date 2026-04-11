package service

import (
	"os"
	"testing"

	"github.com/QuantumNous/new-api/model"
	"github.com/stretchr/testify/assert"
)

func TestCompareKeystrokeProfiles_IdenticalProfiles(t *testing.T) {
	profile := model.KeystrokeProfile{
		AvgHoldTime:   92,
		StdHoldTime:   14,
		AvgFlightTime: 118,
		StdFlightTime: 20,
		TypingSpeed:   5.2,
		SampleCount:   180,
		DigraphData:   `[ {"digraph":"alpha->alpha","avgFlightTime":120}, {"digraph":"alpha->digit","avgFlightTime":105} ]`,
	}

	score := CompareKeystrokeProfiles(profile, profile)
	assert.InDelta(t, 1.0, score, 0.0001)
}

func TestCompareKeystrokeProfiles_DifferentProfiles(t *testing.T) {
	a := model.KeystrokeProfile{
		AvgHoldTime:   80,
		StdHoldTime:   10,
		AvgFlightTime: 95,
		StdFlightTime: 15,
		TypingSpeed:   6.1,
		SampleCount:   150,
		DigraphData:   `[ {"digraph":"alpha->alpha","avgFlightTime":90}, {"digraph":"digit->alpha","avgFlightTime":110} ]`,
	}
	b := model.KeystrokeProfile{
		AvgHoldTime:   260,
		StdHoldTime:   12,
		AvgFlightTime: 320,
		StdFlightTime: 18,
		TypingSpeed:   1.4,
		SampleCount:   160,
		DigraphData:   `[ {"digraph":"alpha->alpha","avgFlightTime":360}, {"digraph":"digit->alpha","avgFlightTime":300} ]`,
	}

	score := CompareKeystrokeProfiles(a, b)
	assert.Less(t, score, 0.30)
}

func TestCompareKeystrokeProfiles_NoCommonDigraphUsesTimingOnly(t *testing.T) {
	a := model.KeystrokeProfile{
		AvgHoldTime:   100,
		StdHoldTime:   20,
		AvgFlightTime: 130,
		StdFlightTime: 25,
		TypingSpeed:   4.0,
		SampleCount:   140,
		DigraphData:   `[ {"digraph":"alpha->digit","avgFlightTime":110} ]`,
	}
	b := model.KeystrokeProfile{
		AvgHoldTime:   101,
		StdHoldTime:   21,
		AvgFlightTime: 132,
		StdFlightTime: 24,
		TypingSpeed:   3.9,
		SampleCount:   145,
		DigraphData:   `[ {"digraph":"digit->alpha","avgFlightTime":112} ]`,
	}

	score := CompareKeystrokeProfiles(a, b)
	assert.Greater(t, score, 0.60)
	assert.LessOrEqual(t, score, 1.0)
}

func TestCompareKeystrokeProfiles_InvalidDigraphJSONIsGraceful(t *testing.T) {
	a := model.KeystrokeProfile{
		AvgHoldTime:   100,
		StdHoldTime:   0,
		AvgFlightTime: 120,
		StdFlightTime: 0,
		TypingSpeed:   4.5,
		SampleCount:   130,
		DigraphData:   `not-json`,
	}
	b := model.KeystrokeProfile{
		AvgHoldTime:   101,
		StdHoldTime:   0,
		AvgFlightTime: 122,
		StdFlightTime: 0,
		TypingSpeed:   4.4,
		SampleCount:   130,
		DigraphData:   `[]`,
	}

	score := CompareKeystrokeProfiles(a, b)
	assert.GreaterOrEqual(t, score, 0.0)
	assert.LessOrEqual(t, score, 1.0)
}

func TestCompareDigraphCorrelation_ZeroVariance(t *testing.T) {
	t.Run("same constant sequences stay high", func(t *testing.T) {
		a := `[ {"digraph":"alpha->alpha","avgFlightTime":120}, {"digraph":"alpha->digit","avgFlightTime":120} ]`
		b := `[ {"digraph":"alpha->alpha","avgFlightTime":120}, {"digraph":"alpha->digit","avgFlightTime":120} ]`
		assert.InDelta(t, 1.0, compareDigraphCorrelation(a, b), 0.0001)
	})

	t.Run("different constant sequences remain distinguishable", func(t *testing.T) {
		a := `[ {"digraph":"alpha->alpha","avgFlightTime":120}, {"digraph":"alpha->digit","avgFlightTime":120} ]`
		b := `[ {"digraph":"alpha->alpha","avgFlightTime":180}, {"digraph":"alpha->digit","avgFlightTime":180} ]`
		score := compareDigraphCorrelation(a, b)
		assert.Greater(t, score, 0.0)
		assert.Less(t, score, 1.0)
	})

	t.Run("single side zero variance falls back to neutral", func(t *testing.T) {
		a := `[ {"digraph":"alpha->alpha","avgFlightTime":120}, {"digraph":"alpha->digit","avgFlightTime":120} ]`
		b := `[ {"digraph":"alpha->alpha","avgFlightTime":120}, {"digraph":"alpha->digit","avgFlightTime":160} ]`
		assert.InDelta(t, 0.5, compareDigraphCorrelation(a, b), 0.0001)
	})
}

func TestCompareMouseProfiles_IdenticalProfiles(t *testing.T) {
	distribution := `{"topLeft":0.25,"topRight":0.25,"bottomLeft":0.25,"bottomRight":0.25}`
	profile := model.MouseProfile{
		AvgSpeed:            1400,
		MaxSpeed:            2100,
		SpeedStd:            180,
		AvgAcceleration:     320,
		AccStd:              70,
		DirectionChangeRate: 0.18,
		AvgScrollDelta:      120,
		ScrollDeltaMode:     0,
		ClickDistribution:   distribution,
		SampleCount:         90,
	}

	score := CompareMouseProfiles(profile, profile)
	assert.InDelta(t, 1.0, score, 0.0001)
}

func TestCompareMouseProfiles_DifferentProfiles(t *testing.T) {
	a := model.MouseProfile{
		AvgSpeed:            1200,
		MaxSpeed:            1800,
		SpeedStd:            120,
		AvgAcceleration:     280,
		AccStd:              60,
		DirectionChangeRate: 0.12,
		AvgScrollDelta:      90,
		ScrollDeltaMode:     0,
		ClickDistribution:   `{"topLeft":0.7,"topRight":0.1,"bottomLeft":0.1,"bottomRight":0.1}`,
		SampleCount:         90,
	}
	b := model.MouseProfile{
		AvgSpeed:            3200,
		MaxSpeed:            5400,
		SpeedStd:            820,
		AvgAcceleration:     1100,
		AccStd:              260,
		DirectionChangeRate: 0.78,
		AvgScrollDelta:      420,
		ScrollDeltaMode:     1,
		ClickDistribution:   `{"topLeft":0.1,"topRight":0.1,"bottomLeft":0.1,"bottomRight":0.7}`,
		SampleCount:         95,
	}

	score := CompareMouseProfiles(a, b)
	assert.Less(t, score, 0.35)
}

func TestCompareMouseProfiles_InvalidClickDistributionIsGraceful(t *testing.T) {
	a := model.MouseProfile{
		AvgSpeed:            1200,
		MaxSpeed:            1800,
		SpeedStd:            120,
		AvgAcceleration:     280,
		AccStd:              60,
		DirectionChangeRate: 0.12,
		AvgScrollDelta:      90,
		ScrollDeltaMode:     0,
		ClickDistribution:   `not-json`,
		SampleCount:         90,
	}
	b := model.MouseProfile{
		AvgSpeed:            1210,
		MaxSpeed:            1810,
		SpeedStd:            122,
		AvgAcceleration:     282,
		AccStd:              62,
		DirectionChangeRate: 0.13,
		AvgScrollDelta:      95,
		ScrollDeltaMode:     0,
		ClickDistribution:   `{"topLeft":0.25,"topRight":0.25,"bottomLeft":0.25,"bottomRight":0.25}`,
		SampleCount:         92,
	}

	score := CompareMouseProfiles(a, b)
	assert.GreaterOrEqual(t, score, 0.0)
	assert.LessOrEqual(t, score, 1.0)
}

func TestGetKeystrokeBehaviorWeight_DefaultAndEnvOverride(t *testing.T) {
	old, existed := os.LookupEnv("FINGERPRINT_WEIGHT_KEYSTROKE")
	t.Cleanup(func() {
		if !existed {
			_ = os.Unsetenv("FINGERPRINT_WEIGHT_KEYSTROKE")
		} else {
			_ = os.Setenv("FINGERPRINT_WEIGHT_KEYSTROKE", old)
		}
	})

	_ = os.Unsetenv("FINGERPRINT_WEIGHT_KEYSTROKE")
	assert.InDelta(t, 0.70, getKeystrokeBehaviorWeight(), 0.0001)

	_ = os.Setenv("FINGERPRINT_WEIGHT_KEYSTROKE", "0.63")
	assert.InDelta(t, 0.63, getKeystrokeBehaviorWeight(), 0.0001)
}

func TestGetMouseBehaviorWeight_DefaultAndEnvOverride(t *testing.T) {
	old, existed := os.LookupEnv("FINGERPRINT_WEIGHT_MOUSE")
	t.Cleanup(func() {
		if !existed {
			_ = os.Unsetenv("FINGERPRINT_WEIGHT_MOUSE")
		} else {
			_ = os.Setenv("FINGERPRINT_WEIGHT_MOUSE", old)
		}
	})

	_ = os.Unsetenv("FINGERPRINT_WEIGHT_MOUSE")
	assert.InDelta(t, 0.65, getMouseBehaviorWeight(), 0.0001)

	_ = os.Setenv("FINGERPRINT_WEIGHT_MOUSE", "0.58")
	assert.InDelta(t, 0.58, getMouseBehaviorWeight(), 0.0001)
}
