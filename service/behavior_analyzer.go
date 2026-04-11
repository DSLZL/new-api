package service

import (
	"math"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
)

type digraphStat struct {
	Digraph       string  `json:"digraph"`
	AvgFlightTime float64 `json:"avgFlightTime"`
	StdFlightTime float64 `json:"stdFlightTime"`
}

type clickDistributionStat struct {
	TopLeft     float64 `json:"topLeft"`
	TopRight    float64 `json:"topRight"`
	BottomLeft  float64 `json:"bottomLeft"`
	BottomRight float64 `json:"bottomRight"`
}

func getKeystrokeBehaviorWeight() float64 {
	return common.GetFingerprintWeightKeystroke()
}

func getKeystrokeMinSamples() int {
	return common.GetFingerprintMinKeystrokeSamples()
}

func getMouseBehaviorWeight() float64 {
	return common.GetFingerprintWeightMouseBehavior()
}

func getMouseMinSamples() int {
	return common.GetFingerprintMinMouseSamples()
}

func CompareKeystrokeProfiles(a, b model.KeystrokeProfile) float64 {
	holdSim := compareByStdDistance(a.AvgHoldTime, b.AvgHoldTime, a.StdHoldTime, b.StdHoldTime)
	flightSim := compareByStdDistance(a.AvgFlightTime, b.AvgFlightTime, a.StdFlightTime, b.StdFlightTime)
	speedSim := compareByStdDistance(a.TypingSpeed, b.TypingSpeed, 0.8, 0.8)
	digraphSim := compareDigraphCorrelation(a.DigraphData, b.DigraphData)

	score := holdSim*0.32 + flightSim*0.30 + digraphSim*0.28 + speedSim*0.10
	if score < 0 {
		return 0
	}
	if score > 1 {
		return 1
	}
	return score
}

func CompareMouseProfiles(a, b model.MouseProfile) float64 {
	speedSim := compareByStdDistance(a.AvgSpeed, b.AvgSpeed, a.SpeedStd, b.SpeedStd)
	maxSpeedSim := compareByStdDistance(a.MaxSpeed, b.MaxSpeed, a.SpeedStd, b.SpeedStd)
	accSim := compareByStdDistance(a.AvgAcceleration, b.AvgAcceleration, a.AccStd, b.AccStd)
	directionSim := compareByStdDistance(a.DirectionChangeRate, b.DirectionChangeRate, 0.1, 0.1)
	scrollSim := compareByStdDistance(a.AvgScrollDelta, b.AvgScrollDelta, 20, 20)
	modeSim := 0.0
	if a.ScrollDeltaMode == b.ScrollDeltaMode {
		modeSim = 1.0
	}
	clickSim := compareClickDistribution(a.ClickDistribution, b.ClickDistribution)

	score := speedSim*0.20 + maxSpeedSim*0.16 + accSim*0.18 + directionSim*0.14 + scrollSim*0.10 + modeSim*0.06 + clickSim*0.16
	return clamp01(score)
}

func compareByStdDistance(aMean, bMean, aStd, bStd float64) float64 {
	scale := (math.Abs(aStd) + math.Abs(bStd)) / 2
	if scale < 1 {
		scale = 1
	}
	distance := math.Abs(aMean-bMean) / scale
	sim := 1 / (1 + distance)
	if sim < 0 {
		return 0
	}
	if sim > 1 {
		return 1
	}
	return sim
}

func compareDigraphCorrelation(aRaw, bRaw string) float64 {
	aStats := parseDigraphStats(aRaw)
	bStats := parseDigraphStats(bRaw)
	if len(aStats) == 0 || len(bStats) == 0 {
		return 0
	}

	commonKeys := make([]string, 0)
	for digraph := range aStats {
		if _, ok := bStats[digraph]; ok {
			commonKeys = append(commonKeys, digraph)
		}
	}
	if len(commonKeys) == 0 {
		return 0
	}

	if len(commonKeys) == 1 {
		diff := math.Abs(aStats[commonKeys[0]] - bStats[commonKeys[0]])
		return 1 / (1 + diff/25)
	}

	var sumA, sumB float64
	for _, key := range commonKeys {
		sumA += aStats[key]
		sumB += bStats[key]
	}
	meanA := sumA / float64(len(commonKeys))
	meanB := sumB / float64(len(commonKeys))

	var num, denA, denB float64
	for _, key := range commonKeys {
		da := aStats[key] - meanA
		db := bStats[key] - meanB
		num += da * db
		denA += da * da
		denB += db * db
	}
	if denA == 0 || denB == 0 {
		if denA == 0 && denB == 0 {
			diff := math.Abs(meanA - meanB)
			return 1 / (1 + diff/25)
		}
		return 0.5
	}
	corr := num / math.Sqrt(denA*denB)
	if corr < -1 {
		corr = -1
	}
	if corr > 1 {
		corr = 1
	}
	return (corr + 1) / 2
}

func parseDigraphStats(raw string) map[string]float64 {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var rows []digraphStat
	if err := common.UnmarshalJsonStr(raw, &rows); err != nil {
		return nil
	}
	result := make(map[string]float64, len(rows))
	for _, row := range rows {
		if row.Digraph == "" {
			continue
		}
		result[row.Digraph] = row.AvgFlightTime
	}
	return result
}

func compareClickDistribution(aRaw, bRaw string) float64 {
	a, okA := parseClickDistribution(aRaw)
	b, okB := parseClickDistribution(bRaw)
	if !okA || !okB {
		return 0
	}
	diff := math.Abs(a.TopLeft-b.TopLeft) +
		math.Abs(a.TopRight-b.TopRight) +
		math.Abs(a.BottomLeft-b.BottomLeft) +
		math.Abs(a.BottomRight-b.BottomRight)
	// L1 距离范围 [0,2]，归一化后转换为相似度
	distance := diff / 2
	if distance < 0 {
		distance = 0
	}
	if distance > 1 {
		distance = 1
	}
	return 1 - distance
}

func parseClickDistribution(raw string) (clickDistributionStat, bool) {
	if strings.TrimSpace(raw) == "" {
		return clickDistributionStat{}, false
	}
	var dist clickDistributionStat
	if err := common.UnmarshalJsonStr(raw, &dist); err != nil {
		return clickDistributionStat{}, false
	}
	if !isFiniteNonNegative(dist.TopLeft) ||
		!isFiniteNonNegative(dist.TopRight) ||
		!isFiniteNonNegative(dist.BottomLeft) ||
		!isFiniteNonNegative(dist.BottomRight) {
		return clickDistributionStat{}, false
	}
	total := dist.TopLeft + dist.TopRight + dist.BottomLeft + dist.BottomRight
	if total <= 0 {
		return clickDistributionStat{}, false
	}
	return clickDistributionStat{
		TopLeft:     dist.TopLeft / total,
		TopRight:    dist.TopRight / total,
		BottomLeft:  dist.BottomLeft / total,
		BottomRight: dist.BottomRight / total,
	}, true
}

func isFiniteNonNegative(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
