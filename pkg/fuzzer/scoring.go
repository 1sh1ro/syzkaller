// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"math"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

// ScoreConfig 配置评分系统的权重参数
type ScoreConfig struct {
	// 覆盖率分数权重 (0.0-1.0)
	CoverageWeight float64 `json:"coverage_weight"`
	// 路径稀有性权重 (0.0-1.0)
	RarityWeight float64 `json:"rarity_weight"`
	// 内核日志分数权重 (0.0-1.0)
	KernelLogWeight float64 `json:"kernel_log_weight"`
	// 执行时间异常权重 (0.0-1.0)
	TimeAnomalyWeight float64 `json:"time_anomaly_weight"`
	// 是否启用评分系统
	Enabled bool `json:"enabled"`
}

// DefaultScoreConfig 返回默认的评分配置
func DefaultScoreConfig() *ScoreConfig {
	return &ScoreConfig{
		CoverageWeight:    0.4,
		RarityWeight:      0.3,
		KernelLogWeight:   0.2,
		TimeAnomalyWeight: 0.1,
		Enabled:           true,
	}
}

// ProgScore 表示程序的综合评分
type ProgScore struct {
	// 总分 (0.0-1.0)
	Total float64 `json:"total"`
	// 覆盖率分数 (0.0-1.0)
	Coverage float64 `json:"coverage"`
	// 路径稀有性分数 (0.0-1.0)
	Rarity float64 `json:"rarity"`
	// 内核日志分数 (0.0-1.0)
	KernelLog float64 `json:"kernel_log"`
	// 执行时间异常分数 (0.0-1.0)
	TimeAnomaly float64 `json:"time_anomaly"`
	// 评分时间戳
	Timestamp time.Time `json:"timestamp"`
}

// ScoreTracker 跟踪和管理程序评分
type ScoreTracker struct {
	mu sync.RWMutex
	
	// 程序评分缓存 (prog hash -> score)
	scores map[string]*ProgScore
	
	// PC 命中计数统计
	pcHitCounts map[uint64]int64
	
	// 路径频率统计 (signal -> frequency)
	pathFrequency map[string]int64
	
	// 执行时间统计
	execTimeStats *TimeStats
	
	// 内核日志模式匹配器
	logMatcher *KernelLogMatcher
	
	// 配置
	config *ScoreConfig
}

// NewScoreTracker 创建新的评分跟踪器
func NewScoreTracker(config *ScoreConfig) *ScoreTracker {
	if config == nil {
		config = DefaultScoreConfig()
	}
	
	return &ScoreTracker{
		scores:        make(map[string]*ProgScore),
		pcHitCounts:   make(map[uint64]int64),
		pathFrequency: make(map[string]int64),
		execTimeStats: NewTimeStats(),
		logMatcher:    NewKernelLogMatcher(),
		config:        config,
	}
}

// UpdateScore 更新程序评分
func (st *ScoreTracker) UpdateScore(prog *prog.Prog, execResult *ExecutionResult) *ProgScore {
	if !st.config.Enabled {
		return &ProgScore{Total: 0.5} // 默认中等分数
	}
	
	st.mu.Lock()
	defer st.mu.Unlock()
	
	progHash := prog.Hash()
	
	// 计算各个维度的分数
	coverageScore := st.calculateCoverageScore(execResult)
	rarityScore := st.calculateRarityScore(execResult)
	kernelLogScore := st.calculateKernelLogScore(execResult)
	timeAnomalyScore := st.calculateTimeAnomalyScore(execResult)
	
	// 计算加权总分
	totalScore := st.config.CoverageWeight*coverageScore +
		st.config.RarityWeight*rarityScore +
		st.config.KernelLogWeight*kernelLogScore +
		st.config.TimeAnomalyWeight*timeAnomalyScore
	
	score := &ProgScore{
		Total:       totalScore,
		Coverage:    coverageScore,
		Rarity:      rarityScore,
		KernelLog:   kernelLogScore,
		TimeAnomaly: timeAnomalyScore,
		Timestamp:   time.Now(),
	}
	
	st.scores[progHash] = score
	
	// 更新统计信息
	st.updateStatistics(execResult)
	
	return score
}

// GetScore 获取程序评分
func (st *ScoreTracker) GetScore(prog *prog.Prog) *ProgScore {
	st.mu.RLock()
	defer st.mu.RUnlock()
	
	progHash := prog.Hash()
	if score, exists := st.scores[progHash]; exists {
		return score
	}
	
	// 返回默认分数
	return &ProgScore{Total: 0.5}
}

// calculateCoverageScore 计算覆盖率分数
func (st *ScoreTracker) calculateCoverageScore(result *ExecutionResult) float64 {
	if result.Signal == nil || result.Signal.Empty() {
		return 0.0
	}
	
	newCoverage := 0
	totalCoverage := result.Signal.Len()
	
	// 计算新覆盖的PC数量
	for _, pc := range result.Signal.ToRaw() {
		if st.pcHitCounts[pc] == 0 {
			newCoverage++
		}
		st.pcHitCounts[pc]++
	}
	
	if totalCoverage == 0 {
		return 0.0
	}
	
	// 新覆盖率占比越高，分数越高
	newCoverageRatio := float64(newCoverage) / float64(totalCoverage)
	
	// 使用对数函数平滑分数分布
	score := math.Log(1 + newCoverageRatio*math.E) / math.Log(1 + math.E)
	
	return math.Min(score, 1.0)
}

// calculateRarityScore 计算路径稀有性分数
func (st *ScoreTracker) calculateRarityScore(result *ExecutionResult) float64 {
	if result.Signal == nil || result.Signal.Empty() {
		return 0.0
	}
	
	signalKey := result.Signal.String()
	frequency := st.pathFrequency[signalKey]
	
	// 频率越低，稀有性分数越高
	if frequency == 0 {
		return 1.0 // 全新路径获得最高分
	}
	
	// 使用反比例函数计算稀有性分数
	score := 1.0 / (1.0 + math.Log(float64(frequency)))
	
	return math.Min(score, 1.0)
}

// calculateKernelLogScore 计算内核日志分数
func (st *ScoreTracker) calculateKernelLogScore(result *ExecutionResult) float64 {
	if len(result.KernelLogs) == 0 {
		return 0.0
	}
	
	return st.logMatcher.CalculateScore(result.KernelLogs)
}

// calculateTimeAnomalyScore 计算执行时间异常分数
func (st *ScoreTracker) calculateTimeAnomalyScore(result *ExecutionResult) float64 {
	if result.ExecTime == 0 {
		return 0.0
	}
	
	return st.execTimeStats.CalculateAnomalyScore(result.ExecTime)
}

// updateStatistics 更新统计信息
func (st *ScoreTracker) updateStatistics(result *ExecutionResult) {
	// 更新路径频率
	if result.Signal != nil && !result.Signal.Empty() {
		signalKey := result.Signal.String()
		st.pathFrequency[signalKey]++
	}
	
	// 更新执行时间统计
	if result.ExecTime > 0 {
		st.execTimeStats.AddSample(result.ExecTime)
	}
}

// GetTopScoredProgs 获取评分最高的程序列表
func (st *ScoreTracker) GetTopScoredProgs(limit int) []string {
	st.mu.RLock()
	defer st.mu.RUnlock()
	
	type progScore struct {
		hash  string
		score float64
	}
	
	var progs []progScore
	for hash, score := range st.scores {
		progs = append(progs, progScore{hash: hash, score: score.Total})
	}
	
	// 按分数降序排序
	for i := 0; i < len(progs)-1; i++ {
		for j := i + 1; j < len(progs); j++ {
			if progs[i].score < progs[j].score {
				progs[i], progs[j] = progs[j], progs[i]
			}
		}
	}
	
	// 返回前 limit 个
	result := make([]string, 0, limit)
	for i := 0; i < len(progs) && i < limit; i++ {
		result = append(result, progs[i].hash)
	}
	
	return result
}

// ExecutionResult 执行结果结构体
type ExecutionResult struct {
	// 覆盖率信号
	Signal signal.Signal
	// 执行时间 (微秒)
	ExecTime uint64
	// 内核日志
	KernelLogs []string
	// 是否发生崩溃
	Crashed bool
	// 错误信息
	Error string
}

// WeightedSelector 基于评分的加权选择器
type WeightedSelector struct {
	mu sync.RWMutex
	
	// 程序权重映射
	weights map[string]float64
	
	// 累积权重数组 (用于快速选择)
	cumulativeWeights []float64
	progHashes        []string
	
	// 是否需要重建权重表
	needRebuild bool
}

// NewWeightedSelector 创建加权选择器
func NewWeightedSelector() *WeightedSelector {
	return &WeightedSelector{
		weights:     make(map[string]float64),
		needRebuild: true,
	}
}

// UpdateWeight 更新程序权重
func (ws *WeightedSelector) UpdateWeight(progHash string, weight float64) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	
	ws.weights[progHash] = weight
	ws.needRebuild = true
}

// SelectWeighted 基于权重随机选择程序
func (ws *WeightedSelector) SelectWeighted(rnd float64) string {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	
	if ws.needRebuild {
		ws.rebuildWeightTable()
	}
	
	if len(ws.cumulativeWeights) == 0 {
		return ""
	}
	
	// 二分查找选择程序
	target := rnd * ws.cumulativeWeights[len(ws.cumulativeWeights)-1]
	
	left, right := 0, len(ws.cumulativeWeights)-1
	for left < right {
		mid := (left + right) / 2
		if ws.cumulativeWeights[mid] < target {
			left = mid + 1
		} else {
			right = mid
		}
	}
	
	return ws.progHashes[left]
}

// rebuildWeightTable 重建权重表
func (ws *WeightedSelector) rebuildWeightTable() {
	ws.cumulativeWeights = ws.cumulativeWeights[:0]
	ws.progHashes = ws.progHashes[:0]
	
	cumulative := 0.0
	for hash, weight := range ws.weights {
		if weight > 0 {
			cumulative += weight
			ws.cumulativeWeights = append(ws.cumulativeWeights, cumulative)
			ws.progHashes = append(ws.progHashes, hash)
		}
	}
	
	ws.needRebuild = false
}