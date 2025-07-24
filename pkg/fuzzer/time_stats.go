// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"math"
	"sync"
)

// TimeStats 执行时间统计
type TimeStats struct {
	mu sync.RWMutex
	
	// 样本数据
	samples []uint64
	
	// 统计指标
	mean     float64
	variance float64
	stdDev   float64
	
	// 样本计数
	count int64
	
	// 是否需要重新计算统计指标
	needRecalc bool
	
	// 最大样本数量 (避免内存无限增长)
	maxSamples int
}

// NewTimeStats 创建时间统计器
func NewTimeStats() *TimeStats {
	return &TimeStats{
		samples:    make([]uint64, 0, 1000),
		maxSamples: 10000,
		needRecalc: true,
	}
}

// AddSample 添加执行时间样本
func (ts *TimeStats) AddSample(execTime uint64) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	
	ts.samples = append(ts.samples, execTime)
	ts.count++
	ts.needRecalc = true
	
	// 如果样本数量超过限制，移除最旧的样本
	if len(ts.samples) > ts.maxSamples {
		// 移除前一半样本
		copy(ts.samples, ts.samples[ts.maxSamples/2:])
		ts.samples = ts.samples[:ts.maxSamples/2]
	}
}

// CalculateAnomalyScore 计算时间异常分数
func (ts *TimeStats) CalculateAnomalyScore(execTime uint64) float64 {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	
	if ts.count < 10 {
		// 样本数量不足，无法计算异常分数
		return 0.0
	}
	
	if ts.needRecalc {
		ts.mu.RUnlock()
		ts.mu.Lock()
		ts.recalculateStats()
		ts.mu.Unlock()
		ts.mu.RLock()
	}
	
	if ts.stdDev == 0 {
		return 0.0
	}
	
	// 计算 Z-score (标准化分数)
	zScore := math.Abs(float64(execTime)-ts.mean) / ts.stdDev
	
	// 将 Z-score 转换为 0-1 范围的异常分数
	// Z-score > 2 被认为是显著异常
	anomalyScore := math.Min(zScore/2.0, 1.0)
	
	return anomalyScore
}

// recalculateStats 重新计算统计指标
func (ts *TimeStats) recalculateStats() {
	if len(ts.samples) == 0 {
		return
	}
	
	// 计算均值
	sum := uint64(0)
	for _, sample := range ts.samples {
		sum += sample
	}
	ts.mean = float64(sum) / float64(len(ts.samples))
	
	// 计算方差
	varianceSum := 0.0
	for _, sample := range ts.samples {
		diff := float64(sample) - ts.mean
		varianceSum += diff * diff
	}
	ts.variance = varianceSum / float64(len(ts.samples))
	
	// 计算标准差
	ts.stdDev = math.Sqrt(ts.variance)
	
	ts.needRecalc = false
}

// GetStats 获取统计信息
func (ts *TimeStats) GetStats() (mean, stdDev float64, count int64) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	
	if ts.needRecalc {
		ts.mu.RUnlock()
		ts.mu.Lock()
		ts.recalculateStats()
		ts.mu.Unlock()
		ts.mu.RLock()
	}
	
	return ts.mean, ts.stdDev, ts.count
}