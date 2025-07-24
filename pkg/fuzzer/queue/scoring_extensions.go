// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package queue

import (
	"time"
)

// ScoringRequest 扩展 Request 结构，添加评分相关字段
type ScoringRequest struct {
	*Request
	
	// 程序评分 (0.0-1.0)
	Score float64
	
	// 评分时间戳
	ScoreTimestamp time.Time
	
	// 是否基于评分选择
	ScoreSelected bool
	
	// 评分详细信息
	ScoreDetails *ScoreDetails
}

// ScoreDetails 评分详细信息
type ScoreDetails struct {
	// 覆盖率分数
	Coverage float64 `json:"coverage"`
	
	// 路径稀有性分数
	Rarity float64 `json:"rarity"`
	
	// 内核日志分数
	KernelLog float64 `json:"kernel_log"`
	
	// 执行时间异常分数
	TimeAnomaly float64 `json:"time_anomaly"`
	
	// 总分
	Total float64 `json:"total"`
}

// NewScoringRequest 创建带评分的请求
func NewScoringRequest(req *Request, score float64, details *ScoreDetails) *ScoringRequest {
	return &ScoringRequest{
		Request:        req,
		Score:          score,
		ScoreTimestamp: time.Now(),
		ScoreSelected:  false,
		ScoreDetails:   details,
	}
}

// ScoringResult 扩展 Result 结构，添加评分相关字段
type ScoringResult struct {
	*Result
	
	// 执行后的评分更新
	UpdatedScore float64
	
	// 内核日志内容 (用于评分计算)
	KernelLogs []string
	
	// 执行时间 (纳秒)
	ExecutionTime uint64
	
	// 是否发现新覆盖
	NewCoverage bool
	
	// 新覆盖的PC数量
	NewPCCount int
	
	// 评分计算时间戳
	ScoreCalculatedAt time.Time
}

// NewScoringResult 创建带评分的结果
func NewScoringResult(result *Result) *ScoringResult {
	execTime := uint64(0)
	if result.Info != nil {
		execTime = result.Info.Elapsed
	}
	
	return &ScoringResult{
		Result:            result,
		UpdatedScore:      0.0,
		KernelLogs:        make([]string, 0),
		ExecutionTime:     execTime,
		NewCoverage:       false,
		NewPCCount:        0,
		ScoreCalculatedAt: time.Now(),
	}
}

// SetKernelLogs 设置内核日志
func (sr *ScoringResult) SetKernelLogs(logs []string) {
	sr.KernelLogs = logs
}

// SetNewCoverage 设置新覆盖信息
func (sr *ScoringResult) SetNewCoverage(newCoverage bool, newPCCount int) {
	sr.NewCoverage = newCoverage
	sr.NewPCCount = newPCCount
}

// UpdateScore 更新评分
func (sr *ScoringResult) UpdateScore(score float64) {
	sr.UpdatedScore = score
	sr.ScoreCalculatedAt = time.Now()
}

// WeightedQueue 基于评分的加权队列
type WeightedQueue struct {
	requests []*ScoringRequest
	weights  []float64
	totalWeight float64
}

// NewWeightedQueue 创建加权队列
func NewWeightedQueue() *WeightedQueue {
	return &WeightedQueue{
		requests: make([]*ScoringRequest, 0),
		weights:  make([]float64, 0),
	}
}

// Submit 提交带评分的请求
func (wq *WeightedQueue) SubmitScored(req *ScoringRequest) {
	wq.requests = append(wq.requests, req)
	weight := req.Score
	if weight <= 0 {
		weight = 0.01 // 最小权重，避免完全忽略
	}
	wq.weights = append(wq.weights, weight)
	wq.totalWeight += weight
}

// NextWeighted 基于权重随机选择请求
func (wq *WeightedQueue) NextWeighted(rnd float64) *ScoringRequest {
	if len(wq.requests) == 0 || wq.totalWeight <= 0 {
		return nil
	}
	
	target := rnd * wq.totalWeight
	cumulative := 0.0
	
	for i, weight := range wq.weights {
		cumulative += weight
		if cumulative >= target {
			// 移除选中的请求
			req := wq.requests[i]
			wq.removeAt(i)
			req.ScoreSelected = true
			return req
		}
	}
	
	// 如果没有选中任何请求，返回最后一个
	if len(wq.requests) > 0 {
		req := wq.requests[len(wq.requests)-1]
		wq.removeAt(len(wq.requests) - 1)
		req.ScoreSelected = true
		return req
	}
	
	return nil
}

// removeAt 移除指定位置的请求
func (wq *WeightedQueue) removeAt(index int) {
	if index < 0 || index >= len(wq.requests) {
		return
	}
	
	// 更新总权重
	wq.totalWeight -= wq.weights[index]
	
	// 移除请求和权重
	copy(wq.requests[index:], wq.requests[index+1:])
	wq.requests[len(wq.requests)-1] = nil
	wq.requests = wq.requests[:len(wq.requests)-1]
	
	copy(wq.weights[index:], wq.weights[index+1:])
	wq.weights = wq.weights[:len(wq.weights)-1]
}

// Len 返回队列长度
func (wq *WeightedQueue) Len() int {
	return len(wq.requests)
}

// Clear 清空队列
func (wq *WeightedQueue) Clear() {
	wq.requests = wq.requests[:0]
	wq.weights = wq.weights[:0]
	wq.totalWeight = 0
}

// GetTopScored 获取评分最高的N个请求
func (wq *WeightedQueue) GetTopScored(n int) []*ScoringRequest {
	if n <= 0 || len(wq.requests) == 0 {
		return nil
	}
	
	// 创建副本并排序
	requests := make([]*ScoringRequest, len(wq.requests))
	copy(requests, wq.requests)
	
	// 简单的冒泡排序 (按评分降序)
	for i := 0; i < len(requests)-1; i++ {
		for j := i + 1; j < len(requests); j++ {
			if requests[i].Score < requests[j].Score {
				requests[i], requests[j] = requests[j], requests[i]
			}
		}
	}
	
	// 返回前N个
	if n > len(requests) {
		n = len(requests)
	}
	
	result := make([]*ScoringRequest, n)
	copy(result, requests[:n])
	return result
}

// GetAverageScore 获取平均评分
func (wq *WeightedQueue) GetAverageScore() float64 {
	if len(wq.requests) == 0 {
		return 0.0
	}
	
	total := 0.0
	for _, req := range wq.requests {
		total += req.Score
	}
	
	return total / float64(len(wq.requests))
}