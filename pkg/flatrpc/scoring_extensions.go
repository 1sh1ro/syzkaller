// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package flatrpc

import (
	"time"
)

// ScoringProgInfo 扩展 ProgInfo，添加评分相关字段
type ScoringProgInfo struct {
	*ProgInfo
	
	// 程序评分
	Score float64 `json:"score"`
	
	// 评分详细信息
	CoverageScore   float64 `json:"coverage_score"`
	RarityScore     float64 `json:"rarity_score"`
	KernelLogScore  float64 `json:"kernel_log_score"`
	TimeAnomalyScore float64 `json:"time_anomaly_score"`
	
	// 评分时间戳
	ScoreTimestamp time.Time `json:"score_timestamp"`
	
	// 内核日志内容
	KernelLogs []string `json:"kernel_logs"`
	
	// 新覆盖的PC数量
	NewPCCount int `json:"new_pc_count"`
	
	// 路径稀有性信息
	PathFrequency int64 `json:"path_frequency"`
	
	// 执行时间异常信息
	TimeAnomalyZScore float64 `json:"time_anomaly_z_score"`
}

// NewScoringProgInfo 创建带评分的程序信息
func NewScoringProgInfo(progInfo *ProgInfo) *ScoringProgInfo {
	return &ScoringProgInfo{
		ProgInfo:         progInfo,
		Score:            0.0,
		CoverageScore:    0.0,
		RarityScore:      0.0,
		KernelLogScore:   0.0,
		TimeAnomalyScore: 0.0,
		ScoreTimestamp:   time.Now(),
		KernelLogs:       make([]string, 0),
		NewPCCount:       0,
		PathFrequency:    0,
		TimeAnomalyZScore: 0.0,
	}
}

// UpdateScore 更新评分信息
func (spi *ScoringProgInfo) UpdateScore(
	totalScore, coverageScore, rarityScore, kernelLogScore, timeAnomalyScore float64) {
	spi.Score = totalScore
	spi.CoverageScore = coverageScore
	spi.RarityScore = rarityScore
	spi.KernelLogScore = kernelLogScore
	spi.TimeAnomalyScore = timeAnomalyScore
	spi.ScoreTimestamp = time.Now()
}

// SetKernelLogs 设置内核日志
func (spi *ScoringProgInfo) SetKernelLogs(logs []string) {
	spi.KernelLogs = logs
}

// SetNewPCCount 设置新PC数量
func (spi *ScoringProgInfo) SetNewPCCount(count int) {
	spi.NewPCCount = count
}

// SetPathFrequency 设置路径频率
func (spi *ScoringProgInfo) SetPathFrequency(frequency int64) {
	spi.PathFrequency = frequency
}

// SetTimeAnomalyInfo 设置时间异常信息
func (spi *ScoringProgInfo) SetTimeAnomalyInfo(zScore float64) {
	spi.TimeAnomalyZScore = zScore
}

// Clone 克隆评分程序信息
func (spi *ScoringProgInfo) Clone() *ScoringProgInfo {
	if spi == nil {
		return nil
	}
	
	cloned := &ScoringProgInfo{
		ProgInfo:          spi.ProgInfo.Clone(),
		Score:             spi.Score,
		CoverageScore:     spi.CoverageScore,
		RarityScore:       spi.RarityScore,
		KernelLogScore:    spi.KernelLogScore,
		TimeAnomalyScore:  spi.TimeAnomalyScore,
		ScoreTimestamp:    spi.ScoreTimestamp,
		NewPCCount:        spi.NewPCCount,
		PathFrequency:     spi.PathFrequency,
		TimeAnomalyZScore: spi.TimeAnomalyZScore,
	}
	
	// 克隆内核日志
	if len(spi.KernelLogs) > 0 {
		cloned.KernelLogs = make([]string, len(spi.KernelLogs))
		copy(cloned.KernelLogs, spi.KernelLogs)
	}
	
	return cloned
}

// ScoringExecResult 扩展 ExecResult，添加评分相关字段
type ScoringExecResult struct {
	*ExecResult
	
	// 评分信息
	ScoringInfo *ScoringProgInfo `json:"scoring_info"`
	
	// 是否计算了评分
	ScoreCalculated bool `json:"score_calculated"`
	
	// 评分计算耗时 (纳秒)
	ScoreCalculationTime int64 `json:"score_calculation_time"`
}

// NewScoringExecResult 创建带评分的执行结果
func NewScoringExecResult(execResult *ExecResult) *ScoringExecResult {
	scoringInfo := NewScoringProgInfo(execResult.Info)
	
	return &ScoringExecResult{
		ExecResult:           execResult,
		ScoringInfo:          scoringInfo,
		ScoreCalculated:      false,
		ScoreCalculationTime: 0,
	}
}

// SetScoreCalculated 设置评分计算状态
func (ser *ScoringExecResult) SetScoreCalculated(calculated bool, calculationTime int64) {
	ser.ScoreCalculated = calculated
	ser.ScoreCalculationTime = calculationTime
}

// GetScore 获取总评分
func (ser *ScoringExecResult) GetScore() float64 {
	if ser.ScoringInfo != nil {
		return ser.ScoringInfo.Score
	}
	return 0.0
}

// Clone 克隆评分执行结果
func (ser *ScoringExecResult) Clone() *ScoringExecResult {
	if ser == nil {
		return nil
	}
	
	// 克隆基础执行结果
	clonedExecResult := &ExecResult{
		Id:     ser.ExecResult.Id,
		Proc:   ser.ExecResult.Proc,
		Hanged: ser.ExecResult.Hanged,
		Error:  ser.ExecResult.Error,
		Info:   ser.ExecResult.Info.Clone(),
	}
	
	// 克隆输出
	if len(ser.ExecResult.Output) > 0 {
		clonedExecResult.Output = make([]byte, len(ser.ExecResult.Output))
		copy(clonedExecResult.Output, ser.ExecResult.Output)
	}
	
	return &ScoringExecResult{
		ExecResult:           clonedExecResult,
		ScoringInfo:          ser.ScoringInfo.Clone(),
		ScoreCalculated:      ser.ScoreCalculated,
		ScoreCalculationTime: ser.ScoreCalculationTime,
	}
}

// ScoreMetrics 评分指标统计
type ScoreMetrics struct {
	// 总请求数
	TotalRequests int64 `json:"total_requests"`
	
	// 基于评分选择的请求数
	ScoreSelectedRequests int64 `json:"score_selected_requests"`
	
	// 平均评分
	AverageScore float64 `json:"average_score"`
	
	// 最高评分
	MaxScore float64 `json:"max_score"`
	
	// 最低评分
	MinScore float64 `json:"min_score"`
	
	// 各维度平均分数
	AvgCoverageScore   float64 `json:"avg_coverage_score"`
	AvgRarityScore     float64 `json:"avg_rarity_score"`
	AvgKernelLogScore  float64 `json:"avg_kernel_log_score"`
	AvgTimeAnomalyScore float64 `json:"avg_time_anomaly_score"`
	
	// 评分计算总耗时 (纳秒)
	TotalScoreCalculationTime int64 `json:"total_score_calculation_time"`
	
	// Smash 统计信息
	TotalSmashJobs        int64   `json:"total_smash_jobs"`
	TotalSmashMutations   int64   `json:"total_smash_mutations"`
	SuccessfulMutations   int64   `json:"successful_mutations"`
	AverageSmashBaseScore float64 `json:"average_smash_base_score"`
	
	// 最后更新时间
	LastUpdated time.Time `json:"last_updated"`
}

// NewScoreMetrics 创建评分指标
func NewScoreMetrics() *ScoreMetrics {
	return &ScoreMetrics{
		LastUpdated: time.Now(),
		MinScore:    1.0, // 初始化为最大值，便于后续比较
	}
}

// UpdateMetrics 更新评分指标
func (sm *ScoreMetrics) UpdateMetrics(score float64, scoreSelected bool, calculationTime int64) {
	sm.TotalRequests++
	
	if scoreSelected {
		sm.ScoreSelectedRequests++
	}
	
	// 更新平均分数
	if sm.TotalRequests == 1 {
		sm.AverageScore = score
		sm.MaxScore = score
		sm.MinScore = score
	} else {
		sm.AverageScore = (sm.AverageScore*float64(sm.TotalRequests-1) + score) / float64(sm.TotalRequests)
		if score > sm.MaxScore {
			sm.MaxScore = score
		}
		if score < sm.MinScore {
			sm.MinScore = score
		}
	}
	
	sm.TotalScoreCalculationTime += calculationTime
	sm.LastUpdated = time.Now()
}

// UpdateDimensionScores 更新各维度分数
func (sm *ScoreMetrics) UpdateDimensionScores(coverage, rarity, kernelLog, timeAnomaly float64) {
	if sm.TotalRequests == 1 {
		sm.AvgCoverageScore = coverage
		sm.AvgRarityScore = rarity
		sm.AvgKernelLogScore = kernelLog
		sm.AvgTimeAnomalyScore = timeAnomaly
	} else {
		count := float64(sm.TotalRequests)
		sm.AvgCoverageScore = (sm.AvgCoverageScore*(count-1) + coverage) / count
		sm.AvgRarityScore = (sm.AvgRarityScore*(count-1) + rarity) / count
		sm.AvgKernelLogScore = (sm.AvgKernelLogScore*(count-1) + kernelLog) / count
		sm.AvgTimeAnomalyScore = (sm.AvgTimeAnomalyScore*(count-1) + timeAnomaly) / count
	}
}

// GetScoreSelectionRatio 获取基于评分选择的比例
func (sm *ScoreMetrics) GetScoreSelectionRatio() float64 {
	if sm.TotalRequests == 0 {
		return 0.0
	}
	return float64(sm.ScoreSelectedRequests) / float64(sm.TotalRequests)
}

// GetAverageCalculationTime 获取平均评分计算时间
func (sm *ScoreMetrics) GetAverageCalculationTime() float64 {
	if sm.TotalRequests == 0 {
		return 0.0
	}
	return float64(sm.TotalScoreCalculationTime) / float64(sm.TotalRequests)
}

// UpdateSmashStats 更新 smash 统计信息
func (sm *ScoreMetrics) UpdateSmashStats(successfulMutations, totalMutations int, baseScore float64) {
	sm.TotalSmashJobs++
	sm.TotalSmashMutations += int64(totalMutations)
	sm.SuccessfulMutations += int64(successfulMutations)
	
	// 更新平均基准分数
	if sm.TotalSmashJobs == 1 {
		sm.AverageSmashBaseScore = baseScore
	} else {
		count := float64(sm.TotalSmashJobs)
		sm.AverageSmashBaseScore = (sm.AverageSmashBaseScore*(count-1) + baseScore) / count
	}
	
	sm.LastUpdated = time.Now()
}

// GetSmashSuccessRate 获取 smash 成功率
func (sm *ScoreMetrics) GetSmashSuccessRate() float64 {
	if sm.TotalSmashMutations == 0 {
		return 0.0
	}
	return float64(sm.SuccessfulMutations) / float64(sm.TotalSmashMutations)
}

// GetAverageSmashMutationsPerJob 获取每个 smash 作业的平均变异次数
func (sm *ScoreMetrics) GetAverageSmashMutationsPerJob() float64 {
	if sm.TotalSmashJobs == 0 {
		return 0.0
	}
	return float64(sm.TotalSmashMutations) / float64(sm.TotalSmashJobs)
}

// GetSmashStats 获取 smash 统计摘要
func (sm *ScoreMetrics) GetSmashStats() map[string]interface{} {
	return map[string]interface{}{
		"total_smash_jobs":              sm.TotalSmashJobs,
		"total_mutations":               sm.TotalSmashMutations,
		"successful_mutations":          sm.SuccessfulMutations,
		"success_rate":                  sm.GetSmashSuccessRate(),
		"avg_mutations_per_job":         sm.GetAverageSmashMutationsPerJob(),
		"avg_base_score":                sm.AverageSmashBaseScore,
	}
}
