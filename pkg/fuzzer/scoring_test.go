// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

func TestScoreTracker(t *testing.T) {
	config := DefaultScoreConfig()
	tracker := NewScoreTracker(config)
	
	// 创建测试程序
	target := getTestTarget()
	p := target.Generate(nil, prog.RecommendedCalls, target.DefaultChoiceTable())
	
	// 创建测试执行结果
	execResult := &ExecutionResult{
		Signal:     signal.Signal{},
		ExecTime:   1000000, // 1ms
		KernelLogs: []string{"KASAN: use-after-free"},
		Crashed:    false,
		Error:      "",
	}
	
	// 测试评分计算
	score := tracker.UpdateScore(p, execResult)
	if score == nil {
		t.Fatal("评分计算失败")
	}
	
	if score.Total < 0 || score.Total > 1 {
		t.Errorf("总评分超出范围 [0,1]: %f", score.Total)
	}
	
	// 验证各维度评分
	if score.Coverage < 0 || score.Coverage > 1 {
		t.Errorf("覆盖率评分超出范围: %f", score.Coverage)
	}
	if score.Rarity < 0 || score.Rarity > 1 {
		t.Errorf("稀有性评分超出范围: %f", score.Rarity)
	}
	if score.KernelLog < 0 || score.KernelLog > 1 {
		t.Errorf("内核日志评分超出范围: %f", score.KernelLog)
	}
	if score.TimeAnomaly < 0 || score.TimeAnomaly > 1 {
		t.Errorf("时间异常评分超出范围: %f", score.TimeAnomaly)
	}
	
	// 测试评分缓存
	cachedScore := tracker.GetScore(p.Hash())
	if cachedScore == nil {
		t.Error("评分缓存失败")
	}
	if cachedScore.Total != score.Total {
		t.Errorf("缓存评分不匹配: 期望 %f, 实际 %f", score.Total, cachedScore.Total)
	}
}

func TestWeightedSelector(t *testing.T) {
	selector := NewWeightedSelector()
	
	// 添加测试权重
	hashes := []string{"hash1", "hash2", "hash3"}
	weights := []float64{0.1, 0.5, 0.9}
	
	for i, hash := range hashes {
		selector.UpdateWeight(hash, weights[i])
	}
	
	// 测试加权选择
	selections := make(map[string]int)
	totalSelections := 1000
	
	for i := 0; i < totalSelections; i++ {
		selected := selector.WeightedSelect(hashes)
		if selected == "" {
			t.Error("加权选择返回空值")
			continue
		}
		selections[selected]++
	}
	
	// 验证选择分布 - 高权重应该被选择更多次
	if selections["hash3"] <= selections["hash1"] {
		t.Error("高权重项目未被优先选择")
	}
	
	t.Logf("选择分布: %v", selections)
}

func TestKernelLogMatcher(t *testing.T) {
	matcher := NewKernelLogMatcher()
	
	testCases := []struct {
		log      string
		expected float64
	}{
		{"KASAN: use-after-free", 0.9},
		{"WARNING: suspicious RCU usage", 0.7},
		{"ERROR: AddressSanitizer", 0.8},
		{"kernel BUG at", 0.95},
		{"normal log message", 0.0},
		{"", 0.0},
	}
	
	for _, tc := range testCases {
		score := matcher.CalculateScore([]string{tc.log})
		if score != tc.expected {
			t.Errorf("日志 '%s' 评分错误: 期望 %f, 实际 %f", tc.log, tc.expected, score)
		}
	}
	
	// 测试多条日志
	multiLogs := []string{
		"KASAN: use-after-free",
		"WARNING: suspicious RCU usage",
	}
	score := matcher.CalculateScore(multiLogs)
	if score <= 0.7 { // 应该取最高分
		t.Errorf("多条日志评分过低: %f", score)
	}
}

func TestTimeStats(t *testing.T) {
	stats := NewTimeStats()
	
	// 添加测试数据
	times := []uint64{1000, 1100, 900, 1200, 800, 1300, 950}
	for _, time := range times {
		stats.AddTime(time)
	}
	
	// 测试异常检测
	normalTime := uint64(1000)
	anomalyTime := uint64(5000) // 明显异常
	
	normalScore := stats.CalculateAnomalyScore(normalTime)
	anomalyScore := stats.CalculateAnomalyScore(anomalyTime)
	
	if anomalyScore <= normalScore {
		t.Errorf("异常时间未被正确检测: 正常=%f, 异常=%f", normalScore, anomalyScore)
	}
	
	// 测试统计信息
	mean := stats.GetMean()
	stddev := stats.GetStdDev()
	
	if mean <= 0 || stddev < 0 {
		t.Errorf("统计信息错误: 均值=%f, 标准差=%f", mean, stddev)
	}
	
	t.Logf("时间统计: 均值=%f, 标准差=%f", mean, stddev)
}

func TestScoreConfig(t *testing.T) {
	config := DefaultScoreConfig()
	
	// 验证默认配置
	if !config.Enabled {
		t.Error("默认配置应该启用评分系统")
	}
	
	// 验证权重总和
	totalWeight := config.CoverageWeight + config.RarityWeight + 
		config.KernelLogWeight + config.TimeAnomalyWeight
	
	if totalWeight != 1.0 {
		t.Errorf("权重总和应为1.0, 实际为 %f", totalWeight)
	}
	
	// 测试配置验证
	invalidConfig := &ScoreConfig{
		Enabled:           true,
		CoverageWeight:    -0.1, // 无效权重
		RarityWeight:      0.3,
		KernelLogWeight:   0.4,
		TimeAnomalyWeight: 0.4,
	}
	
	if err := invalidConfig.Validate(); err == nil {
		t.Error("无效配置应该返回错误")
	}
}

func BenchmarkScoreCalculation(b *testing.B) {
	config := DefaultScoreConfig()
	tracker := NewScoreTracker(config)
	
	target := getTestTarget()
	p := target.Generate(nil, prog.RecommendedCalls, target.DefaultChoiceTable())
	
	execResult := &ExecutionResult{
		Signal:     signal.Signal{},
		ExecTime:   1000000,
		KernelLogs: []string{"KASAN: use-after-free", "WARNING: test"},
		Crashed:    false,
		Error:      "",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tracker.UpdateScore(p, execResult)
	}
}

func BenchmarkWeightedSelection(b *testing.B) {
	selector := NewWeightedSelector()
	
	// 准备测试数据
	hashes := make([]string, 100)
	for i := 0; i < 100; i++ {
		hash := string(rune('a' + i%26)) + string(rune('0' + i%10))
		hashes[i] = hash
		selector.UpdateWeight(hash, float64(i%10)/10.0)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		selector.WeightedSelect(hashes)
	}
}

func TestScoreSystemIntegration(t *testing.T) {
	// 集成测试：测试整个评分系统的协同工作
	config := DefaultScoreConfig()
	tracker := NewScoreTracker(config)
	selector := NewWeightedSelector()
	
	target := getTestTarget()
	
	// 生成多个测试程序
	programs := make([]*prog.Prog, 10)
	for i := 0; i < 10; i++ {
		programs[i] = target.Generate(nil, prog.RecommendedCalls, target.DefaultChoiceTable())
	}
	
	// 为每个程序计算评分
	scores := make([]*ProgScore, 10)
	for i, p := range programs {
		execResult := &ExecutionResult{
			Signal:     signal.Signal{},
			ExecTime:   uint64(1000000 + i*100000), // 递增执行时间
			KernelLogs: []string{},
			Crashed:    i%3 == 0, // 部分程序崩溃
			Error:      "",
		}
		
		// 为部分程序添加内核日志
		if i%2 == 0 {
			execResult.KernelLogs = append(execResult.KernelLogs, "KASAN: use-after-free")
		}
		
		scores[i] = tracker.UpdateScore(p, execResult)
		selector.UpdateWeight(p.Hash(), scores[i].Total)
	}
	
	// 验证评分分布
	var totalScore float64
	for _, score := range scores {
		totalScore += score.Total
	}
	avgScore := totalScore / float64(len(scores))
	
	if avgScore <= 0 || avgScore >= 1 {
		t.Errorf("平均评分异常: %f", avgScore)
	}
	
	// 测试加权选择
	hashes := make([]string, len(programs))
	for i, p := range programs {
		hashes[i] = p.Hash()
	}
	
	selected := selector.WeightedSelect(hashes)
	if selected == "" {
		t.Error("加权选择失败")
	}
	
	t.Logf("集成测试完成: 平均评分=%f, 选择程序=%s", avgScore, selected)
}

// 辅助函数
func getTestTarget() *prog.Target {
	// 这里应该返回一个测试用的 target
	// 实际实现中需要根据 syzkaller 的测试框架来获取
	return nil // 占位符
}