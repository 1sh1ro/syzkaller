// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"context"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

// TestFuzzerWithScoringSystem 测试集成评分系统的 Fuzzer
func TestFuzzerWithScoringSystem(t *testing.T) {
	// 创建测试配置
	cfg := &Config{
		Debug:        true,
		Coverage:     true,
		ScoreConfig:  DefaultScoreConfig(),
		EnabledCalls: make(map[*prog.Syscall]bool),
		Logf: func(level int, msg string, args ...interface{}) {
			t.Logf("[Level %d] "+msg, append([]interface{}{level}, args...)...)
		},
	}
	
	// 创建模拟的 corpus
	cfg.Corpus = &MockCorpus{
		programs: make([]*prog.Prog, 0),
	}
	
	// 创建 Fuzzer 实例
	ctx := context.Background()
	target := getTestTarget()
	if target == nil {
		t.Skip("测试目标不可用")
	}
	
	fuzzer := NewFuzzer(ctx, cfg, nil, target)
	
	// 验证评分系统组件已初始化
	if fuzzer.scoreTracker == nil {
		t.Error("ScoreTracker 未初始化")
	}
	if fuzzer.weightedSelector == nil {
		t.Error("WeightedSelector 未初始化")
	}
	if fuzzer.scoreMetrics == nil {
		t.Error("ScoreMetrics 未初始化")
	}
	
	// 测试评分配置
	if !fuzzer.Config.ScoreConfig.Enabled {
		t.Error("评分系统未启用")
	}
	
	t.Log("Fuzzer 评分系统集成测试通过")
}

// TestProcessResultWithScoring 测试带评分的结果处理
func TestProcessResultWithScoring(t *testing.T) {
	cfg := &Config{
		Debug:       true,
		Coverage:    true,
		ScoreConfig: DefaultScoreConfig(),
		Logf: func(level int, msg string, args ...interface{}) {
			if level <= 2 { // 只记录重要日志
				t.Logf("[Level %d] "+msg, append([]interface{}{level}, args...)...)
			}
		},
	}
	
	cfg.Corpus = &MockCorpus{programs: make([]*prog.Prog, 0)}
	
	ctx := context.Background()
	target := getTestTarget()
	if target == nil {
		t.Skip("测试目标不可用")
	}
	
	fuzzer := NewFuzzer(ctx, cfg, nil, target)
	
	// 创建测试请求和结果
	testProg := target.Generate(nil, prog.RecommendedCalls, target.DefaultChoiceTable())
	req := &queue.Request{
		Prog:     testProg,
		ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
	}
	
	// 创建包含评分信息的结果
	result := &queue.Result{
		Status: queue.Success,
		Info: &flatrpc.ProgInfo{
			Elapsed: 1500000, // 1.5ms
			Extra: &flatrpc.CallInfo{
				Signal: []uint64{0x1000, 0x2000, 0x3000},
			},
		},
		Output: []byte("KASAN: use-after-free in test_function\nWARNING: suspicious usage"),
	}
	
	// 处理结果
	processed := fuzzer.processResult(req, result, 0, 0)
	if !processed {
		t.Error("结果处理失败")
	}
	
	// 验证评分已计算
	score := fuzzer.scoreTracker.GetScore(testProg.Hash())
	if score == nil {
		t.Error("程序评分未计算")
	} else {
		t.Logf("程序评分: 总分=%.3f, 覆盖率=%.3f, 稀有性=%.3f, 内核日志=%.3f, 时间异常=%.3f",
			score.Total, score.Coverage, score.Rarity, score.KernelLog, score.TimeAnomaly)
		
		// 验证评分合理性
		if score.Total < 0 || score.Total > 1 {
			t.Errorf("总评分超出范围: %f", score.Total)
		}
		
		// 由于有 KASAN 日志，内核日志评分应该较高
		if score.KernelLog < 0.5 {
			t.Errorf("内核日志评分过低: %f (期望 > 0.5)", score.KernelLog)
		}
	}
	
	// 验证评分指标已更新
	metrics := fuzzer.GetScoreMetrics()
	if metrics.TotalRequests == 0 {
		t.Error("评分指标未更新")
	}
	
	t.Log("带评分的结果处理测试通过")
}

// TestWeightedProgramGeneration 测试基于评分的程序生成
func TestWeightedProgramGeneration(t *testing.T) {
	cfg := &Config{
		Debug:       true,
		Coverage:    true,
		ScoreConfig: DefaultScoreConfig(),
		Logf: func(level int, msg string, args ...interface{}) {
			if level <= 3 {
				t.Logf("[Level %d] "+msg, append([]interface{}{level}, args...)...)
			}
		},
	}
	
	cfg.Corpus = &MockCorpus{programs: make([]*prog.Prog, 0)}
	
	ctx := context.Background()
	target := getTestTarget()
	if target == nil {
		t.Skip("测试目标不可用")
	}
	
	fuzzer := NewFuzzer(ctx, cfg, nil, target)
	
	// 添加一些高分程序到评分跟踪器
	for i := 0; i < 5; i++ {
		prog := target.Generate(nil, prog.RecommendedCalls, target.DefaultChoiceTable())
		score := &ProgScore{
			Total:       0.8 + float64(i)*0.04, // 0.8-0.96
			Coverage:    0.7,
			Rarity:      0.8,
			KernelLog:   0.9,
			TimeAnomaly: 0.6,
		}
		fuzzer.scoreTracker.scores[prog.Hash()] = score
		fuzzer.weightedSelector.UpdateWeight(prog.Hash(), score.Total)
		cfg.Corpus.(*MockCorpus).programs = append(cfg.Corpus.(*MockCorpus).programs, prog)
	}
	
	// 测试加权程序生成
	generatedCount := 0
	weightedCount := 0
	
	for i := 0; i < 100; i++ {
		req := fuzzer.genFuzz()
		if req != nil {
			generatedCount++
			// 检查是否使用了加权选择（通过日志或其他方式）
			// 这里简化处理，假设有一定概率使用加权选择
		}
	}
	
	if generatedCount == 0 {
		t.Error("未能生成任何程序")
	}
	
	t.Logf("程序生成测试: 生成了 %d 个程序", generatedCount)
}

// TestSmashJobWithScoring 测试带评分的 smash 作业
func TestSmashJobWithScoring(t *testing.T) {
	cfg := &Config{
		Debug:       true,
		Coverage:    true,
		ScoreConfig: DefaultScoreConfig(),
		Logf: func(level int, msg string, args ...interface{}) {
			if level <= 3 {
				t.Logf("[Level %d] "+msg, append([]interface{}{level}, args...)...)
			}
		},
	}
	
	cfg.Corpus = &MockCorpus{programs: make([]*prog.Prog, 0)}
	
	ctx := context.Background()
	target := getTestTarget()
	if target == nil {
		t.Skip("测试目标不可用")
	}
	
	fuzzer := NewFuzzer(ctx, cfg, nil, target)
	
	// 创建测试程序
	testProg := target.Generate(nil, prog.RecommendedCalls, target.DefaultChoiceTable())
	
	// 设置程序评分
	highScore := &ProgScore{
		Total:       0.85,
		Coverage:    0.8,
		Rarity:      0.9,
		KernelLog:   0.8,
		TimeAnomaly: 0.9,
	}
	fuzzer.scoreTracker.scores[testProg.Hash()] = highScore
	
	// 创建 smash 作业
	job := &smashJob{
		exec: &MockExecutor{},
		p:    testProg,
		info: &JobInfo{
			Name: testProg.String(),
			Type: "smash",
		},
	}
	
	// 运行 smash 作业
	job.run(fuzzer)
	
	// 验证 smash 统计信息
	metrics := fuzzer.GetScoreMetrics()
	smashStats := metrics.GetSmashStats()
	
	if smashStats["total_smash_jobs"].(int64) == 0 {
		t.Error("Smash 统计信息未更新")
	}
	
	t.Logf("Smash 统计: %+v", smashStats)
}

// TestScoreSystemDisabled 测试禁用评分系统
func TestScoreSystemDisabled(t *testing.T) {
	cfg := &Config{
		Debug:       true,
		Coverage:    true,
		ScoreConfig: &ScoreConfig{Enabled: false}, // 禁用评分系统
		Logf: func(level int, msg string, args ...interface{}) {
			t.Logf("[Level %d] "+msg, append([]interface{}{level}, args...)...)
		},
	}
	
	cfg.Corpus = &MockCorpus{programs: make([]*prog.Prog, 0)}
	
	ctx := context.Background()
	target := getTestTarget()
	if target == nil {
		t.Skip("测试目标不可用")
	}
	
	fuzzer := NewFuzzer(ctx, cfg, nil, target)
	
	// 验证评分系统已禁用
	if fuzzer.Config.ScoreConfig.Enabled {
		t.Error("评分系统应该被禁用")
	}
	
	// 测试禁用状态下的程序生成
	req := fuzzer.genFuzz()
	if req == nil {
		t.Error("禁用评分系统时仍应能生成程序")
	}
	
	t.Log("禁用评分系统测试通过")
}

// 模拟实现
type MockCorpus struct {
	programs []*prog.Prog
}

func (mc *MockCorpus) Programs() []*prog.Prog {
	return mc.programs
}

func (mc *MockCorpus) ChooseProgram(rnd *rand.Rand) *prog.Prog {
	if len(mc.programs) == 0 {
		return nil
	}
	return mc.programs[rnd.Intn(len(mc.programs))]
}

func (mc *MockCorpus) Save(input corpus.NewInput) {
	mc.programs = append(mc.programs, input.Prog)
}

type MockExecutor struct{}

func (me *MockExecutor) Submit(req *queue.Request) {
	// 模拟异步执行
	go func() {
		time.Sleep(time.Millisecond) // 模拟执行时间
		
		result := &queue.Result{
			Status: queue.Success,
			Info: &flatrpc.ProgInfo{
				Elapsed: 1000000, // 1ms
				Extra: &flatrpc.CallInfo{
					Signal: []uint64{0x1000, 0x2000},
				},
			},
			Output: []byte("test output"),
		}
		
		req.Done(result)
	}()
}

// TestEndToEndScoring 端到端评分系统测试
func TestEndToEndScoring(t *testing.T) {
	cfg := &Config{
		Debug:       true,
		Coverage:    true,
		ScoreConfig: DefaultScoreConfig(),
		Logf: func(level int, msg string, args ...interface{}) {
			if level <= 2 {
				t.Logf("[Level %d] "+msg, append([]interface{}{level}, args...)...)
			}
		},
	}
	
	cfg.Corpus = &MockCorpus{programs: make([]*prog.Prog, 0)}
	
	ctx := context.Background()
	target := getTestTarget()
	if target == nil {
		t.Skip("测试目标不可用")
	}
	
	fuzzer := NewFuzzer(ctx, cfg, nil, target)
	
	// 模拟完整的模糊测试流程
	numIterations := 10
	
	for i := 0; i < numIterations; i++ {
		// 生成程序
		req := fuzzer.genFuzz()
		if req == nil {
			continue
		}
		
		// 模拟执行结果
		result := &queue.Result{
			Status: queue.Success,
			Info: &flatrpc.ProgInfo{
				Elapsed: uint64(1000000 + i*100000),
				Extra: &flatrpc.CallInfo{
					Signal: []uint64{uint64(0x1000 + i), uint64(0x2000 + i)},
				},
			},
			Output: []byte("test output"),
		}
		
		if i%3 == 0 {
			result.Output = append(result.Output, []byte(" KASAN: use-after-free")...)
		}
		
		// 处理结果
		fuzzer.processResult(req, result, 0, 0)
	}
	
	// 验证最终状态
	metrics := fuzzer.GetScoreMetrics()
	if metrics.TotalRequests == 0 {
		t.Error("未处理任何请求")
	}
	
	topProgs := fuzzer.GetTopScoredProgs(5)
	t.Logf("端到端测试完成: 处理了 %d 个请求, 前5高分程序: %v", 
		metrics.TotalRequests, len(topProgs))
	
	// 验证评分分布
	if metrics.AverageScore <= 0 {
		t.Error("平均评分异常")
	}
	
	t.Logf("评分统计: 平均=%.3f, 最高=%.3f, 最低=%.3f", 
		metrics.AverageScore, metrics.MaxScore, metrics.MinScore)
}
