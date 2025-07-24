// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"context"
	"fmt"
	"math/rand"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/signal"
)

// TestScoreSystemPerformance 测试评分系统性能影响
func TestScoreSystemPerformance(t *testing.T) {
	// 测试配置
	numPrograms := 1000
	numWorkers := runtime.NumCPU()
	
	// 创建评分系统
	config := DefaultScoreConfig()
	tracker := NewScoreTracker(config)
	selector := NewWeightedSelector()
	
	t.Logf("开始性能测试: %d 个程序, %d 个工作线程", numPrograms, numWorkers)
	
	// 准备测试数据
	programs := make([]*TestProgram, numPrograms)
	for i := 0; i < numPrograms; i++ {
		programs[i] = &TestProgram{
			Hash:    fmt.Sprintf("prog_%d", i),
			Content: fmt.Sprintf("test_program_%d", i),
		}
	}
	
	// 测试并发评分计算
	start := time.Now()
	var wg sync.WaitGroup
	
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			
			for j := workerID; j < numPrograms; j += numWorkers {
				prog := programs[j]
				execResult := &ExecutionResult{
					Signal:     signal.Signal{},
					ExecTime:   uint64(1000000 + rand.Intn(500000)),
					KernelLogs: generateRandomKernelLogs(),
					Crashed:    rand.Intn(10) == 0,
					Error:      "",
				}
				
				score := tracker.UpdateScore(prog, execResult)
				selector.UpdateWeight(prog.Hash, score.Total)
			}
		}(i)
	}
	
	wg.Wait()
	duration := time.Since(start)
	
	// 计算性能指标
	programsPerSecond := float64(numPrograms) / duration.Seconds()
	avgTimePerProgram := duration.Nanoseconds() / int64(numPrograms)
	
	t.Logf("并发评分性能:")
	t.Logf("  总时间: %v", duration)
	t.Logf("  程序/秒: %.2f", programsPerSecond)
	t.Logf("  平均每程序: %d ns", avgTimePerProgram)
	
	// 性能阈值检查
	if programsPerSecond < 100 {
		t.Errorf("评分性能过低: %.2f 程序/秒 (期望 > 100)", programsPerSecond)
	}
	
	// 测试加权选择性能
	hashes := make([]string, numPrograms)
	for i, prog := range programs {
		hashes[i] = prog.Hash
	}
	
	selectionStart := time.Now()
	numSelections := 10000
	
	for i := 0; i < numSelections; i++ {
		selector.WeightedSelect(hashes)
	}
	
	selectionDuration := time.Since(selectionStart)
	selectionsPerSecond := float64(numSelections) / selectionDuration.Seconds()
	
	t.Logf("加权选择性能:")
	t.Logf("  选择/秒: %.2f", selectionsPerSecond)
	
	if selectionsPerSecond < 1000 {
		t.Errorf("选择性能过低: %.2f 选择/秒 (期望 > 1000)", selectionsPerSecond)
	}
}

// TestMemoryUsage 测试内存使用情况
func TestMemoryUsage(t *testing.T) {
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)
	
	// 创建大量评分数据
	config := DefaultScoreConfig()
	tracker := NewScoreTracker(config)
	selector := NewWeightedSelector()
	
	numPrograms := 10000
	for i := 0; i < numPrograms; i++ {
		prog := &TestProgram{
			Hash:    fmt.Sprintf("prog_%d", i),
			Content: fmt.Sprintf("test_program_%d", i),
		}
		
		execResult := &ExecutionResult{
			Signal:     signal.Signal{},
			ExecTime:   uint64(1000000 + i*1000),
			KernelLogs: []string{"test log"},
			Crashed:    false,
			Error:      "",
		}
		
		score := tracker.UpdateScore(prog, execResult)
		selector.UpdateWeight(prog.Hash, score.Total)
	}
	
	runtime.GC()
	runtime.ReadMemStats(&m2)
	
	memoryUsed := m2.Alloc - m1.Alloc
	memoryPerProgram := memoryUsed / uint64(numPrograms)
	
	t.Logf("内存使用情况:")
	t.Logf("  总内存: %d bytes", memoryUsed)
	t.Logf("  每程序: %d bytes", memoryPerProgram)
	
	// 内存使用阈值检查 (每个程序不应超过 1KB)
	if memoryPerProgram > 1024 {
		t.Errorf("内存使用过高: %d bytes/程序 (期望 < 1024)", memoryPerProgram)
	}
}

// TestConcurrentAccess 测试并发访问安全性
func TestConcurrentAccess(t *testing.T) {
	config := DefaultScoreConfig()
	tracker := NewScoreTracker(config)
	selector := NewWeightedSelector()
	
	numWorkers := 10
	numOperations := 1000
	
	var wg sync.WaitGroup
	errors := make(chan error, numWorkers*numOperations)
	
	// 并发读写测试
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			
			for j := 0; j < numOperations; j++ {
				prog := &TestProgram{
					Hash:    fmt.Sprintf("worker_%d_prog_%d", workerID, j),
					Content: fmt.Sprintf("content_%d_%d", workerID, j),
				}
				
				execResult := &ExecutionResult{
					Signal:     signal.Signal{},
					ExecTime:   uint64(1000000 + j*1000),
					KernelLogs: []string{},
					Crashed:    false,
					Error:      "",
				}
				
				// 写操作
				score := tracker.UpdateScore(prog, execResult)
				selector.UpdateWeight(prog.Hash, score.Total)
				
				// 读操作
				cachedScore := tracker.GetScore(prog.Hash)
				if cachedScore == nil {
					errors <- fmt.Errorf("worker %d: 无法获取评分", workerID)
					continue
				}
				
				// 选择操作
				hashes := []string{prog.Hash}
				selected := selector.WeightedSelect(hashes)
				if selected == "" {
					errors <- fmt.Errorf("worker %d: 选择失败", workerID)
				}
			}
		}(i)
	}
	
	wg.Wait()
	close(errors)
	
	// 检查错误
	errorCount := 0
	for err := range errors {
		t.Error(err)
		errorCount++
	}
	
	if errorCount > 0 {
		t.Errorf("并发访问测试失败: %d 个错误", errorCount)
	} else {
		t.Log("并发访问测试通过")
	}
}

// TestScoreSystemOverhead 测试评分系统开销
func TestScoreSystemOverhead(t *testing.T) {
	numPrograms := 1000
	
	// 测试不启用评分系统的性能
	disabledConfig := &ScoreConfig{Enabled: false}
	disabledTracker := NewScoreTracker(disabledConfig)
	
	start := time.Now()
	for i := 0; i < numPrograms; i++ {
		prog := &TestProgram{
			Hash:    fmt.Sprintf("prog_%d", i),
			Content: fmt.Sprintf("content_%d", i),
		}
		
		execResult := &ExecutionResult{
			Signal:     signal.Signal{},
			ExecTime:   uint64(1000000 + i*1000),
			KernelLogs: []string{},
			Crashed:    false,
			Error:      "",
		}
		
		disabledTracker.UpdateScore(prog, execResult)
	}
	disabledDuration := time.Since(start)
	
	// 测试启用评分系统的性能
	enabledConfig := DefaultScoreConfig()
	enabledTracker := NewScoreTracker(enabledConfig)
	
	start = time.Now()
	for i := 0; i < numPrograms; i++ {
		prog := &TestProgram{
			Hash:    fmt.Sprintf("prog_%d", i),
			Content: fmt.Sprintf("content_%d", i),
		}
		
		execResult := &ExecutionResult{
			Signal:     signal.Signal{},
			ExecTime:   uint64(1000000 + i*1000),
			KernelLogs: []string{"KASAN: test"},
			Crashed:    false,
			Error:      "",
		}
		
		enabledTracker.UpdateScore(prog, execResult)
	}
	enabledDuration := time.Since(start)
	
	// 计算开销
	overhead := enabledDuration - disabledDuration
	overheadPercent := float64(overhead) / float64(disabledDuration) * 100
	
	t.Logf("评分系统开销分析:")
	t.Logf("  禁用评分: %v", disabledDuration)
	t.Logf("  启用评分: %v", enabledDuration)
	t.Logf("  额外开销: %v (%.2f%%)", overhead, overheadPercent)
	
	// 开销阈值检查 (不应超过 50%)
	if overheadPercent > 50 {
		t.Errorf("评分系统开销过高: %.2f%% (期望 < 50%%)", overheadPercent)
	}
}

// 辅助结构和函数
type TestProgram struct {
	Hash    string
	Content string
}

func (tp *TestProgram) Hash() string {
	return tp.Hash
}

func generateRandomKernelLogs() []string {
	logs := []string{
		"KASAN: use-after-free",
		"WARNING: suspicious RCU usage",
		"ERROR: AddressSanitizer",
		"kernel BUG at",
		"general protection fault",
	}
	
	if rand.Intn(3) == 0 {
		return []string{}
	}
	
	numLogs := 1 + rand.Intn(3)
	result := make([]string, numLogs)
	for i := 0; i < numLogs; i++ {
		result[i] = logs[rand.Intn(len(logs))]
	}
	
	return result
}

// BenchmarkScoreCalculationComponents 基准测试各个评分组件
func BenchmarkScoreCalculationComponents(b *testing.B) {
	config := DefaultScoreConfig()
	
	b.Run("CoverageScore", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			calculateCoverageScore(signal.Signal{}, config)
		}
	})
	
	b.Run("RarityScore", func(b *testing.B) {
		stats := make(map[string]int64)
		stats["test"] = 100
		for i := 0; i < b.N; i++ {
			calculateRarityScore("test", stats, config)
		}
	})
	
	b.Run("KernelLogScore", func(b *testing.B) {
		matcher := NewKernelLogMatcher()
		logs := []string{"KASAN: use-after-free", "WARNING: test"}
		for i := 0; i < b.N; i++ {
			matcher.CalculateScore(logs)
		}
	})
	
	b.Run("TimeAnomalyScore", func(b *testing.B) {
		timeStats := NewTimeStats()
		// 添加一些基础数据
		for i := 0; i < 100; i++ {
			timeStats.AddTime(uint64(1000000 + i*1000))
		}
		for i := 0; i < b.N; i++ {
			timeStats.CalculateAnomalyScore(1500000)
		}
	})
}