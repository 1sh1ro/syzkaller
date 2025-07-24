// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"regexp"
	"strings"
	"sync"
)

// LogPattern 日志模式定义
type LogPattern struct {
	// 正则表达式
	Pattern *regexp.Regexp
	// 分数权重
	Score float64
	// 模式描述
	Description string
}

// KernelLogMatcher 内核日志匹配器
type KernelLogMatcher struct {
	mu sync.RWMutex
	
	// 预定义的日志模式
	patterns []LogPattern
}

// NewKernelLogMatcher 创建内核日志匹配器
func NewKernelLogMatcher() *KernelLogMatcher {
	matcher := &KernelLogMatcher{}
	matcher.initializePatterns()
	return matcher
}

// initializePatterns 初始化日志模式
func (klm *KernelLogMatcher) initializePatterns() {
	// 定义各种内核日志模式及其分数权重
	patterns := []struct {
		regex       string
		score       float64
		description string
	}{
		// KASAN 错误 (最高优先级)
		{`KASAN:.*`, 1.0, "KASAN memory error"},
		{`AddressSanitizer:.*`, 1.0, "AddressSanitizer error"},
		
		// 内核崩溃和恐慌
		{`kernel BUG at.*`, 0.9, "Kernel BUG"},
		{`Kernel panic.*`, 0.9, "Kernel panic"},
		{`Oops:.*`, 0.8, "Kernel Oops"},
		
		// 内存相关错误
		{`general protection fault.*`, 0.8, "General protection fault"},
		{`page fault.*`, 0.7, "Page fault"},
		{`double fault.*`, 0.9, "Double fault"},
		{`stack segment.*`, 0.8, "Stack segment fault"},
		
		// 锁相关问题
		{`possible deadlock.*`, 0.7, "Possible deadlock"},
		{`lockdep.*`, 0.6, "Lockdep warning"},
		{`sleeping function called from invalid context.*`, 0.6, "Invalid sleep context"},
		
		// RCU 相关
		{`rcu_.*stall.*`, 0.6, "RCU stall"},
		{`RCU.*`, 0.5, "RCU related"},
		
		// 警告信息
		{`WARNING:.*`, 0.5, "Kernel warning"},
		{`WARN_ON.*`, 0.5, "WARN_ON triggered"},
		
		// 内存泄漏和引用计数
		{`memory leak.*`, 0.6, "Memory leak"},
		{`refcount_t.*`, 0.6, "Reference count error"},
		
		// 文件系统错误
		{`EXT4-fs error.*`, 0.4, "EXT4 filesystem error"},
		{`XFS.*error.*`, 0.4, "XFS filesystem error"},
		
		// 网络相关错误
		{`net.*warning.*`, 0.3, "Network warning"},
		{`TCP.*error.*`, 0.3, "TCP error"},
		
		// 设备驱动错误
		{`device.*error.*`, 0.3, "Device error"},
		{`driver.*warning.*`, 0.2, "Driver warning"},
		
		// 一般错误信息
		{`ERROR:.*`, 0.4, "General error"},
		{`error.*`, 0.2, "Generic error"},
	}
	
	klm.patterns = make([]LogPattern, 0, len(patterns))
	
	for _, p := range patterns {
		regex, err := regexp.Compile(p.regex)
		if err != nil {
			continue // 跳过无效的正则表达式
		}
		
		klm.patterns = append(klm.patterns, LogPattern{
			Pattern:     regex,
			Score:       p.score,
			Description: p.description,
		})
	}
}

// CalculateScore 计算内核日志分数
func (klm *KernelLogMatcher) CalculateScore(logs []string) float64 {
	klm.mu.RLock()
	defer klm.mu.RUnlock()
	
	if len(logs) == 0 {
		return 0.0
	}
	
	maxScore := 0.0
	matchedPatterns := make(map[string]bool)
	
	// 遍历所有日志行
	for _, log := range logs {
		log = strings.TrimSpace(log)
		if log == "" {
			continue
		}
		
		// 检查每个模式
		for _, pattern := range klm.patterns {
			if pattern.Pattern.MatchString(log) {
				// 避免重复计分同一类型的模式
				key := pattern.Description
				if !matchedPatterns[key] {
					matchedPatterns[key] = true
					if pattern.Score > maxScore {
						maxScore = pattern.Score
					}
				}
			}
		}
	}
	
	// 如果匹配了多个不同类型的模式，给予额外加分
	bonusScore := 0.0
	if len(matchedPatterns) > 1 {
		bonusScore = float64(len(matchedPatterns)-1) * 0.1
	}
	
	totalScore := maxScore + bonusScore
	
	// 确保分数在 0-1 范围内
	if totalScore > 1.0 {
		totalScore = 1.0
	}
	
	return totalScore
}

// AddCustomPattern 添加自定义日志模式
func (klm *KernelLogMatcher) AddCustomPattern(regex string, score float64, description string) error {
	pattern, err := regexp.Compile(regex)
	if err != nil {
		return err
	}
	
	klm.mu.Lock()
	defer klm.mu.Unlock()
	
	klm.patterns = append(klm.patterns, LogPattern{
		Pattern:     pattern,
		Score:       score,
		Description: description,
	})
	
	return nil
}

// GetMatchedPatterns 获取匹配的模式信息
func (klm *KernelLogMatcher) GetMatchedPatterns(logs []string) []string {
	klm.mu.RLock()
	defer klm.mu.RUnlock()
	
	var matched []string
	matchedSet := make(map[string]bool)
	
	for _, log := range logs {
		log = strings.TrimSpace(log)
		if log == "" {
			continue
		}
		
		for _, pattern := range klm.patterns {
			if pattern.Pattern.MatchString(log) {
				if !matchedSet[pattern.Description] {
					matchedSet[pattern.Description] = true
					matched = append(matched, pattern.Description)
				}
			}
		}
	}
	
	return matched
}