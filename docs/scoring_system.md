# syzkaller 增强覆盖率导向模糊测试系统

## 概述

本文档介绍了 syzkaller 增强覆盖率导向模糊测试系统的设计、实现和使用方法。该系统通过实现基于多因子评分的智能输入选择机制，显著提高了模糊测试的效率和漏洞发现能力。

## 核心特性

### 1. 多维度评分系统
- **覆盖率评分**: 基于新发现代码路径的对数函数评分
- **路径稀有性评分**: 基于路径访问频率的反比例函数评分  
- **内核日志评分**: 基于 KASAN/WARNING/ERROR 等关键日志的模式匹配评分
- **执行时间异常评分**: 基于 Z-score 的执行时间异常检测评分

### 2. 智能输入选择
- 基于评分的加权随机选择算法
- 优先处理高价值输入程序
- 动态权重调整机制

### 3. 增强的变异策略
- 根据程序评分调整变异强度
- 高分程序采用保守变异策略
- 低分程序采用激进变异策略

## 系统架构

### 核心组件

```
pkg/fuzzer/
├── scoring.go              # 评分系统核心实现
├── time_stats.go          # 执行时间统计和异常检测
├── kernel_log_matcher.go  # 内核日志模式匹配
├── fuzzer.go              # 集成评分系统的模糊测试器
├── job.go                 # 增强的作业处理（smash等）
└── queue/
    └── scoring_extensions.go # 队列扩展

pkg/flatrpc/
└── scoring_extensions.go   # RPC 协议扩展
```

### 评分函数

综合评分函数 S(P) 定义为：

```
S(P) = w1 × Coverage(P) + w2 × Rarity(P) + w3 × KernelLog(P) + w4 × TimeAnomaly(P)
```

其中：
- w1, w2, w3, w4 为可配置权重参数，满足 w1 + w2 + w3 + w4 = 1
- 各维度评分范围均为 [0, 1]

#### 各维度评分算法

1. **覆盖率评分**:
   ```
   Coverage(P) = log(1 + newPCs) / log(1 + maxPossiblePCs)
   ```

2. **稀有性评分**:
   ```
   Rarity(P) = 1 / (1 + log(1 + frequency))
   ```

3. **内核日志评分**:
   - KASAN 相关: 0.9
   - kernel BUG/panic: 0.95
   - WARNING: 0.7
   - ERROR: 0.8
   - 其他: 0.0

4. **时间异常评分**:
   ```
   TimeAnomaly(P) = min(1.0, |z-score| / 3.0)
   ```

## 配置说明

### 评分系统配置

```go
type ScoreConfig struct {
    Enabled           bool    // 是否启用评分系统
    CoverageWeight    float64 // 覆盖率权重 (默认: 0.4)
    RarityWeight      float64 // 稀有性权重 (默认: 0.3)
    KernelLogWeight   float64 // 内核日志权重 (默认: 0.2)
    TimeAnomalyWeight float64 // 时间异常权重 (默认: 0.1)
    
    // 高级配置
    MaxScoreCache     int     // 最大评分缓存数量 (默认: 10000)
    TimeWindowSize    int     // 时间统计窗口大小 (默认: 1000)
    WeightedSelectProb float64 // 加权选择概率 (默认: 0.3)
}
```

### 默认配置

```go
func DefaultScoreConfig() *ScoreConfig {
    return &ScoreConfig{
        Enabled:            true,
        CoverageWeight:     0.4,
        RarityWeight:       0.3,
        KernelLogWeight:    0.2,
        TimeAnomalyWeight:  0.1,
        MaxScoreCache:      10000,
        TimeWindowSize:     1000,
        WeightedSelectProb: 0.3,
    }
}
```

## 使用方法

### 1. 启用评分系统

在 syzkaller 配置文件中添加评分系统配置：

```json
{
    "target": "linux/amd64",
    "http": "127.0.0.1:56741",
    "workdir": "./workdir",
    "kernel_obj": "./linux",
    "image": "./stretch.img",
    "sshkey": "./stretch.id_rsa",
    "syzkaller": "./bin",
    "procs": 8,
    "type": "qemu",
    "vm": {
        "count": 4,
        "kernel": "./linux/arch/x86/boot/bzImage",
        "cpu": 2,
        "mem": 2048
    },
    "scoring": {
        "enabled": true,
        "coverage_weight": 0.4,
        "rarity_weight": 0.3,
        "kernel_log_weight": 0.2,
        "time_anomaly_weight": 0.1
    }
}
```

### 2. 编程接口

```go
// 创建带评分系统的 Fuzzer
cfg := &fuzzer.Config{
    ScoreConfig: fuzzer.DefaultScoreConfig(),
    // ... 其他配置
}

fuzzer := fuzzer.NewFuzzer(ctx, cfg, rnd, target)

// 获取评分指标
metrics := fuzzer.GetScoreMetrics()
fmt.Printf("平均评分: %.3f\n", metrics.AverageScore)
fmt.Printf("加权选择比例: %.2f%%\n", metrics.GetScoreSelectionRatio()*100)

// 获取高分程序
topProgs := fuzzer.GetTopScoredProgs(10)
fmt.Printf("前10高分程序: %v\n", topProgs)

// 更新评分配置
newConfig := &fuzzer.ScoreConfig{
    Enabled:         true,
    CoverageWeight:  0.5,
    RarityWeight:    0.2,
    KernelLogWeight: 0.2,
    TimeAnomalyWeight: 0.1,
}
fuzzer.UpdateScoreConfig(newConfig)
```

### 3. 监控和调试

启用调试模式可以查看详细的评分信息：

```go
cfg := &fuzzer.Config{
    Debug: true,
    ScoreConfig: fuzzer.DefaultScoreConfig(),
    Logf: func(level int, msg string, args ...interface{}) {
        log.Printf("[Level %d] "+msg, append([]interface{}{level}, args...)...)
    },
}
```

调试日志示例：
```
[Level 3] 程序评分: 总分=0.756, 覆盖率=0.823, 稀有性=0.654, 内核日志=0.900, 时间异常=0.234
[Level 3] 使用基于评分的加权选择生成程序
[Level 2] smash 完成: 基准分数=0.756, 成功变异=12/25 (48.0%)
```

## 性能优化

### 1. 评分缓存

系统使用 LRU 缓存来存储程序评分，避免重复计算：

```go
// 配置缓存大小
config.MaxScoreCache = 20000 // 增加缓存容量
```

### 2. 并发处理

评分计算支持并发处理，使用读写锁保证线程安全：

```go
// 评分跟踪器内部使用 sync.RWMutex
type ScoreTracker struct {
    mu     sync.RWMutex
    scores map[string]*ProgScore
    // ...
}
```

### 3. 性能监控

```go
// 获取性能统计
metrics := fuzzer.GetScoreMetrics()
avgCalcTime := metrics.GetAverageCalculationTime()
fmt.Printf("平均评分计算时间: %.2f μs\n", avgCalcTime/1000)
```

## 测试和验证

### 1. 单元测试

```bash
cd pkg/fuzzer
go test -v -run TestScoreTracker
go test -v -run TestWeightedSelector
go test -v -run TestKernelLogMatcher
```

### 2. 性能测试

```bash
go test -v -run TestScoreSystemPerformance
go test -bench=BenchmarkScoreCalculation
go test -bench=BenchmarkWeightedSelection
```

### 3. 集成测试

```bash
go test -v -run TestEndToEndScoring
go test -v -run TestFuzzerWithScoringSystem
```

## 故障排除

### 常见问题

1. **评分系统未启用**
   - 检查配置文件中 `scoring.enabled` 是否为 `true`
   - 验证 `ScoreConfig.Enabled` 字段

2. **评分计算异常**
   - 检查权重配置是否合理（总和应为1.0）
   - 查看调试日志中的评分详情

3. **性能问题**
   - 调整评分缓存大小
   - 降低加权选择概率
   - 检查内核日志匹配器的正则表达式效率

### 调试技巧

1. **启用详细日志**:
   ```go
   cfg.Debug = true
   cfg.Logf = func(level int, msg string, args ...interface{}) {
       if level <= 3 {
           log.Printf("[Level %d] "+msg, append([]interface{}{level}, args...)...)
       }
   }
   ```

2. **监控评分分布**:
   ```go
   metrics := fuzzer.GetScoreMetrics()
   fmt.Printf("评分分布: 最小=%.3f, 平均=%.3f, 最大=%.3f\n", 
       metrics.MinScore, metrics.AverageScore, metrics.MaxScore)
   ```

3. **分析 Smash 效果**:
   ```go
   smashStats := metrics.GetSmashStats()
   fmt.Printf("Smash 成功率: %.2f%%\n", smashStats["success_rate"].(float64)*100)
   ```

## 扩展开发

### 添加新的评分维度

1. 在 `ProgScore` 结构中添加新字段
2. 在 `ScoreConfig` 中添加对应权重
3. 实现评分计算函数
4. 在 `calculateScore` 中集成新维度

示例：
```go
// 添加新的网络活动评分
type ProgScore struct {
    // ... 现有字段
    NetworkActivity float64 `json:"network_activity"`
}

func calculateNetworkActivityScore(execResult *ExecutionResult) float64 {
    // 实现网络活动评分逻辑
    return score
}
```

### 自定义变异策略

```go
// 实现自定义变异策略
func (job *smashJob) customMutate(p *prog.Prog, rnd *rand.Rand, fuzzer *Fuzzer, score float64) {
    if score > 0.8 {
        // 超高分程序的特殊处理
        job.ultraConservativeMutate(p, rnd, fuzzer)
    } else {
        // 标准处理
        job.conservativeMutate(p, rnd, fuzzer)
    }
}
```

## 最佳实践

1. **权重调优**: 根据目标系统特点调整各维度权重
2. **缓存管理**: 合理设置缓存大小，平衡内存使用和性能
3. **监控指标**: 定期检查评分分布和选择效果
4. **渐进启用**: 在生产环境中逐步启用评分系统，观察效果

## 参考资料

- [syzkaller 官方文档](https://github.com/google/syzkaller/tree/master/docs)
- [覆盖率导向模糊测试原理](https://en.wikipedia.org/wiki/Fuzzing#Coverage-guided_fuzzing)
- [内核漏洞检测技术](https://www.kernel.org/doc/html/latest/dev-tools/kasan.html)