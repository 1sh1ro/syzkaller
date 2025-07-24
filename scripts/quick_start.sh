#!/bin/bash

# syzkaller 增强覆盖率导向模糊测试系统 - 快速启动脚本
# 使用方法: ./scripts/quick_start.sh

set -e

echo "🚀 syzkaller 增强覆盖率导向模糊测试系统 - 快速启动"
echo "=================================================="

# 检查当前目录
if [ ! -f "Makefile" ] || [ ! -d "pkg/fuzzer" ]; then
    echo "❌ 错误: 请在 syzkaller-master 根目录下运行此脚本"
    exit 1
fi

# 检查 Go 环境
echo "🔍 检查 Go 环境..."
if ! command -v go &> /dev/null; then
    echo "❌ 错误: 未找到 Go 环境，请先安装 Go 1.19+"
    exit 1
fi

GO_VERSION=$(go version | grep -oE 'go[0-9]+\.[0-9]+' | sed 's/go//')
if [ "$(printf '%s\n' "1.19" "$GO_VERSION" | sort -V | head -n1)" != "1.19" ]; then
    echo "⚠️  警告: Go 版本 $GO_VERSION 可能不兼容，建议使用 1.19+"
fi

echo "✅ Go 版本: $GO_VERSION"

# 编译系统
echo ""
echo "🔨 编译 syzkaller 系统..."
if ! make -j$(nproc) > build.log 2>&1; then
    echo "❌ 编译失败，请查看 build.log 文件"
    tail -20 build.log
    exit 1
fi

echo "✅ 编译完成"

# 运行测试
echo ""
echo "🧪 运行评分系统测试..."

# 运行核心测试
echo "  - 测试评分跟踪器..."
if ! (cd pkg/fuzzer && go test -run TestScoreTracker -timeout 30s > /dev/null 2>&1); then
    echo "⚠️  评分跟踪器测试失败，但可以继续运行"
else
    echo "    ✅ 评分跟踪器测试通过"
fi

echo "  - 测试加权选择器..."
if ! (cd pkg/fuzzer && go test -run TestWeightedSelector -timeout 30s > /dev/null 2>&1); then
    echo "⚠️  加权选择器测试失败，但可以继续运行"
else
    echo "    ✅ 加权选择器测试通过"
fi

echo "  - 测试内核日志匹配器..."
if ! (cd pkg/fuzzer && go test -run TestKernelLogMatcher -timeout 30s > /dev/null 2>&1); then
    echo "⚠️  内核日志匹配器测试失败，但可以继续运行"
else
    echo "    ✅ 内核日志匹配器测试通过"
fi

# 创建示例配置
echo ""
echo "📝 创建示例配置文件..."

cat > example-config.json << 'EOF'
{
    "target": "linux/amd64",
    "http": "127.0.0.1:56741",
    "workdir": "./workdir",
    "kernel_obj": "/path/to/linux",
    "image": "./stretch.img",
    "sshkey": "./stretch.id_rsa",
    "syzkaller": "./bin",
    "procs": 4,
    "type": "qemu",
    "vm": {
        "count": 2,
        "kernel": "/path/to/linux/arch/x86/boot/bzImage",
        "cpu": 2,
        "mem": 2048
    },
    "scoring": {
        "enabled": true,
        "coverage_weight": 0.4,
        "rarity_weight": 0.3,
        "kernel_log_weight": 0.2,
        "time_anomaly_weight": 0.1,
        "max_score_cache": 10000,
        "time_window_size": 1000,
        "weighted_select_prob": 0.3
    },
    "enable_syscalls": [
        "openat", "read", "write", "close", "mmap", "munmap",
        "brk", "rt_sigaction", "rt_sigprocmask", "ioctl", "pread64",
        "pwrite64", "readv", "writev", "access", "pipe", "select",
        "sched_yield", "mremap", "msync", "mincore", "madvise"
    ]
}
EOF

echo "✅ 已创建 example-config.json"

# 创建启动脚本
echo ""
echo "📜 创建启动脚本..."

cat > start-syzkaller.sh << 'EOF'
#!/bin/bash

# 检查配置文件
if [ ! -f "config.json" ]; then
    echo "❌ 错误: 未找到 config.json 配置文件"
    echo "请复制 example-config.json 为 config.json 并修改相应路径"
    exit 1
fi

# 检查必要文件
echo "🔍 检查配置..."

KERNEL_OBJ=$(grep -o '"kernel_obj": "[^"]*"' config.json | cut -d'"' -f4)
IMAGE=$(grep -o '"image": "[^"]*"' config.json | cut -d'"' -f4)
SSHKEY=$(grep -o '"sshkey": "[^"]*"' config.json | cut -d'"' -f4)
KERNEL=$(grep -o '"kernel": "[^"]*"' config.json | cut -d'"' -f4)

if [ ! -d "$KERNEL_OBJ" ]; then
    echo "⚠️  警告: 内核源码目录不存在: $KERNEL_OBJ"
fi

if [ ! -f "$IMAGE" ]; then
    echo "⚠️  警告: 虚拟机镜像不存在: $IMAGE"
    echo "可以下载: wget https://storage.googleapis.com/syzkaller/stretch.img"
fi

if [ ! -f "$SSHKEY" ]; then
    echo "⚠️  警告: SSH 密钥不存在: $SSHKEY"
    echo "可以下载: wget https://storage.googleapis.com/syzkaller/stretch.id_rsa"
fi

if [ ! -f "$KERNEL" ]; then
    echo "⚠️  警告: 内核镜像不存在: $KERNEL"
fi

# 创建工作目录
mkdir -p workdir

echo ""
echo "🚀 启动 syzkaller 管理器..."
echo "Web 界面: http://127.0.0.1:56741"
echo "按 Ctrl+C 停止"
echo ""

# 启动管理器
exec ./bin/syz-manager -config=config.json -debug
EOF

chmod +x start-syzkaller.sh
echo "✅ 已创建 start-syzkaller.sh"

# 创建测试脚本
echo ""
echo "🧪 创建测试脚本..."

cat > run-tests.sh << 'EOF'
#!/bin/bash

echo "🧪 运行 syzkaller 增强评分系统测试套件"
echo "========================================"

cd pkg/fuzzer

echo ""
echo "1️⃣  单元测试..."
echo "  - 评分跟踪器测试"
go test -v -run TestScoreTracker -timeout 60s

echo "  - 加权选择器测试"
go test -v -run TestWeightedSelector -timeout 60s

echo "  - 内核日志匹配器测试"
go test -v -run TestKernelLogMatcher -timeout 60s

echo "  - 时间统计测试"
go test -v -run TestTimeStats -timeout 60s

echo ""
echo "2️⃣  性能测试..."
go test -v -run TestScoreSystemPerformance -timeout 120s

echo ""
echo "3️⃣  基准测试..."
go test -bench=BenchmarkScoreCalculation -benchtime=5s
go test -bench=BenchmarkWeightedSelection -benchtime=5s

echo ""
echo "4️⃣  集成测试..."
go test -v -run TestEndToEndScoring -timeout 180s

echo ""
echo "✅ 测试完成！"
EOF

chmod +x run-tests.sh
echo "✅ 已创建 run-tests.sh"

# 显示下一步操作
echo ""
echo "🎉 快速启动完成！"
echo "=================="
echo ""
echo "📋 下一步操作:"
echo ""
echo "1. 准备环境:"
echo "   - 下载虚拟机镜像: wget https://storage.googleapis.com/syzkaller/stretch.img"
echo "   - 下载 SSH 密钥: wget https://storage.googleapis.com/syzkaller/stretch.id_rsa"
echo "   - 编译 Linux 内核 (参考 docs/运行指南.md)"
echo ""
echo "2. 配置系统:"
echo "   - 复制配置文件: cp example-config.json config.json"
echo "   - 编辑配置文件: nano config.json"
echo "   - 修改内核路径、镜像路径等"
echo ""
echo "3. 运行测试:"
echo "   - 运行测试套件: ./run-tests.sh"
echo ""
echo "4. 启动系统:"
echo "   - 启动 syzkaller: ./start-syzkaller.sh"
echo "   - 访问 Web 界面: http://127.0.0.1:56741"
echo ""
echo "📖 详细文档:"
echo "   - 运行指南: docs/运行指南.md"
echo "   - 系统文档: docs/scoring_system.md"
echo ""
echo "🆘 如遇问题:"
echo "   - 查看编译日志: cat build.log"
echo "   - 运行测试诊断: ./run-tests.sh"
echo "   - 查看详细文档获取故障排除信息"

echo ""
echo "🌟 享受增强的 syzkaller 模糊测试体验！"