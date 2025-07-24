@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo 🚀 syzkaller 增强覆盖率导向模糊测试系统 - 快速启动
echo ==================================================

REM 检查当前目录
if not exist "Makefile" (
    if not exist "pkg\fuzzer" (
        echo ❌ 错误: 请在 syzkaller-master 根目录下运行此脚本
        pause
        exit /b 1
    )
)

REM 检查 Go 环境
echo 🔍 检查 Go 环境...
go version >nul 2>&1
if errorlevel 1 (
    echo ❌ 错误: 未找到 Go 环境，请先安装 Go 1.19+
    pause
    exit /b 1
)

for /f "tokens=3" %%i in ('go version') do set GO_VERSION=%%i
echo ✅ Go 版本: !GO_VERSION!

REM 编译系统
echo.
echo 🔨 编译 syzkaller 系统...
make > build.log 2>&1
if errorlevel 1 (
    echo ❌ 编译失败，请查看 build.log 文件
    type build.log | findstr /C:"error" /C:"Error" /C:"ERROR"
    pause
    exit /b 1
)

echo ✅ 编译完成

REM 运行测试
echo.
echo 🧪 运行评分系统测试...

echo   - 测试评分跟踪器...
cd pkg\fuzzer
go test -run TestScoreTracker -timeout 30s >nul 2>&1
if errorlevel 1 (
    echo     ⚠️  评分跟踪器测试失败，但可以继续运行
) else (
    echo     ✅ 评分跟踪器测试通过
)

echo   - 测试加权选择器...
go test -run TestWeightedSelector -timeout 30s >nul 2>&1
if errorlevel 1 (
    echo     ⚠️  加权选择器测试失败，但可以继续运行
) else (
    echo     ✅ 加权选择器测试通过
)

echo   - 测试内核日志匹配器...
go test -run TestKernelLogMatcher -timeout 30s >nul 2>&1
if errorlevel 1 (
    echo     ⚠️  内核日志匹配器测试失败，但可以继续运行
) else (
    echo     ✅ 内核日志匹配器测试通过
)

cd ..\..

REM 创建示例配置
echo.
echo 📝 创建示例配置文件...

(
echo {
echo     "target": "linux/amd64",
echo     "http": "127.0.0.1:56741",
echo     "workdir": "./workdir",
echo     "kernel_obj": "C:/path/to/linux",
echo     "image": "./stretch.img",
echo     "sshkey": "./stretch.id_rsa",
echo     "syzkaller": "./bin",
echo     "procs": 4,
echo     "type": "qemu",
echo     "vm": {
echo         "count": 2,
echo         "kernel": "C:/path/to/linux/arch/x86/boot/bzImage",
echo         "cpu": 2,
echo         "mem": 2048
echo     },
echo     "scoring": {
echo         "enabled": true,
echo         "coverage_weight": 0.4,
echo         "rarity_weight": 0.3,
echo         "kernel_log_weight": 0.2,
echo         "time_anomaly_weight": 0.1,
echo         "max_score_cache": 10000,
echo         "time_window_size": 1000,
echo         "weighted_select_prob": 0.3
echo     },
echo     "enable_syscalls": [
echo         "openat", "read", "write", "close", "mmap", "munmap",
echo         "brk", "rt_sigaction", "rt_sigprocmask", "ioctl", "pread64",
echo         "pwrite64", "readv", "writev", "access", "pipe", "select",
echo         "sched_yield", "mremap", "msync", "mincore", "madvise"
echo     ]
echo }
) > example-config.json

echo ✅ 已创建 example-config.json

REM 创建启动脚本
echo.
echo 📜 创建启动脚本...

(
echo @echo off
echo chcp 65001 ^>nul
echo.
echo REM 检查配置文件
echo if not exist "config.json" ^(
echo     echo ❌ 错误: 未找到 config.json 配置文件
echo     echo 请复制 example-config.json 为 config.json 并修改相应路径
echo     pause
echo     exit /b 1
echo ^)
echo.
echo REM 创建工作目录
echo if not exist "workdir" mkdir workdir
echo.
echo echo 🚀 启动 syzkaller 管理器...
echo echo Web 界面: http://127.0.0.1:56741
echo echo 按 Ctrl+C 停止
echo echo.
echo.
echo REM 启动管理器
echo .\bin\syz-manager.exe -config=config.json -debug
) > start-syzkaller.bat

echo ✅ 已创建 start-syzkaller.bat

REM 创建测试脚本
echo.
echo 🧪 创建测试脚本...

(
echo @echo off
echo chcp 65001 ^>nul
echo.
echo echo 🧪 运行 syzkaller 增强评分系统测试套件
echo echo ========================================
echo.
echo cd pkg\fuzzer
echo.
echo echo.
echo echo 1️⃣  单元测试...
echo echo   - 评分跟踪器测试
echo go test -v -run TestScoreTracker -timeout 60s
echo.
echo echo   - 加权选择器测试
echo go test -v -run TestWeightedSelector -timeout 60s
echo.
echo echo   - 内核日志匹配器测试
echo go test -v -run TestKernelLogMatcher -timeout 60s
echo.
echo echo   - 时间统计测试
echo go test -v -run TestTimeStats -timeout 60s
echo.
echo echo.
echo echo 2️⃣  性能测试...
echo go test -v -run TestScoreSystemPerformance -timeout 120s
echo.
echo echo.
echo echo 3️⃣  基准测试...
echo go test -bench=BenchmarkScoreCalculation -benchtime=5s
echo go test -bench=BenchmarkWeightedSelection -benchtime=5s
echo.
echo echo.
echo echo 4️⃣  集成测试...
echo go test -v -run TestEndToEndScoring -timeout 180s
echo.
echo cd ..\..
echo.
echo echo.
echo echo ✅ 测试完成！
echo pause
) > run-tests.bat

echo ✅ 已创建 run-tests.bat

REM 显示下一步操作
echo.
echo 🎉 快速启动完成！
echo ==================
echo.
echo 📋 下一步操作:
echo.
echo 1. 准备环境:
echo    - 安装 WSL2 或 Linux 虚拟机用于运行内核
echo    - 下载虚拟机镜像和 SSH 密钥
echo    - 编译 Linux 内核 ^(参考 docs/运行指南.md^)
echo.
echo 2. 配置系统:
echo    - 复制配置文件: copy example-config.json config.json
echo    - 编辑配置文件: notepad config.json
echo    - 修改内核路径、镜像路径等
echo.
echo 3. 运行测试:
echo    - 运行测试套件: run-tests.bat
echo.
echo 4. 启动系统:
echo    - 启动 syzkaller: start-syzkaller.bat
echo    - 访问 Web 界面: http://127.0.0.1:56741
echo.
echo 📖 详细文档:
echo    - 运行指南: docs\运行指南.md
echo    - 系统文档: docs\scoring_system.md
echo.
echo 🆘 如遇问题:
echo    - 查看编译日志: type build.log
echo    - 运行测试诊断: run-tests.bat
echo    - 查看详细文档获取故障排除信息
echo.
echo 🌟 享受增强的 syzkaller 模糊测试体验！
echo.
pause