# Lab 3：对称密码算法的软件实现与优化

本项目围绕 AES-128 与 SM4 的软件实现和性能优化展开，并进一步实现、验证和优化 CTR、GCM、XTS 三种工作模式。所有实现均以 OpenSSL 输出作为正确性基准，通过 `memcmp` 进行逐字节比对；性能测试使用 `RDTSC/RDTSCP` 统计 CPU 周期数。

完整实验设计、性能分析和关键代码说明见 [`report/report.pdf`](report/report.pdf)。

> 本项目为课程实验代码，重点是算法原理与性能优化研究。T-Table 等实现可能受到缓存侧信道攻击影响，不应直接用于生产系统。

## 实验内容

### 分组密码实现

- AES-128 基础 S-Box 实现
- AES-128 T-Table 优化
- AES-NI 硬件指令加速
- SM4 基础 S-Box 实现
- SM4 T-Table 优化
- SM4 SSSE3 SIMD Shuffle 优化

### 工作模式优化

- CTR：AES-NI/SM4 的 4-Way 并行流水线
- GCM：4-Way CTR 与 PCLMULQDQ 加速的 GHASH
- XTS：4-Way AES-NI 与无分支 Tweak 向量化更新

## 主要实验结果

| 测试项目 | 基础实现 | 优化实现 | 报告加速比 |
| --- | ---: | ---: | ---: |
| AES-128 单分组 | 948.25 cycles/block | AES-NI：5.06 cycles/block | 187.51x |
| SM4 单分组 | 624.07 cycles/block | SIMD Shuffle：310.21 cycles/block | 2.01x |
| AES-128 CTR | 61.33 cycles/byte | 4-Way：1.24 cycles/byte | 49.31x |
| SM4 CTR | 36.85 cycles/byte | 4-Way：18.61 cycles/byte | 1.98x |
| AES-128 GCM | 207.81 cycles/byte | PCLMULQDQ：145.12 cycles/byte | 1.43x |
| AES-128 XTS | 63.68 cycles/byte | 4-Way SIMD：0.47 cycles/byte | 136.06x |

性能结果与 CPU 型号、编译器、OpenSSL 版本、系统负载和处理器频率有关，重新运行时数值可能变化。实验报告中的数据用于展示同一环境下各实现的相对性能。

## 成员与分工

| 成员 | 分工 |
| --- | --- |
| 王浩博（负责人，202322460131） | 整体架构设计；AES-NI/PCLMULQDQ 核心优化；XTS 向量化；报告统筹 |
| 孙增吉（202300460070） | CTR/GCM 的 4-Way 并行流水线；GHASH 无进位乘法调试 |
| 衣洪顺（202322460128） | SM4 SIMD Shuffle；AES/SM4 T-Table 预计算优化 |
| 邓方旭（202300460162） | CMake 测试环境；Benchmark 框架；OpenSSL 一致性验证与数据收集 |

四名成员共同参与代码审阅、性能瓶颈排查、结果核对和实验报告审阅。

## 项目结构

```text
.
├── CMakeLists.txt       # CMake 构建配置
├── include/
│   ├── aes.h            # AES-128 接口
│   ├── sm4.h            # SM4 接口
│   ├── modes.h          # CTR/GCM/XTS 接口
│   └── cycles.h         # RDTSC/RDTSCP 周期计数
├── src/
│   ├── aes.c            # AES 基础、T-Table、AES-NI 实现
│   ├── sm4.c            # SM4 基础、T-Table、Shuffle 实现
│   └── modes.c          # CTR、GCM、XTS 及优化实现
├── tests/
│   ├── test_aes.c       # AES 正确性与性能测试
│   ├── test_sm4.c       # SM4 正确性与性能测试
│   ├── test_ctr.c       # AES/SM4 CTR 测试
│   ├── test_gcm.c       # AES-GCM 与 GHASH 测试
│   └── test_xts.c       # AES-XTS 测试
└── report/
    ├── report.tex       # 实验报告 LaTeX 源文件
    ├── report.pdf       # 最终实验报告
    ├── sdu_report_style.tex
    └── images/          # 校徽与性能测试截图
```

`build/` 仅用于本地构建，属于可再生文件，因此由 `.gitignore` 排除，不提交到仓库。

## 环境要求

- x86-64 处理器，并支持 AES-NI、SSSE3 和 PCLMULQDQ
- GCC 或 Clang
- CMake 3.10 或更高版本
- OpenSSL 开发库（需包含 AES、SM4、CTR、GCM、XTS EVP 接口）

推荐在较新的 Ubuntu/Debian 环境中运行：

```bash
sudo apt update
sudo apt install -y build-essential cmake libssl-dev
```

可使用以下命令确认 CPU 指令集支持：

```bash
grep -m1 -oE 'aes|ssse3|pclmulqdq' /proc/cpuinfo | sort -u
```

## 构建

在项目根目录执行：

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

项目使用 `-O3 -march=native -Wall`。生成的程序位于 `build/`。

## 运行测试

```bash
./build/test_aes
./build/test_sm4
./build/test_ctr
./build/test_gcm
./build/test_xts
```

每个程序先将自研实现与 OpenSSL 结果进行比较；只有正确性验证通过后才输出性能数据。CTR、GCM 和 XTS 测试会处理大量 64 KB 数据块，运行时间通常长于单分组 AES/SM4 测试。

## 重新编译报告

安装带 XeLaTeX 的 TeX Live 后执行：

```bash
cd report
xelatex -interaction=nonstopmode -halt-on-error report.tex
xelatex -interaction=nonstopmode -halt-on-error report.tex
```

连续编译两次用于刷新目录、页码和交叉引用，输出文件为 `report/report.pdf`。

## 正确性与安全说明

- AES 与 SM4 基础实现、优化实现均与 OpenSSL 参考结果逐字节比较。
- 测试向量和密钥仅用于课程实验，不是实际业务密钥。
- `-march=native` 会根据当前 CPU 生成机器相关指令，编译产物不应复制到不兼容的处理器运行。
- AES-NI 通常能够减少缓存计时侧信道风险；T-Table 实现主要用于性能对比，不适合作为生产环境默认方案。
