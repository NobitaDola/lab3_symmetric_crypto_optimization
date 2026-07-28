# 作业 3：对称密码算法的软件实现与优化

本项目实现并验证 AES-128、SM4、GIFT-128、TWINE-128 四种分组密码，并在 AES-128 上实现 CTR、GCM、XTS 三种工作模式。代码同时保留易读的基础版本和面向 x86-64 的优化版本，测试以公开标准向量、OpenSSL 差分结果和随机差分测试作为正确性证据。

> 本项目用于课程实验与性能研究，不是生产密码库。T-table 会泄漏数据相关的访存模式；接口也没有提供生产系统所需的密钥生命周期、错误日志和平台调度能力。

## 成员与分工

| 成员 | 学号 | 主要分工 |
| --- | --- | --- |
| 王浩博 | 202322460131 | 总体架构、AES-NI/PCLMULQDQ、XTS、报告统筹 |
| 孙增吉 | 202300460070 | CTR/GCM 并行化、GHASH 和模式测试 |
| 衣洪顺 | 202322460128 | T-table、PSHUFB Shuffle、轻量级密码优化 |
| 邓方旭 | 202300460162 | CMake/CTest、差分测试、基准测试与数据复核 |

全体成员共同参与代码审查、实验结果分析和报告完善。

## 要求覆盖矩阵

| 课程要求 | 实现 | 验收证据 |
| --- | --- | --- |
| AES 软件实现 | 基础 S-box、T-table、AES-NI；基础版/AES-NI 加解密 | FIPS-197 向量、OpenSSL 差分 |
| SM4 软件实现 | 基础 S-box、T-table、4 路交错 T-table、PSHUFB 端序转换；加解密 | GB/T 32907 向量、OpenSSL 差分 |
| GIFT 软件实现 | GIFT-128 逐半字节基础版、32 位 bitslice 版、解密；BMI2 PEXT 加速置换 | 设计者发布的 3 组向量 |
| TWINE 软件实现 | TWINE-128 基础版、解密、8 路 SSSE3 PSHUFB S-box/块置换 | 原论文附录向量 |
| T-table | AES、SM4 | 基础版/优化版输出逐字节一致 |
| Shuffle | TWINE 8 路 PSHUFB；SM4 输入输出端序 PSHUFB | 标准向量与吞吐基准 |
| 新指令集方法（至少两种） | AES-NI、PCLMULQDQ；另含 SSSE3、BMI2 | 指令内建函数、随机差分测试 |
| CTR | AES 基础版/4 路 AES-NI；SM4 基础版/4 路交错 T-table | NIST CTR 向量、OpenSSL 差分、任意长度 |
| GCM | 基础逐位 GHASH；AES-NI CTR + PCLMULQDQ GHASH；认证解密 | NIST GCM 向量、1000 组 GF 差分、篡改拒绝 |
| XTS | 基础版/4 路 AES-NI；加解密和 ciphertext stealing | OpenSSL 差分、16～79 字节边界测试 |

GCM 和 XTS 的规范都以 128 位分组密码为基础，因此这里选 AES-128 实现。TWINE 的分组长度是 64 位，不能直接替换进标准 GCM 或 XTS；这不是遗漏，而是模式参数约束。CTR 没有该限制，项目额外提供了 SM4-CTR 作为第二组分组密码模式实验。

## 目录

```text
include/
  aes.h sm4.h gift128.h twine.h modes.h cycles.h
src/
  aes.c sm4.c gift128.c twine.c modes.c
tests/
  test_block_vectors.c   # AES/SM4 独立标准向量
  test_lightweight.c     # GIFT/TWINE 标准向量与基准
  test_modes_vectors.c   # CTR/GCM/XTS 独立向量和边界测试
  test_aes.c ...         # OpenSSL 差分与性能基准
report/
  report.tex report.pdf images/
```

## 构建与测试

要求：x86-64、支持 AES-NI/PCLMULQDQ/SSSE3 的处理器、CMake 3.16+、GCC 或 Clang。OpenSSL 是差分基准的可选依赖；没有 OpenSSL 时仍会构建三个独立向量测试。

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Windows 且项目路径含中文时，建议使用 Ninja，避免旧版 `mingw32-make` 的路径编码问题：

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

如果目标机器没有 BMI2，可关闭 GIFT 的 PEXT 路径并使用可移植回退：

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCRYPTO_HW3_NATIVE=OFF
```

单独运行基准：

```bash
./build/test_aes
./build/test_sm4
./build/test_lightweight
./build/test_ctr
./build/test_gcm
./build/test_xts
./build/benchmark_all
```

性能输出使用序列化的 `RDTSC/RDTSCP`，结果随 CPU、频率调节、编译器和系统负载变化。提交报告中的数据必须来自最终代码在同一台机器上的重新测量，不能把历史数据当成固定结论。

## 实现要点

- AES T-table 将 `SubBytes + ShiftRows + MixColumns` 合并为 32 位查表；AES-NI 版使用 10 轮专用指令，并提供逆轮密钥和解密。
- SM4 T-table 合并 S 盒和线性变换。CTR 优化版在每轮交错推进四个独立计数器状态，增加指令级并行度。
- GIFT-128 基础版逐位执行规范置换；bitslice 版用四个 32 位平面同时执行 32 个 S 盒，BMI2 路径用 `PEXT` 汇聚置换位。
- TWINE-128 优化版把八个分组放入独立 SIMD 状态，使用 `PSHUFB` 同时完成 4 位 S 盒查找和块置换，隐藏单分组轮依赖。
- GCM 优化版确实调用 `_mm_clmulepi64_si128` 生成 256 位无进位乘积，并按多项式 `x^128+x^7+x^2+x+1` 两次折叠约减。
- XTS 对非 16 字节倍数的数据单元实现 IEEE 1619 ciphertext stealing；长度小于 16 字节时明确返回失败，不再静默丢弃尾部。

## 正确性与安全边界

- GCM 解密先验证 128 位标签，标签不匹配时返回 `0` 并清空输出缓冲区。
- CTR 的加密和解密是同一操作；不得在同一密钥下复用计数器初值。
- XTS 只提供存储数据的保密性，不提供完整性；两个 128 位子密钥必须独立。
- 所有硬件优化目标都要求对应 CPU 特性。跨机器分发时应增加运行时 CPUID 分派，本课程版本通过构建参数选择目标指令集。

完整设计、算法说明、测试方法和结果分析见 [`report/report.pdf`](report/report.pdf)。
