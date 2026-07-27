#ifndef SM4_H
#define SM4_H

#include <stdint.h>

#define SM4_BLOCK_SIZE 16
#define SM4_KEY_SIZE 16
#define SM4_NUM_ROUNDS 32

// 1. 标准 SM4 密钥扩展
void sm4_key_expansion_basic(const uint8_t *key, uint32_t *rk);

// 2. 三种层次的加密实现
// (1) 基础 S-Box 实现
void sm4_encrypt_basic(const uint8_t *in, uint8_t *out, const uint32_t *rk);

// (2) T-Table 查找表优化实现
void sm4_init_ttables(void);
void sm4_encrypt_ttable(const uint8_t *in, uint8_t *out, const uint32_t *rk);

// (3) SIMD Shuffle 向量化优化实现 (基于 SSSE3 _mm_shuffle_epi8 字节重排与并行加速)
void sm4_encrypt_shuffle(const uint8_t *in, uint8_t *out, const uint32_t *rk);

#endif // SM4_H