#ifndef MODES_H
#define MODES_H

#include <stdint.h>
#include <stddef.h>

// ===========================================================================
// AES-128 CTR 模式接口 (加密与解密逻辑完全一致)
// ===========================================================================

// 1. 串行单块基准实现
void aes128_ctr_encrypt_basic(const uint8_t *in, uint8_t *out, size_t len,
                              const uint8_t key[16], const uint8_t iv[16]);

// 2. 4-Way AES-NI 指令流水线并行优化实现
void aes128_ctr_encrypt_parallel(const uint8_t *in, uint8_t *out, size_t len,
                                 const uint8_t key[16], const uint8_t iv[16]);

// ===========================================================================
// SM4 CTR 模式接口
// ===========================================================================

// 1. 串行单块基准实现
void sm4_ctr_encrypt_basic(const uint8_t *in, uint8_t *out, size_t len,
                           const uint8_t key[16], const uint8_t iv[16]);

// 2. 4-Way T-Table / SIMD 循环展开并行优化实现
void sm4_ctr_encrypt_parallel(const uint8_t *in, uint8_t *out, size_t len,
                              const uint8_t key[16], const uint8_t iv[16]);

// ===========================================================================
// AES-128 GCM 模式接口 (AEAD 加密与 Tag 生成)
// ===========================================================================

// 1. GCM 串行/基础实现 (逐位 GF(2^128) 乘法)
void aes128_gcm_encrypt_basic(const uint8_t *in, size_t in_len,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t key[16], const uint8_t iv[12],
                              uint8_t *out, uint8_t tag[16]);

// 2. GCM 硬件加速优化实现 (4-Way CTR 流水线 + PCLMULQDQ GHASH 加速)
void aes128_gcm_encrypt_opt(const uint8_t *in, size_t in_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t key[16], const uint8_t iv[12],
                            uint8_t *out, uint8_t tag[16]);
int aes128_gcm_decrypt_basic(const uint8_t *in, size_t in_len,
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t key[16], const uint8_t iv[12],
                             const uint8_t tag[16], uint8_t *out);
int aes128_gcm_decrypt_opt(const uint8_t *in, size_t in_len,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t key[16], const uint8_t iv[12],
                           const uint8_t tag[16], uint8_t *out);

/* Exposed for differential testing of the PCLMULQDQ field primitive. */
void gcm_gf_mul_basic(const uint8_t a[16], const uint8_t b[16], uint8_t out[16]);
void gcm_gf_mul_pclmul(const uint8_t a[16], const uint8_t b[16], uint8_t out[16]);
// ===========================================================================
// AES-128 XTS 模式接口 (存储加密模式)
// ===========================================================================

// 1. XTS 基础单块串行实现
int aes128_xts_encrypt_basic(const uint8_t *in, uint8_t *out, size_t len,
                             const uint8_t key[32], const uint8_t iv[16]);
int aes128_xts_decrypt_basic(const uint8_t *in, uint8_t *out, size_t len,
                             const uint8_t key[32], const uint8_t iv[16]);

// 2. XTS 4-Way SIMD Tweak + AES-NI 流水线并行优化实现
int aes128_xts_encrypt_opt(const uint8_t *in, uint8_t *out, size_t len,
                           const uint8_t key[32], const uint8_t iv[16]);
int aes128_xts_decrypt_opt(const uint8_t *in, uint8_t *out, size_t len,
                           const uint8_t key[32], const uint8_t iv[16]);
#endif // MODES_H
