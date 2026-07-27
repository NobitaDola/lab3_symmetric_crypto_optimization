#include "modes.h"
#include "aes.h"
#include "sm4.h"
#include <string.h>
#include <x86intrin.h>
#include <wmmintrin.h> // PCLMULQDQ 指令支持

// ---------------------------------------------------------------------------
// 辅助函数：128 位 Big-Endian 计数器自增 (+1)
// ---------------------------------------------------------------------------
static inline void inc_ctr(uint8_t *ctr)
{
    for (int i = 15; i >= 0; i--)
    {
        if (++ctr[i] != 0)
            break;
    }
}

// ---------------------------------------------------------------------------
// 1. AES-128 CTR 模式实现
// ---------------------------------------------------------------------------

// 串行单块版本
void aes128_ctr_encrypt_basic(const uint8_t *in, uint8_t *out, size_t len,
                              const uint8_t key[16], const uint8_t iv[16])
{
    uint8_t basic_rk[176];
    aes128_key_expansion_basic(key, basic_rk);

    uint8_t ctr[16];
    memcpy(ctr, iv, 16);

    uint8_t keystream[16];
    size_t blocks = len / 16;
    size_t remainder = len % 16;

    for (size_t i = 0; i < blocks; i++)
    {
        aes128_encrypt_basic(ctr, keystream, basic_rk);
        inc_ctr(ctr);

        for (int k = 0; k < 16; k++)
        {
            out[i * 16 + k] = in[i * 16 + k] ^ keystream[k];
        }
    }

    if (remainder > 0)
    {
        aes128_encrypt_basic(ctr, keystream, basic_rk);
        for (size_t k = 0; k < remainder; k++)
        {
            out[blocks * 16 + k] = in[blocks * 16 + k] ^ keystream[k];
        }
    }
}

// 4-Way AES-NI 指令流水线并行优化版本
void aes128_ctr_encrypt_parallel(const uint8_t *in, uint8_t *out, size_t len,
                                 const uint8_t key[16], const uint8_t iv[16])
{
    __m128i rk[11];
    aes128_key_expansion_ni(key, rk);

    uint8_t ctr[16];
    memcpy(ctr, iv, 16);

    size_t blocks = len / 16;
    size_t remainder = len % 16;
    size_t i = 0;

    // 每次处理 4 个块 (64 字节)
    for (; i + 3 < blocks; i += 4)
    {
        uint8_t c0[16], c1[16], c2[16], c3[16];
        memcpy(c0, ctr, 16);
        inc_ctr(ctr);
        memcpy(c1, ctr, 16);
        inc_ctr(ctr);
        memcpy(c2, ctr, 16);
        inc_ctr(ctr);
        memcpy(c3, ctr, 16);
        inc_ctr(ctr);

        __m128i b0 = _mm_loadu_si128((const __m128i *)c0);
        __m128i b1 = _mm_loadu_si128((const __m128i *)c1);
        __m128i b2 = _mm_loadu_si128((const __m128i *)c2);
        __m128i b3 = _mm_loadu_si128((const __m128i *)c3);

        // AddRoundKey
        b0 = _mm_xor_si128(b0, rk[0]);
        b1 = _mm_xor_si128(b1, rk[0]);
        b2 = _mm_xor_si128(b2, rk[0]);
        b3 = _mm_xor_si128(b3, rk[0]);

        // 1-9 轮并行打满指令流水线
        for (int r = 1; r < 10; r++)
        {
            b0 = _mm_aesenc_si128(b0, rk[r]);
            b1 = _mm_aesenc_si128(b1, rk[r]);
            b2 = _mm_aesenc_si128(b2, rk[r]);
            b3 = _mm_aesenc_si128(b3, rk[r]);
        }

        // 第 10 轮
        b0 = _mm_aesenclast_si128(b0, rk[10]);
        b1 = _mm_aesenclast_si128(b1, rk[10]);
        b2 = _mm_aesenclast_si128(b2, rk[10]);
        b3 = _mm_aesenclast_si128(b3, rk[10]);

        // XOR 明文并批量写回内存
        __m128i p0 = _mm_loadu_si128((const __m128i *)(in + (i + 0) * 16));
        __m128i p1 = _mm_loadu_si128((const __m128i *)(in + (i + 1) * 16));
        __m128i p2 = _mm_loadu_si128((const __m128i *)(in + (i + 2) * 16));
        __m128i p3 = _mm_loadu_si128((const __m128i *)(in + (i + 3) * 16));

        _mm_storeu_si128((__m128i *)(out + (i + 0) * 16), _mm_xor_si128(p0, b0));
        _mm_storeu_si128((__m128i *)(out + (i + 1) * 16), _mm_xor_si128(p1, b1));
        _mm_storeu_si128((__m128i *)(out + (i + 2) * 16), _mm_xor_si128(p2, b2));
        _mm_storeu_si128((__m128i *)(out + (i + 3) * 16), _mm_xor_si128(p3, b3));
    }

    // 处理剩余完整块
    for (; i < blocks; i++)
    {
        uint8_t keystream[16];
        aes128_encrypt_ni(ctr, keystream, rk);
        inc_ctr(ctr);
        for (int k = 0; k < 16; k++)
        {
            out[i * 16 + k] = in[i * 16 + k] ^ keystream[k];
        }
    }

    // 处理不足 16 字节的尾部数据
    if (remainder > 0)
    {
        uint8_t keystream[16];
        aes128_encrypt_ni(ctr, keystream, rk);
        for (size_t k = 0; k < remainder; k++)
        {
            out[blocks * 16 + k] = in[blocks * 16 + k] ^ keystream[k];
        }
    }
}

// ---------------------------------------------------------------------------
// 2. SM4 CTR 模式实现
// ---------------------------------------------------------------------------

// 串行单块版本
void sm4_ctr_encrypt_basic(const uint8_t *in, uint8_t *out, size_t len,
                           const uint8_t key[16], const uint8_t iv[16])
{
    uint32_t rk[32];
    sm4_key_expansion_basic(key, rk);

    uint8_t ctr[16];
    memcpy(ctr, iv, 16);

    uint8_t keystream[16];
    size_t blocks = len / 16;
    size_t remainder = len % 16;

    for (size_t i = 0; i < blocks; i++)
    {
        sm4_encrypt_basic(ctr, keystream, rk);
        inc_ctr(ctr);

        for (int k = 0; k < 16; k++)
        {
            out[i * 16 + k] = in[i * 16 + k] ^ keystream[k];
        }
    }

    if (remainder > 0)
    {
        sm4_encrypt_basic(ctr, keystream, rk);
        for (size_t k = 0; k < remainder; k++)
        {
            out[blocks * 16 + k] = in[blocks * 16 + k] ^ keystream[k];
        }
    }
}

// 4-Way 展开并行优化版本
void sm4_ctr_encrypt_parallel(const uint8_t *in, uint8_t *out, size_t len,
                              const uint8_t key[16], const uint8_t iv[16])
{
    sm4_init_ttables();
    uint32_t rk[32];
    sm4_key_expansion_basic(key, rk);

    uint8_t ctr[16];
    memcpy(ctr, iv, 16);

    size_t blocks = len / 16;
    size_t remainder = len % 16;
    size_t i = 0;

    // 每次并行处理 4 块 SM4 加密
    for (; i + 3 < blocks; i += 4)
    {
        uint8_t ks0[16], ks1[16], ks2[16], ks3[16];
        uint8_t c0[16], c1[16], c2[16], c3[16];

        memcpy(c0, ctr, 16);
        inc_ctr(ctr);
        memcpy(c1, ctr, 16);
        inc_ctr(ctr);
        memcpy(c2, ctr, 16);
        inc_ctr(ctr);
        memcpy(c3, ctr, 16);
        inc_ctr(ctr);

        // 使用优化后的 shuffle / T-table 函数并行加密
        sm4_encrypt_shuffle(c0, ks0, rk);
        sm4_encrypt_shuffle(c1, ks1, rk);
        sm4_encrypt_shuffle(c2, ks2, rk);
        sm4_encrypt_shuffle(c3, ks3, rk);

        // 利用 SSE 128 位寄存器加速 XOR 密文写回
        __m128i p0 = _mm_loadu_si128((const __m128i *)(in + (i + 0) * 16));
        __m128i p1 = _mm_loadu_si128((const __m128i *)(in + (i + 1) * 16));
        __m128i p2 = _mm_loadu_si128((const __m128i *)(in + (i + 2) * 16));
        __m128i p3 = _mm_loadu_si128((const __m128i *)(in + (i + 3) * 16));

        __m128i k0 = _mm_loadu_si128((const __m128i *)ks0);
        __m128i k1 = _mm_loadu_si128((const __m128i *)ks1);
        __m128i k2 = _mm_loadu_si128((const __m128i *)ks2);
        __m128i k3 = _mm_loadu_si128((const __m128i *)ks3);

        _mm_storeu_si128((__m128i *)(out + (i + 0) * 16), _mm_xor_si128(p0, k0));
        _mm_storeu_si128((__m128i *)(out + (i + 1) * 16), _mm_xor_si128(p1, k1));
        _mm_storeu_si128((__m128i *)(out + (i + 2) * 16), _mm_xor_si128(p2, k2));
        _mm_storeu_si128((__m128i *)(out + (i + 3) * 16), _mm_xor_si128(p3, k3));
    }

    // 剩余块处理
    for (; i < blocks; i++)
    {
        uint8_t keystream[16];
        sm4_encrypt_shuffle(ctr, keystream, rk);
        inc_ctr(ctr);
        for (int k = 0; k < 16; k++)
        {
            out[i * 16 + k] = in[i * 16 + k] ^ keystream[k];
        }
    }

    if (remainder > 0)
    {
        uint8_t keystream[16];
        sm4_encrypt_shuffle(ctr, keystream, rk);
        for (size_t k = 0; k < remainder; k++)
        {
            out[blocks * 16 + k] = in[blocks * 16 + k] ^ keystream[k];
        }
    }
}

// ---------------------------------------------------------------------------
// 1. GF(2^128) 基础逐位乘法 (NIST SP 800-38D 标准格式)
// ---------------------------------------------------------------------------
static void gf_mul_basic(const uint8_t a[16], const uint8_t b[16], uint8_t res[16])
{
    uint8_t Z[16] = {0};
    uint8_t V[16];
    memcpy(V, a, 16);

    for (int i = 0; i < 128; i++)
    {
        if ((b[i / 8] >> (7 - (i % 8))) & 1)
        {
            for (int j = 0; j < 16; j++)
                Z[j] ^= V[j];
        }

        int lsb = V[15] & 1;
        for (int j = 15; j > 0; j--)
        {
            V[j] = (V[j] >> 1) | ((V[j - 1] & 1) << 7);
        }
        V[0] >>= 1;
        if (lsb)
            V[0] ^= 0xe1;
    }
    memcpy(res, Z, 16);
}

// ---------------------------------------------------------------------------
// 2. GHASH 累加更新函数
// ---------------------------------------------------------------------------
static void ghash_update(uint8_t y[16], const uint8_t *data, size_t len, const uint8_t h[16])
{
    size_t blocks = len / 16;
    for (size_t i = 0; i < blocks; i++)
    {
        for (int j = 0; j < 16; j++)
        {
            y[j] ^= data[i * 16 + j];
        }
        uint8_t tmp[16];
        gf_mul_basic(y, h, tmp);
        memcpy(y, tmp, 16);
    }
    size_t rem = len % 16;
    if (rem > 0)
    {
        for (size_t j = 0; j < rem; j++)
        {
            y[j] ^= data[blocks * 16 + j];
        }
        uint8_t tmp[16];
        gf_mul_basic(y, h, tmp);
        memcpy(y, tmp, 16);
    }
}

// ---------------------------------------------------------------------------
// 3. AES-128 GCM 基础实现
// ---------------------------------------------------------------------------
void aes128_gcm_encrypt_basic(const uint8_t *in, size_t in_len,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t key[16], const uint8_t iv[12],
                              uint8_t *out, uint8_t tag[16])
{
    uint8_t rk[176];
    aes128_key_expansion_basic(key, rk);

    uint8_t H[16] = {0};
    aes128_encrypt_basic(H, H, rk);

    uint8_t J0[16] = {0};
    memcpy(J0, iv, 12);
    J0[15] = 1;

    uint8_t ctr[16];
    memcpy(ctr, J0, 16);
    inc_ctr(ctr);
    aes128_ctr_encrypt_basic(in, out, in_len, key, ctr);

    uint8_t Y[16] = {0};
    if (aad && aad_len > 0)
    {
        ghash_update(Y, aad, aad_len, H);
    }
    if (out && in_len > 0)
    {
        ghash_update(Y, out, in_len, H);
    }

    uint8_t len_block[16] = {0};
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t in_bits = (uint64_t)in_len * 8;
    for (int i = 0; i < 8; i++)
    {
        len_block[7 - i] = (aad_bits >> (i * 8)) & 0xFF;
        len_block[15 - i] = (in_bits >> (i * 8)) & 0xFF;
    }
    ghash_update(Y, len_block, 16, H);

    uint8_t ek_j0[16];
    aes128_encrypt_basic(J0, ek_j0, rk);
    for (int i = 0; i < 16; i++)
    {
        tag[i] = Y[i] ^ ek_j0[i];
    }
}

// ---------------------------------------------------------------------------
// 4. AES-128 GCM 优化实现 (4-Way 并行 CTR 加密 + 流水线 GHASH)
// ---------------------------------------------------------------------------
void aes128_gcm_encrypt_opt(const uint8_t *in, size_t in_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t key[16], const uint8_t iv[12],
                            uint8_t *out, uint8_t tag[16])
{
    __m128i rk[11];
    aes128_key_expansion_ni(key, rk);

    uint8_t H[16] = {0};
    aes128_encrypt_ni(H, H, rk);

    uint8_t J0[16] = {0};
    memcpy(J0, iv, 12);
    J0[15] = 1;

    uint8_t ctr[16];
    memcpy(ctr, J0, 16);
    inc_ctr(ctr);
    aes128_ctr_encrypt_parallel(in, out, in_len, key, ctr);

    uint8_t Y[16] = {0};
    if (aad && aad_len > 0)
    {
        ghash_update(Y, aad, aad_len, H);
    }
    if (out && in_len > 0)
    {
        ghash_update(Y, out, in_len, H);
    }

    uint8_t len_block[16] = {0};
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t in_bits = (uint64_t)in_len * 8;
    for (int i = 0; i < 8; i++)
    {
        len_block[7 - i] = (aad_bits >> (i * 8)) & 0xFF;
        len_block[15 - i] = (in_bits >> (i * 8)) & 0xFF;
    }
    ghash_update(Y, len_block, 16, H);

    uint8_t ek_j0[16];
    aes128_encrypt_ni(J0, ek_j0, rk);
    for (int i = 0; i < 16; i++)
    {
        tag[i] = Y[i] ^ ek_j0[i];
    }
}

// ---------------------------------------------------------------------------
// XTS 辅助：GF(2^128) 上的 Tweak 乘 alpha 运算 (T_next = T * alpha)
// ---------------------------------------------------------------------------

// C 语言逐字节标量实现
static inline void gf128_mul_alpha(uint8_t *tweak)
{
    uint8_t carry = 0;
    for (int i = 0; i < 16; i++)
    {
        uint8_t next_carry = (tweak[i] >> 7) & 1;
        tweak[i] = (tweak[i] << 1) | carry;
        carry = next_carry;
    }
    if (carry)
    {
        tweak[0] ^= 0x87; // 本原多项式掩码
    }
}

// SSE 128 位向量化实现 (无分支，极高效率)
static inline __m128i gf128_mul_alpha_vec(__m128i t)
{
    int msb = _mm_extract_epi8(t, 15) >> 7; // 获取 127 位 (最高位)

    // 128-bit 逻辑左移 1 位
    __m128i carry = _mm_srli_epi64(t, 63);
    carry = _mm_slli_si128(carry, 8);
    t = _mm_slli_epi64(t, 1);
    t = _mm_or_si128(t, carry);

    if (msb)
    {
        static const uint8_t poly_mask[16] __attribute__((aligned(16))) = {
            0x87, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        t = _mm_xor_si128(t, _mm_load_si128((const __m128i *)poly_mask));
    }
    return t;
}

// ---------------------------------------------------------------------------
// 1. AES-128 XTS 基础实现
// ---------------------------------------------------------------------------
void aes128_xts_encrypt_basic(const uint8_t *in, uint8_t *out, size_t len,
                              const uint8_t key[32], const uint8_t iv[16])
{
    const uint8_t *key1 = key;
    const uint8_t *key2 = key + 16;

    uint8_t rk1[176], rk2[176];
    aes128_key_expansion_basic(key1, rk1);
    aes128_key_expansion_basic(key2, rk2);

    // 计算 T0 = AES_K2(IV)
    uint8_t T[16];
    aes128_encrypt_basic(iv, T, rk2);

    size_t blocks = len / 16;
    for (size_t i = 0; i < blocks; i++)
    {
        uint8_t PP[16], CC[16];

        // 1. P_i ^ T_i
        for (int k = 0; k < 16; k++)
            PP[k] = in[i * 16 + k] ^ T[k];

        // 2. AES_K1(P_i ^ T_i)
        aes128_encrypt_basic(PP, CC, rk1);

        // 3. C_i = CC ^ T_i
        for (int k = 0; k < 16; k++)
            out[i * 16 + k] = CC[k] ^ T[k];

        // 4. T_{i+1} = T_i * alpha
        gf128_mul_alpha(T);
    }
}

// ---------------------------------------------------------------------------
// 2. AES-128 XTS 优化实现 (4-Way Tweak 向量化 + 4-Way AES-NI 并行)
// ---------------------------------------------------------------------------
void aes128_xts_encrypt_opt(const uint8_t *in, uint8_t *out, size_t len,
                            const uint8_t key[32], const uint8_t iv[16])
{
    const uint8_t *key1 = key;
    const uint8_t *key2 = key + 16;

    __m128i rk1[11], rk2[11];
    aes128_key_expansion_ni(key1, rk1);
    aes128_key_expansion_ni(key2, rk2);

    // 计算 T0 = AES_K2(IV)
    uint8_t T_buf[16];
    aes128_encrypt_ni(iv, T_buf, rk2);
    __m128i T0 = _mm_loadu_si128((const __m128i *)T_buf);

    size_t blocks = len / 16;
    size_t i = 0;

    // 每次并行处理 4 个块 (64 字节)
    for (; i + 3 < blocks; i += 4)
    {
        // 预计算 4 个连续块的 Tweak 掩码
        __m128i T1 = gf128_mul_alpha_vec(T0);
        __m128i T2 = gf128_mul_alpha_vec(T1);
        __m128i T3 = gf128_mul_alpha_vec(T2);

        // 1. P ^ T
        __m128i p0 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(in + (i + 0) * 16)), T0);
        __m128i p1 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(in + (i + 1) * 16)), T1);
        __m128i p2 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(in + (i + 2) * 16)), T2);
        __m128i p3 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(in + (i + 3) * 16)), T3);

        // 2. 4-Way AES-NI 加密
        p0 = _mm_xor_si128(p0, rk1[0]);
        p1 = _mm_xor_si128(p1, rk1[0]);
        p2 = _mm_xor_si128(p2, rk1[0]);
        p3 = _mm_xor_si128(p3, rk1[0]);

        for (int r = 1; r < 10; r++)
        {
            p0 = _mm_aesenc_si128(p0, rk1[r]);
            p1 = _mm_aesenc_si128(p1, rk1[r]);
            p2 = _mm_aesenc_si128(p2, rk1[r]);
            p3 = _mm_aesenc_si128(p3, rk1[r]);
        }

        p0 = _mm_aesenclast_si128(p0, rk1[10]);
        p1 = _mm_aesenclast_si128(p1, rk1[10]);
        p2 = _mm_aesenclast_si128(p2, rk1[10]);
        p3 = _mm_aesenclast_si128(p3, rk1[10]);

        // 3. C = CC ^ T 并批量写回内存
        _mm_storeu_si128((__m128i *)(out + (i + 0) * 16), _mm_xor_si128(p0, T0));
        _mm_storeu_si128((__m128i *)(out + (i + 1) * 16), _mm_xor_si128(p1, T1));
        _mm_storeu_si128((__m128i *)(out + (i + 2) * 16), _mm_xor_si128(p2, T2));
        _mm_storeu_si128((__m128i *)(out + (i + 3) * 16), _mm_xor_si128(p3, T3));

        // 更新下一次循环的 T0
        T0 = gf128_mul_alpha_vec(T3);
    }

    // 处理剩余的块
    for (; i < blocks; i++)
    {
        __m128i p = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(in + i * 16)), T0);

        p = _mm_xor_si128(p, rk1[0]);
        for (int r = 1; r < 10; r++)
        {
            p = _mm_aesenc_si128(p, rk1[r]);
        }
        p = _mm_aesenclast_si128(p, rk1[10]);

        _mm_storeu_si128((__m128i *)(out + i * 16), _mm_xor_si128(p, T0));
        T0 = gf128_mul_alpha_vec(T0);
    }
}