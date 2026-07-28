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
        uint8_t counters[64], keystream[64];

        memcpy(counters, ctr, 16);
        inc_ctr(ctr);
        memcpy(counters + 16, ctr, 16);
        inc_ctr(ctr);
        memcpy(counters + 32, ctr, 16);
        inc_ctr(ctr);
        memcpy(counters + 48, ctr, 16);
        inc_ctr(ctr);
        sm4_encrypt4_ttable(counters, keystream, rk);

        // 利用 SSE 128 位寄存器加速 XOR 密文写回
        __m128i p0 = _mm_loadu_si128((const __m128i *)(in + (i + 0) * 16));
        __m128i p1 = _mm_loadu_si128((const __m128i *)(in + (i + 1) * 16));
        __m128i p2 = _mm_loadu_si128((const __m128i *)(in + (i + 2) * 16));
        __m128i p3 = _mm_loadu_si128((const __m128i *)(in + (i + 3) * 16));

        __m128i k0 = _mm_loadu_si128((const __m128i *)keystream);
        __m128i k1 = _mm_loadu_si128((const __m128i *)(keystream + 16));
        __m128i k2 = _mm_loadu_si128((const __m128i *)(keystream + 32));
        __m128i k3 = _mm_loadu_si128((const __m128i *)(keystream + 48));

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
void gcm_gf_mul_basic(const uint8_t a[16], const uint8_t b[16], uint8_t res[16])
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

static inline __m128i gcm_reverse_bits(__m128i value)
{
    static const uint8_t reverse_nibble[16] __attribute__((aligned(16))) = {
        0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15};
    const __m128i table = _mm_load_si128((const __m128i *)reverse_nibble);
    const __m128i low_mask = _mm_set1_epi8(0x0f);
    __m128i low = _mm_and_si128(value, low_mask);
    __m128i high = _mm_and_si128(_mm_srli_epi16(value, 4), low_mask);
    low = _mm_shuffle_epi8(table, low);
    low = _mm_add_epi8(low, low);
    low = _mm_add_epi8(low, low);
    low = _mm_add_epi8(low, low);
    low = _mm_add_epi8(low, low);
    return _mm_or_si128(low, _mm_shuffle_epi8(table, high));
}

void gcm_gf_mul_pclmul(const uint8_t a[16], const uint8_t b[16], uint8_t res[16])
{
    __m128i x = gcm_reverse_bits(_mm_loadu_si128((const __m128i *)a));
    __m128i y = gcm_reverse_bits(_mm_loadu_si128((const __m128i *)b));

    __m128i z0 = _mm_clmulepi64_si128(x, y, 0x00);
    __m128i z1 = _mm_xor_si128(_mm_clmulepi64_si128(x, y, 0x01),
                               _mm_clmulepi64_si128(x, y, 0x10));
    __m128i z2 = _mm_clmulepi64_si128(x, y, 0x11);
    __m128i lo = _mm_xor_si128(z0, _mm_slli_si128(z1, 8));
    __m128i hi = _mm_xor_si128(z2, _mm_srli_si128(z1, 8));

    uint64_t p[4];
    _mm_storeu_si128((__m128i *)&p[0], lo);
    _mm_storeu_si128((__m128i *)&p[2], hi);

    /* x^128 = x^7 + x^2 + x + 1; fold the high half twice. */
    const __m128i poly = _mm_set_epi64x(0, 0x87);
    __m128i t0 = _mm_clmulepi64_si128(_mm_set_epi64x(0, (long long)p[2]), poly, 0x00);
    __m128i t1 = _mm_clmulepi64_si128(_mm_set_epi64x(0, (long long)p[3]), poly, 0x00);
    uint64_t f0[2], f1[2], f2[2];
    _mm_storeu_si128((__m128i *)f0, t0);
    _mm_storeu_si128((__m128i *)f1, t1);
    __m128i t2 = _mm_clmulepi64_si128(_mm_set_epi64x(0, (long long)f1[1]), poly, 0x00);
    _mm_storeu_si128((__m128i *)f2, t2);
    __m128i reduced = _mm_set_epi64x((long long)(p[1] ^ f0[1] ^ f1[0] ^ f2[1]),
                                     (long long)(p[0] ^ f0[0] ^ f2[0]));
    reduced = gcm_reverse_bits(reduced);
    _mm_storeu_si128((__m128i *)res, reduced);
}

// ---------------------------------------------------------------------------
// 2. GHASH 累加更新函数
// ---------------------------------------------------------------------------
typedef void (*gf_mul_fn)(const uint8_t[16], const uint8_t[16], uint8_t[16]);

static void ghash_update(uint8_t y[16], const uint8_t *data, size_t len,
                         const uint8_t h[16], gf_mul_fn multiply)
{
    size_t blocks = len / 16;
    for (size_t i = 0; i < blocks; i++)
    {
        for (int j = 0; j < 16; j++)
        {
            y[j] ^= data[i * 16 + j];
        }
        uint8_t tmp[16];
        multiply(y, h, tmp);
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
        multiply(y, h, tmp);
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
        ghash_update(Y, aad, aad_len, H, gcm_gf_mul_basic);
    }
    if (out && in_len > 0)
    {
        ghash_update(Y, out, in_len, H, gcm_gf_mul_basic);
    }

    uint8_t len_block[16] = {0};
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t in_bits = (uint64_t)in_len * 8;
    for (int i = 0; i < 8; i++)
    {
        len_block[7 - i] = (aad_bits >> (i * 8)) & 0xFF;
        len_block[15 - i] = (in_bits >> (i * 8)) & 0xFF;
    }
    ghash_update(Y, len_block, 16, H, gcm_gf_mul_basic);

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
        ghash_update(Y, aad, aad_len, H, gcm_gf_mul_pclmul);
    }
    if (out && in_len > 0)
    {
        ghash_update(Y, out, in_len, H, gcm_gf_mul_pclmul);
    }

    uint8_t len_block[16] = {0};
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t in_bits = (uint64_t)in_len * 8;
    for (int i = 0; i < 8; i++)
    {
        len_block[7 - i] = (aad_bits >> (i * 8)) & 0xFF;
        len_block[15 - i] = (in_bits >> (i * 8)) & 0xFF;
    }
    ghash_update(Y, len_block, 16, H, gcm_gf_mul_pclmul);

    uint8_t ek_j0[16];
    aes128_encrypt_ni(J0, ek_j0, rk);
    for (int i = 0; i < 16; i++)
    {
        tag[i] = Y[i] ^ ek_j0[i];
    }
}

static int constant_time_tag_equal(const uint8_t a[16], const uint8_t b[16])
{
    uint8_t diff = 0;
    for (unsigned i = 0; i < 16; ++i)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

static void gcm_length_block(size_t text_len, size_t aad_len, uint8_t block[16])
{
    uint64_t aad_bits = (uint64_t)aad_len * 8U;
    uint64_t text_bits = (uint64_t)text_len * 8U;
    memset(block, 0, 16);
    for (unsigned i = 0; i < 8; ++i) {
        block[7U - i] = (uint8_t)(aad_bits >> (8U * i));
        block[15U - i] = (uint8_t)(text_bits >> (8U * i));
    }
}

static int gcm_decrypt_common(const uint8_t *in, size_t in_len,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t key[16], const uint8_t iv[12],
                              const uint8_t tag[16], uint8_t *out, int optimized)
{
    uint8_t H[16] = {0}, J0[16] = {0}, Y[16] = {0};
    uint8_t len_block[16], expected[16], ek_j0[16];
    gf_mul_fn multiply = optimized ? gcm_gf_mul_pclmul : gcm_gf_mul_basic;
    memcpy(J0, iv, 12);
    J0[15] = 1;

    if (optimized) {
        __m128i rk[11];
        aes128_key_expansion_ni(key, rk);
        aes128_encrypt_ni(H, H, rk);
        aes128_encrypt_ni(J0, ek_j0, rk);
    } else {
        uint8_t rk[176];
        aes128_key_expansion_basic(key, rk);
        aes128_encrypt_basic(H, H, rk);
        aes128_encrypt_basic(J0, ek_j0, rk);
    }
    if (aad && aad_len)
        ghash_update(Y, aad, aad_len, H, multiply);
    if (in && in_len)
        ghash_update(Y, in, in_len, H, multiply);
    gcm_length_block(in_len, aad_len, len_block);
    ghash_update(Y, len_block, 16, H, multiply);
    for (unsigned i = 0; i < 16; ++i)
        expected[i] = Y[i] ^ ek_j0[i];
    if (!constant_time_tag_equal(expected, tag)) {
        if (out && in_len) memset(out, 0, in_len);
        return 0;
    }

    uint8_t ctr[16];
    memcpy(ctr, J0, 16);
    inc_ctr(ctr);
    if (optimized)
        aes128_ctr_encrypt_parallel(in, out, in_len, key, ctr);
    else
        aes128_ctr_encrypt_basic(in, out, in_len, key, ctr);
    return 1;
}

int aes128_gcm_decrypt_basic(const uint8_t *in, size_t in_len,
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t key[16], const uint8_t iv[12],
                             const uint8_t tag[16], uint8_t *out)
{
    return gcm_decrypt_common(in, in_len, aad, aad_len, key, iv, tag, out, 0);
}

int aes128_gcm_decrypt_opt(const uint8_t *in, size_t in_len,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t key[16], const uint8_t iv[12],
                           const uint8_t tag[16], uint8_t *out)
{
    return gcm_decrypt_common(in, in_len, aad, aad_len, key, iv, tag, out, 1);
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
static void xts_block_basic(const uint8_t in[16], uint8_t out[16],
                            const uint8_t tweak[16], const uint8_t rk[176],
                            int decrypt)
{
    uint8_t x[16], y[16];
    for (unsigned i = 0; i < 16; ++i) x[i] = in[i] ^ tweak[i];
    if (decrypt) aes128_decrypt_basic(x, y, rk);
    else aes128_encrypt_basic(x, y, rk);
    for (unsigned i = 0; i < 16; ++i) out[i] = y[i] ^ tweak[i];
}

static int xts_crypt_basic(const uint8_t *in, uint8_t *out, size_t len,
                           const uint8_t key[32], const uint8_t iv[16], int decrypt)
{
    if (len < 16) return 0;
    uint8_t rk1[176], rk2[176], tweak[16];
    aes128_key_expansion_basic(key, rk1);
    aes128_key_expansion_basic(key + 16, rk2);
    aes128_encrypt_basic(iv, tweak, rk2);
    size_t blocks = len / 16;
    size_t rem = len % 16;
    size_t normal = blocks - (rem != 0);
    for (size_t i = 0; i < normal; ++i) {
        xts_block_basic(in + 16 * i, out + 16 * i, tweak, rk1, decrypt);
        gf128_mul_alpha(tweak);
    }
    if (!rem) return 1;

    uint8_t next_tweak[16], a[16], b[16];
    memcpy(next_tweak, tweak, 16);
    gf128_mul_alpha(next_tweak);
    size_t off = normal * 16;
    if (!decrypt) {
        xts_block_basic(in + off, a, tweak, rk1, 0);
        memcpy(b, in + off + 16, rem);
        memcpy(b + rem, a + rem, 16 - rem);
        xts_block_basic(b, out + off, next_tweak, rk1, 0);
        memcpy(out + off + 16, a, rem);
    } else {
        xts_block_basic(in + off, a, next_tweak, rk1, 1);
        memcpy(b, in + off + 16, rem);
        memcpy(out + off + 16, a, rem);
        memcpy(b + rem, a + rem, 16 - rem);
        xts_block_basic(b, out + off, tweak, rk1, 1);
    }
    return 1;
}

int aes128_xts_encrypt_basic(const uint8_t *in, uint8_t *out, size_t len,
                             const uint8_t key[32], const uint8_t iv[16])
{
    return xts_crypt_basic(in, out, len, key, iv, 0);
}

int aes128_xts_decrypt_basic(const uint8_t *in, uint8_t *out, size_t len,
                             const uint8_t key[32], const uint8_t iv[16])
{
    return xts_crypt_basic(in, out, len, key, iv, 1);
}

// ---------------------------------------------------------------------------
// 2. AES-128 XTS 优化实现 (4-Way Tweak 向量化 + 4-Way AES-NI 并行)
// ---------------------------------------------------------------------------
static inline __m128i aesni_crypt_vec(__m128i x, const __m128i rk[11], int decrypt)
{
    x = _mm_xor_si128(x, rk[0]);
    if (decrypt) {
        for (unsigned r = 1; r < 10; ++r) x = _mm_aesdec_si128(x, rk[r]);
        return _mm_aesdeclast_si128(x, rk[10]);
    }
    for (unsigned r = 1; r < 10; ++r) x = _mm_aesenc_si128(x, rk[r]);
    return _mm_aesenclast_si128(x, rk[10]);
}

static int xts_crypt_opt(const uint8_t *in, uint8_t *out, size_t len,
                         const uint8_t key[32], const uint8_t iv[16], int decrypt)
{
    if (len < 16) return 0;
    __m128i enc1[11], rk1[11], rk2[11];
    aes128_key_expansion_ni(key, enc1);
    aes128_key_expansion_ni(key + 16, rk2);
    if (decrypt) aes128_key_expansion_dec_ni(enc1, rk1);
    else memcpy(rk1, enc1, sizeof(rk1));
    uint8_t tweak_buf[16];
    aes128_encrypt_ni(iv, tweak_buf, rk2);
    __m128i tweak = _mm_loadu_si128((const __m128i *)tweak_buf);
    size_t blocks = len / 16, rem = len % 16;
    size_t normal = blocks - (rem != 0), i = 0;

    for (; i + 3 < normal; i += 4) {
        __m128i t[4];
        t[0] = tweak;
        t[1] = gf128_mul_alpha_vec(t[0]);
        t[2] = gf128_mul_alpha_vec(t[1]);
        t[3] = gf128_mul_alpha_vec(t[2]);
        __m128i x[4];
        for (unsigned b = 0; b < 4; ++b)
            x[b] = _mm_xor_si128(_mm_loadu_si128(
                (const __m128i *)(in + 16 * (i + b))), t[b]);
        for (unsigned r = 0; r < 11; ++r) {
            if (r == 0) {
                for (unsigned b = 0; b < 4; ++b) x[b] = _mm_xor_si128(x[b], rk1[0]);
            } else if (r == 10) {
                for (unsigned b = 0; b < 4; ++b)
                    x[b] = decrypt ? _mm_aesdeclast_si128(x[b], rk1[10])
                                   : _mm_aesenclast_si128(x[b], rk1[10]);
            } else {
                for (unsigned b = 0; b < 4; ++b)
                    x[b] = decrypt ? _mm_aesdec_si128(x[b], rk1[r])
                                   : _mm_aesenc_si128(x[b], rk1[r]);
            }
        }
        for (unsigned b = 0; b < 4; ++b)
            _mm_storeu_si128((__m128i *)(out + 16 * (i + b)), _mm_xor_si128(x[b], t[b]));
        tweak = gf128_mul_alpha_vec(t[3]);
    }
    for (; i < normal; ++i) {
        __m128i x = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(in + 16 * i)), tweak);
        x = aesni_crypt_vec(x, rk1, decrypt);
        _mm_storeu_si128((__m128i *)(out + 16 * i), _mm_xor_si128(x, tweak));
        tweak = gf128_mul_alpha_vec(tweak);
    }
    if (!rem) return 1;

    size_t off = normal * 16;
    __m128i next = gf128_mul_alpha_vec(tweak);
    uint8_t a[16], b[16];
    if (!decrypt) {
        __m128i x = aesni_crypt_vec(_mm_xor_si128(
            _mm_loadu_si128((const __m128i *)(in + off)), tweak), rk1, 0);
        _mm_storeu_si128((__m128i *)a, _mm_xor_si128(x, tweak));
        memcpy(b, in + off + 16, rem);
        memcpy(b + rem, a + rem, 16 - rem);
        x = aesni_crypt_vec(_mm_xor_si128(_mm_loadu_si128((const __m128i *)b), next), rk1, 0);
        _mm_storeu_si128((__m128i *)(out + off), _mm_xor_si128(x, next));
        memcpy(out + off + 16, a, rem);
    } else {
        __m128i x = aesni_crypt_vec(_mm_xor_si128(
            _mm_loadu_si128((const __m128i *)(in + off)), next), rk1, 1);
        _mm_storeu_si128((__m128i *)a, _mm_xor_si128(x, next));
        memcpy(b, in + off + 16, rem);
        memcpy(out + off + 16, a, rem);
        memcpy(b + rem, a + rem, 16 - rem);
        x = aesni_crypt_vec(_mm_xor_si128(_mm_loadu_si128((const __m128i *)b), tweak), rk1, 1);
        _mm_storeu_si128((__m128i *)(out + off), _mm_xor_si128(x, tweak));
    }
    return 1;
}

int aes128_xts_encrypt_opt(const uint8_t *in, uint8_t *out, size_t len,
                           const uint8_t key[32], const uint8_t iv[16])
{
    return xts_crypt_opt(in, out, len, key, iv, 0);
}

int aes128_xts_decrypt_opt(const uint8_t *in, uint8_t *out, size_t len,
                           const uint8_t key[32], const uint8_t iv[16])
{
    return xts_crypt_opt(in, out, len, key, iv, 1);
}
