#include "sm4.h"
#include <string.h>
#include <immintrin.h> // SSSE3 & SSE4.1 硬件指令集

// SM4 字节替换盒 (S-Box)
static const uint8_t sbox[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48};

// 系统固定参数 FK
static const uint32_t FK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};

// 辅助内联工具函数
static inline uint32_t rotl32(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

static inline uint32_t load_u32_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void store_u32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static inline uint32_t get_ck(int i)
{
    uint8_t c0 = (7 * (4 * i + 0)) & 0xFF;
    uint8_t c1 = (7 * (4 * i + 1)) & 0xFF;
    uint8_t c2 = (7 * (4 * i + 2)) & 0xFF;
    uint8_t c3 = (7 * (4 * i + 3)) & 0xFF;
    return ((uint32_t)c0 << 24) | ((uint32_t)c1 << 16) | ((uint32_t)c2 << 8) | c3;
}

// S-Box 逐字代换 S(x)
static inline uint32_t sm4_sub_word(uint32_t x)
{
    return ((uint32_t)sbox[(x >> 24) & 0xFF] << 24) |
           ((uint32_t)sbox[(x >> 16) & 0xFF] << 16) |
           ((uint32_t)sbox[(x >> 8) & 0xFF] << 8) |
           (uint32_t)sbox[x & 0xFF];
}

// 线性变换 L(b) - 用于加密轮函数
static inline uint32_t sm4_l_enc(uint32_t b)
{
    return b ^ rotl32(b, 2) ^ rotl32(b, 10) ^ rotl32(b, 18) ^ rotl32(b, 24);
}

// 线性变换 L'(b) - 用于密钥扩展
static inline uint32_t sm4_l_key(uint32_t b)
{
    return b ^ rotl32(b, 13) ^ rotl32(b, 23);
}

static inline uint32_t sm4_t_enc(uint32_t x)
{
    return sm4_l_enc(sm4_sub_word(x));
}

static inline uint32_t sm4_t_key(uint32_t x)
{
    return sm4_l_key(sm4_sub_word(x));
}

// ---------------------------------------------------------------------------
// 1. 标准 C 密钥扩展实现
// ---------------------------------------------------------------------------
void sm4_key_expansion_basic(const uint8_t *key, uint32_t *rk)
{
    uint32_t k[36];
    k[0] = load_u32_be(key) ^ FK[0];
    k[1] = load_u32_be(key + 4) ^ FK[1];
    k[2] = load_u32_be(key + 8) ^ FK[2];
    k[3] = load_u32_be(key + 12) ^ FK[3];

    for (int i = 0; i < 32; i++)
    {
        k[i + 4] = k[i] ^ sm4_t_key(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ get_ck(i));
        rk[i] = k[i + 4];
    }
}

// ---------------------------------------------------------------------------
// 2. Basic SM4 加密实现
// ---------------------------------------------------------------------------
void sm4_encrypt_basic(const uint8_t *in, uint8_t *out, const uint32_t *rk)
{
    uint32_t x[36];
    x[0] = load_u32_be(in);
    x[1] = load_u32_be(in + 4);
    x[2] = load_u32_be(in + 8);
    x[3] = load_u32_be(in + 12);

    for (int i = 0; i < 32; i++)
    {
        x[i + 4] = x[i] ^ sm4_t_enc(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i]);
    }

    // 反序输出 (X35, X34, X33, X32)
    store_u32_be(out, x[35]);
    store_u32_be(out + 4, x[34]);
    store_u32_be(out + 8, x[33]);
    store_u32_be(out + 12, x[32]);
}

void sm4_decrypt_basic(const uint8_t *in, uint8_t *out, const uint32_t *rk)
{
    uint32_t reversed[32];
    for (unsigned i = 0; i < 32; ++i)
        reversed[i] = rk[31U - i];
    sm4_encrypt_basic(in, out, reversed);
}

// ---------------------------------------------------------------------------
// 3. T-Table 优化实现 (32位T表 + 4路循环展开)
// ---------------------------------------------------------------------------
static uint32_t T0[256], T1[256], T2[256], T3[256];
static int sm4_ttables_initialized = 0;

void sm4_init_ttables(void)
{
    if (sm4_ttables_initialized)
        return;
    for (int i = 0; i < 256; i++)
    {
        uint32_t s = (uint32_t)sbox[i];
        T0[i] = sm4_l_enc(s << 24);
        T1[i] = rotl32(T0[i], 24);
        T2[i] = rotl32(T0[i], 16);
        T3[i] = rotl32(T0[i], 8);
    }
    sm4_ttables_initialized = 1;
}

void sm4_encrypt_ttable(const uint8_t *in, uint8_t *out, const uint32_t *rk)
{
    uint32_t x0 = load_u32_be(in);
    uint32_t x1 = load_u32_be(in + 4);
    uint32_t x2 = load_u32_be(in + 8);
    uint32_t x3 = load_u32_be(in + 12);

    for (int i = 0; i < 32; i += 4)
    {
        uint32_t t0 = x1 ^ x2 ^ x3 ^ rk[i];
        x0 ^= T0[(t0 >> 24) & 0xFF] ^ T1[(t0 >> 16) & 0xFF] ^ T2[(t0 >> 8) & 0xFF] ^ T3[t0 & 0xFF];

        uint32_t t1 = x2 ^ x3 ^ x0 ^ rk[i + 1];
        x1 ^= T0[(t1 >> 24) & 0xFF] ^ T1[(t1 >> 16) & 0xFF] ^ T2[(t1 >> 8) & 0xFF] ^ T3[t1 & 0xFF];

        uint32_t t2 = x3 ^ x0 ^ x1 ^ rk[i + 2];
        x2 ^= T0[(t2 >> 24) & 0xFF] ^ T1[(t2 >> 16) & 0xFF] ^ T2[(t2 >> 8) & 0xFF] ^ T3[t2 & 0xFF];

        uint32_t t3 = x0 ^ x1 ^ x2 ^ rk[i + 3];
        x3 ^= T0[(t3 >> 24) & 0xFF] ^ T1[(t3 >> 16) & 0xFF] ^ T2[(t3 >> 8) & 0xFF] ^ T3[t3 & 0xFF];
    }

    store_u32_be(out, x3);
    store_u32_be(out + 4, x2);
    store_u32_be(out + 8, x1);
    store_u32_be(out + 12, x0);
}

void sm4_encrypt4_ttable(const uint8_t in[64], uint8_t out[64], const uint32_t *rk)
{
    uint32_t x0[4], x1[4], x2[4], x3[4];
    for (unsigned b = 0; b < 4; ++b) {
        x0[b] = load_u32_be(in + 16U * b);
        x1[b] = load_u32_be(in + 16U * b + 4);
        x2[b] = load_u32_be(in + 16U * b + 8);
        x3[b] = load_u32_be(in + 16U * b + 12);
    }
    for (unsigned round = 0; round < 32; round += 4) {
        for (unsigned b = 0; b < 4; ++b) {
            uint32_t t = x1[b] ^ x2[b] ^ x3[b] ^ rk[round];
            x0[b] ^= T0[t >> 24] ^ T1[(t >> 16) & 255] ^ T2[(t >> 8) & 255] ^ T3[t & 255];
        }
        for (unsigned b = 0; b < 4; ++b) {
            uint32_t t = x2[b] ^ x3[b] ^ x0[b] ^ rk[round + 1];
            x1[b] ^= T0[t >> 24] ^ T1[(t >> 16) & 255] ^ T2[(t >> 8) & 255] ^ T3[t & 255];
        }
        for (unsigned b = 0; b < 4; ++b) {
            uint32_t t = x3[b] ^ x0[b] ^ x1[b] ^ rk[round + 2];
            x2[b] ^= T0[t >> 24] ^ T1[(t >> 16) & 255] ^ T2[(t >> 8) & 255] ^ T3[t & 255];
        }
        for (unsigned b = 0; b < 4; ++b) {
            uint32_t t = x0[b] ^ x1[b] ^ x2[b] ^ rk[round + 3];
            x3[b] ^= T0[t >> 24] ^ T1[(t >> 16) & 255] ^ T2[(t >> 8) & 255] ^ T3[t & 255];
        }
    }
    for (unsigned b = 0; b < 4; ++b) {
        store_u32_be(out + 16U * b, x3[b]);
        store_u32_be(out + 16U * b + 4, x2[b]);
        store_u32_be(out + 16U * b + 8, x1[b]);
        store_u32_be(out + 16U * b + 12, x0[b]);
    }
}

// ---------------------------------------------------------------------------
// 4. SIMD Shuffle 优化实现 (基于 SSSE3 _mm_shuffle_epi8 指令)
// ---------------------------------------------------------------------------
void sm4_encrypt_shuffle(const uint8_t *in, uint8_t *out, const uint32_t *rk)
{
    // 1. 使用 SSSE3 _mm_shuffle_epi8 高效加载 Big-Endian 数据并完成字节序重排
    __m128i state = _mm_loadu_si128((const __m128i *)in);
    static const uint8_t bswap_mask_data[16] __attribute__((aligned(16))) = {
        3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12};
    __m128i bswap_mask = _mm_load_si128((const __m128i *)bswap_mask_data);
    state = _mm_shuffle_epi8(state, bswap_mask);

    // 提取为 4 个 32 位寄存器状态
    uint32_t x0 = (uint32_t)_mm_cvtsi128_si32(state);
    uint32_t x1 = (uint32_t)_mm_extract_epi32(state, 1);
    uint32_t x2 = (uint32_t)_mm_extract_epi32(state, 2);
    uint32_t x3 = (uint32_t)_mm_extract_epi32(state, 3);

    // 2. 32 轮迭代计算 (T-Table + 4路展开)
    for (int i = 0; i < 32; i += 4)
    {
        uint32_t t0 = x1 ^ x2 ^ x3 ^ rk[i];
        x0 ^= T0[(t0 >> 24) & 0xFF] ^ T1[(t0 >> 16) & 0xFF] ^ T2[(t0 >> 8) & 0xFF] ^ T3[t0 & 0xFF];

        uint32_t t1 = x2 ^ x3 ^ x0 ^ rk[i + 1];
        x1 ^= T0[(t1 >> 24) & 0xFF] ^ T1[(t1 >> 16) & 0xFF] ^ T2[(t1 >> 8) & 0xFF] ^ T3[t1 & 0xFF];

        uint32_t t2 = x3 ^ x0 ^ x1 ^ rk[i + 2];
        x2 ^= T0[(t2 >> 24) & 0xFF] ^ T1[(t2 >> 16) & 0xFF] ^ T2[(t2 >> 8) & 0xFF] ^ T3[t2 & 0xFF];

        uint32_t t3 = x0 ^ x1 ^ x2 ^ rk[i + 3];
        x3 ^= T0[(t3 >> 24) & 0xFF] ^ T1[(t3 >> 16) & 0xFF] ^ T2[(t3 >> 8) & 0xFF] ^ T3[t3 & 0xFF];
    }

    // 3. 使用 SSSE3 _mm_shuffle_epi8 将反序结果 (x3, x2, x1, x0) 一次性写回内存
    __m128i res = _mm_set_epi32((int)x0, (int)x1, (int)x2, (int)x3);
    res = _mm_shuffle_epi8(res, bswap_mask);
    _mm_storeu_si128((__m128i *)out, res);
}
