#include "aes.h"
#include <string.h>

// S-Box 盒
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

static const uint8_t rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

// 有限域 GF(2^8) 乘 2
static inline uint8_t xtime(uint8_t x)
{
    return (x << 1) ^ ((x >> 7) * 0x1b);
}

// ---------------------------------------------------------------------------
// 1. 标准 C 实现密钥扩展
// ---------------------------------------------------------------------------
void aes128_key_expansion_basic(const uint8_t *key, uint8_t *round_keys)
{
    memcpy(round_keys, key, 16);
    uint8_t temp[4];
    int bytes_generated = 16;
    int rcon_iteration = 0;

    while (bytes_generated < 176)
    {
        for (int i = 0; i < 4; i++)
        {
            temp[i] = round_keys[bytes_generated - 4 + i];
        }

        if (bytes_generated % 16 == 0)
        {
            // RotWord
            uint8_t k = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = k;

            // SubWord
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];

            // Rcon
            temp[0] ^= rcon[rcon_iteration++];
        }

        for (int i = 0; i < 4; i++)
        {
            round_keys[bytes_generated] = round_keys[bytes_generated - 16] ^ temp[i];
            bytes_generated++;
        }
    }
}

// ---------------------------------------------------------------------------
// 2. Basic AES 加密实现
// ---------------------------------------------------------------------------
void aes128_encrypt_basic(const uint8_t *in, uint8_t *out, const uint8_t *round_keys)
{
    uint8_t state[16];
    for (int i = 0; i < 16; i++)
        state[i] = in[i] ^ round_keys[i];

    for (int round = 1; round <= 10; round++)
    {
        uint8_t temp[16];
        // SubBytes & ShiftRows
        temp[0] = sbox[state[0]];
        temp[4] = sbox[state[4]];
        temp[8] = sbox[state[8]];
        temp[12] = sbox[state[12]];
        temp[1] = sbox[state[5]];
        temp[5] = sbox[state[9]];
        temp[9] = sbox[state[13]];
        temp[13] = sbox[state[1]];
        temp[2] = sbox[state[10]];
        temp[6] = sbox[state[14]];
        temp[10] = sbox[state[2]];
        temp[14] = sbox[state[6]];
        temp[3] = sbox[state[15]];
        temp[7] = sbox[state[3]];
        temp[11] = sbox[state[7]];
        temp[15] = sbox[state[11]];

        if (round < 10)
        {
            // MixColumns
            for (int i = 0; i < 4; i++)
            {
                uint8_t a = temp[i * 4];
                uint8_t b = temp[i * 4 + 1];
                uint8_t c = temp[i * 4 + 2];
                uint8_t d = temp[i * 4 + 3];
                uint8_t e = a ^ b ^ c ^ d;
                state[i * 4] = a ^ e ^ xtime(a ^ b);
                state[i * 4 + 1] = b ^ e ^ xtime(b ^ c);
                state[i * 4 + 2] = c ^ e ^ xtime(c ^ d);
                state[i * 4 + 3] = d ^ e ^ xtime(d ^ a);
            }
        }
        else
        {
            memcpy(state, temp, 16);
        }

        const uint8_t *rk = round_keys + round * 16;
        for (int i = 0; i < 16; i++)
            state[i] ^= rk[i];
    }
    memcpy(out, state, 16);
}

// ---------------------------------------------------------------------------
// 3. T-Table 优化实现
// ---------------------------------------------------------------------------
static uint32_t T0[256], T1[256], T2[256], T3[256];
static int ttables_initialized = 0;

void aes128_init_ttables(void)
{
    if (ttables_initialized)
        return;
    for (int i = 0; i < 256; i++)
    {
        uint8_t s = sbox[i];
        uint8_t s2 = xtime(s);
        uint8_t s3 = s2 ^ s;

        // 大端模式排列，匹配字节列
        T0[i] = ((uint32_t)s2 << 24) | ((uint32_t)s << 16) | ((uint32_t)s << 8) | (uint32_t)s3;
        T1[i] = (T0[i] >> 8) | (T0[i] << 24);
        T2[i] = (T0[i] >> 16) | (T0[i] << 16);
        T3[i] = (T0[i] >> 24) | (T0[i] << 8);
    }
    ttables_initialized = 1;
}

void aes128_encrypt_ttable(const uint8_t *in, uint8_t *out, const uint8_t *round_keys)
{
    uint32_t s0, s1, s2, s3, t0, t1, t2, t3;

    // 按字节安全装载 state，防止大小端错位
    s0 = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | ((uint32_t)in[2] << 8) | in[3];
    s1 = ((uint32_t)in[4] << 24) | ((uint32_t)in[5] << 16) | ((uint32_t)in[6] << 8) | in[7];
    s2 = ((uint32_t)in[8] << 24) | ((uint32_t)in[9] << 16) | ((uint32_t)in[10] << 8) | in[11];
    s3 = ((uint32_t)in[12] << 24) | ((uint32_t)in[13] << 16) | ((uint32_t)in[14] << 8) | in[15];

    // Round 0 AddRoundKey
    const uint8_t *rk = round_keys;
    s0 ^= ((uint32_t)rk[0] << 24) | ((uint32_t)rk[1] << 16) | ((uint32_t)rk[2] << 8) | rk[3];
    s1 ^= ((uint32_t)rk[4] << 24) | ((uint32_t)rk[5] << 16) | ((uint32_t)rk[6] << 8) | rk[7];
    s2 ^= ((uint32_t)rk[8] << 24) | ((uint32_t)rk[9] << 16) | ((uint32_t)rk[10] << 8) | rk[11];
    s3 ^= ((uint32_t)rk[12] << 24) | ((uint32_t)rk[13] << 16) | ((uint32_t)rk[14] << 8) | rk[15];

    for (int r = 1; r < 10; r++)
    {
        rk += 16;
        uint32_t rk0 = ((uint32_t)rk[0] << 24) | ((uint32_t)rk[1] << 16) | ((uint32_t)rk[2] << 8) | rk[3];
        uint32_t rk1 = ((uint32_t)rk[4] << 24) | ((uint32_t)rk[5] << 16) | ((uint32_t)rk[6] << 8) | rk[7];
        uint32_t rk2 = ((uint32_t)rk[8] << 24) | ((uint32_t)rk[9] << 16) | ((uint32_t)rk[10] << 8) | rk[11];
        uint32_t rk3 = ((uint32_t)rk[12] << 24) | ((uint32_t)rk[13] << 16) | ((uint32_t)rk[14] << 8) | rk[15];

        t0 = T0[s0 >> 24] ^ T1[(s1 >> 16) & 0xff] ^ T2[(s2 >> 8) & 0xff] ^ T3[s3 & 0xff] ^ rk0;
        t1 = T0[s1 >> 24] ^ T1[(s2 >> 16) & 0xff] ^ T2[(s3 >> 8) & 0xff] ^ T3[s0 & 0xff] ^ rk1;
        t2 = T0[s2 >> 24] ^ T1[(s3 >> 16) & 0xff] ^ T2[(s0 >> 8) & 0xff] ^ T3[s1 & 0xff] ^ rk2;
        t3 = T0[s3 >> 24] ^ T1[(s0 >> 16) & 0xff] ^ T2[(s1 >> 8) & 0xff] ^ T3[s2 & 0xff] ^ rk3;

        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
    }

    // 最后一轮 (Round 10)
    rk += 16;
    out[0] = sbox[s0 >> 24] ^ rk[0];
    out[1] = sbox[(s1 >> 16) & 0xff] ^ rk[1];
    out[2] = sbox[(s2 >> 8) & 0xff] ^ rk[2];
    out[3] = sbox[s3 & 0xff] ^ rk[3];

    out[4] = sbox[s1 >> 24] ^ rk[4];
    out[5] = sbox[(s2 >> 16) & 0xff] ^ rk[5];
    out[6] = sbox[(s3 >> 8) & 0xff] ^ rk[6];
    out[7] = sbox[s0 & 0xff] ^ rk[7];

    out[8] = sbox[s2 >> 24] ^ rk[8];
    out[9] = sbox[(s3 >> 16) & 0xff] ^ rk[9];
    out[10] = sbox[(s0 >> 8) & 0xff] ^ rk[10];
    out[11] = sbox[s1 & 0xff] ^ rk[11];

    out[12] = sbox[s3 >> 24] ^ rk[12];
    out[13] = sbox[(s0 >> 16) & 0xff] ^ rk[13];
    out[14] = sbox[(s1 >> 8) & 0xff] ^ rk[14];
    out[15] = sbox[s2 & 0xff] ^ rk[15];
}

// ---------------------------------------------------------------------------
// 4. AES-NI 硬件扩展指令实现
// ---------------------------------------------------------------------------
#define AES_KEY_EXP(k, rcon) _mm_aeskeygenassist_si128(k, rcon)
static __m128i aes128_key_expand_assistant(__m128i key, __m128i keygened)
{
    keygened = _mm_shuffle_epi32(keygened, 0xff);
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygened);
}

void aes128_key_expansion_ni(const uint8_t *key, __m128i *comp_rk)
{
    comp_rk[0] = _mm_loadu_si128((const __m128i *)key);
    comp_rk[1] = aes128_key_expand_assistant(comp_rk[0], AES_KEY_EXP(comp_rk[0], 0x01));
    comp_rk[2] = aes128_key_expand_assistant(comp_rk[1], AES_KEY_EXP(comp_rk[1], 0x02));
    comp_rk[3] = aes128_key_expand_assistant(comp_rk[2], AES_KEY_EXP(comp_rk[2], 0x04));
    comp_rk[4] = aes128_key_expand_assistant(comp_rk[3], AES_KEY_EXP(comp_rk[3], 0x08));
    comp_rk[5] = aes128_key_expand_assistant(comp_rk[4], AES_KEY_EXP(comp_rk[4], 0x10));
    comp_rk[6] = aes128_key_expand_assistant(comp_rk[5], AES_KEY_EXP(comp_rk[5], 0x20));
    comp_rk[7] = aes128_key_expand_assistant(comp_rk[6], AES_KEY_EXP(comp_rk[6], 0x40));
    comp_rk[8] = aes128_key_expand_assistant(comp_rk[7], AES_KEY_EXP(comp_rk[7], 0x80));
    comp_rk[9] = aes128_key_expand_assistant(comp_rk[8], AES_KEY_EXP(comp_rk[8], 0x1B));
    comp_rk[10] = aes128_key_expand_assistant(comp_rk[9], AES_KEY_EXP(comp_rk[9], 0x36));
}

void aes128_encrypt_ni(const uint8_t *in, uint8_t *out, const __m128i *comp_rk)
{
    __m128i m = _mm_loadu_si128((const __m128i *)in);
    m = _mm_xor_si128(m, comp_rk[0]);
    m = _mm_aesenc_si128(m, comp_rk[1]);
    m = _mm_aesenc_si128(m, comp_rk[2]);
    m = _mm_aesenc_si128(m, comp_rk[3]);
    m = _mm_aesenc_si128(m, comp_rk[4]);
    m = _mm_aesenc_si128(m, comp_rk[5]);
    m = _mm_aesenc_si128(m, comp_rk[6]);
    m = _mm_aesenc_si128(m, comp_rk[7]);
    m = _mm_aesenc_si128(m, comp_rk[8]);
    m = _mm_aesenc_si128(m, comp_rk[9]);
    m = _mm_aesenclast_si128(m, comp_rk[10]);
    _mm_storeu_si128((__m128i *)out, m);
}