#include "gift128.h"
#include <string.h>
#if defined(__BMI2__)
#include <immintrin.h>
#endif

static const uint8_t gift_sbox[16] = {
    0x1, 0xa, 0x4, 0xc, 0x6, 0xf, 0x3, 0x9,
    0x2, 0xd, 0xb, 0x7, 0x5, 0x0, 0x8, 0xe};

static const uint8_t gift_inv_sbox[16] = {
    0xd, 0x0, 0x8, 0x6, 0x2, 0xc, 0x4, 0xb,
    0xe, 0x7, 0x1, 0xa, 0x3, 0x9, 0xf, 0x5};

static const uint8_t gift_rc[GIFT128_ROUNDS] = {
    0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3e, 0x3d, 0x3b,
    0x37, 0x2f, 0x1e, 0x3c, 0x39, 0x33, 0x27, 0x0e,
    0x1d, 0x3a, 0x35, 0x2b, 0x16, 0x2c, 0x18, 0x30,
    0x21, 0x02, 0x05, 0x0b, 0x17, 0x2e, 0x1c, 0x38,
    0x31, 0x23, 0x06, 0x0d, 0x1b, 0x36, 0x2d, 0x1a};

static void bytes_to_nibbles_le(const uint8_t in[16], uint8_t n[32])
{
    for (unsigned i = 0; i < 16; ++i) {
        unsigned j = 15U - i;
        n[2U * j] = in[i] & 0x0f;
        n[2U * j + 1U] = in[i] >> 4;
    }
}

static void nibbles_le_to_bytes(const uint8_t n[32], uint8_t out[16])
{
    for (unsigned i = 0; i < 16; ++i) {
        unsigned j = 15U - i;
        out[i] = (uint8_t)((n[2U * j + 1U] << 4) | n[2U * j]);
    }
}

static uint32_t pack_key_bits(const uint8_t key_nibbles[32], unsigned first)
{
    uint32_t value = 0;
    for (unsigned i = 0; i < 8; ++i)
        value |= (uint32_t)key_nibbles[first + i] << (4U * i);
    return value;
}

static void update_key(uint8_t key[32])
{
    uint8_t temp[32];
    for (unsigned i = 0; i < 32; ++i)
        temp[i] = key[(i + 8U) & 31U];
    memcpy(key, temp, 24);
    key[24] = temp[27];
    key[25] = temp[24];
    key[26] = temp[25];
    key[27] = temp[26];
    key[28] = (uint8_t)(((temp[28] & 0x0c) >> 2) | ((temp[29] & 0x03) << 2));
    key[29] = (uint8_t)(((temp[29] & 0x0c) >> 2) | ((temp[30] & 0x03) << 2));
    key[30] = (uint8_t)(((temp[30] & 0x0c) >> 2) | ((temp[31] & 0x03) << 2));
    key[31] = (uint8_t)(((temp[31] & 0x0c) >> 2) | ((temp[28] & 0x03) << 2));
}

void gift128_key_expansion(const uint8_t key[16], gift128_key_schedule *schedule)
{
    uint8_t k[32];
    bytes_to_nibbles_le(key, k);
    for (unsigned round = 0; round < GIFT128_ROUNDS; ++round) {
        schedule->u[round] = pack_key_bits(k, 0);
        schedule->v[round] = pack_key_bits(k, 16);
        update_key(k);
    }
}

static unsigned perm_index(unsigned bit)
{
    unsigned nibble = bit >> 2;
    unsigned plane = bit & 3U;
    unsigned dest_nibble = (nibble >> 2) + 8U * ((plane - (nibble & 3U)) & 3U);
    return (dest_nibble << 2) | plane;
}

static void add_round_key_nibbles(uint8_t state[32], uint32_t u, uint32_t v,
                                  uint8_t rc)
{
    for (unsigned i = 0; i < 32; ++i) {
        state[i] ^= (uint8_t)(((u >> i) & 1U) << 1);
        state[i] ^= (uint8_t)(((v >> i) & 1U) << 2);
    }
    for (unsigned i = 0; i < 6; ++i)
        state[i] ^= (uint8_t)(((rc >> i) & 1U) << 3);
    state[31] ^= 8;
}

void gift128_encrypt_basic(const uint8_t in[16], uint8_t out[16],
                           const gift128_key_schedule *schedule)
{
    uint8_t state[32], next[32] = {0};
    bytes_to_nibbles_le(in, state);
    for (unsigned round = 0; round < GIFT128_ROUNDS; ++round) {
        for (unsigned i = 0; i < 32; ++i)
            state[i] = gift_sbox[state[i]];
        memset(next, 0, sizeof(next));
        for (unsigned bit = 0; bit < 128; ++bit) {
            unsigned dst = perm_index(bit);
            next[dst >> 2] |= (uint8_t)(((state[bit >> 2] >> (bit & 3U)) & 1U)
                                         << (dst & 3U));
        }
        memcpy(state, next, sizeof(state));
        add_round_key_nibbles(state, schedule->u[round], schedule->v[round],
                              gift_rc[round]);
    }
    nibbles_le_to_bytes(state, out);
}

void gift128_decrypt_basic(const uint8_t in[16], uint8_t out[16],
                           const gift128_key_schedule *schedule)
{
    uint8_t state[32], prev[32] = {0};
    bytes_to_nibbles_le(in, state);
    for (int round = GIFT128_ROUNDS - 1; round >= 0; --round) {
        add_round_key_nibbles(state, schedule->u[round], schedule->v[round],
                              gift_rc[round]);
        memset(prev, 0, sizeof(prev));
        for (unsigned bit = 0; bit < 128; ++bit) {
            unsigned src = perm_index(bit);
            prev[bit >> 2] |= (uint8_t)(((state[src >> 2] >> (src & 3U)) & 1U)
                                         << (bit & 3U));
        }
        for (unsigned i = 0; i < 32; ++i)
            state[i] = gift_inv_sbox[prev[i]];
    }
    nibbles_le_to_bytes(state, out);
}

static uint32_t perm_plane(uint32_t x, unsigned plane)
{
#if defined(__BMI2__)
    static const uint32_t masks[4] = {
        0x11111111U, 0x22222222U, 0x44444444U, 0x88888888U};
    uint32_t y = 0;
    for (unsigned r = 0; r < 4; ++r)
        y |= _pext_u32(x, masks[r]) << (8U * ((plane - r) & 3U));
    return y;
#else
    uint32_t y = 0;
    for (unsigned i = 0; i < 32; ++i) {
        unsigned d = (i >> 2) + 8U * ((plane - (i & 3U)) & 3U);
        y |= ((x >> i) & 1U) << d;
    }
    return y;
#endif
}

void gift128_encrypt_bitslice(const uint8_t in[16], uint8_t out[16],
                              const gift128_key_schedule *schedule)
{
    uint8_t n[32];
    uint32_t s0 = 0, s1 = 0, s2 = 0, s3 = 0;
    bytes_to_nibbles_le(in, n);
    for (unsigned i = 0; i < 32; ++i) {
        s0 |= (uint32_t)(n[i] & 1U) << i;
        s1 |= (uint32_t)((n[i] >> 1) & 1U) << i;
        s2 |= (uint32_t)((n[i] >> 2) & 1U) << i;
        s3 |= (uint32_t)((n[i] >> 3) & 1U) << i;
    }

    for (unsigned round = 0; round < GIFT128_ROUNDS; ++round) {
        /* GIFT S-box as a bitsliced Boolean circuit. */
        s1 ^= s0 & s2;
        s0 ^= s1 & s3;
        s2 ^= s0 | s1;
        s3 ^= s2;
        s1 ^= s3;
        s3 = ~s3;
        s2 ^= s0 & s1;
        { uint32_t t = s0; s0 = s3; s3 = t; }

        s0 = perm_plane(s0, 0);
        s1 = perm_plane(s1, 1);
        s2 = perm_plane(s2, 2);
        s3 = perm_plane(s3, 3);
        s1 ^= schedule->u[round];
        s2 ^= schedule->v[round];
        s3 ^= (uint32_t)gift_rc[round] | 0x80000000U;
    }

    for (unsigned i = 0; i < 32; ++i)
        n[i] = (uint8_t)(((s0 >> i) & 1U) | (((s1 >> i) & 1U) << 1) |
                         (((s2 >> i) & 1U) << 2) | (((s3 >> i) & 1U) << 3));
    nibbles_le_to_bytes(n, out);
}
