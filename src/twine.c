#include "twine.h"
#include <string.h>
#include <tmmintrin.h>

static const uint8_t twine_sbox[16] = {
    0xc, 0x0, 0xf, 0xa, 0x2, 0xb, 0x9, 0x5,
    0x8, 0x3, 0xd, 0x7, 0x1, 0xe, 0x6, 0x4};

static const uint8_t twine_pi[16] = {
    5, 0, 1, 4, 7, 12, 3, 8, 13, 6, 9, 2, 15, 10, 11, 14};

static const uint8_t twine_pi_inv[16] = {
    1, 2, 11, 6, 3, 0, 9, 4, 7, 10, 13, 14, 5, 8, 15, 12};

static const uint8_t twine_con[TWINE_ROUNDS] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x03, 0x06, 0x0c,
    0x18, 0x30, 0x23, 0x05, 0x0a, 0x14, 0x28, 0x13, 0x26,
    0x0f, 0x1e, 0x3c, 0x3b, 0x35, 0x29, 0x11, 0x22, 0x07,
    0x0e, 0x1c, 0x38, 0x33, 0x25, 0x09, 0x12, 0x24, 0x0b};

static void bytes_to_nibbles(const uint8_t in[8], uint8_t n[16])
{
    for (unsigned i = 0; i < 8; ++i) {
        n[2U * i] = in[i] >> 4;
        n[2U * i + 1U] = in[i] & 0x0f;
    }
}

static void nibbles_to_bytes(const uint8_t n[16], uint8_t out[8])
{
    for (unsigned i = 0; i < 8; ++i)
        out[i] = (uint8_t)((n[2U * i] << 4) | n[2U * i + 1U]);
}

static void extract_round_key(const uint8_t wk[32], uint8_t rk[8])
{
    static const uint8_t index[8] = {2, 3, 12, 15, 17, 18, 28, 31};
    for (unsigned i = 0; i < 8; ++i)
        rk[i] = wk[index[i]];
}

static void prepare_shuffle_key(twine128_key_schedule *schedule, unsigned round)
{
    memset(schedule->rk_shuffle[round], 0, 16);
    for (unsigned i = 0; i < 8; ++i)
        schedule->rk_shuffle[round][2U * i + 1U] = schedule->rk[round][i];
}

void twine128_key_expansion(const uint8_t key[16], twine128_key_schedule *schedule)
{
    uint8_t wk[32], temp[4];
    for (unsigned i = 0; i < 16; ++i) {
        wk[2U * i] = key[i] >> 4;
        wk[2U * i + 1U] = key[i] & 0x0f;
    }
    extract_round_key(wk, schedule->rk[0]);
    prepare_shuffle_key(schedule, 0);
    for (unsigned round = 1; round < TWINE_ROUNDS; ++round) {
        wk[1] ^= twine_sbox[wk[0]];
        wk[4] ^= twine_sbox[wk[16]];
        wk[23] ^= twine_sbox[wk[30]];
        wk[7] ^= twine_con[round - 1U] >> 3;
        wk[19] ^= twine_con[round - 1U] & 7U;
        memcpy(temp, wk, sizeof(temp));
        memmove(wk, wk + 4, 28);
        wk[28] = temp[1];
        wk[29] = temp[2];
        wk[30] = temp[3];
        wk[31] = temp[0];
        extract_round_key(wk, schedule->rk[round]);
        prepare_shuffle_key(schedule, round);
    }
}

static void round_f(uint8_t state[16], const uint8_t rk[8])
{
    for (unsigned i = 0; i < 8; ++i)
        state[2U * i + 1U] ^= twine_sbox[state[2U * i] ^ rk[i]];
}

void twine128_encrypt_basic(const uint8_t in[8], uint8_t out[8],
                            const twine128_key_schedule *schedule)
{
    uint8_t state[16], next[16];
    bytes_to_nibbles(in, state);
    for (unsigned round = 0; round < TWINE_ROUNDS - 1U; ++round) {
        round_f(state, schedule->rk[round]);
        for (unsigned i = 0; i < 16; ++i)
            next[twine_pi[i]] = state[i];
        memcpy(state, next, sizeof(state));
    }
    round_f(state, schedule->rk[TWINE_ROUNDS - 1U]);
    nibbles_to_bytes(state, out);
}

void twine128_decrypt_basic(const uint8_t in[8], uint8_t out[8],
                            const twine128_key_schedule *schedule)
{
    uint8_t state[16], prev[16];
    bytes_to_nibbles(in, state);
    for (int round = TWINE_ROUNDS - 1; round >= 1; --round) {
        round_f(state, schedule->rk[round]);
        for (unsigned i = 0; i < 16; ++i)
            prev[twine_pi_inv[i]] = state[i];
        memcpy(state, prev, sizeof(state));
    }
    round_f(state, schedule->rk[0]);
    nibbles_to_bytes(state, out);
}

void twine128_encrypt_shuffle(const uint8_t in[8], uint8_t out[8],
                              const twine128_key_schedule *schedule)
{
    static const uint8_t even_source[16] __attribute__((aligned(16))) = {
        0, 0, 0, 2, 0, 4, 0, 6, 0, 8, 0, 10, 0, 12, 0, 14};
    static const uint8_t odd_mask_data[16] __attribute__((aligned(16))) = {
        0, 0xff, 0, 0xff, 0, 0xff, 0, 0xff,
        0, 0xff, 0, 0xff, 0, 0xff, 0, 0xff};
    /* output[j] = input[pi^-1[j]] */
    static const uint8_t perm_mask_data[16] __attribute__((aligned(16))) = {
        1, 2, 11, 6, 3, 0, 9, 4, 7, 10, 13, 14, 5, 8, 15, 12};
    uint8_t n[16];
    bytes_to_nibbles(in, n);
    __m128i state = _mm_loadu_si128((const __m128i *)n);
    const __m128i sbox = _mm_loadu_si128((const __m128i *)twine_sbox);
    const __m128i even = _mm_load_si128((const __m128i *)even_source);
    const __m128i odd_mask = _mm_load_si128((const __m128i *)odd_mask_data);
    const __m128i perm = _mm_load_si128((const __m128i *)perm_mask_data);

    for (unsigned round = 0; round < TWINE_ROUNDS; ++round) {
        __m128i inputs = _mm_shuffle_epi8(state, even);
        inputs = _mm_xor_si128(inputs,
            _mm_loadu_si128((const __m128i *)schedule->rk_shuffle[round]));
        __m128i sub = _mm_and_si128(_mm_shuffle_epi8(sbox, inputs), odd_mask);
        state = _mm_xor_si128(state, sub);
        if (round != TWINE_ROUNDS - 1U)
            state = _mm_shuffle_epi8(state, perm);
    }
    _mm_storeu_si128((__m128i *)n, state);
    nibbles_to_bytes(n, out);
}

void twine128_encrypt_8way_shuffle(const uint8_t in[64], uint8_t out[64],
                                   const twine128_key_schedule *schedule)
{
    static const uint8_t even_source[16] __attribute__((aligned(16))) = {
        0, 0, 0, 2, 0, 4, 0, 6, 0, 8, 0, 10, 0, 12, 0, 14};
    static const uint8_t odd_mask_data[16] __attribute__((aligned(16))) = {
        0, 0xff, 0, 0xff, 0, 0xff, 0, 0xff,
        0, 0xff, 0, 0xff, 0, 0xff, 0, 0xff};
    static const uint8_t perm_mask_data[16] __attribute__((aligned(16))) = {
        1, 2, 11, 6, 3, 0, 9, 4, 7, 10, 13, 14, 5, 8, 15, 12};
    uint8_t n[8][16];
    __m128i state[8];
    for (unsigned b = 0; b < 8; ++b) {
        bytes_to_nibbles(in + b * 8U, n[b]);
        state[b] = _mm_loadu_si128((const __m128i *)n[b]);
    }
    const __m128i sbox = _mm_loadu_si128((const __m128i *)twine_sbox);
    const __m128i even = _mm_load_si128((const __m128i *)even_source);
    const __m128i odd_mask = _mm_load_si128((const __m128i *)odd_mask_data);
    const __m128i perm = _mm_load_si128((const __m128i *)perm_mask_data);
    for (unsigned round = 0; round < TWINE_ROUNDS; ++round) {
        const __m128i rk = _mm_loadu_si128(
            (const __m128i *)schedule->rk_shuffle[round]);
        for (unsigned b = 0; b < 8; ++b) {
            __m128i x = _mm_xor_si128(_mm_shuffle_epi8(state[b], even), rk);
            state[b] = _mm_xor_si128(state[b],
                _mm_and_si128(_mm_shuffle_epi8(sbox, x), odd_mask));
        }
        if (round != TWINE_ROUNDS - 1U)
            for (unsigned b = 0; b < 8; ++b)
                state[b] = _mm_shuffle_epi8(state[b], perm);
    }
    for (unsigned b = 0; b < 8; ++b) {
        _mm_storeu_si128((__m128i *)n[b], state[b]);
        nibbles_to_bytes(n[b], out + b * 8U);
    }
}
