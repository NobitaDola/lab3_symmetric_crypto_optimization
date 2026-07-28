#ifndef GIFT128_H
#define GIFT128_H

#include <stdint.h>

#define GIFT128_BLOCK_SIZE 16
#define GIFT128_KEY_SIZE 16
#define GIFT128_ROUNDS 40

typedef struct {
    uint32_t u[GIFT128_ROUNDS];
    uint32_t v[GIFT128_ROUNDS];
} gift128_key_schedule;

void gift128_key_expansion(const uint8_t key[GIFT128_KEY_SIZE],
                           gift128_key_schedule *schedule);

/* Straightforward nibble/bit-permutation implementation. */
void gift128_encrypt_basic(const uint8_t in[GIFT128_BLOCK_SIZE],
                           uint8_t out[GIFT128_BLOCK_SIZE],
                           const gift128_key_schedule *schedule);
void gift128_decrypt_basic(const uint8_t in[GIFT128_BLOCK_SIZE],
                           uint8_t out[GIFT128_BLOCK_SIZE],
                           const gift128_key_schedule *schedule);

/* 32-bit bitsliced implementation; uses BMI2 PEXT/PDEP when available. */
void gift128_encrypt_bitslice(const uint8_t in[GIFT128_BLOCK_SIZE],
                              uint8_t out[GIFT128_BLOCK_SIZE],
                              const gift128_key_schedule *schedule);

#endif
