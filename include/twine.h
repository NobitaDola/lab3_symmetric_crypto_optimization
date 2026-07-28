#ifndef TWINE_H
#define TWINE_H

#include <stdint.h>

#define TWINE_BLOCK_SIZE 8
#define TWINE128_KEY_SIZE 16
#define TWINE_ROUNDS 36

typedef struct {
    uint8_t rk[TWINE_ROUNDS][8];
    uint8_t rk_shuffle[TWINE_ROUNDS][16];
} twine128_key_schedule;

void twine128_key_expansion(const uint8_t key[TWINE128_KEY_SIZE],
                            twine128_key_schedule *schedule);
void twine128_encrypt_basic(const uint8_t in[TWINE_BLOCK_SIZE],
                            uint8_t out[TWINE_BLOCK_SIZE],
                            const twine128_key_schedule *schedule);
void twine128_decrypt_basic(const uint8_t in[TWINE_BLOCK_SIZE],
                            uint8_t out[TWINE_BLOCK_SIZE],
                            const twine128_key_schedule *schedule);

/* SSSE3 PSHUFB implementation of the parallel nibble S-box and block shuffle. */
void twine128_encrypt_shuffle(const uint8_t in[TWINE_BLOCK_SIZE],
                              uint8_t out[TWINE_BLOCK_SIZE],
                              const twine128_key_schedule *schedule);
void twine128_encrypt_8way_shuffle(const uint8_t in[8 * TWINE_BLOCK_SIZE],
                                   uint8_t out[8 * TWINE_BLOCK_SIZE],
                                   const twine128_key_schedule *schedule);

#endif
