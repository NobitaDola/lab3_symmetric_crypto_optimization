#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <wmmintrin.h> // AES-NI Intrinsics

// 1. 标准 AES 密钥扩展
void aes128_key_expansion_basic(const uint8_t *key, uint8_t *round_keys);

// 2. 三种加密实现
void aes128_encrypt_basic(const uint8_t *in, uint8_t *out, const uint8_t *round_keys);
void aes128_decrypt_basic(const uint8_t *in, uint8_t *out, const uint8_t *round_keys);

void aes128_init_ttables(void);
void aes128_encrypt_ttable(const uint8_t *in, uint8_t *out, const uint8_t *round_keys);

void aes128_key_expansion_ni(const uint8_t *key, __m128i *key_schedule);
void aes128_encrypt_ni(const uint8_t *in, uint8_t *out, const __m128i *key_schedule);
void aes128_key_expansion_dec_ni(const __m128i *enc_schedule, __m128i *dec_schedule);
void aes128_decrypt_ni(const uint8_t *in, uint8_t *out, const __m128i *dec_schedule);

#endif // AES_H
