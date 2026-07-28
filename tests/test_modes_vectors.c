#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "modes.h"

static int eq(const char *name, const uint8_t *a, const uint8_t *b, size_t n)
{
    if (memcmp(a, b, n) == 0) return 1;
    fprintf(stderr, "[ERROR] %s\n", name);
    fprintf(stderr, "actual:   ");
    for (size_t i = 0; i < n; ++i) fprintf(stderr, "%02x", a[i]);
    fprintf(stderr, "\nexpected: ");
    for (size_t i = 0; i < n; ++i) fprintf(stderr, "%02x", b[i]);
    fprintf(stderr, "\n");
    return 0;
}

static uint32_t prng_state = 0x12345678U;
static uint8_t next_byte(void)
{
    prng_state ^= prng_state << 13;
    prng_state ^= prng_state >> 17;
    prng_state ^= prng_state << 5;
    return (uint8_t)prng_state;
}

static int test_gf(void)
{
    uint8_t a[16], b[16], basic[16], opt[16];
    memset(a, 0, 16); memset(b, 0, 16);
    a[0] = 0x12; a[15] = 0x34; b[0] = 0x80;
    gcm_gf_mul_basic(a, b, basic);
    gcm_gf_mul_pclmul(a, b, opt);
    if (!eq("PCLMULQDQ identity test", opt, basic, 16)) return 0;
    for (unsigned test = 0; test < 1000; ++test) {
        for (unsigned i = 0; i < 16; ++i) { a[i] = next_byte(); b[i] = next_byte(); }
        gcm_gf_mul_basic(a, b, basic);
        gcm_gf_mul_pclmul(a, b, opt);
        if (!eq("PCLMULQDQ GF(2^128) differential test", opt, basic, 16)) return 0;
    }
    return 1;
}

static int test_ctr(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    static const uint8_t iv[16] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff};
    static const uint8_t pt[64] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
        0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
        0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
        0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
    static const uint8_t ct[64] = {
        0x87,0x4d,0x61,0x91,0xb6,0x20,0xe3,0x26,0x1b,0xef,0x68,0x64,0x99,0x0d,0xb6,0xce,
        0x98,0x06,0xf6,0x6b,0x79,0x70,0xfd,0xff,0x86,0x17,0x18,0x7b,0xb9,0xff,0xfd,0xff,
        0x5a,0xe4,0xdf,0x3e,0xdb,0xd5,0xd3,0x5e,0x5b,0x4f,0x09,0x02,0x0d,0xb0,0x3e,0xab,
        0x1e,0x03,0x1d,0xda,0x2f,0xbe,0x03,0xd1,0x79,0x21,0x70,0xa0,0xf3,0x00,0x9c,0xee};
    uint8_t out[64], recovered[64];
    aes128_ctr_encrypt_basic(pt, out, 64, key, iv);
    if (!eq("AES-CTR basic NIST vector", out, ct, 64)) return 0;
    aes128_ctr_encrypt_parallel(pt, out, 64, key, iv);
    if (!eq("AES-CTR optimized NIST vector", out, ct, 64)) return 0;
    aes128_ctr_encrypt_parallel(out, recovered, 64, key, iv);
    return eq("AES-CTR decrypt", recovered, pt, 64);
}

static int test_gcm(void)
{
    static const uint8_t zero[16] = {0};
    static const uint8_t iv[12] = {0};
    static const uint8_t ct_expected[16] = {
        0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78};
    static const uint8_t tag_expected[16] = {
        0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf};
    uint8_t out[16], tag[16], recovered[16], bad_tag[16];
    aes128_gcm_encrypt_basic(zero, 16, NULL, 0, zero, iv, out, tag);
    if (!eq("AES-GCM basic ciphertext", out, ct_expected, 16) ||
        !eq("AES-GCM basic tag", tag, tag_expected, 16)) return 0;
    aes128_gcm_encrypt_opt(zero, 16, NULL, 0, zero, iv, out, tag);
    if (!eq("AES-GCM PCLMUL ciphertext", out, ct_expected, 16) ||
        !eq("AES-GCM PCLMUL tag", tag, tag_expected, 16)) return 0;
    if (!aes128_gcm_decrypt_basic(out, 16, NULL, 0, zero, iv, tag, recovered) ||
        !eq("AES-GCM basic decrypt", recovered, zero, 16)) return 0;
    if (!aes128_gcm_decrypt_opt(out, 16, NULL, 0, zero, iv, tag, recovered) ||
        !eq("AES-GCM optimized decrypt", recovered, zero, 16)) return 0;
    memcpy(bad_tag, tag, 16); bad_tag[0] ^= 1;
    memset(recovered, 0xa5, 16);
    if (aes128_gcm_decrypt_opt(out, 16, NULL, 0, zero, iv, bad_tag, recovered)) {
        fprintf(stderr, "[ERROR] AES-GCM accepted an invalid tag\n"); return 0;
    }
    return eq("AES-GCM clears unauthenticated plaintext", recovered, zero, 16);
}

static int test_xts(void)
{
    static const uint8_t xts31_expected[31] = {
        0x37,0x92,0x5d,0x55,0x23,0x4e,0xce,0x8a,0x7e,0x59,0xaa,0xbf,0xfe,0x56,0x4a,0xdc,
        0xad,0x96,0x34,0xc2,0x54,0xbe,0xe9,0x59,0xe4,0xa0,0xa1,0xe4,0xec,0xe8,0xd3};
    uint8_t key[32], iv[16], pt[80], basic[80], opt[80], recovered[80], inplace[80];
    for (unsigned i = 0; i < sizeof(key); ++i) key[i] = (uint8_t)i;
    for (unsigned i = 0; i < sizeof(iv); ++i) iv[i] = (uint8_t)(0xf0U + i);
    for (unsigned i = 0; i < sizeof(pt); ++i) pt[i] = (uint8_t)(3U * i + 1U);
    static const size_t lengths[] = {16, 17, 31, 32, 47, 64, 79};
    if (aes128_xts_encrypt_basic(pt, basic, 15, key, iv) != 0 ||
        aes128_xts_encrypt_opt(pt, opt, 15, key, iv) != 0) {
        fprintf(stderr, "[ERROR] XTS accepted a data unit shorter than one block\n"); return 0;
    }
    for (unsigned n = 0; n < sizeof(lengths)/sizeof(lengths[0]); ++n) {
        size_t len = lengths[n];
        if (!aes128_xts_encrypt_basic(pt, basic, len, key, iv) ||
            !aes128_xts_encrypt_opt(pt, opt, len, key, iv) ||
            !eq("AES-XTS basic/optimized", basic, opt, len)) return 0;
        if (!aes128_xts_decrypt_basic(basic, recovered, len, key, iv) ||
            !eq("AES-XTS basic round trip", recovered, pt, len)) return 0;
        if (!aes128_xts_decrypt_opt(opt, recovered, len, key, iv) ||
            !eq("AES-XTS optimized round trip", recovered, pt, len)) return 0;
        memcpy(inplace, pt, len);
        if (!aes128_xts_encrypt_opt(inplace, inplace, len, key, iv) ||
            !aes128_xts_decrypt_opt(inplace, inplace, len, key, iv) ||
            !eq("AES-XTS optimized in-place round trip", inplace, pt, len)) return 0;
        if (len == 31 && !eq("AES-XTS external CTS vector", basic, xts31_expected, 31))
            return 0;
    }
    return 1;
}

int main(void)
{
    if (!test_gf() || !test_ctr() || !test_gcm() || !test_xts()) return 1;
    puts("[SUCCESS] CTR, GCM/PCLMUL and XTS/CTS tests passed.");
    return 0;
}
