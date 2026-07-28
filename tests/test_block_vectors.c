#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "aes.h"
#include "sm4.h"

static int equal(const char *name, const uint8_t *a, const uint8_t *b)
{
    if (memcmp(a, b, 16) == 0) return 1;
    fprintf(stderr, "[ERROR] %s\n", name);
    return 0;
}

int main(void)
{
    static const uint8_t aes_key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    static const uint8_t aes_pt[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    static const uint8_t aes_ct[16] = {
        0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
        0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
    uint8_t rk[176], out[16], recovered[16];
    __m128i erk[11], drk[11];
    aes128_key_expansion_basic(aes_key, rk);
    aes128_init_ttables();
    aes128_encrypt_basic(aes_pt, out, rk);
    if (!equal("AES basic KAT", out, aes_ct)) return 1;
    aes128_encrypt_ttable(aes_pt, out, rk);
    if (!equal("AES T-table KAT", out, aes_ct)) return 1;
    aes128_decrypt_basic(aes_ct, recovered, rk);
    if (!equal("AES basic decrypt KAT", recovered, aes_pt)) return 1;
    aes128_key_expansion_ni(aes_key, erk);
    aes128_encrypt_ni(aes_pt, out, erk);
    if (!equal("AES-NI KAT", out, aes_ct)) return 1;
    aes128_key_expansion_dec_ni(erk, drk);
    aes128_decrypt_ni(aes_ct, recovered, drk);
    if (!equal("AES-NI decrypt KAT", recovered, aes_pt)) return 1;

    static const uint8_t sm4_key[16] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    static const uint8_t sm4_ct[16] = {
        0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,
        0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46};
    uint32_t sm4_rk[32];
    uint8_t sm4_in4[64], sm4_out4[64];
    sm4_key_expansion_basic(sm4_key, sm4_rk);
    sm4_encrypt_basic(sm4_key, out, sm4_rk);
    if (!equal("SM4 basic KAT", out, sm4_ct)) return 1;
    sm4_init_ttables();
    sm4_encrypt_ttable(sm4_key, out, sm4_rk);
    if (!equal("SM4 T-table KAT", out, sm4_ct)) return 1;
    sm4_encrypt_shuffle(sm4_key, out, sm4_rk);
    if (!equal("SM4 shuffle KAT", out, sm4_ct)) return 1;
    for (unsigned i = 0; i < 4; ++i) memcpy(sm4_in4 + 16U * i, sm4_key, 16);
    sm4_encrypt4_ttable(sm4_in4, sm4_out4, sm4_rk);
    for (unsigned i = 0; i < 4; ++i)
        if (!equal("SM4 4-way T-table KAT", sm4_out4 + 16U * i, sm4_ct)) return 1;
    sm4_decrypt_basic(sm4_ct, recovered, sm4_rk);
    if (!equal("SM4 decrypt KAT", recovered, sm4_key)) return 1;

    puts("[SUCCESS] AES-128 and SM4 encryption/decryption vectors passed.");
    return 0;
}
