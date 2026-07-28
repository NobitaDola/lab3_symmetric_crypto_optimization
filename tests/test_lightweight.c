#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "gift128.h"
#include "twine.h"
#include "cycles.h"

#define TEST_LOOPS 100000

static int check_equal(const char *name, const uint8_t *actual,
                       const uint8_t *expected, size_t len)
{
    if (memcmp(actual, expected, len) == 0)
        return 1;
    fprintf(stderr, "[ERROR] %s mismatch\nexpected: ", name);
    for (size_t i = 0; i < len; ++i) fprintf(stderr, "%02x", expected[i]);
    fprintf(stderr, "\nactual:   ");
    for (size_t i = 0; i < len; ++i) fprintf(stderr, "%02x", actual[i]);
    fprintf(stderr, "\n");
    return 0;
}

static int test_gift(void)
{
    static const uint8_t keys[3][16] = {
        {0},
        {0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10},
        {0xd0,0xf5,0xc5,0x9a,0x77,0x00,0xd3,0xe7,0x99,0x02,0x8f,0xa9,0xf9,0x0a,0xd8,0x37}};
    static const uint8_t pts[3][16] = {
        {0},
        {0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10},
        {0xe3,0x9c,0x14,0x1f,0xa5,0x7d,0xba,0x43,0xf0,0x8a,0x85,0xb6,0xa9,0x1f,0x86,0xc1}};
    static const uint8_t cts[3][16] = {
        {0xcd,0x0b,0xd7,0x38,0x38,0x8a,0xd3,0xf6,0x68,0xb1,0x5a,0x36,0xce,0xb6,0xff,0x92},
        {0x84,0x22,0x24,0x1a,0x6d,0xbf,0x5a,0x93,0x46,0xaf,0x46,0x84,0x09,0xee,0x01,0x52},
        {0x13,0xed,0xe6,0x7c,0xbd,0xcc,0x3d,0xbf,0x40,0x0a,0x62,0xd6,0x97,0x72,0x65,0xea}};
    uint8_t basic[16], opt[16], recovered[16];
    gift128_key_schedule ks;
    for (unsigned i = 0; i < 3; ++i) {
        gift128_key_expansion(keys[i], &ks);
        gift128_encrypt_basic(pts[i], basic, &ks);
        gift128_encrypt_bitslice(pts[i], opt, &ks);
        gift128_decrypt_basic(cts[i], recovered, &ks);
        if (!check_equal("GIFT-128 basic KAT", basic, cts[i], 16) ||
            !check_equal("GIFT-128 bitslice KAT", opt, cts[i], 16) ||
            !check_equal("GIFT-128 decrypt KAT", recovered, pts[i], 16))
            return 0;
    }
    gift128_key_expansion(keys[0], &ks);
    uint64_t start = start_rdtsc();
    for (unsigned i = 0; i < TEST_LOOPS; ++i) gift128_encrypt_basic(pts[0], basic, &ks);
    uint64_t end = end_rdtsc();
    double basic_cycles = (double)(end - start) / TEST_LOOPS;
    start = start_rdtsc();
    for (unsigned i = 0; i < TEST_LOOPS; ++i) gift128_encrypt_bitslice(pts[0], opt, &ks);
    end = end_rdtsc();
    double opt_cycles = (double)(end - start) / TEST_LOOPS;
    printf("GIFT-128 basic: %.2f cycles/block, bitslice: %.2f (%.2fx)\n",
           basic_cycles, opt_cycles, basic_cycles / opt_cycles);
    return 1;
}

static int test_twine(void)
{
    static const uint8_t key[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    static const uint8_t pt[8] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
    static const uint8_t ct[8] = {0x97,0x9f,0xf9,0xb3,0x79,0xb5,0xa9,0xb8};
    uint8_t basic[8], opt[8], recovered[8];
    uint8_t input8[64], output8[64];
    twine128_key_schedule ks;
    twine128_key_expansion(key, &ks);
    twine128_encrypt_basic(pt, basic, &ks);
    twine128_encrypt_shuffle(pt, opt, &ks);
    twine128_decrypt_basic(ct, recovered, &ks);
    if (!check_equal("TWINE-128 basic KAT", basic, ct, 8) ||
        !check_equal("TWINE-128 shuffle KAT", opt, ct, 8) ||
        !check_equal("TWINE-128 decrypt KAT", recovered, pt, 8))
        return 0;
    uint64_t start = start_rdtsc();
    for (unsigned i = 0; i < TEST_LOOPS; ++i) twine128_encrypt_basic(pt, basic, &ks);
    uint64_t end = end_rdtsc();
    double basic_cycles = (double)(end - start) / TEST_LOOPS;
    start = start_rdtsc();
    for (unsigned b = 0; b < 8; ++b) memcpy(input8 + b * 8U, pt, 8);
    for (unsigned i = 0; i < TEST_LOOPS; ++i)
        twine128_encrypt_8way_shuffle(input8, output8, &ks);
    end = end_rdtsc();
    double opt_cycles = (double)(end - start) / (TEST_LOOPS * 8U);
    printf("TWINE-128 basic: %.2f cycles/block, shuffle: %.2f (%.2fx)\n",
           basic_cycles, opt_cycles, basic_cycles / opt_cycles);
    return 1;
}

int main(void)
{
    if (!test_gift() || !test_twine()) return 1;
    puts("[SUCCESS] GIFT-128 and TWINE-128 standard vectors passed.");
    return 0;
}
