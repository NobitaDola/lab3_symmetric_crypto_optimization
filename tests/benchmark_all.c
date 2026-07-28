#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "aes.h"
#include "sm4.h"
#include "gift128.h"
#include "twine.h"
#include "modes.h"
#include "cycles.h"

#define BLOCK_LOOPS 100000U
#define DATA_SIZE (64U * 1024U)
#define MODE_LOOPS 50U

static void result(const char *name, double basic, double opt, const char *unit)
{
    printf("%-20s %10.2f -> %10.2f %-12s speedup %7.2fx\n",
           name, basic, opt, unit, basic / opt);
}

int main(void)
{
    uint8_t key[32], in[64], out[64], iv[16] = {0};
    for (unsigned i = 0; i < sizeof(key); ++i) key[i] = (uint8_t)i;
    for (unsigned i = 0; i < sizeof(in); ++i) in[i] = (uint8_t)(3U * i + 1U);
    uint64_t begin, end;

    uint8_t aes_rk[176]; __m128i aesni_rk[11];
    aes128_key_expansion_basic(key, aes_rk); aes128_key_expansion_ni(key, aesni_rk);
    aes128_init_ttables();
    begin = start_rdtsc();
    for (unsigned i = 0; i < BLOCK_LOOPS; ++i) aes128_encrypt_basic(in, out, aes_rk);
    end = end_rdtsc(); double aes_basic = (double)(end-begin)/BLOCK_LOOPS;
    begin = start_rdtsc();
    for (unsigned i = 0; i < BLOCK_LOOPS; ++i) aes128_encrypt_ttable(in, out, aes_rk);
    end = end_rdtsc(); double aes_tt = (double)(end-begin)/BLOCK_LOOPS;
    result("AES T-table", aes_basic, aes_tt, "cycles/block");
    begin = start_rdtsc();
    for (unsigned i = 0; i < BLOCK_LOOPS; ++i) aes128_encrypt_ni(in, out, aesni_rk);
    end = end_rdtsc(); double aes_ni = (double)(end-begin)/BLOCK_LOOPS;
    result("AES AES-NI", aes_basic, aes_ni, "cycles/block");

    uint32_t sm4_rk[32]; sm4_key_expansion_basic(key, sm4_rk); sm4_init_ttables();
    begin = start_rdtsc();
    for (unsigned i = 0; i < BLOCK_LOOPS; ++i) sm4_encrypt_basic(in, out, sm4_rk);
    end = end_rdtsc(); double sm4_basic = (double)(end-begin)/BLOCK_LOOPS;
    begin = start_rdtsc();
    for (unsigned i = 0; i < BLOCK_LOOPS; ++i) sm4_encrypt_ttable(in, out, sm4_rk);
    end = end_rdtsc(); double sm4_tt = (double)(end-begin)/BLOCK_LOOPS;
    result("SM4 T-table", sm4_basic, sm4_tt, "cycles/block");

    gift128_key_schedule gift;
    gift128_key_expansion(key, &gift);
    begin = start_rdtsc();
    for (unsigned i = 0; i < BLOCK_LOOPS; ++i) gift128_encrypt_basic(in, out, &gift);
    end = end_rdtsc(); double gift_basic = (double)(end-begin)/BLOCK_LOOPS;
    begin = start_rdtsc();
    for (unsigned i = 0; i < BLOCK_LOOPS; ++i) gift128_encrypt_bitslice(in, out, &gift);
    end = end_rdtsc(); double gift_opt = (double)(end-begin)/BLOCK_LOOPS;
    result("GIFT-128 bitslice", gift_basic, gift_opt, "cycles/block");

    twine128_key_schedule twine;
    twine128_key_expansion(key, &twine);
    begin = start_rdtsc();
    for (unsigned i = 0; i < BLOCK_LOOPS; ++i) twine128_encrypt_basic(in, out, &twine);
    end = end_rdtsc(); double twine_basic = (double)(end-begin)/BLOCK_LOOPS;
    begin = start_rdtsc();
    for (unsigned i = 0; i < BLOCK_LOOPS; ++i) twine128_encrypt_8way_shuffle(in, out, &twine);
    end = end_rdtsc(); double twine_opt = (double)(end-begin)/(BLOCK_LOOPS*8U);
    result("TWINE 8-way", twine_basic, twine_opt, "cycles/block");

    uint8_t *data = (uint8_t *)malloc(DATA_SIZE);
    uint8_t *cipher = (uint8_t *)malloc(DATA_SIZE);
    uint8_t *tmp = (uint8_t *)malloc(DATA_SIZE);
    if (!data || !cipher || !tmp) return 2;
    for (unsigned i = 0; i < DATA_SIZE; ++i) data[i] = (uint8_t)i;

#define BENCH_MODE(label, basic_call, opt_call) do { \
    begin=start_rdtsc(); for(unsigned j=0;j<MODE_LOOPS;++j){basic_call;} end=end_rdtsc(); \
    double b=(double)(end-begin)/(MODE_LOOPS*DATA_SIZE); \
    begin=start_rdtsc(); for(unsigned j=0;j<MODE_LOOPS;++j){opt_call;} end=end_rdtsc(); \
    double o=(double)(end-begin)/(MODE_LOOPS*DATA_SIZE); result(label,b,o,"cycles/byte"); \
} while(0)

    BENCH_MODE("AES-CTR", aes128_ctr_encrypt_basic(data,cipher,DATA_SIZE,key,iv),
               aes128_ctr_encrypt_parallel(data,tmp,DATA_SIZE,key,iv));
    BENCH_MODE("SM4-CTR", sm4_ctr_encrypt_basic(data,cipher,DATA_SIZE,key,iv),
               sm4_ctr_encrypt_parallel(data,tmp,DATA_SIZE,key,iv));
    uint8_t tag[16], iv12[12] = {0};
    BENCH_MODE("AES-GCM", aes128_gcm_encrypt_basic(data,DATA_SIZE,NULL,0,key,iv12,cipher,tag),
               aes128_gcm_encrypt_opt(data,DATA_SIZE,NULL,0,key,iv12,tmp,tag));
    BENCH_MODE("AES-XTS", aes128_xts_encrypt_basic(data,cipher,DATA_SIZE,key,iv),
               aes128_xts_encrypt_opt(data,tmp,DATA_SIZE,key,iv));

    free(data); free(cipher); free(tmp);
    return 0;
}
