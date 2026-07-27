#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include "modes.h"
#include "cycles.h"

#define TEST_DATA_SIZE (64 * 1024) // 64 KB 扇区数据量
#define TEST_LOOPS 5000

int main()
{
    printf("==================================================\n");
    printf("   XTS Mode Vectorized Optimization Benchmarking  \n");
    printf("==================================================\n\n");

    // 32-byte Key (16B Key1 + 16B Key2)
    uint8_t key[32] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        0x3c, 0x4f, 0xcf, 0x09, 0x88, 0x15, 0xf7, 0xab, 0xa6, 0xd2, 0xae, 0x28, 0x16, 0x15, 0x7e, 0x2b};
    // 16-byte Tweak / Sector Number
    uint8_t iv[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

    uint8_t *in = malloc(TEST_DATA_SIZE);
    uint8_t *out_openssl = malloc(TEST_DATA_SIZE);
    uint8_t *out_basic = malloc(TEST_DATA_SIZE);
    uint8_t *out_opt = malloc(TEST_DATA_SIZE);

    for (size_t i = 0; i < TEST_DATA_SIZE; i++)
    {
        in[i] = (uint8_t)(i & 0xFF);
    }

    // 1. OpenSSL AES-128 XTS 标准基准
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_xts(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, out_openssl, &len, in, TEST_DATA_SIZE);
    EVP_EncryptFinal_ex(ctx, out_openssl + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    // 2. 执行自研基础版与优化版
    aes128_xts_encrypt_basic(in, out_basic, TEST_DATA_SIZE, key, iv);
    aes128_xts_encrypt_opt(in, out_opt, TEST_DATA_SIZE, key, iv);

    // 3. 正确性断言
    if (memcmp(out_openssl, out_basic, TEST_DATA_SIZE) == 0 &&
        memcmp(out_openssl, out_opt, TEST_DATA_SIZE) == 0)
    {
        printf("[SUCCESS] AES-128 XTS outputs matched OpenSSL perfectly!\n\n");
    }
    else
    {
        printf("[ERROR] AES-128 XTS result mismatch detected!\n");
        return -1;
    }

    // 4. 性能评估
    uint64_t start = start_rdtsc();
    for (int i = 0; i < TEST_LOOPS; i++)
    {
        aes128_xts_encrypt_basic(in, out_basic, TEST_DATA_SIZE, key, iv);
    }
    uint64_t end = end_rdtsc();
    double cycles_xts_basic = (double)(end - start) / (TEST_LOOPS * TEST_DATA_SIZE);

    start = start_rdtsc();
    for (int i = 0; i < TEST_LOOPS; i++)
    {
        aes128_xts_encrypt_opt(in, out_opt, TEST_DATA_SIZE, key, iv);
    }
    end = end_rdtsc();
    double cycles_xts_opt = (double)(end - start) / (TEST_LOOPS * TEST_DATA_SIZE);

    printf("Performance Summary (64KB Storage Sector):\n");
    printf("--------------------------------------------------\n");
    printf("1. Basic Serial XTS         : %6.2f cycles/byte\n", cycles_xts_basic);
    printf("2. 4-Way SIMD Pipelined XTS : %6.2f cycles/byte (Speedup: %.2fx)\n",
           cycles_xts_opt, cycles_xts_basic / cycles_xts_opt);
    printf("--------------------------------------------------\n");

    free(in);
    free(out_openssl);
    free(out_basic);
    free(out_opt);
    return 0;
}