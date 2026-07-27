#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include "modes.h"
#include "cycles.h"

#define TEST_DATA_SIZE (64 * 1024) // 64 KB 测试数据
#define TEST_LOOPS 5000

int main()
{
    printf("==================================================\n");
    printf("   CTR Mode Parallel Optimization Benchmarking    \n");
    printf("==================================================\n\n");

    uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t iv[16] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};

    uint8_t *in = malloc(TEST_DATA_SIZE);
    uint8_t *out_openssl = malloc(TEST_DATA_SIZE);
    uint8_t *out_basic = malloc(TEST_DATA_SIZE);
    uint8_t *out_opt = malloc(TEST_DATA_SIZE);

    for (size_t i = 0; i < TEST_DATA_SIZE; i++)
    {
        in[i] = (uint8_t)(i & 0xFF);
    }

    // -----------------------------------------------------------------------
    // 1. AES-128 CTR 测试与验证
    // -----------------------------------------------------------------------
    printf("--- AES-128 CTR Verification ---\n");

    // OpenSSL AES CTR
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, final_len;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, out_openssl, &len, in, TEST_DATA_SIZE);
    EVP_EncryptFinal_ex(ctx, out_openssl + len, &final_len);
    EVP_CIPHER_CTX_free(ctx);

    aes128_ctr_encrypt_basic(in, out_basic, TEST_DATA_SIZE, key, iv);
    aes128_ctr_encrypt_parallel(in, out_opt, TEST_DATA_SIZE, key, iv);

    if (memcmp(out_openssl, out_basic, TEST_DATA_SIZE) == 0 &&
        memcmp(out_openssl, out_opt, TEST_DATA_SIZE) == 0)
    {
        printf("[SUCCESS] AES-128 CTR outputs matched OpenSSL perfectly!\n");
    }
    else
    {
        printf("[ERROR] AES-128 CTR result mismatch detected!\n");
        return -1;
    }

    // 性能评估
    uint64_t start = start_rdtsc();
    for (int i = 0; i < TEST_LOOPS; i++)
    {
        aes128_ctr_encrypt_basic(in, out_basic, TEST_DATA_SIZE, key, iv);
    }
    uint64_t end = end_rdtsc();
    double cycles_aes_basic = (double)(end - start) / (TEST_LOOPS * TEST_DATA_SIZE);

    start = start_rdtsc();
    for (int i = 0; i < TEST_LOOPS; i++)
    {
        aes128_ctr_encrypt_parallel(in, out_opt, TEST_DATA_SIZE, key, iv);
    }
    end = end_rdtsc();
    double cycles_aes_opt = (double)(end - start) / (TEST_LOOPS * TEST_DATA_SIZE);

    printf("AES-128 CTR Basic Serial  : %6.2f cycles/byte\n", cycles_aes_basic);
    printf("AES-128 CTR 4-Way Parallel: %6.2f cycles/byte (Speedup: %.2fx)\n\n",
           cycles_aes_opt, cycles_aes_basic / cycles_aes_opt);

    // -----------------------------------------------------------------------
    // 2. SM4 CTR 测试与验证
    // -----------------------------------------------------------------------
    printf("--- SM4 CTR Verification ---\n");

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_sm4_ctr(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, out_openssl, &len, in, TEST_DATA_SIZE);
    EVP_EncryptFinal_ex(ctx, out_openssl + len, &final_len);
    EVP_CIPHER_CTX_free(ctx);

    sm4_ctr_encrypt_basic(in, out_basic, TEST_DATA_SIZE, key, iv);
    sm4_ctr_encrypt_parallel(in, out_opt, TEST_DATA_SIZE, key, iv);

    if (memcmp(out_openssl, out_basic, TEST_DATA_SIZE) == 0 &&
        memcmp(out_openssl, out_opt, TEST_DATA_SIZE) == 0)
    {
        printf("[SUCCESS] SM4 CTR outputs matched OpenSSL perfectly!\n");
    }
    else
    {
        printf("[ERROR] SM4 CTR result mismatch detected!\n");
        return -1;
    }

    start = start_rdtsc();
    for (int i = 0; i < TEST_LOOPS; i++)
    {
        sm4_ctr_encrypt_basic(in, out_basic, TEST_DATA_SIZE, key, iv);
    }
    end = end_rdtsc();
    double cycles_sm4_basic = (double)(end - start) / (TEST_LOOPS * TEST_DATA_SIZE);

    start = start_rdtsc();
    for (int i = 0; i < TEST_LOOPS; i++)
    {
        sm4_ctr_encrypt_parallel(in, out_opt, TEST_DATA_SIZE, key, iv);
    }
    end = end_rdtsc();
    double cycles_sm4_opt = (double)(end - start) / (TEST_LOOPS * TEST_DATA_SIZE);

    printf("SM4 CTR Basic Serial  : %6.2f cycles/byte\n", cycles_sm4_basic);
    printf("SM4 CTR 4-Way Parallel: %6.2f cycles/byte (Speedup: %.2fx)\n",
           cycles_sm4_opt, cycles_sm4_basic / cycles_sm4_opt);
    printf("--------------------------------------------------\n");

    free(in);
    free(out_openssl);
    free(out_basic);
    free(out_opt);
    return 0;
}