#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include "modes.h"
#include "cycles.h"

#define TEST_DATA_SIZE (64 * 1024)
#define AAD_SIZE 128
#define TEST_LOOPS 2000

void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printf("%-18s: ", label);
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

int main()
{
    printf("==================================================\n");
    printf("   GCM Mode & GHASH PCLMUL Optimization Benchmark \n");
    printf("==================================================\n\n");

    uint8_t key[16] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
    uint8_t iv[12] = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};

    uint8_t *in = malloc(TEST_DATA_SIZE);
    uint8_t *aad = malloc(AAD_SIZE);
    uint8_t *out_openssl = malloc(TEST_DATA_SIZE);
    uint8_t *out_basic = malloc(TEST_DATA_SIZE);
    uint8_t *out_opt = malloc(TEST_DATA_SIZE);

    uint8_t tag_openssl[16], tag_basic[16], tag_opt[16];
    uint8_t *recovered = malloc(TEST_DATA_SIZE);

    for (size_t i = 0; i < TEST_DATA_SIZE; i++)
        in[i] = (uint8_t)(i & 0xFF);
    for (size_t i = 0; i < AAD_SIZE; i++)
        aad[i] = (uint8_t)((i + 0x55) & 0xFF);

    // OpenSSL AES-128 GCM 基准
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_EncryptUpdate(ctx, NULL, &len, aad, AAD_SIZE);
    EVP_EncryptUpdate(ctx, out_openssl, &len, in, TEST_DATA_SIZE);
    EVP_EncryptFinal_ex(ctx, out_openssl + len, &len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag_openssl);
    EVP_CIPHER_CTX_free(ctx);

    // 自研函数加密
    aes128_gcm_encrypt_basic(in, TEST_DATA_SIZE, aad, AAD_SIZE, key, iv, out_basic, tag_basic);
    aes128_gcm_encrypt_opt(in, TEST_DATA_SIZE, aad, AAD_SIZE, key, iv, out_opt, tag_opt);

    // 校验逻辑与诊断输出
    int pass = 1;
    if (memcmp(out_openssl, out_basic, TEST_DATA_SIZE) != 0)
    {
        printf("[ERROR] Basic Ciphertext mismatch!\n");
        pass = 0;
    }
    if (memcmp(out_openssl, out_opt, TEST_DATA_SIZE) != 0)
    {
        printf("[ERROR] Opt Ciphertext mismatch!\n");
        pass = 0;
    }
    if (memcmp(tag_openssl, tag_basic, 16) != 0)
    {
        printf("[ERROR] Basic Tag mismatch!\n");
        print_hex("Tag OpenSSL", tag_openssl, 16);
        print_hex("Tag Basic  ", tag_basic, 16);
        pass = 0;
    }
    if (memcmp(tag_openssl, tag_opt, 16) != 0)
    {
        printf("[ERROR] Opt Tag mismatch!\n");
        print_hex("Tag OpenSSL", tag_openssl, 16);
        print_hex("Tag Opt    ", tag_opt, 16);
        pass = 0;
    }

    if (pass)
    {
        printf("[SUCCESS] AES-128 GCM Ciphertext & Tag matched OpenSSL perfectly!\n\n");
    }
    else
    {
        return -1;
    }

    if (!aes128_gcm_decrypt_basic(out_basic, TEST_DATA_SIZE, aad, AAD_SIZE,
                                  key, iv, tag_basic, recovered) ||
        memcmp(recovered, in, TEST_DATA_SIZE) != 0 ||
        !aes128_gcm_decrypt_opt(out_opt, TEST_DATA_SIZE, aad, AAD_SIZE,
                                key, iv, tag_opt, recovered) ||
        memcmp(recovered, in, TEST_DATA_SIZE) != 0)
    {
        printf("[ERROR] AES-128 GCM authenticated decryption failed!\n");
        return -1;
    }
    tag_opt[0] ^= 1;
    if (aes128_gcm_decrypt_opt(out_opt, TEST_DATA_SIZE, aad, AAD_SIZE,
                               key, iv, tag_opt, recovered))
    {
        printf("[ERROR] AES-128 GCM accepted a modified tag!\n");
        return -1;
    }
    tag_opt[0] ^= 1;

    // 性能对比测试
    uint64_t start = start_rdtsc();
    for (int i = 0; i < TEST_LOOPS; i++)
    {
        aes128_gcm_encrypt_basic(in, TEST_DATA_SIZE, aad, AAD_SIZE, key, iv, out_basic, tag_basic);
    }
    uint64_t end = end_rdtsc();
    double cycles_gcm_basic = (double)(end - start) / (TEST_LOOPS * TEST_DATA_SIZE);

    start = start_rdtsc();
    for (int i = 0; i < TEST_LOOPS; i++)
    {
        aes128_gcm_encrypt_opt(in, TEST_DATA_SIZE, aad, AAD_SIZE, key, iv, out_opt, tag_opt);
    }
    end = end_rdtsc();
    double cycles_gcm_opt = (double)(end - start) / (TEST_LOOPS * TEST_DATA_SIZE);

    printf("Performance Summary (64KB Data + 128B AAD):\n");
    printf("--------------------------------------------------\n");
    printf("1. Basic GF(2^128) GCM      : %6.2f cycles/byte\n", cycles_gcm_basic);
    printf("2. PCLMULQDQ Opt GCM        : %6.2f cycles/byte (Speedup: %.2fx)\n",
           cycles_gcm_opt, cycles_gcm_basic / cycles_gcm_opt);
    printf("--------------------------------------------------\n");

    free(in);
    free(aad);
    free(out_openssl);
    free(out_basic);
    free(out_opt);
    free(recovered);
    return 0;
}
