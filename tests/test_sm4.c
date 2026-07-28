#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include "sm4.h"
#include "cycles.h"

#define TEST_LOOPS 100000

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
    printf("   SM4 Performance Benchmarking (Cycles/Block)    \n");
    printf("==================================================\n\n");

    // 国密 SM4 标准测试向量 (GB/T 32907-2016)
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t in[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t out_basic[16], out_ttable[16], out_shuffle[16], out_openssl[16], recovered[16];

    // 初始化 T-Table 查找表
    sm4_init_ttables();

    // 1. 生成轮密钥
    uint32_t rk[32];
    sm4_key_expansion_basic(key, rk);

    // 2. OpenSSL SM4 加密 (基于 EVP 标准接口)
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, final_len;
    EVP_EncryptInit_ex(ctx, EVP_sm4_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptUpdate(ctx, out_openssl, &len, in, 16);
    EVP_EncryptFinal_ex(ctx, out_openssl + len, &final_len);
    EVP_CIPHER_CTX_free(ctx);

    // 执行各版本加密
    sm4_encrypt_basic(in, out_basic, rk);
    sm4_encrypt_ttable(in, out_ttable, rk);
    sm4_encrypt_shuffle(in, out_shuffle, rk);
    sm4_decrypt_basic(out_basic, recovered, rk);

    // 打印加密结果方便排错
    print_hex("OpenSSL Standard", out_openssl, 16);
    print_hex("Basic S-Box", out_basic, 16);
    print_hex("T-Table Opt", out_ttable, 16);
    print_hex("SIMD Shuffle Opt", out_shuffle, 16);
    printf("\n");

    // 正确性断言
    if (memcmp(out_openssl, out_basic, 16) == 0 &&
        memcmp(out_openssl, out_ttable, 16) == 0 &&
        memcmp(out_openssl, out_shuffle, 16) == 0 && memcmp(recovered, in, 16) == 0)
    {
        printf("[SUCCESS] All 3 implementations matched OpenSSL output perfectly!\n\n");
    }
    else
    {
        printf("[ERROR] Result mismatch detected!\n");
        return -1;
    }

    // 性能评估
    uint64_t start, end;

    // Basic 测试
    start = start_rdtsc();
    for (int i = 0; i < TEST_LOOPS; i++)
    {
        sm4_encrypt_basic(in, out_basic, rk);
    }
    end = end_rdtsc();
    double cycles_basic = (double)(end - start) / TEST_LOOPS;

    // T-Table 测试
    start = start_rdtsc();
    for (int i = 0; i < TEST_LOOPS; i++)
    {
        sm4_encrypt_ttable(in, out_ttable, rk);
    }
    end = end_rdtsc();
    double cycles_ttable = (double)(end - start) / TEST_LOOPS;

    // SIMD Shuffle 测试
    start = start_rdtsc();
    for (int i = 0; i < TEST_LOOPS; i++)
    {
        sm4_encrypt_shuffle(in, out_shuffle, rk);
    }
    end = end_rdtsc();
    double cycles_shuffle = (double)(end - start) / TEST_LOOPS;

    printf("Performance Summary (Avg Cycles per 16-byte Block):\n");
    printf("--------------------------------------------------\n");
    printf("1. Basic S-Box Implementation : %8.2f cycles\n", cycles_basic);
    printf("2. T-Table Optimization       : %8.2f cycles (Speedup: %.2fx)\n", cycles_ttable, cycles_basic / cycles_ttable);
    printf("3. SIMD Shuffle Acceleration  : %8.2f cycles (Speedup: %.2fx)\n", cycles_shuffle, cycles_basic / cycles_shuffle);
    printf("--------------------------------------------------\n");

    return 0;
}
