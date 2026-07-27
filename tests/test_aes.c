#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include "aes.h"
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
    printf("   AES-128 Performance Benchmarking (Cycles/Block)\n");
    printf("==================================================\n\n");

    uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t in[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    uint8_t out_basic[16], out_ttable[16], out_ni[16], out_openssl[16];

    // 初始化 T-Table 查找表
    aes128_init_ttables();

    // 1. 生成我们自己的标准轮密钥 (用于 Basic 和 T-Table)
    uint8_t basic_rk[176];
    aes128_key_expansion_basic(key, basic_rk);

    // 2. 生成 AES-NI 专用的轮密钥
    __m128i ni_rk[11];
    aes128_key_expansion_ni(key, ni_rk);

    // 3. OpenSSL 密钥生成
    AES_KEY openssl_key;
    AES_set_encrypt_key(key, 128, &openssl_key);

    // 执行各版本加密
    AES_encrypt(in, out_openssl, &openssl_key);
    aes128_encrypt_basic(in, out_basic, basic_rk);
    aes128_encrypt_ttable(in, out_ttable, basic_rk);
    aes128_encrypt_ni(in, out_ni, ni_rk);

    // 打印加密结果方便排错
    print_hex("OpenSSL Standard", out_openssl, 16);
    print_hex("Basic S-Box", out_basic, 16);
    print_hex("T-Table Opt", out_ttable, 16);
    print_hex("AES-NI Opt", out_ni, 16);
    printf("\n");

    // 正确性断言
    if (memcmp(out_openssl, out_basic, 16) == 0 &&
        memcmp(out_openssl, out_ttable, 16) == 0 &&
        memcmp(out_openssl, out_ni, 16) == 0)
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
        aes128_encrypt_basic(in, out_basic, basic_rk);
    }
    end = end_rdtsc();
    double cycles_basic = (double)(end - start) / TEST_LOOPS;

    // T-Table 测试
    start = start_rdtsc();
    for (int i = 0; i < TEST_LOOPS; i++)
    {
        aes128_encrypt_ttable(in, out_ttable, basic_rk);
    }
    end = end_rdtsc();
    double cycles_ttable = (double)(end - start) / TEST_LOOPS;

    // AES-NI 测试
    start = start_rdtsc();
    for (int i = 0; i < TEST_LOOPS; i++)
    {
        aes128_encrypt_ni(in, out_ni, ni_rk);
    }
    end = end_rdtsc();
    double cycles_ni = (double)(end - start) / TEST_LOOPS;

    printf("Performance Summary (Avg Cycles per 16-byte Block):\n");
    printf("--------------------------------------------------\n");
    printf("1. Basic S-Box Implementation : %8.2f cycles\n", cycles_basic);
    printf("2. T-Table Optimization       : %8.2f cycles (Speedup: %.2fx)\n", cycles_ttable, cycles_basic / cycles_ttable);
    printf("3. AES-NI Hardware Acceleration: %8.2f cycles (Speedup: %.2fx)\n", cycles_ni, cycles_basic / cycles_ni);
    printf("--------------------------------------------------\n");

    return 0;
}