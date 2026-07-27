#ifndef CYCLES_H
#define CYCLES_H

#include <x86intrin.h>
#include <stdint.h>

// 读取 CPU 时间戳计数器 (RDTSC)
static inline uint64_t start_rdtsc(void)
{
    uint32_t low, high;
    __asm__ __volatile__(
        "cpuid\n\t"
        "rdtsc\n\t"
        "mov %%eax, %0\n\t"
        "mov %%edx, %1\n\t"
        : "=r"(low), "=r"(high)
        :
        : "%rax", "%rbx", "%rcx", "%rdx");
    return ((uint64_t)high << 32) | low;
}

static inline uint64_t end_rdtsc(void)
{
    uint32_t low, high;
    __asm__ __volatile__(
        "rdtscp\n\t"
        "mov %%eax, %0\n\t"
        "mov %%edx, %1\n\t"
        "cpuid\n\t"
        : "=r"(low), "=r"(high)
        :
        : "%rax", "%rbx", "%rcx", "%rdx");
    return ((uint64_t)high << 32) | low;
}

#endif // CYCLES_H