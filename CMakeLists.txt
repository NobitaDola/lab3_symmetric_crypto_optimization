cmake_minimum_required(VERSION 3.16)
project(crypto_hw3 VERSION 2.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(CRYPTO_HW3_NATIVE "Enable host-specific BMI2 optimizations" ON)
option(CRYPTO_HW3_OPENSSL_TESTS "Build OpenSSL differential benchmarks" ON)

add_library(crypto_hw3 STATIC
    src/aes.c
    src/sm4.c
    src/gift128.c
    src/twine.c
    src/modes.c)
target_include_directories(crypto_hw3 PUBLIC include)

if(MSVC)
    target_compile_options(crypto_hw3 PRIVATE /O2 /W4 /arch:AVX2)
else()
    target_compile_options(crypto_hw3 PRIVATE
        -Wall -Wextra -Wpedantic
        $<$<CONFIG:Release>:-O3>
        -maes -mpclmul -mssse3 -msse4.1)
    if(CRYPTO_HW3_NATIVE)
        target_compile_options(crypto_hw3 PRIVATE -mbmi2)
    endif()
endif()

enable_testing()

function(add_hw3_test name source)
    add_executable(${name} ${source})
    target_link_libraries(${name} PRIVATE crypto_hw3)
    if(NOT MSVC)
        target_compile_options(${name} PRIVATE -maes -mpclmul -mssse3 -msse4.1)
    endif()
    add_test(NAME ${name} COMMAND ${name})
endfunction()

add_hw3_test(test_block_vectors tests/test_block_vectors.c)
add_hw3_test(test_lightweight tests/test_lightweight.c)
add_hw3_test(test_modes_vectors tests/test_modes_vectors.c)

add_executable(benchmark_all tests/benchmark_all.c)
target_link_libraries(benchmark_all PRIVATE crypto_hw3)
if(NOT MSVC)
    target_compile_options(benchmark_all PRIVATE -maes -mpclmul -mssse3 -msse4.1)
endif()

if(CRYPTO_HW3_OPENSSL_TESTS)
    find_package(OpenSSL QUIET)
    if(OpenSSL_FOUND)
        foreach(name IN ITEMS test_aes test_sm4 test_ctr test_gcm test_xts)
            add_executable(${name} tests/${name}.c)
            target_link_libraries(${name} PRIVATE crypto_hw3 OpenSSL::Crypto)
            if(NOT MSVC)
                target_compile_options(${name} PRIVATE -maes -mpclmul -mssse3 -msse4.1)
            endif()
            add_test(NAME ${name} COMMAND ${name})
        endforeach()
    else()
        message(WARNING "OpenSSL not found: differential benchmark targets are skipped")
    endif()
endif()
