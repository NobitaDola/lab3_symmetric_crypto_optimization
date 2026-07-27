cmake_minimum_required(VERSION 3.10)
project(crypto_hw3 C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -march=native -Wall")

include_directories(include)

find_package(OpenSSL REQUIRED)

# AES 测试目标
add_executable(test_aes tests/test_aes.c src/aes.c)
target_link_libraries(test_aes OpenSSL::Crypto)

# SM4 测试目标
add_executable(test_sm4 tests/test_sm4.c src/sm4.c)
target_link_libraries(test_sm4 OpenSSL::Crypto)

# CTR / GCM / XTS 工作模式测试
add_executable(test_ctr tests/test_ctr.c src/modes.c src/aes.c src/sm4.c)
target_link_libraries(test_ctr OpenSSL::Crypto)

add_executable(test_gcm tests/test_gcm.c src/modes.c src/aes.c src/sm4.c)
target_link_libraries(test_gcm OpenSSL::Crypto)

add_executable(test_xts tests/test_xts.c src/modes.c src/aes.c src/sm4.c)
target_link_libraries(test_xts OpenSSL::Crypto)