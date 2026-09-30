# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 finlay@tuta.com
# The engine test runs sessions against each other over fake_net.c instead of real sockets.
# The fuzz targets need clang (libFuzzer): configure with -DCHAT_FUZZ=ON -DCMAKE_C_COMPILER=clang.
if(WIN32)
    message(FATAL_ERROR "chat: the tests build on Linux only")
endif()

set(CHAT_CORE_SOURCES
    ${PROJECT_SOURCE_DIR}/src/app/tui.c
    ${PROJECT_SOURCE_DIR}/src/core/chat.c
    ${PROJECT_SOURCE_DIR}/src/core/cmd.c
    ${PROJECT_SOURCE_DIR}/src/crypto/crypto.c
    ${PROJECT_SOURCE_DIR}/src/crypto/age.c
    ${PROJECT_SOURCE_DIR}/src/crypto/pgp.c
    ${PROJECT_SOURCE_DIR}/src/transport/dht.c
    ${PROJECT_SOURCE_DIR}/src/transport/nostr.c
    ${PROJECT_SOURCE_DIR}/src/transport/tls.c
    ${PROJECT_SOURCE_DIR}/src/transport/tor.c
    ${PROJECT_SOURCE_DIR}/src/transport/bridges.c
    ${PROJECT_SOURCE_DIR}/src/transport/portmap.c
    ${PROJECT_SOURCE_DIR}/src/common/util.c
    ${PROJECT_SOURCE_DIR}/src/common/bencode.c
    ${PROJECT_SOURCE_DIR}/src/common/json.c
    ${PROJECT_SOURCE_DIR}/src/platform/${CHAT_OS}/platform.c
    ${CMAKE_CURRENT_SOURCE_DIR}/fake_net.c
)

function(chat_test_executable name)
    add_executable(${name} ${ARGN} ${CHAT_CORE_SOURCES})
    add_dependencies(${name} libsodium_ext liboqs_ext mbedtls_ext secp256k1_ext)
    target_compile_definitions(${name} PRIVATE CHAT_VERSION="test" MBEDTLS_USER_CONFIG_FILE="${CHAT_MBEDTLS_CONFIG}")
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/src
                               ${PROJECT_SOURCE_DIR}/src/platform/${CHAT_OS} ${SODIUM_INCLUDE_DIRS} ${OQS_INCLUDE_DIRS}
                               ${MBEDTLS_INCLUDE_DIRS} ${SECP256K1_INCLUDE_DIRS})
    target_link_libraries(${name} PRIVATE ${SODIUM_STATIC_LIB} ${OQS_STATIC_LIB} ${MBEDTLS_STATIC_LIBS}
                          ${SECP256K1_STATIC_LIB} Threads::Threads)
    target_compile_options(${name} PRIVATE -Wall -Wextra)
endfunction()

chat_test_executable(engine_test engine_test.c)
add_test(NAME engine COMMAND engine_test)

if(CHAT_FUZZ)
    foreach(target fuzz_bencode fuzz_pgp fuzz_text fuzz_engine fuzz_json)
        chat_test_executable(${target} ${target}.c)
        target_compile_options(${target} PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g)
        target_link_options(${target} PRIVATE -fsanitize=fuzzer,address,undefined)
    endforeach()
endif()
