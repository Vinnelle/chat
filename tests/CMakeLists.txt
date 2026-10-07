# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 finlay@tuta.com
# The engine test runs sessions against each other over fake_net.c instead of real sockets, on
# Linux or (cross-built with zig) Windows. The fuzz targets need clang (libFuzzer) and Linux:
# configure with -DCHAT_FUZZ=ON -DCMAKE_C_COMPILER=clang.
if(WIN32 AND CHAT_FUZZ)
    message(FATAL_ERROR "chat: the fuzz targets build on Linux only")
endif()

set(CHAT_CORE_SOURCES
    ${PROJECT_SOURCE_DIR}/src/app/tui.c
    ${PROJECT_SOURCE_DIR}/src/core/chat.c
    ${PROJECT_SOURCE_DIR}/src/core/cmd.c
    ${PROJECT_SOURCE_DIR}/src/core/files.c
    ${PROJECT_SOURCE_DIR}/src/core/trust.c
    ${PROJECT_SOURCE_DIR}/src/crypto/crypto.c
    ${PROJECT_SOURCE_DIR}/src/crypto/age.c
    ${PROJECT_SOURCE_DIR}/src/crypto/pgp.c
    ${PROJECT_SOURCE_DIR}/src/transport/dht.c
    ${PROJECT_SOURCE_DIR}/src/transport/nostr.c
    ${PROJECT_SOURCE_DIR}/src/transport/tls.c
    ${PROJECT_SOURCE_DIR}/src/transport/tor.c
    ${PROJECT_SOURCE_DIR}/src/transport/portmap.c
    ${PROJECT_SOURCE_DIR}/src/common/util.c
    ${PROJECT_SOURCE_DIR}/src/common/bencode.c
    ${PROJECT_SOURCE_DIR}/src/common/json.c
    ${PROJECT_SOURCE_DIR}/src/common/toml.c
    ${PROJECT_SOURCE_DIR}/src/common/image.c
    ${PROJECT_SOURCE_DIR}/src/common/qr.c
    ${PROJECT_SOURCE_DIR}/src/common/bytewords.c
    ${PROJECT_SOURCE_DIR}/src/platform/${CHAT_OS}/platform.c
    ${CMAKE_CURRENT_SOURCE_DIR}/fake_net.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test_os.c
)

function(chat_test_executable name)
    add_executable(${name} ${ARGN} ${CHAT_CORE_SOURCES})
    add_dependencies(${name} libsodium_ext liboqs_ext mbedtls_ext secp256k1_ext)
    target_compile_definitions(${name} PRIVATE CHAT_VERSION="test" MBEDTLS_USER_CONFIG_FILE="${CHAT_MBEDTLS_CONFIG}")
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/src
                               ${PROJECT_SOURCE_DIR}/src/platform/${CHAT_OS} ${SODIUM_INCLUDE_DIRS} ${OQS_INCLUDE_DIRS}
                               ${MBEDTLS_INCLUDE_DIRS} ${SECP256K1_INCLUDE_DIRS})
    target_link_libraries(${name} PRIVATE ${SODIUM_STATIC_LIB} ${OQS_STATIC_LIB} ${MBEDTLS_STATIC_LIBS}
                          ${SECP256K1_STATIC_LIB})
    if(WIN32)
        target_compile_definitions(${name} PRIVATE SODIUM_STATIC=1 SECP256K1_STATIC=1 WIN32_LEAN_AND_MEAN)
        target_link_libraries(${name} PRIVATE ws2_32 bcrypt ncrypt advapi32 shell32 user32 crypt32 iphlpapi)
    else()
        target_link_libraries(${name} PRIVATE Threads::Threads m)
    endif()
    target_compile_options(${name} PRIVATE -Wall -Wextra)
    if(CHAT_SANITIZE)
        # Any report fails the test, not just a line in its output.
        target_compile_options(${name} PRIVATE -fsanitize=address,undefined -fno-sanitize-recover=all
                               -fno-omit-frame-pointer -g)
        target_link_options(${name} PRIVATE -fsanitize=address,undefined)
    endif()
endfunction()

# The saves' code, with a device and a security key of the test's own in engine_test.c.
chat_test_executable(engine_test engine_test.c ${PROJECT_SOURCE_DIR}/src/app/install.c)
add_test(NAME engine COMMAND engine_test)

if(CHAT_FUZZ)
    foreach(target fuzz_bencode fuzz_pgp fuzz_text fuzz_engine fuzz_json fuzz_image fuzz_toml fuzz_save fuzz_ctap2
                   fuzz_tpm2)
        set(extra)
        if(target STREQUAL "fuzz_ctap2")
            set(extra ${PROJECT_SOURCE_DIR}/src/platform/linux/ctap2.c)
        elseif(target STREQUAL "fuzz_tpm2")
            set(extra ${PROJECT_SOURCE_DIR}/src/platform/linux/tpm2.c)
        endif()
        chat_test_executable(${target} ${target}.c ${extra})
        target_compile_definitions(${target} PRIVATE FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
        target_compile_options(${target} PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g)
        target_link_options(${target} PRIVATE -fsanitize=fuzzer,address,undefined)
    endforeach()
endif()
