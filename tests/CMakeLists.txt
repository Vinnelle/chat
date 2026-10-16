# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 finlay@tuta.com
# The engine test (engine/) runs sessions against each other over support/fake_net.c instead of real sockets, on
# Linux or (cross-built with zig) Windows. The fuzz targets need clang (libFuzzer) and Linux:
# configure with -DCHAT_FUZZ=ON -DCMAKE_C_COMPILER=clang.
if(WIN32 AND CHAT_FUZZ)
    message(FATAL_ERROR "chat: the fuzz targets build on Linux only")
endif()

# The top level's CHAT_CORE_SOURCES, with the sockets and the platform's own code faked.
set(TEST_SOURCES ${CHAT_CORE_SOURCES} ${CMAKE_CURRENT_SOURCE_DIR}/support/fake_net.c
                 ${CMAKE_CURRENT_SOURCE_DIR}/support/test_os.c)

function(chat_test_executable name)
    add_executable(${name} EXCLUDE_FROM_ALL ${ARGN} ${TEST_SOURCES})
    add_dependencies(${name} libsodium_ext liboqs_ext mbedtls_ext secp256k1_ext)
    target_compile_definitions(${name} PRIVATE CHAT_VERSION="test" MBEDTLS_USER_CONFIG_FILE="${CHAT_MBEDTLS_CONFIG}")
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/support ${PROJECT_SOURCE_DIR}/src
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

# The engine test runs its files' tests in the order engine_test.c lists them. It builds the saves'
# code too, with a device and a security key of the test's own in engine/saves_test.c.
chat_test_executable(engine_test engine/engine_test.c engine/harness.c engine/sessions_test.c engine/parsers_test.c
                     engine/platform_test.c engine/identity_test.c engine/saves_test.c engine/pictures_test.c
                     engine/files_test.c engine/move_test.c ${PROJECT_SOURCE_DIR}/src/app/install.c
                     ${PROJECT_SOURCE_DIR}/src/app/rooms.c)
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
        chat_test_executable(${target} fuzz/${target}.c ${extra})
        target_compile_definitions(${target} PRIVATE FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
        target_compile_options(${target} PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g)
        target_link_options(${target} PRIVATE -fsanitize=fuzzer,address,undefined)
    endforeach()
endif()
