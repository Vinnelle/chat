# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 finlay@tuta.com
# The engine test runs sessions against each other over fake_net.c instead of real sockets.
# The fuzz targets need clang (libFuzzer): configure with -DCHAT_FUZZ=ON -DCMAKE_C_COMPILER=clang.
if(WIN32)
    message(FATAL_ERROR "chat: the tests build on Linux only")
endif()

set(CHAT_CORE_SOURCES
    ${PROJECT_SOURCE_DIR}/src/chat.c
    ${PROJECT_SOURCE_DIR}/src/cmd.c
    ${PROJECT_SOURCE_DIR}/src/dht.c
    ${PROJECT_SOURCE_DIR}/src/bencode.c
    ${PROJECT_SOURCE_DIR}/src/crypto.c
    ${PROJECT_SOURCE_DIR}/src/util.c
    ${PROJECT_SOURCE_DIR}/src/age.c
    ${PROJECT_SOURCE_DIR}/src/pgp.c
    ${PROJECT_SOURCE_DIR}/src/tui.c
    ${PROJECT_SOURCE_DIR}/src/${CHAT_OS}/platform.c
    ${CMAKE_CURRENT_SOURCE_DIR}/fake_net.c
)

function(chat_test_executable name)
    add_executable(${name} ${ARGN} ${CHAT_CORE_SOURCES})
    add_dependencies(${name} libsodium_ext liboqs_ext)
    target_compile_definitions(${name} PRIVATE CHAT_VERSION="test")
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/src
                               ${PROJECT_SOURCE_DIR}/src/${CHAT_OS} ${SODIUM_INCLUDE_DIRS} ${OQS_INCLUDE_DIRS})
    target_link_libraries(${name} PRIVATE ${SODIUM_STATIC_LIB} ${OQS_STATIC_LIB} Threads::Threads)
    target_compile_options(${name} PRIVATE -Wall -Wextra)
endfunction()

chat_test_executable(engine_test engine_test.c)
add_test(NAME engine COMMAND engine_test)

if(CHAT_FUZZ)
    foreach(target fuzz_bencode fuzz_pgp fuzz_text fuzz_engine)
        chat_test_executable(${target} ${target}.c)
        target_compile_options(${target} PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g)
        target_link_options(${target} PRIVATE -fsanitize=fuzzer,address,undefined)
    endforeach()
endif()
