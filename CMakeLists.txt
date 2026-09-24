# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 finlay@tuta.com
cmake_minimum_required(VERSION 3.15)
project(chat VERSION 0.1.1 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(WIN32)
    set(CHAT_OS windows)
else()
    set(CHAT_OS linux)
    add_compile_definitions(_POSIX_C_SOURCE=200809L)
endif()

include(ExternalProject)

set(DEP_CC_ARGS "")
set(OQS_CROSS_ARGS "")
if(CMAKE_CROSSCOMPILING)
    set(DEP_CC_ARGS CC=${CMAKE_C_COMPILER} AR=${CMAKE_AR} RANLIB=${CMAKE_RANLIB} --host=${CHAT_HOST_TRIPLE})
    set(OQS_CROSS_ARGS -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE})
endif()

set(SODIUM_VERSION 1.0.20-stable)
set(SODIUM_PREFIX ${CMAKE_BINARY_DIR}/libsodium-ext)
ExternalProject_Add(libsodium_ext
    URL https://download.libsodium.org/libsodium/releases/libsodium-${SODIUM_VERSION}.tar.gz
    URL_HASH SHA256=b6b1d2a8802cd8bfa611638c0e9ce31d14ef324e16062c39a76854091cba6d7f
    DOWNLOAD_EXTRACT_TIMESTAMP true
    PREFIX ${SODIUM_PREFIX}
    BUILD_IN_SOURCE 1
    CONFIGURE_COMMAND <SOURCE_DIR>/configure --disable-shared --enable-static --with-pic
                       --prefix=${SODIUM_PREFIX}/install ${DEP_CC_ARGS}
    BUILD_COMMAND ${CMAKE_MAKE_PROGRAM} -j
    INSTALL_COMMAND ${CMAKE_MAKE_PROGRAM} install
    BUILD_BYPRODUCTS ${SODIUM_PREFIX}/install/lib/libsodium.a
)
set(SODIUM_INCLUDE_DIRS ${SODIUM_PREFIX}/install/include)
set(SODIUM_STATIC_LIB ${SODIUM_PREFIX}/install/lib/libsodium.a)

set(OQS_VERSION 0.16.0)
set(OQS_PREFIX ${CMAKE_BINARY_DIR}/liboqs-ext)
ExternalProject_Add(liboqs_ext
    URL https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${OQS_VERSION}.tar.gz
    URL_HASH SHA256=162d5b510518ee5f285f82fa1f16402a885176e818bf1b1a4c3c91c9a2f01eae
    DOWNLOAD_EXTRACT_TIMESTAMP true
    PREFIX ${OQS_PREFIX}
    CMAKE_ARGS
        -DCMAKE_BUILD_TYPE=Release
        -DCMAKE_INSTALL_PREFIX=${OQS_PREFIX}/install
        -DBUILD_SHARED_LIBS=OFF
        -DOQS_BUILD_ONLY_LIB=ON
        -DOQS_USE_OPENSSL=OFF
        -DOQS_MINIMAL_BUILD=KEM_ml_kem_768
        -DOQS_DIST_BUILD=OFF
        ${OQS_CROSS_ARGS}
    BUILD_BYPRODUCTS ${OQS_PREFIX}/install/lib/liboqs.a
)
set(OQS_INCLUDE_DIRS ${OQS_PREFIX}/install/include)
set(OQS_STATIC_LIB ${OQS_PREFIX}/install/lib/liboqs.a)

add_executable(chat
    src/main.c
    src/chat.c
    src/cmd.c
    src/dht.c
    src/bencode.c
    src/crypto.c
    src/util.c
    src/age.c
    src/pgp.c
    src/tui.c
    src/update.c
    src/${CHAT_OS}/net.c
    src/${CHAT_OS}/platform.c
)

add_custom_target(build_stamp ALL
    COMMAND ${CMAKE_COMMAND} -DOUT=${CMAKE_BINARY_DIR}/build_stamp.h -P ${CMAKE_SOURCE_DIR}/cmake/stamp.cmake
    BYPRODUCTS ${CMAKE_BINARY_DIR}/build_stamp.h)
add_dependencies(chat libsodium_ext liboqs_ext build_stamp)
target_compile_definitions(chat PRIVATE CHAT_VERSION="${PROJECT_VERSION}")
target_include_directories(chat PRIVATE src src/${CHAT_OS} ${CMAKE_BINARY_DIR} ${SODIUM_INCLUDE_DIRS} ${OQS_INCLUDE_DIRS})
target_link_libraries(chat PRIVATE ${SODIUM_STATIC_LIB} ${OQS_STATIC_LIB})

if(WIN32)

    target_compile_definitions(chat PRIVATE SODIUM_STATIC=1 WIN32_LEAN_AND_MEAN)

    target_link_libraries(chat PRIVATE ws2_32 bcrypt advapi32 shell32 user32)
    target_link_options(chat PRIVATE -static)
else()
    find_package(Threads REQUIRED)
    target_link_libraries(chat PRIVATE Threads::Threads)
endif()

if(MSVC)
    target_compile_options(chat PRIVATE /W4)
else()
    target_compile_options(chat PRIVATE -Wall -Wextra)
endif()

include(CheckCCompilerFlag)
include(CheckLinkerFlag OPTIONAL RESULT_VARIABLE HAVE_CHECK_LINKER_FLAG)

check_c_compiler_flag(-Werror=unused-command-line-argument CFLAG_STRICT_UNUSED_ARG)

function(chat_try_compile_flag flag)
    string(MAKE_C_IDENTIFIER "CFLAG${flag}" var)
    set(probe "")
    if(CFLAG_STRICT_UNUSED_ARG)
        set(probe "-Werror=unused-command-line-argument")
    endif()
    foreach(extra IN LISTS ARGN)
        set(probe "${probe} ${extra}")
    endforeach()
    set(CMAKE_REQUIRED_FLAGS "${probe}")
    check_c_compiler_flag(${flag} ${var})
    if(${var})
        target_compile_options(chat PRIVATE ${flag})
    endif()
endfunction()

function(chat_try_link_flag flag)
    string(MAKE_C_IDENTIFIER "LDFLAG${flag}" var)

    set(CMAKE_TRY_COMPILE_TARGET_TYPE EXECUTABLE)
    if(HAVE_CHECK_LINKER_FLAG)
        check_linker_flag(C ${flag} ${var})
    else()

        set(CMAKE_REQUIRED_LINK_OPTIONS ${flag})
        check_c_compiler_flag("" ${var})
    endif()
    if(${var})
        target_link_options(chat PRIVATE ${flag})
    endif()
endfunction()

if(NOT MSVC)

    chat_try_compile_flag(-fstack-protector-strong)
    chat_try_compile_flag(-fstack-clash-protection)

    chat_try_compile_flag(-fcf-protection=full)

    if(CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
        chat_try_compile_flag(-D_FORTIFY_SOURCE=3)
    endif()

    chat_try_compile_flag(-Wformat)
    chat_try_compile_flag(-Werror=format-security -Wformat)

    chat_try_compile_flag(-fwrapv)
    chat_try_compile_flag(-fno-strict-aliasing)
    chat_try_compile_flag(-fno-delete-null-pointer-checks)
endif()

if(WIN32)

    chat_try_link_flag(-Wl,--dynamicbase)
    chat_try_link_flag(-Wl,--nxcompat)
    chat_try_link_flag(-Wl,--high-entropy-va)
elseif(NOT MSVC)

    chat_try_compile_flag(-fPIE)
    chat_try_link_flag(-pie)
    chat_try_link_flag(-Wl,-z,relro)
    chat_try_link_flag(-Wl,-z,now)
    chat_try_link_flag(-Wl,-z,noexecstack)
endif()

chat_try_compile_flag(-ffunction-sections)
chat_try_compile_flag(-fdata-sections)
if(APPLE)
    chat_try_link_flag(-Wl,-dead_strip)
else()
    chat_try_link_flag(-Wl,--gc-sections)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    include(CheckIPOSupported)
    check_ipo_supported(RESULT CHAT_IPO_OK OUTPUT CHAT_IPO_WHY LANGUAGES C)
    if(CHAT_IPO_OK)
        set_property(TARGET chat PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
    else()
        message(STATUS "chat: link-time optimisation unavailable (${CHAT_IPO_WHY})")
    endif()
endif()
