# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 finlay@tuta.com
cmake_minimum_required(VERSION 3.15)
project(chat VERSION 0.1.10 LANGUAGES C)

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

# Each function and object in a section of its own, so --gc-sections drops what chat never calls.
set(DEP_SECTION_FLAGS "")
if(NOT MSVC)
    set(DEP_SECTION_FLAGS "-ffunction-sections -fdata-sections")
endif()

set(DEP_CC_ARGS "")
set(OQS_CROSS_ARGS "")
if(CMAKE_CROSSCOMPILING)
    set(DEP_CC_ARGS CC=${CMAKE_C_COMPILER} AR=${CMAKE_AR} RANLIB=${CMAKE_RANLIB} --host=${CHAT_HOST_TRIPLE})
    # Absolute: the dependencies configure in their own directories, where a relative path breaks.
    get_filename_component(CHAT_TOOLCHAIN_FILE "${CMAKE_TOOLCHAIN_FILE}" ABSOLUTE BASE_DIR "${CMAKE_SOURCE_DIR}")
    set(OQS_CROSS_ARGS -DCMAKE_TOOLCHAIN_FILE=${CHAT_TOOLCHAIN_FILE})
endif()

set(SODIUM_VERSION 1.0.20-stable)
set(SODIUM_PREFIX ${CMAKE_BINARY_DIR}/libsodium-ext)
# As many compilers at once as there are CPUs: a bare -j starts one per file, which can run a
# small machine out of memory in the middle of the build.
include(ProcessorCount)
ProcessorCount(DEP_JOBS)
if(DEP_JOBS EQUAL 0)
    set(DEP_JOBS 2)
endif()
ExternalProject_Add(libsodium_ext
    URL https://download.libsodium.org/libsodium/releases/libsodium-${SODIUM_VERSION}.tar.gz
    URL_HASH SHA256=b6b1d2a8802cd8bfa611638c0e9ce31d14ef324e16062c39a76854091cba6d7f
    DOWNLOAD_EXTRACT_TIMESTAMP true
    PREFIX ${SODIUM_PREFIX}
    BUILD_IN_SOURCE 1
    # CFLAGS given replace libsodium's default -O3, so it's named here along with the sections.
    CONFIGURE_COMMAND <SOURCE_DIR>/configure --disable-shared --enable-static --with-pic
                       --prefix=${SODIUM_PREFIX}/install ${DEP_CC_ARGS} "CFLAGS=-O3 ${DEP_SECTION_FLAGS}"
    BUILD_COMMAND ${CMAKE_MAKE_PROGRAM} -j${DEP_JOBS}
    INSTALL_COMMAND ${CMAKE_MAKE_PROGRAM} install
    BUILD_BYPRODUCTS ${SODIUM_PREFIX}/install/lib/libsodium.a
)
set(SODIUM_INCLUDE_DIRS ${SODIUM_PREFIX}/install/include)
set(SODIUM_STATIC_LIB ${SODIUM_PREFIX}/install/lib/libsodium.a)

set(OQS_VERSION 0.16.0)
set(OQS_PREFIX ${CMAKE_BINARY_DIR}/liboqs-ext)
# A native build without OQS_DIST_BUILD takes the build machine's CPU features for granted, and a
# copy on another machine (just test-build) dies on a CPU without them: it picks AVX2 code at run
# time instead. A cross build (the releases, through zig) has plain C only, since zig's assembler
# leaves the AVX2 assembly empty; a handshake's ML-KEM takes well under a millisecond either way.
if(CMAKE_CROSSCOMPILING)
    set(OQS_DIST OFF)
else()
    set(OQS_DIST ON)
endif()
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
        -DOQS_DIST_BUILD=${OQS_DIST}
        "-DCMAKE_C_FLAGS=${DEP_SECTION_FLAGS}"
        ${OQS_CROSS_ARGS}
    BUILD_BYPRODUCTS ${OQS_PREFIX}/install/lib/liboqs.a
)
set(OQS_INCLUDE_DIRS ${OQS_PREFIX}/install/include)
set(OQS_STATIC_LIB ${OQS_PREFIX}/install/lib/liboqs.a)

# TLS for the Nostr relays' wss:// connections, configured down to a client (cmake/mbedtls-config.h).
set(MBEDTLS_VERSION 3.6.7)
set(MBEDTLS_PREFIX ${CMAKE_BINARY_DIR}/mbedtls-ext)
set(CHAT_MBEDTLS_CONFIG ${CMAKE_SOURCE_DIR}/cmake/mbedtls-config.h)
ExternalProject_Add(mbedtls_ext
    URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-${MBEDTLS_VERSION}/mbedtls-${MBEDTLS_VERSION}.tar.bz2
    URL_HASH SHA256=a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6
    DOWNLOAD_EXTRACT_TIMESTAMP true
    PREFIX ${MBEDTLS_PREFIX}
    CMAKE_ARGS
        -DCMAKE_BUILD_TYPE=Release
        -DCMAKE_INSTALL_PREFIX=${MBEDTLS_PREFIX}/install
        -DCMAKE_INSTALL_LIBDIR=lib
        -DENABLE_PROGRAMS=OFF
        -DENABLE_TESTING=OFF
        -DUSE_SHARED_MBEDTLS_LIBRARY=OFF
        -DUSE_STATIC_MBEDTLS_LIBRARY=ON
        -DMBEDTLS_FATAL_WARNINGS=OFF
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON
        -DMBEDTLS_USER_CONFIG_FILE=${CHAT_MBEDTLS_CONFIG}
        "-DCMAKE_C_FLAGS=${DEP_SECTION_FLAGS}"
        ${OQS_CROSS_ARGS}
    BUILD_BYPRODUCTS ${MBEDTLS_PREFIX}/install/lib/libmbedtls.a ${MBEDTLS_PREFIX}/install/lib/libmbedx509.a
                     ${MBEDTLS_PREFIX}/install/lib/libmbedcrypto.a
)
# A change to the config rebuilds the library, as it does chat.
ExternalProject_Add_StepDependencies(mbedtls_ext configure ${CHAT_MBEDTLS_CONFIG})
set(MBEDTLS_INCLUDE_DIRS ${MBEDTLS_PREFIX}/install/include)
set(MBEDTLS_STATIC_LIBS ${MBEDTLS_PREFIX}/install/lib/libmbedtls.a ${MBEDTLS_PREFIX}/install/lib/libmbedx509.a
                        ${MBEDTLS_PREFIX}/install/lib/libmbedcrypto.a)

# BIP-340 Schnorr signatures, which Nostr events carry.
set(SECP256K1_VERSION 0.7.1)
set(SECP256K1_PREFIX ${CMAKE_BINARY_DIR}/secp256k1-ext)
ExternalProject_Add(secp256k1_ext
    URL https://github.com/bitcoin-core/secp256k1/archive/refs/tags/v${SECP256K1_VERSION}.tar.gz
    URL_HASH SHA256=958f204dbafc117e73a2604285dc2eb2a5128344d3499c114dcba5de54cb7a9e
    DOWNLOAD_EXTRACT_TIMESTAMP true
    PREFIX ${SECP256K1_PREFIX}
    CMAKE_ARGS
        -DCMAKE_BUILD_TYPE=Release
        -DCMAKE_INSTALL_PREFIX=${SECP256K1_PREFIX}/install
        -DCMAKE_INSTALL_LIBDIR=lib
        -DBUILD_SHARED_LIBS=OFF
        -DSECP256K1_INSTALL=ON
        -DSECP256K1_BUILD_TESTS=OFF
        -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF
        -DSECP256K1_BUILD_BENCHMARK=OFF
        -DSECP256K1_BUILD_CTIME_TESTS=OFF
        -DSECP256K1_ENABLE_MODULE_ECDH=OFF
        -DSECP256K1_ENABLE_MODULE_MUSIG=OFF
        -DSECP256K1_ENABLE_MODULE_ELLSWIFT=OFF
        # chat only signs (each Nostr event, with a key of its own) and never verifies: the
        # smallest verification tables (1 MiB less), and the middle signing one (64 KiB less).
        -DSECP256K1_ECMULT_WINDOW_SIZE=2
        -DSECP256K1_ECMULT_GEN_KB=22
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON
        "-DCMAKE_C_FLAGS=${DEP_SECTION_FLAGS}"
        ${OQS_CROSS_ARGS}
    BUILD_BYPRODUCTS ${SECP256K1_PREFIX}/install/lib/libsecp256k1.a
)
set(SECP256K1_INCLUDE_DIRS ${SECP256K1_PREFIX}/install/include)
set(SECP256K1_STATIC_LIB ${SECP256K1_PREFIX}/install/lib/libsecp256k1.a)

add_executable(chat
    src/app/main.c
    src/app/tui.c
    src/app/update.c
    src/core/chat.c
    src/core/cmd.c
    src/crypto/crypto.c
    src/crypto/age.c
    src/crypto/pgp.c
    src/transport/dht.c
    src/transport/nostr.c
    src/transport/tls.c
    src/transport/tor.c
    src/transport/torproc.c
    src/transport/portmap.c
    src/common/util.c
    src/common/bencode.c
    src/common/json.c
    src/platform/${CHAT_OS}/net.c
    src/platform/${CHAT_OS}/platform.c
)

add_custom_target(build_stamp ALL
    COMMAND ${CMAKE_COMMAND} -DOUT=${CMAKE_BINARY_DIR}/build_stamp.h -DSRC=${CMAKE_SOURCE_DIR} -P ${CMAKE_SOURCE_DIR}/cmake/stamp.cmake
    BYPRODUCTS ${CMAKE_BINARY_DIR}/build_stamp.h)
add_dependencies(chat libsodium_ext liboqs_ext mbedtls_ext secp256k1_ext build_stamp)
target_compile_definitions(chat PRIVATE CHAT_VERSION="${PROJECT_VERSION}" MBEDTLS_USER_CONFIG_FILE="${CHAT_MBEDTLS_CONFIG}")

# /update installs only releases whose SHA256SUMS the key in minisign.pub signed (`just keygen`
# makes one). Without the file the build still works, but refuses every update.
set(CHAT_PUBKEY_FILE ${CMAKE_SOURCE_DIR}/minisign.pub CACHE FILEPATH "minisign public key releases are checked with")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${CHAT_PUBKEY_FILE})
if(EXISTS ${CHAT_PUBKEY_FILE})
    file(STRINGS ${CHAT_PUBKEY_FILE} CHAT_PUBKEY_LINES)
    list(LENGTH CHAT_PUBKEY_LINES CHAT_PUBKEY_N)
    if(CHAT_PUBKEY_N LESS 2)
        message(FATAL_ERROR "chat: minisign.pub should have a comment line and a key line")
    endif()
    list(GET CHAT_PUBKEY_LINES 1 CHAT_RELEASE_PUBKEY)
    string(STRIP "${CHAT_RELEASE_PUBKEY}" CHAT_RELEASE_PUBKEY)
    if(NOT CHAT_RELEASE_PUBKEY MATCHES "^RW[A-Za-z0-9+/]+$")
        message(FATAL_ERROR "chat: minisign.pub's second line isn't a minisign public key")
    endif()
    target_compile_definitions(chat PRIVATE CHAT_RELEASE_PUBKEY="${CHAT_RELEASE_PUBKEY}")
else()
    message(WARNING "chat: no minisign.pub - this build will refuse every update (`just keygen` makes one)")
endif()
target_include_directories(chat PRIVATE src src/platform/${CHAT_OS} ${CMAKE_BINARY_DIR} ${SODIUM_INCLUDE_DIRS} ${OQS_INCLUDE_DIRS}
                           ${MBEDTLS_INCLUDE_DIRS} ${SECP256K1_INCLUDE_DIRS})
target_link_libraries(chat PRIVATE ${SODIUM_STATIC_LIB} ${OQS_STATIC_LIB} ${MBEDTLS_STATIC_LIBS} ${SECP256K1_STATIC_LIB})

if(WIN32)

    target_compile_definitions(chat PRIVATE SODIUM_STATIC=1 SECP256K1_STATIC=1 WIN32_LEAN_AND_MEAN)

    target_link_libraries(chat PRIVATE ws2_32 bcrypt advapi32 shell32 user32 crypt32 iphlpapi)
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
    # Stack variables start zeroed, so a missed initialisation can't leak an earlier call's key bytes.
    chat_try_compile_flag(-ftrivial-auto-var-init=zero)
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
# Symbols only make a release bigger: stripped as it's linked. Debug builds keep them.
if(NOT MSVC AND (CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "MinSizeRel"))
    chat_try_link_flag(-s)
endif()

option(CHAT_TESTS "Build the engine test (tests/)" OFF)
option(CHAT_FUZZ "Also build the libFuzzer targets (needs clang)" OFF)
if(CHAT_TESTS OR CHAT_FUZZ)
    enable_testing()
    add_subdirectory(tests)
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
