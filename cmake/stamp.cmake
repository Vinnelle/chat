# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 finlay@tuta.com
# Writes build_stamp.h: when the build ran and which source it came from. CHAT_BUILD_ID is the
# same in a filename-safe form, used by `just build test`, which sets CHAT_TEST_BUILD.
string(TIMESTAMP now "%Y-%m-%d %H:%M:%S UTC" UTC)
string(TIMESTAMP compact "%Y%m%d-%H%M%S" UTC)
set(rev "nogit")
if(SRC)
    execute_process(COMMAND git describe --tags --always --dirty
                    WORKING_DIRECTORY "${SRC}" OUTPUT_VARIABLE out RESULT_VARIABLE rc
                    OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
    if(rc EQUAL 0 AND out MATCHES "^[A-Za-z0-9._-]+$")
        set(rev "${out}")
    endif()
endif()
set(content "#define CHAT_BUILD_STAMP \"${now}, ${rev}\"\n#define CHAT_BUILD_ID \"${rev}-${compact}\"\n")
if("$ENV{CHAT_TEST_BUILD}" STREQUAL "1")
    string(APPEND content "#define CHAT_TEST_BUILD 1\n")
endif()
set(old "")
if(EXISTS "${OUT}")
    file(READ "${OUT}" old)
endif()
if(NOT "${old}" STREQUAL "${content}")
    file(WRITE "${OUT}" "${content}")
endif()
