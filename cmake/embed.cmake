# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 finlay@tuta.com
# Writes OUT, a header holding the file IN as `static const char NAME[]` (with a NUL after it),
# so :changelog can show the changelog without reading anything at run time.
file(READ "${IN}" hex HEX)
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," bytes "${hex}")
string(REGEX REPLACE "((0x..,){24})" "\\1\n    " bytes "${bytes}")
set(content "static const char ${NAME}[] = {\n    ${bytes}0x00\n};\n")
set(old "")
if(EXISTS "${OUT}")
    file(READ "${OUT}" old)
endif()
if(NOT "${old}" STREQUAL "${content}")
    file(WRITE "${OUT}" "${content}")
endif()
