# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 finlay@tuta.com
string(TIMESTAMP now "%Y-%m-%d %H:%M UTC" UTC)
set(content "#define CHAT_BUILD_STAMP \"${now}\"\n")
set(old "")
if(EXISTS "${OUT}")
    file(READ "${OUT}" old)
endif()
if(NOT "${old}" STREQUAL "${content}")
    file(WRITE "${OUT}" "${content}")
endif()
