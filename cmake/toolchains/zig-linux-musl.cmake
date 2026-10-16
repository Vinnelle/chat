# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 finlay@tuta.com
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR x86_64)
get_filename_component(_here "${CMAKE_CURRENT_LIST_FILE}" DIRECTORY)
set(CMAKE_C_COMPILER   "${_here}/zig-cc-musl")
set(CMAKE_ASM_COMPILER "${_here}/zig-cc-musl")
set(CMAKE_AR           "${_here}/zig-ar"     CACHE FILEPATH "")
set(CMAKE_RANLIB       "${_here}/zig-ranlib" CACHE FILEPATH "")
set(CMAKE_C_COMPILER_AR     "${_here}/zig-ar"     CACHE FILEPATH "")
set(CMAKE_C_COMPILER_RANLIB "${_here}/zig-ranlib" CACHE FILEPATH "")
set(CHAT_HOST_TRIPLE   x86_64-linux-musl)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
