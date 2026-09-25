version := `sed -n 's/^project(chat VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt`

# List recipes
default:
    @just --list

# Configure and build the native binary
build:
    cmake -B build
    cmake --build build -j {{num_cpus()}}

# Build a static musl Linux binary (needs zig on PATH)
build-static:
    cmake -B build-static -DCMAKE_TOOLCHAIN_FILE=cmake/zig-linux-musl.cmake
    cmake --build build-static -j {{num_cpus()}}

# Cross-build the Windows binary (needs zig on PATH)
build-win:
    cmake -B build-win -DCMAKE_TOOLCHAIN_FILE=cmake/zig-windows.cmake
    cmake --build build-win -j {{num_cpus()}}

# Build native and Windows binaries
all: build build-win

# Build, then run chat with the given arguments
[positional-arguments]
run *args: build
    ./build/chat "$@"

# Put standalone release binaries and SHA256SUMS in dist/
dist: build-static build-win
    rm -rf dist
    mkdir dist
    cp build-static/chat dist/chat-linux-x86_64
    cp build-win/chat.exe dist/chat-windows-x86_64.exe
    strip dist/chat-linux-x86_64
    cd dist && sha256sum chat-linux-x86_64 chat-windows-x86_64.exe > SHA256SUMS
    @echo "dist/ ready for v{{version}}"

# Remove build directories and release output
clean:
    rm -rf build build-static build-win dist
