#!/bin/sh
set -eu

ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

if [ "$(uname -s)" != Darwin ]; then
    printf '%s\n' 'Host tests require macOS and Xcode command-line tools.' >&2
    exit 1
fi

BUILD="$ROOT/.build/tests"
SDK=$(xcrun --sdk macosx --show-sdk-path)
CC=$(xcrun --sdk macosx --find clang)
mkdir -p "$BUILD/include/xpf"
cp BaseBin/XPF/src/xpf.h "$BUILD/include/xpf/"

python3 -m unittest discover -s tests -v
"$CC" -isysroot "$SDK" -Wall -Wextra -Werror tests/bootlog_tests.c -o "$BUILD/bootlog_tests"
"$BUILD/bootlog_tests" "$BUILD/boot-phase.log"
for ownership in -fobjc-arc -fno-objc-arc; do
    "$CC" -isysroot "$SDK" "$ownership" -fsyntax-only -Werror \
        tests/xpc_ownership_tests.m
done
printf '%s\n' 'XPC return-ownership checks passed with and without ARC.'

"$CC" -isysroot "$SDK" -fblocks -fsyntax-only -Werror tests/ane_header_tests.m
printf '%s\n' 'ANE relocation header compatibility and layout checks passed.'

"$CC" -isysroot "$SDK" -Werror tests/dyld_symbol_tests.c \
    BaseBin/systemhook/src/image_symbols.c -o "$BUILD/dyld_symbol_tests"
"$BUILD/dyld_symbol_tests"

"${MAKE:-make}" -C BaseBin/XPF output/macos/libxpf.dylib CHOMA_PATH=../ChOma
export DYLD_LIBRARY_PATH="$ROOT/BaseBin/XPF/output/macos${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"

"$CC" -isysroot "$SDK" -fobjc-arc -framework Foundation -Wl,-adhoc_codesign \
    tests/version_tests.m Application/Dopamine/Extensions/NSString+Version.m \
    -o "$BUILD/version_tests"
"$BUILD/version_tests"

"$CC" -isysroot "$SDK" -fblocks -Wno-deprecated-declarations \
    -IBaseBin/ChOma/include -LBaseBin/XPF/output/macos -lxpf -framework Foundation \
    tests/code_signing_tests.c BaseBin/libjailbreak/src/roothider/code_signing.c \
    -o "$BUILD/code_signing_tests"
"$BUILD/code_signing_tests" "$BUILD/version_tests"

"$CC" -isysroot "$SDK" -fobjc-arc -fblocks -Wno-deprecated-declarations \
    -IBaseBin/ChOma/include -idirafter BaseBin/_external/include \
    -LBaseBin/XPF/output/macos -lxpf -framework Foundation \
    tests/trust_signatures_tests.m BaseBin/libjailbreak/src/signatures.c \
    BaseBin/libjailbreak/src/roothider/recdhash.m \
    BaseBin/libjailbreak/src/roothider/code_signing.c -o "$BUILD/trust_signatures_tests"
for binary in killall dash; do
    tar -xOf Application/Dopamine/Resources/bootstrap_1900.tar.zst "./usr/bin/$binary" > "$BUILD/trust-fixture-$binary"
    "$BUILD/trust_signatures_tests" "$BUILD/trust-fixture-$binary" "$BUILD"
done

"$CC" -isysroot "$SDK" -fblocks -I"$BUILD/include" -IBaseBin/ChOma/include \
    -LBaseBin/XPF/output/macos -lxpf tests/patchfinder_tests.c \
    Application/Dopamine/Jailbreak/DORoothidePatchfinder.c -o "$BUILD/patchfinder_tests"

if [ "$#" -eq 0 ]; then
    printf '%s\n' 'Kernel-fixture checks not run; pass explicit kernelcache paths to include them.'
else
    for kernel in "$@"; do
        "$BUILD/patchfinder_tests" "$kernel"
    done
fi

printf '%s\n' 'Host regressions passed. These tests do not establish on-device correctness.'
