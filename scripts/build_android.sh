#!/usr/bin/env bash
# Cross-compile quic_api (+ xquic, BoringSSL, libevent) as static libraries for Android.
#
#   ANDROID_NDK_HOME=/path/to/android-ndk-r27c scripts/build_android.sh
#
# Environment:
#   ANDROID_NDK_HOME  Linux-host NDK (r27 or newer). Required.
#   ABI               arm64-v8a (default) or x86_64 (Android emulator).
#   API               Android API level. Default 32 (Quest / Horizon OS).
#   JOBS              Parallel build jobs. Default: nproc.
#
# Output: build-android/$ABI/out/{include,lib}. Link an application with the
# NDK's clang++ (BoringSSL needs the C++ runtime):
#   -lquic_api -lxquic-static -lssl -lcrypto -levent_core -llog -lm
set -euo pipefail

ABI="${ABI:-arm64-v8a}"
API="${API:-32}"
JOBS="${JOBS:-$(nproc)}"
NDK="${ANDROID_NDK_HOME:-}"

LIBEVENT_VER=2.1.12-stable
LIBEVENT_URL="https://github.com/libevent/libevent/releases/download/release-${LIBEVENT_VER}/libevent-${LIBEVENT_VER}.tar.gz"
LIBEVENT_SHA256=92e6de1be9ec176428fd2367677e61ceffc2ee1cb119035037a27d346b0403bb

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLCHAIN="$NDK/build/cmake/android.toolchain.cmake"
if [ -z "$NDK" ] || [ ! -f "$TOOLCHAIN" ]; then
    echo "ANDROID_NDK_HOME must point at an Android NDK (no $TOOLCHAIN)" >&2
    exit 2
fi
if [ ! -f "$ROOT/boringssl/CMakeLists.txt" ]; then
    echo "boringssl submodule missing: run git submodule update --init --recursive" >&2
    exit 2
fi

B="$ROOT/build-android/$ABI"
DEPS="$ROOT/build-android/_deps"
OUT="$B/out"
mkdir -p "$B" "$DEPS"

COMMON=(
    -G "Unix Makefiles"
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN"
    -DANDROID_ABI="$ABI"
    -DANDROID_PLATFORM="android-$API"
    -DANDROID_STL=c++_static
    -DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON
    -DCMAKE_BUILD_TYPE=Release
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON
)

echo "== BoringSSL ($ABI, android-$API)"
cmake -S "$ROOT/boringssl" -B "$B/boringssl" "${COMMON[@]}" -DBUILD_TESTING=OFF
cmake --build "$B/boringssl" --target ssl crypto -j "$JOBS"
SSL_A="$(find "$B/boringssl" -name libssl.a | head -1)"
CRYPTO_A="$(find "$B/boringssl" -name libcrypto.a | head -1)"
[ -f "$SSL_A" ] && [ -f "$CRYPTO_A" ]

echo "== libevent $LIBEVENT_VER"
LE_SRC="$DEPS/libevent-$LIBEVENT_VER"
if [ ! -d "$LE_SRC" ]; then
    curl -fL --retry 3 -o "$DEPS/libevent.tar.gz" "$LIBEVENT_URL"
    echo "$LIBEVENT_SHA256  $DEPS/libevent.tar.gz" | sha256sum -c -
    tar -xzf "$DEPS/libevent.tar.gz" -C "$DEPS"
fi
# libevent 2.1.12 declares cmake_minimum_required(3.1), which CMake 4 rejects, and
# only defines _GNU_SOURCE (needed for pipe2) the first time it is configured.
cmake -S "$LE_SRC" -B "$B/libevent" "${COMMON[@]}" \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DCMAKE_C_FLAGS=-D_GNU_SOURCE \
    -DEVENT__LIBRARY_TYPE=STATIC \
    -DEVENT__DISABLE_OPENSSL=ON \
    -DEVENT__DISABLE_THREAD_SUPPORT=ON \
    -DEVENT__DISABLE_TESTS=ON \
    -DEVENT__DISABLE_REGRESS=ON \
    -DEVENT__DISABLE_SAMPLES=ON \
    -DEVENT__DISABLE_BENCHMARK=ON
cmake --build "$B/libevent" --target event_core_static -j "$JOBS"
EVENT_A="$B/libevent/lib/libevent_core.a"
[ -f "$EVENT_A" ]

# One include dir holding libevent's source headers plus its generated event-config.h.
rm -rf "$OUT"
mkdir -p "$OUT/include" "$OUT/lib"
cp -r "$LE_SRC/include/." "$OUT/include/"
cp -r "$B/libevent/include/." "$OUT/include/"

echo "== xquic + quic_api"
cmake -S "$ROOT" -B "$B/xquic" "${COMMON[@]}" \
    -DSSL_TYPE=boringssl \
    -DSSL_PATH="$ROOT/boringssl" \
    -DSSL_INC_PATH="$ROOT/boringssl/include" \
    -DSSL_LIB_PATH="$SSL_A;$CRYPTO_A" \
    -DLIBEVENT_LIB="$EVENT_A" \
    -DLIBEVENT_INC_PATH="$OUT/include" \
    -DXQC_ENABLE_BBR2=1 \
    -DXQC_ENABLE_RENO=1 \
    -DXQC_ENABLE_EVENT_LOG=1 \
    -DXQC_ENABLE_TESTING=0 \
    -DGCOV=off \
    -DXQC_BUILD_APPS=OFF
cmake --build "$B/xquic" --target quic_api -j "$JOBS"

# Configuring writes include/xquic/xqc_configure.h into the source tree; it is tracked.
if ! git -C "$ROOT" diff --quiet -- include/xquic/xqc_configure.h; then
    echo "warning: include/xquic/xqc_configure.h changed; review before committing" >&2
fi

cp "$B/xquic/libquic_api.a" "$B/xquic/libxquic-static.a" "$SSL_A" "$CRYPTO_A" "$EVENT_A" "$OUT/lib/"
cp "$ROOT"/api/quic_api.h "$ROOT"/api/quic_rtp.h "$ROOT"/api/quic_fec.h "$OUT/include/"
cp -r "$ROOT/include/xquic" "$OUT/include/"

echo "== done: $OUT"
ls -l "$OUT/lib"
