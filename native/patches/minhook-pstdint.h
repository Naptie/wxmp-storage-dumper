/*
 * MSVC compatibility shim for MinHook's vendored HDE length-decoder.
 *
 * MinHook's src/hde/hde64.h includes <pstdint.h>, which is a MinGW-only header.
 * Per its own comment in that file, MSVC users should use <stdint.h> instead.
 * MSVC also provides the BitScan intrinsics MinHook relies on via <intrin.h>.
 *
 * This shim exists so the VENDORED MinHook sources stay byte-for-byte as
 * published (no local edits to third-party code).
 */
#pragma once

#include <stdint.h>
#include <intrin.h>