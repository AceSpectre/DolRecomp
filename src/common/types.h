#ifndef DOLRECOMP_TYPES_H
#define DOLRECOMP_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#ifdef _MSC_VER
#include <stdlib.h> /* _byteswap_* */
#endif

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;
typedef float    f32;
typedef double   f64;

// sign-extend from N bits to s32
static inline s32 sign_extend(u32 value, int bits) {
    u32 mask = 1u << (bits - 1);
    return (s32)((value ^ mask) - mask);
}

// byte swap — compiler intrinsics, not shift/or chains. MSVC does not
// reliably recognise the byte-at-a-time pattern, and ~50% of the emitted
// guest instructions are memory accesses that funnel through these.
#ifdef _MSC_VER
static inline u16 bswap16(u16 v) { return _byteswap_ushort(v); }
static inline u32 bswap32(u32 v) { return _byteswap_ulong(v); }
static inline u64 bswap64(u64 v) { return _byteswap_uint64(v); }
#elif defined(__GNUC__) || defined(__clang__)
static inline u16 bswap16(u16 v) { return __builtin_bswap16(v); }
static inline u32 bswap32(u32 v) { return __builtin_bswap32(v); }
static inline u64 bswap64(u64 v) { return __builtin_bswap64(v); }
#else
static inline u16 bswap16(u16 v) {
    return (u16)((v >> 8) | (v << 8));
}
static inline u32 bswap32(u32 v) {
    return ((v >> 24) & 0x000000FF) |
           ((v >>  8) & 0x0000FF00) |
           ((v <<  8) & 0x00FF0000) |
           ((v << 24) & 0xFF000000);
}
static inline u64 bswap64(u64 v) {
    return ((u64)bswap32((u32)v) << 32) | bswap32((u32)(v >> 32));
}
#endif

// big-endian read/write: memcpy load/store (unaligned-safe, folds to a plain
// mov on x86) plus one bswap.
static inline u16 read_be16(const u8* p) {
    u16 v; memcpy(&v, p, sizeof v); return bswap16(v);
}

static inline u32 read_be32(const u8* p) {
    u32 v; memcpy(&v, p, sizeof v); return bswap32(v);
}

static inline u64 read_be64(const u8* p) {
    u64 v; memcpy(&v, p, sizeof v); return bswap64(v);
}

static inline void write_be16(u8* p, u16 v) {
    v = bswap16(v); memcpy(p, &v, sizeof v);
}

static inline void write_be32(u8* p, u32 v) {
    v = bswap32(v); memcpy(p, &v, sizeof v);
}

static inline void write_be64(u8* p, u64 v) {
    v = bswap64(v); memcpy(p, &v, sizeof v);
}

#endif /* DOLRECOMP_TYPES_H */
