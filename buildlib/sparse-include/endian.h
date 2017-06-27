/* COPYRIGHT (c) 2017 Obsidian Research Corporation.
   Licensed under BSD (MIT variant) or GPLv2. See COPYING. */

#ifndef _SPARSE_ENDIAN_H_
#define _SPARSE_ENDIAN_H_

#include_next <endian.h>

#include <util/compiler.h>

#undef htobe16
#undef htole16
#undef be16toh
#undef le16toh

#undef htobe32
#undef htole32
#undef be32toh
#undef le32toh

#undef htobe64
#undef htole64
#undef be64toh
#undef le64toh

/* These do not actually work, but this trivially ensures that sparse sees all
 * the types. */

#define htobe16(x) ((__force __be16)__builtin_bswap16(x))
#define htole16(x) ((__force __le16)__builtin_bswap16(x))
#define be16toh(x) ((uint16_t)__builtin_bswap16((__force uint16_t)(__be16)(x)))
#define le16toh(x) ((uint16_t)__builtin_bswap16((__force uint16_t)(__le16)(x)))

#define htobe32(x) ((__force __be32)__builtin_bswap32(x))
#define htole32(x) ((__force __le32)__builtin_bswap32(x))
#define be32toh(x) ((uint32_t)__builtin_bswap32((__force uint32_t)(__be32)(x)))
#define le32toh(x) ((uint32_t)__builtin_bswap32((__force uint32_t)(__le32)(x)))

#define htobe64(x) ((__force __be64)__builtin_bswap64(x))
#define htole64(x) ((__force __le64)__builtin_bswap64(x))
#define be64toh(x) ((uint64_t)__builtin_bswap64((__force uint64_t)(__be64)(x)))
#define le64toh(x) ((uint64_t)__builtin_bswap64((__force uint64_t)(__le64)(x)))

#endif
