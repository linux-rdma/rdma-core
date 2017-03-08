/*
 * This header is only used if sparse is detected and cmake arranges for it to
 * replace all includes for glibc's endian.h.  Redefine the glibc endianness
 * conversion macros in such a way that sparse can detect endianness
 * mismatches when building with -D__CHECK_ENDIAN__.
 */

#ifndef _ENDIAN_H_
#define _ENDIAN_H_

#ifdef __CHECKER__
# define __force __attribute__((force))
#else
# define __force
#endif

#include_next <endian.h>
#include <stdint.h>
#include <linux/types.h> /* __be16, __be32 and __be64 */

static inline uint16_t rdma_be16toh(uint16_t val) { return be16toh(val); }
static inline uint32_t rdma_be32toh(uint32_t val) { return be32toh(val); }
static inline uint64_t rdma_be64toh(uint64_t val) { return be64toh(val); }
static inline uint16_t rdma_htobe16(uint16_t val) { return htobe16(val); }
static inline uint32_t rdma_htobe32(uint32_t val) { return htobe32(val); }
static inline uint64_t rdma_htobe64(uint64_t val) { return htobe64(val); }
static inline uint16_t rdma_le16toh(uint16_t val) { return le16toh(val); }
static inline uint32_t rdma_le32toh(uint32_t val) { return le32toh(val); }
static inline uint64_t rdma_le64toh(uint64_t val) { return le64toh(val); }
static inline uint16_t rdma_htole16(uint16_t val) { return htole16(val); }
static inline uint32_t rdma_htole32(uint32_t val) { return htole32(val); }
static inline uint64_t rdma_htole64(uint64_t val) { return htole64(val); }

#undef be16toh
#undef be32toh
#undef be64toh
#undef htobe16
#undef htobe32
#undef htobe64
#undef le16toh
#undef le32toh
#undef le64toh
#undef htole16
#undef htole32
#undef htole64

/*
 * Note: the casts to uint64_t ensure that formatting macros like PRIx64 keep
 * working as expected.
 */

#define be16toh(val) rdma_be16toh((__force uint16_t)(__be16)(val))
#define be32toh(val) rdma_be32toh((__force uint32_t)(__be32)(val))
#define be64toh(val) (uint64_t)rdma_be64toh((__force uint64_t)(__be64)(val))
#define htobe16(val) ((__force __be16)rdma_htobe16(val))
#define htobe32(val) ((__force __be32)rdma_htobe32(val))
#define htobe64(val) ((__force __be64)rdma_htobe64(val))

#define le16toh(val) rdma_le16toh((__force uint16_t)(__le16)(val))
#define le32toh(val) rdma_le32toh((__force uint32_t)(__le32)(val))
#define le64toh(val) (uint64_t)rdma_le64toh((__force uint64_t)(__le64)(val))
#define htole16(val) ((__force __le16)rdma_htole16(val))
#define htole32(val) ((__force __le32)rdma_htole32(val))
#define htole64(val) ((__force __le64)rdma_htobe64(val))

#endif /* _ENDIAN_H_ */
