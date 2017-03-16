/*
 * This header is only used if sparse is detected and cmake arranges for it to
 * replace all includes for glibc's <netinet/in.h>. Redefine the glibc socket
 * data structures and macros in such a way that sparse can detect endianness
 * mismatches when building with -D__CHECK_ENDIAN__.
 */

#ifndef _RDMA_NETINET_IN_H_
#define _RDMA_NETINET_IN_H_

#include <endian.h>
#include_next <netinet/in.h>
#include <util/compiler.h> /* __force */

#define in_addr_t __be32

#undef INADDR_ANY
#define INADDR_ANY		htobe32(0)
#undef INADDR_BROADCAST
#define INADDR_BROADCAST	htobe32(0xffffffffU)
#undef INADDR_NONE
#define INADDR_NONE		htobe32(0xffffffffU)
#undef INADDR_LOOPBACK
#define INADDR_LOOPBACK		0x7f000001 /* Inet 127.0.0.1.  */

struct in_addr_annotated {
	in_addr_t s_addr;
};

#define in_addr in_addr_annotated

struct sockaddr_in_annotated {
	__SOCKADDR_COMMON(sin_);
	__be16 sin_port;
	struct in_addr sin_addr;            /* Internet address.  */
};

#define sockaddr_in sockaddr_in_annotated

static inline int rdma_in6_is_addr_v4mapped(const struct in6_addr *a)
{
	return IN6_IS_ADDR_V4MAPPED(a);
}

struct in6_addr_annotated {
	union {
		uint8_t	__u6_addr8[16];
		__be16	__u6_addr16[8];
		__be32	__u6_addr32[4];
	} __in6_u;
};

#undef IN6_IS_ADDR_V4MAPPED
static inline int IN6_IS_ADDR_V4MAPPED(const struct in6_addr_annotated *a)
{
	return rdma_in6_is_addr_v4mapped((const struct in6_addr *)(a));
}

#define in6_addr in6_addr_annotated

#define in6addr_any (struct in6_addr) \
	{ { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } } }

struct sockaddr_in6_annotated {
	__SOCKADDR_COMMON(sin6_);
	__be16 sin6_port;        /* Transport layer port # */
	uint32_t sin6_flowinfo;     /* IPv6 flow information */
	struct in6_addr sin6_addr;  /* IPv6 address */
	uint32_t sin6_scope_id;     /* IPv6 scope-id */
};

#define sockaddr_in6 sockaddr_in6_annotated

#endif /* _RDMA_NETINET_IN_H_ */
