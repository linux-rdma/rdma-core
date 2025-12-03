#ifndef __FREEBSD_LINUX_IN6_H__
#define __FREEBSD_LINUX_IN6_H__

#include <linux/types.h>
#include <netinet/in.h>

struct linux_in6_addr {
	union {
		__u8            __u6_addr8[16];
		__be16          __u6_addr16[8];
		__be32          __u6_addr32[4];
	} __in6_u;
};

#undef s6_addr
#define s6_addr                 __in6_u.__u6_addr8
#undef s6_addr16
#define s6_addr16               __in6_u.__u6_addr16
#undef s6_addr32
#define s6_addr32               __in6_u.__u6_addr32

#define in6_addr	linux_in6_addr
#define in6_u		__in6_u

#endif
