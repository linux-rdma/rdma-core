#ifndef __FREEBSD_LINUX_IP_H__
#define	__FREEBSD_LINUX_IP_H__

#include <sys/endian.h>
#include <sys/socket.h>
#include <linux/types.h>

struct iphdr {
#if BYTE_ORDER == LITTLE_ENDIAN
	__u8    ihl:4,
		version:4;
#endif
#if BYTE_ORDER == BIG_ENDIAN
	__u8    version:4,
		ihl:4;
#endif
	__u8    tos;
	__be16  tot_len;
	__be16  id;
	__be16  frag_off;
	__u8    ttl;
	__u8    protocol;
	__sum16 check;
	__struct_group(/* no tag */, addrs, /* no attrs */,
		__be32  saddr;
		__be32  daddr;
	);
	/*The options start here. */
};

#endif
