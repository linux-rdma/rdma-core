#ifndef __FREEBSD_NETINET_IN_H__
#define __FREEBSD_NETINET_IN_H__

#include_next <netinet/in.h>

#undef IN6_IS_ADDR_V4MAPPED
#define IN6_IS_ADDR_V4MAPPED(a) \
  (__extension__                                                              \
   ({ const struct in6_addr *__a = (const struct in6_addr *) (a);             \
      __a->__in6_u.__u6_addr32[0] == 0                                        \
      && __a->__in6_u.__u6_addr32[1] == 0                                     \
      && __a->__in6_u.__u6_addr32[2] == htonl (0xffff); }))

#endif
