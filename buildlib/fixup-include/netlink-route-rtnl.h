#ifndef _FIXUP_NETLINK_ROUTE_RTNL_H
#define _FIXUP_NETLINK_ROUTE_RTNL_H

#include <netlink/attr.h>

struct rtnl_addr;
struct rtnl_neigh;
struct rtnl_route;
struct rtnl_nexthop;

static inline struct rtnl_neigh *
rtnl_neigh_get(struct nl_cache *cache, int ifindex, struct nl_addr *dst)
{
	return NULL;
}

static inline struct rtnl_link *rtnl_link_get(struct nl_cache *cache,
					      int ifindex)
{
	return NULL;
}

static void rtnl_neigh_put(struct rtnl_neigh *neigh)
{
}

static inline int rtnl_addr_get_family(struct rtnl_addr *addr)
{
	return -1;
}

static inline struct nl_addr *rtnl_neigh_get_lladdr(struct rtnl_neigh *neigh)
{
	return NULL;
}

static inline struct rtnl_neigh *rtnl_neigh_alloc(void)
{
	return NULL;
}

static inline void rtnl_neigh_set_ifindex(struct rtnl_neigh *neigh, int ifindex)
{
}
static inline int rtnl_neigh_set_dst(struct rtnl_neigh *neigh,
				     struct nl_addr *addr)
{
	return -1;
}

static inline uint8_t rtnl_route_get_type(struct rtnl_route *route)
{
	return 0;
}

static inline struct nl_addr *rtnl_route_get_pref_src(struct rtnl_route *route)
{
	return NULL;
}

static inline struct rtnl_nexthop *rtnl_route_nexthop_n(struct rtnl_route *r,
							int n)
{
	return NULL;
}

static inline int rtnl_route_nh_get_ifindex(struct rtnl_nexthop *nh)
{
	return -1;
}

static inline struct nl_addr *rtnl_route_nh_get_gateway(struct rtnl_nexthop *nh)
{
	return NULL;
}

static inline int rtnl_link_alloc_cache(struct nl_sock *sk, int family,
					struct nl_cache **result)
{
	return -1;
}

static inline struct nl_addr *rtnl_link_get_addr(struct rtnl_link *link)
{
	return NULL;
}

static inline int rtnl_link_vlan_get_id(struct rtnl_link *link)
{
	return -1;
}

static inline void rtnl_link_put(struct rtnl_link *link)
{
}

static inline int rtnl_link_is_vlan(struct rtnl_link *link)
{
	return -1;
}

static inline int rtnl_route_alloc_cache(struct nl_sock *sk, int family,
					 int flags, struct nl_cache **result)
{
	return -1;
}

static inline int rtnl_neigh_alloc_cache(struct nl_sock *sock,
					 struct nl_cache **result)
{
	return -1;
}

#endif
