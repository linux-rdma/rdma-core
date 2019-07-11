#ifndef _FIXUP_NETLINK_ATTR_H
#define _FIXUP_NETLINK_ATTR_H

#include <linux/netlink.h>

#include <netdb.h>
#include <stdint.h>
#include <stdlib.h>

struct nlmsghdr;
struct nl_msg;
struct nl_sock;
struct nlattr;
struct nl_cb;
struct sockaddr_nl;
struct nlmsgerr;
struct nl_addr;
struct nl_cache;
struct nl_object;

typedef int (*nl_recvmsg_msg_cb_t)(struct nl_msg *msg, void *arg);
typedef int (*nl_recvmsg_err_cb_t)(struct sockaddr_nl *nla,
				   struct nlmsgerr *nlerr, void *arg);

struct nla_policy {
	int type;
};

enum {
	NLA_U8,
	NLA_U32,
	NLA_U64,
	NL_AUTO_PORT,
	NL_AUTO_SEQ,
	NL_STOP,
	NL_OK,
	NL_CB_DEFAULT,
	NL_CB_VALID,
	NL_CB_CUSTOM,
	NLE_PARSE_ERR,
	NLE_NOMEM,
};

static inline struct nl_sock *nl_socket_alloc(void)
{
	return NULL;
}

static inline int nl_connect(struct nl_sock *sk, int kind)
{
	return -1;
}

static inline void nl_socket_free(struct nl_sock *sk)
{
}

static inline void nl_socket_disable_auto_ack(struct nl_sock *sk)
{
}

static inline void nl_socket_disable_msg_peek(struct nl_sock *sk)
{
}

static inline void nl_socket_disable_seq_check(struct nl_sock *sk)
{
}

static inline int nl_socket_get_fd(struct nl_sock *sk)
{
	return -1;
}

static inline int nl_socket_add_membership(struct nl_sock *sk, int group)
{
	return -1;
}

static inline struct nlmsghdr *nlmsg_put(struct nl_msg *msg, uint32_t pid,
					 uint32_t seq, int type, int payload,
					 int flags)
{
	return NULL;
}

static inline struct nl_msg *nlmsg_alloc(void)
{
	return NULL;
}

static inline struct nl_msg *nlmsg_alloc_simple(int nlmsgtype, int flags)

{
	return NULL;
}

static inline void nlmsg_free(struct nl_msg *msg)
{
}

static inline int nl_send_auto(struct nl_sock *sk, struct nl_msg *msg)
{
	return -1;
}

static inline struct nlmsghdr *nlmsg_hdr(struct nl_msg *msg)
{
	return NULL;
}

static inline int nlmsg_parse(struct nlmsghdr *nlh, int hdrlen,
			      struct nlattr *tb[], int maxtype,
			      struct nla_policy *policy)
{
	return -1;
}

static inline int nl_msg_parse(struct nl_msg *msg,
			       void (*cb)(struct nl_object *, void *),
			       void *arg)
{
	return -1;
}

static inline int nlmsg_append(struct nl_msg *n, void *data, size_t len,
			       int pad)
{
	return -1;
}

static inline int nl_send_simple(struct nl_sock *sk, int type, int flags,
				 void *buf, size_t size)
{
	return -1;
}

static inline int nl_recvmsgs(struct nl_sock *sk, struct nl_cb *cb)
{
	return -1;
}

static inline int nl_recvmsgs_default(struct nl_sock *sk)
{
	return -1;
}

static inline struct nl_cb *nl_cb_alloc(int kind)
{
	return NULL;
}

static inline int nl_cb_set(struct nl_cb *cb, int type, int kind,
			    nl_recvmsg_msg_cb_t func, void *arg)
{
	return -1;
}

static inline int nl_socket_modify_err_cb(struct nl_sock *sk, int kind,
					  nl_recvmsg_err_cb_t func, void *arg)
{
	return -1;
}

static inline int nl_socket_modify_cb(struct nl_sock *sk, int type, int kind,
				      nl_recvmsg_msg_cb_t func, void *arg)
{
	return -1;
}

#define NLA_PUT_U32(msg, attrtype, value) ({ goto nla_put_failure; })
#define NLA_PUT_STRING(msg, attrtype, value) ({ goto nla_put_failure; })
#define NLA_PUT_ADDR(msg, attrtype, value) ({ goto nla_put_failure; })

static inline const char *nla_get_string(struct nlattr *tb)
{
	return NULL;
}

static inline uint8_t nla_get_u8(struct nlattr *tb)
{
	return 0;
}

static inline uint32_t nla_get_u32(struct nlattr *tb)
{
	return 0;
}

static inline uint64_t nla_get_u64(struct nlattr *tb)
{
	return 0;
}

static inline struct nl_addr *nl_addr_clone(struct nl_addr *src)
{
	return NULL;
}

static inline int nl_addr_info(struct nl_addr *addr, struct addrinfo **result)
{
	return -1;
}

static inline struct nl_addr *nl_addr_build(int family, void *buf, size_t size)
{
	return NULL;
}

static inline unsigned int nl_addr_get_len(struct nl_addr *addr)
{
	return 0;
}

static inline void *nl_addr_get_binary_addr(struct nl_addr *addr)
{
	return NULL;
}

static inline int nl_addr_get_family(struct nl_addr *addr)
{
	return -1;
}

static inline int nl_addr_get_prefixlen(struct nl_addr *addr)
{
	return -1;
}

static inline int nl_addr_fill_sockaddr(struct nl_addr *addr,
					struct sockaddr *sa, socklen_t *salen)
{
	return -1;
}

static inline void nl_addr_put(struct nl_addr *addr)
{
}

static inline void nl_addr_set_prefixlen(struct nl_addr *addr, int prefixlen)
{
}

static inline void nl_cache_mngt_unprovide(struct nl_cache *cache)
{
}

static inline void nl_cache_free(struct nl_cache *cache)
{
}

static inline int nl_object_match_filter(struct nl_object *obj,
					 struct nl_object *filter)
{
	return -1;
}

static inline int nl_cache_refill(struct nl_sock *sk, struct nl_cache *cache)
{
	return -1;
}

static inline void nl_cache_mngt_provide(struct nl_cache *cache)
{
}

#endif
