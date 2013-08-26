#ifndef _RDMA_NETLINK_H
#define _RDMA_NETLINK_H

#include <linux/types.h>

enum {
	RDMA_NL_RDMA_CM = 1,
    	RDMA_NL_NES,
	RDMA_NL_CHELSIO
};

enum {
	RDMA_NL_GROUP_CM = 1,
	RDMA_NL_GROUP_IWPM,
	RDMA_NL_NUM_GROUPS
};

#define RDMA_NL_GET_CLIENT(type) ((type & (((1 << 6) - 1) << 10)) >> 10)
#define RDMA_NL_GET_OP(type) (type & ((1 << 10) - 1))
#define RDMA_NL_GET_TYPE(client, op) ((client << 10) + op)

enum {
	RDMA_NL_RDMA_CM_ID_STATS = 0,
	RDMA_NL_RDMA_CM_NUM_OPS
};

enum {
	RDMA_NL_RDMA_CM_ATTR_SRC_ADDR = 1,
	RDMA_NL_RDMA_CM_ATTR_DST_ADDR,
	RDMA_NL_RDMA_CM_NUM_ATTR,
};

enum {
	RDMA_NL_IWPM_REG_PID = 0,
	RDMA_NL_IWPM_ADD_MAPPING,
	RDMA_NL_IWPM_QUERY_MAPPING,
	RDMA_NL_IWPM_REMOVE_MAPPING,
	RDMA_NL_IWPM_HANDLE_ERR,
	RDMA_NL_IWPM_MAP_INFO,
	RDMA_NL_IWPM_MAP_INFO_NUM,
	RDMA_NL_IWPM_NUM_OPS
};

struct rdma_cm_id_stats {
	__u32	qp_num;
	__u32	bound_dev_if;
	__u32	port_space;
	__s32	pid;
	__u8	cm_state;
	__u8	node_type;
	__u8	port_num;
	__u8	qp_type;
};

/* iwpm netlink register pid request attributes */
enum {
	IWPM_NLA_REG_PID_UNSPEC = 0,
	IWPM_NLA_REG_PID_SEQ,
	IWPM_NLA_REG_IF_NAME,
	IWPM_NLA_REG_IBDEV_NAME,
	IWPM_NLA_REG_ULIB_NAME,
	IWPM_NLA_REG_PID_MAX
};

/* iwpm netlink register pid response attributes */
enum {
	IWPM_NLA_RREG_PID_UNSPEC = 0,
	IWPM_NLA_RREG_PID_SEQ,
	IWPM_NLA_RREG_IBDEV_NAME,
	IWPM_NLA_RREG_ULIB_NAME,
	IWPM_NLA_RREG_ULIB_VER,
	IWPM_NLA_RREG_PID_ERR,
	IWPM_NLA_RREG_PID_MAX

};

/* iwpm netlink manage mapping attributes */
/* The R op-word means that the field is used in the response only */
enum {
	IWPM_NLA_MANAGE_MAPPING_UNSPEC = 0,
	IWPM_NLA_MANAGE_MAPPING_SEQ,
	IWPM_NLA_MANAGE_ADDR,
	IWPM_NLA_MANAGE_MAPPED_LOC_ADDR,
	IWPM_NLA_RMANAGE_MAPPING_ERR,
	IWPM_NLA_RMANAGE_MAPPING_MAX
};

/* iwpm netlink add/remove mapping request attribute number */
#define IWPM_NLA_MANAGE_MAPPING_MAX    3
/* attribute number of iwpm netlink mapping info message to userspace */
#define IWPM_NLA_REPORT_MAPPING_MAX    4

enum {
	IWPM_NLA_QUERY_MAPPING_UNSPEC = 0,
	IWPM_NLA_QUERY_MAPPING_SEQ,
	IWPM_NLA_QUERY_LOCAL_ADDR,
	IWPM_NLA_QUERY_REMOTE_ADDR,
	IWPM_NLA_RQUERY_MAPPED_LOC_ADDR,
	IWPM_NLA_RQUERY_MAPPED_REM_ADDR,
	IWPM_NLA_RQUERY_MAPPING_ERR,
	IWPM_NLA_RQUERY_MAPPING_MAX
};

/* iwpm netlink query mapping request attribute number */
#define IWPM_NLA_QUERY_MAPPING_MAX  4

enum {
	IWPM_NLA_MAPINFO_REQ_UNSPEC = 0,
	IWPM_NLA_MAPINFO_ULIB_NAME,
	IWPM_NLA_MAPINFO_ULIB_VER,
	IWPM_NLA_MAPINFO_REQ_MAX
};
	
enum {
	IWPM_NLA_MAPINFO_UNSPEC = 0,
	IWPM_NLA_MAPINFO_LOCAL_ADDR,
	IWPM_NLA_MAPINFO_MAPPED_ADDR,
	IWPM_NLA_MAPINFO_MAX
};

enum {
	IWPM_NLA_MAPINFO_COUNT_UNSPEC = 0,
	IWPM_NLA_MAPINFO_SEQ,
	IWPM_NLA_MAPINFO_NUMBER,
	IWPM_NLA_MAPINFO_COUNT_MAX
};

enum {
	IWPM_NLA_ERR_UNSPEC = 0,
	IWPM_NLA_ERR_SEQ,
	IWPM_NLA_ERR_CODE,
	IWPM_NLA_ERR_MAX
};

#ifdef __KERNEL__

#include <linux/netlink.h>

struct ibnl_client_cbs {
	int (*dump)(struct sk_buff *skb, struct netlink_callback *nlcb);
};

int ibnl_init(void);
void ibnl_cleanup(void);

/**
 * Add a a client to the list of IB netlink exporters.
 * @index: Index of the added client
 * @nops: Number of supported ops by the added client.
 * @cb_table: A table for op->callback
 *
 * Returns 0 on success or a negative error code.
 */
int ibnl_add_client(int index, int nops,
		    const struct ibnl_client_cbs cb_table[]);

/**
 * Remove a client from IB netlink.
 * @index: Index of the removed IB client.
 *
 * Returns 0 on success or a negative error code.
 */
int ibnl_remove_client(int index);

/**
 * Put a new message in a supplied skb.
 * @skb: The netlink skb.
 * @nlh: Pointer to put the header of the new netlink message.
 * @seq: The message sequence number.
 * @len: The requested message length to allocate.
 * @client: Calling IB netlink client.
 * @op: message content op.
 * Returns the allocated buffer on success and NULL on failure.
 */
void *ibnl_put_msg(struct sk_buff *skb, struct nlmsghdr **nlh, int seq,
		   int len, int client, int op, int flags);
/**
 * Put a new attribute in a supplied skb.
 * @skb: The netlink skb.
 * @nlh: Header of the netlink message to append the attribute to.
 * @len: The length of the attribute data.
 * @data: The attribute data to put.
 * @type: The attribute type.
 * Returns the 0 and a negative error code on failure.
 */
int ibnl_put_attr(struct sk_buff *skb, struct nlmsghdr *nlh,
		  int len, void *data, int type);

/**
 * Send the supplied skb to a specific userspace PID.
 * @skb: The netlink skb.
 * @nlh: Header of the netlink message to append the attribute to.
 * @pid: Userspace netlink process ID.
 * Returns the 0 and a negative error code on failure.
 */
int ibnl_unicast(struct sk_buff *skb, struct nlmsghdr *nlh, 
			__u32 pid);

/**
 * Send the supplied skb to a netlink group.
 * @skb: The netlink skb.
 * @nlh: Header of the netlink message to append the attribute to.
 * @group: Netlink group ID. 
 * @flags: allocation flags 
 * Returns the 0 and a negative error code on failure.
 */
int ibnl_multicast(struct sk_buff *skb, struct nlmsghdr *nlh,
			unsigned int group, gfp_t flags);

#endif /* __KERNEL__ */

#endif /* _RDMA_NETLINK_H */
