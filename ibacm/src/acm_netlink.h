/*
 * Copyright (c) 2015 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under the OpenFabrics.org BSD license
 * below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AWV
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#if !defined(ACM_NETLINK_H)
#define ACM_NETLINK_H

/*
 * This header file basically copies the local service related defines and
 * structures from the latest kernel include/uapi/rdma/rdma_netlink.h file
 * so that ibacm can be built without the latest kernel patches.
 */

enum {
	RDMA_NL_LS = 4,	/* RDMA Local Services */
};

enum {
	RDMA_NL_GROUP_LS = 3,
};

/*
 * Local service operations:
 *   RESOLVE - The client requests the local service to resolve a path.
 *   SET_TIMEOUT - The local service requests the client to set the timeout.
 */
enum {
	RDMA_NL_LS_OP_RESOLVE = 0,
	RDMA_NL_LS_OP_SET_TIMEOUT,
	RDMA_NL_LS_NUM_OPS
};

/* Local service netlink message flags */
#define RDMA_NL_LS_F_ERR	0x0100	/* Failed response */

/*
 * Local service resolve operation family header.
 * The layout for the resolve operation:
 *    nlmsg header
 *    family header
 *    attributes
 */

/*
 * Local service path use:
 * Specify how the path(s) will be used.
 *   ALL - For connected CM operation (6 pathrecords)
 *   UNIDIRECTIONAL - For unidirectional UD (1 pathrecord)
 *   GMP - For miscellaneous GMP like operation (at least 1 reversible
 *         pathrecord)
 */
enum {
	LS_RESOLVE_PATH_USE_ALL = 0,
	LS_RESOLVE_PATH_USE_UNIDIRECTIONAL,
	LS_RESOLVE_PATH_USE_GMP,
	LS_RESOLVE_PATH_USE_MAX
};

#define LS_DEVICE_NAME_MAX 64

struct rdma_ls_resolve_header {
	__u8 device_name[LS_DEVICE_NAME_MAX];
	__u8 port_num;
	__u8 path_use;
};

/* Local service attribute type */
#define RDMA_NLA_F_MANDATORY	(1 << 13)
#define RDMA_NLA_TYPE_MASK	(~(NLA_F_NESTED | NLA_F_NET_BYTEORDER | \
				  RDMA_NLA_F_MANDATORY))

/*
 * Local service attributes:
 *   Attr Name       Size                       Byte order
 *   -----------------------------------------------------
 *   PATH_RECORD     struct ib_path_rec_data
 *   TIMEOUT         u32                        cpu
 *   SERVICE_ID      u64                        cpu
 *   DGID            u8[16]                     BE
 *   SGID            u8[16]                     BE
 *   TCLASS          u8
 *   PKEY            u16                        cpu
 *   QOS_CLASS       u16                        cpu
 */
enum {
	LS_NLA_TYPE_UNSPEC = 0,
	LS_NLA_TYPE_PATH_RECORD,
	LS_NLA_TYPE_TIMEOUT,
	LS_NLA_TYPE_SERVICE_ID,
	LS_NLA_TYPE_DGID,
	LS_NLA_TYPE_SGID,
	LS_NLA_TYPE_TCLASS,
	LS_NLA_TYPE_PKEY,
	LS_NLA_TYPE_QOS_CLASS,
	LS_NLA_TYPE_MAX
};

/* Local service DGID/SGID attribute: big endian */
struct rdma_nla_ls_gid {
	__u8		gid[16];
};

#endif /* ACM_NETLINK_H */
