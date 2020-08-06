/*
 * Copyright (c) 2019, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *      Redistribution and use in source and binary forms, with or
 *      without modification, are permitted provided that the following
 *      conditions are met:
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
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <util/rdma_nl.h>

#include <stdbool.h>
#include <sys/sysmacros.h>

struct nla_policy rdmanl_policy[RDMA_NLDEV_ATTR_MAX] = {
	[RDMA_NLDEV_ATTR_CHARDEV] = { .type = NLA_U64 },
	[RDMA_NLDEV_ATTR_CHARDEV_ABI] = { .type = NLA_U64 },
	[RDMA_NLDEV_ATTR_DEV_INDEX] = { .type = NLA_U32 },
	[RDMA_NLDEV_ATTR_DEV_NODE_TYPE] = { .type = NLA_U8 },
	[RDMA_NLDEV_ATTR_NODE_GUID] = { .type = NLA_U64 },
	[RDMA_NLDEV_ATTR_UVERBS_DRIVER_ID] = { .type = NLA_U32 },
#ifdef NLA_NUL_STRING
	[RDMA_NLDEV_ATTR_CHARDEV_NAME] = { .type = NLA_NUL_STRING },
	[RDMA_NLDEV_ATTR_DEV_NAME] = { .type = NLA_NUL_STRING },
	[RDMA_NLDEV_ATTR_DEV_PROTOCOL] = { .type = NLA_NUL_STRING },
	[RDMA_NLDEV_ATTR_FW_VERSION] = { .type = NLA_NUL_STRING },
#endif /* NLA_NUL_STRING */
};

static int rdmanl_saw_err_cb(struct sockaddr_nl *nla, struct nlmsgerr *nlerr,
			     void *arg)
{
	bool *failed = arg;

	*failed = true;
	return 0;
}

struct nl_sock *rdmanl_socket_alloc(void)
{
	struct nl_sock *nl;

	nl = nl_socket_alloc();
	if (!nl)
		return NULL;
	nl_socket_disable_auto_ack(nl);
	nl_socket_disable_msg_peek(nl);

	if (nl_connect(nl, NETLINK_RDMA)) {
		nl_socket_free(nl);
		return NULL;
	}
	return nl;
}

int rdmanl_get_devices(struct nl_sock *nl, nl_recvmsg_msg_cb_t cb_func,
		       void *data)
{
	bool failed = false;
	int ret;

	if (nl_send_simple(nl,
			   RDMA_NL_GET_TYPE(RDMA_NL_NLDEV, RDMA_NLDEV_CMD_GET),
			   NLM_F_DUMP, NULL, 0) < 0)
		return -1;

	if (nl_socket_modify_err_cb(nl, NL_CB_CUSTOM, rdmanl_saw_err_cb,
				    &failed))
		return -1;
	if (nl_socket_modify_cb(nl, NL_CB_VALID, NL_CB_CUSTOM, cb_func, data))
		return -1;
	do {
		ret = nl_recvmsgs_default(nl);
	} while (ret > 0);
	nl_socket_modify_err_cb(nl, NL_CB_CUSTOM, NULL, NULL);

	if (ret || failed)
		return -1;
	return 0;
}

int rdmanl_get_chardev(struct nl_sock *nl, int ibidx, const char *name,
		       nl_recvmsg_msg_cb_t cb_func, void *data)

{
	bool failed = false;
	struct nl_msg *msg;
	int ret;

	msg = nlmsg_alloc_simple(
		RDMA_NL_GET_TYPE(RDMA_NL_NLDEV, RDMA_NLDEV_CMD_GET_CHARDEV), 0);
	if (!msg)
		return -1;
	if (ibidx != -1)
		NLA_PUT_U32(msg, RDMA_NLDEV_ATTR_DEV_INDEX, ibidx);
	NLA_PUT_STRING(msg, RDMA_NLDEV_ATTR_CHARDEV_TYPE, name);
	ret = nl_send_auto(nl, msg);
	nlmsg_free(msg);
	if (ret < 0)
		return -1;

	if (nl_socket_modify_err_cb(nl, NL_CB_CUSTOM, rdmanl_saw_err_cb,
				    &failed))
		return -1;
	if (nl_socket_modify_cb(nl, NL_CB_VALID, NL_CB_CUSTOM, cb_func, data))
		return -1;
	do {
		ret = nl_recvmsgs_default(nl);
	} while (ret > 0);
	nl_socket_modify_err_cb(nl, NL_CB_CUSTOM, NULL, NULL);

	if (ret || failed)
		return -1;
	return 0;

nla_put_failure:
	nlmsg_free(msg);
	return -1;
}
