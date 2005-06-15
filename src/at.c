/*
 * Copyright (c) 2005 Voltaire, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
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
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * $Id:$
 */

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <string.h>
#include <glob.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <poll.h>
#include <unistd.h>

#include <infiniband/at.h>
#include <infiniband/at_abi.h>

#define IB_UAT_DEV_PATH "/dev/infiniband/uat"
#define PFX "libuat: "

#define AT_CREATE_MSG_CMD_RESP(msg, cmd, resp, type, size) \
do {                                        \
	struct at_abi_cmd_hdr *hdr;         \
                                            \
	size = sizeof(*hdr) + sizeof(*cmd); \
	msg = alloca(size);                 \
	if (!msg)                           \
		return -ENOMEM;             \
	hdr = msg;                          \
	cmd = msg + sizeof(*hdr);           \
	hdr->cmd = type;                    \
	hdr->in  = sizeof(*cmd);            \
	hdr->out = sizeof(*resp);           \
	memset(cmd, 0, sizeof(*cmd));       \
	resp = alloca(sizeof(*resp));       \
	if (!resp)                          \
		return -ENOMEM;             \
	cmd->response = (unsigned long)resp;\
} while (0)

#define AT_CREATE_MSG_CMD(msg, cmd, type, size) \
do {                                        \
	struct at_abi_cmd_hdr *hdr;         \
                                            \
	size = sizeof(*hdr) + sizeof(*cmd); \
	msg = alloca(size);                 \
	if (!msg)                           \
		return -ENOMEM;             \
	hdr = msg;                          \
	cmd = msg + sizeof(*hdr);           \
	hdr->cmd = type;                    \
	hdr->in  = sizeof(*cmd);            \
	hdr->out = 0;                       \
	memset(cmd, 0, sizeof(*cmd));       \
} while (0)

static int fd;

static void __attribute__((constructor)) ib_at_init(void)
{
	fd = open(IB_UAT_DEV_PATH, O_RDWR);
        if (fd < 0)
		fprintf(stderr, PFX
			"Error <%d:%d> couldn't open IB at device <%s>\n",
			fd, errno, IB_UAT_DEV_PATH);

}

int ib_at_route_by_ip(uint32_t dst_ip, uint32_t src_ip, int tos, uint16_t flags,
		      struct ib_at_ib_route *ib_route,
		      struct ib_at_completion *async_comp)
{
	struct at_abi_route_by_ip *cmd;
	void *msg;
	int result;
	int size;

	AT_CREATE_MSG_CMD(msg, cmd, IB_USER_AT_CMD_ROUTE_BY_IP, size);

	cmd->dst_ip = dst_ip;
	cmd->src_ip = src_ip;
	cmd->tos = tos;
	cmd->flags = flags;
	cmd->ib_route = (struct at_abi_ib_route *)ib_route;
	cmd->async_comp = (struct at_abi_completion *)async_comp;

	result = write(fd, msg, size);
	return result;
}

int ib_at_paths_by_route(struct ib_at_ib_route *ib_route, uint32_t mpath_type,
			 struct ib_sa_path_rec *path_arr, int npath,
			 struct ib_at_completion *async_comp, uint64_t *req_id)
{
	struct at_abi_paths_by_route *cmd;
	struct at_abi_paths_by_route_resp *resp;
	void *msg;
	int result;
	int size;

	if (!ib_route || !path_arr || !req_id)
		return -EINVAL;

	AT_CREATE_MSG_CMD_RESP(msg, cmd, resp,
			       IB_USER_AT_CMD_PATHS_BY_ROUTE, size);

	cmd->ib_route = (struct at_abi_ib_route *)ib_route;
	cmd->mpath_type = mpath_type;
	cmd->path_arr = (struct at_abi_path_rec *)path_arr;
	cmd->npath = npath;
	cmd->async_comp = (struct at_abi_completion *)async_comp;

	result = write(fd, msg, size);
	*req_id = resp->req_id;
	return result;
}

int ib_at_ips_by_gid(union ibv_gid *gid, uint32_t *dst_ips, int nips,
		     struct ib_at_completion *async_comp)
{
	struct at_abi_ips_by_gid *cmd;
	void *msg;
	int result;
	int size;

	if (!gid || !dst_ips)
		return -EINVAL;

	AT_CREATE_MSG_CMD(msg, cmd, IB_USER_AT_CMD_IPS_BY_GID, size);

	memcpy(cmd->gid, gid, sizeof(*cmd->gid));
	cmd->dst_ips = dst_ips;
	cmd->nips = nips;
	cmd->async_comp = (struct at_abi_completion *)async_comp;

	result = write(fd, msg, size);
	return result;
}

int ib_at_ips_by_subnet(uint32_t network, uint32_t netmask,
			uint32_t *dst_ips, int nips)
{
	struct at_abi_ips_by_subnet *cmd;
	void *msg;
	int result; 
	int size;

	if (!dst_ips)
		return -EINVAL;

	AT_CREATE_MSG_CMD(msg, cmd, IB_USER_AT_CMD_IPS_BY_SUBNET, size);

	cmd->network = network;
	cmd->netmask = netmask;
	cmd->dst_ips = dst_ips;
	cmd->nips = nips;

	result = write(fd, msg, size);
	return result;
}

int ib_at_invalidate_paths(struct ib_at_ib_route *ib_route)
{
	struct at_abi_invalidate_paths *cmd;
	void *msg;
	int result;
	int size;

	if (!ib_route)
		return -EINVAL;

	AT_CREATE_MSG_CMD(msg, cmd, IB_USER_AT_CMD_INVALIDATE_PATHS, size);

	cmd->ib_route = (struct at_abi_ib_route *)ib_route;

	result = write(fd, msg, size);
	return result;
}

int ib_at_cancel(uint64_t req_id)
{
	struct at_abi_cancel *cmd;
	void *msg;
	int result;
	int size;

	AT_CREATE_MSG_CMD(msg, cmd, IB_USER_AT_CMD_CANCEL, size);

	cmd->req_id = req_id;

	result = write(fd, msg, size);
	return result;
}

int ib_at_status(uint64_t req_id)
{
	struct at_abi_status *cmd;
	void *msg;
	int result;
	int size;

	AT_CREATE_MSG_CMD(msg, cmd, IB_USER_AT_CMD_STATUS, size);

	cmd->req_id = req_id;

	result = write(fd, msg, size);
	return result;
}

/*
 * event processing
 */
int ib_at_callback_get()
{
	struct at_abi_cmd_hdr *hdr;
	struct at_abi_event_get *cmd;
	struct at_abi_event_resp *resp;
	void *msg;
	void (*callback)(__u64 req_id, void *context, int rec_num);
	int result = 0;
	int size;

	size = sizeof(*hdr) + sizeof(*cmd);
	msg = alloca(size);
	if (!msg)
		return -ENOMEM;

	hdr = msg;
	cmd = msg + sizeof(*hdr);

	hdr->cmd = IB_USER_AT_CMD_EVENT;
	hdr->in  = sizeof(*cmd);
	hdr->out = sizeof(*resp);

	resp = alloca(sizeof(*resp));
	if (!resp)
		return -ENOMEM;

	cmd->response = (unsigned long)resp;

	result = write(fd, msg, size);

	/*
	 * callback event.
	 */
	callback = (void *)(unsigned long)resp->callback;
	callback(resp->req_id, (void *)(unsigned long)resp->context, resp->rec_num);

	result = 0;
	return result;
}

int ib_at_get_fd(void)
{
	return fd;
}

int ib_at_callback_get_timed(int timeout_ms)
{
	struct pollfd ufds;
	int result;

	ufds.fd      = ib_at_get_fd();
	ufds.events  = POLLIN;
	ufds.revents = 0;

	result = poll(&ufds, 1, timeout_ms);
	if (!result)
		return -ETIMEDOUT;

	return ib_at_callback_get();
}
