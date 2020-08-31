/*
 * Copyright (c) 2018 Mellanox Technologies, Ltd.  All rights reserved.
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
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <infiniband/cmd_write.h>

#include <net/if.h>

static void copy_query_port_resp_to_port_attr(struct ibv_port_attr *port_attr,
				       struct ib_uverbs_query_port_resp *resp)
{
	port_attr->state	   = resp->state;
	port_attr->max_mtu	   = resp->max_mtu;
	port_attr->active_mtu      = resp->active_mtu;
	port_attr->gid_tbl_len     = resp->gid_tbl_len;
	port_attr->port_cap_flags  = resp->port_cap_flags;
	port_attr->max_msg_sz      = resp->max_msg_sz;
	port_attr->bad_pkey_cntr   = resp->bad_pkey_cntr;
	port_attr->qkey_viol_cntr  = resp->qkey_viol_cntr;
	port_attr->pkey_tbl_len    = resp->pkey_tbl_len;
	port_attr->lid		   = resp->lid;
	port_attr->sm_lid	   = resp->sm_lid;
	port_attr->lmc		   = resp->lmc;
	port_attr->max_vl_num      = resp->max_vl_num;
	port_attr->sm_sl	   = resp->sm_sl;
	port_attr->subnet_timeout  = resp->subnet_timeout;
	port_attr->init_type_reply = resp->init_type_reply;
	port_attr->active_width    = resp->active_width;
	port_attr->active_speed    = resp->active_speed;
	port_attr->phys_state      = resp->phys_state;
	port_attr->link_layer      = resp->link_layer;
	port_attr->flags	   = resp->flags;
}

int ibv_cmd_query_port(struct ibv_context *context, uint8_t port_num,
		       struct ibv_port_attr *port_attr,
		       struct ibv_query_port *cmd, size_t cmd_size)
{
	DECLARE_FBCMD_BUFFER(cmdb, UVERBS_OBJECT_DEVICE,
			     UVERBS_METHOD_QUERY_PORT, 2, NULL);
	int ret;
	struct ib_uverbs_query_port_resp_ex resp_ex = {};

	fill_attr_const_in(cmdb, UVERBS_ATTR_QUERY_PORT_PORT_NUM, port_num);
	fill_attr_out_ptr(cmdb, UVERBS_ATTR_QUERY_PORT_RESP, &resp_ex);

	switch (execute_ioctl_fallback(context, query_port, cmdb, &ret)) {
	case TRY_WRITE: {
		struct ib_uverbs_query_port_resp resp;

		cmd->port_num = port_num;
		memset(cmd->reserved, 0, sizeof(cmd->reserved));
		memset(&resp, 0, sizeof(resp));

		ret = execute_cmd_write(context,
					IB_USER_VERBS_CMD_QUERY_PORT, cmd,
					cmd_size, &resp, sizeof(resp));
		if (ret)
			return ret;

		copy_query_port_resp_to_port_attr(port_attr, &resp);
		break;
	}
	case SUCCESS:
		copy_query_port_resp_to_port_attr(port_attr,
						  &resp_ex.legacy_resp);
		port_attr->port_cap_flags2 = resp_ex.port_cap_flags2;
		break;
	default:
		return ret;
	};

	return 0;
}

int ibv_cmd_alloc_async_fd(struct ibv_context *context)
{
	DECLARE_COMMAND_BUFFER(cmdb, UVERBS_OBJECT_ASYNC_EVENT,
			       UVERBS_METHOD_ASYNC_EVENT_ALLOC, 1);
	struct ib_uverbs_attr *handle;
	int ret;

	handle = fill_attr_out_fd(cmdb, UVERBS_ATTR_ASYNC_EVENT_ALLOC_FD_HANDLE,
				  0);

	ret = execute_ioctl(context, cmdb);
	if (ret)
		return ret;

	context->async_fd =
		read_attr_fd(UVERBS_ATTR_ASYNC_EVENT_ALLOC_FD_HANDLE, handle);
	return 0;
}

static int cmd_get_context(struct verbs_context *context_ex,
				struct ibv_command_buffer *link)
{
	DECLARE_FBCMD_BUFFER(cmdb, UVERBS_OBJECT_DEVICE,
			     UVERBS_METHOD_GET_CONTEXT, 2, link);

	struct ibv_context *context = &context_ex->context;
	struct verbs_device *verbs_device;
	uint64_t core_support;
	uint32_t num_comp_vectors;
	int ret;

	fill_attr_out_ptr(cmdb, UVERBS_ATTR_GET_CONTEXT_NUM_COMP_VECTORS,
			  &num_comp_vectors);
	fill_attr_out_ptr(cmdb, UVERBS_ATTR_GET_CONTEXT_CORE_SUPPORT,
			  &core_support);

	/* Using free_context cmd_name as alloc context is not in
	 * verbs_context_ops while free_context is and doesn't use ioctl
	 */
	switch (execute_ioctl_fallback(context, free_context, cmdb, &ret)) {
	case TRY_WRITE: {
		DECLARE_LEGACY_UHW_BUFS(link, IB_USER_VERBS_CMD_GET_CONTEXT);

		ret = execute_write_bufs(context, IB_USER_VERBS_CMD_GET_CONTEXT,
					 req, resp);
		if (ret)
			return ret;

		context->async_fd = resp->async_fd;
		context->num_comp_vectors = resp->num_comp_vectors;

		return 0;
	}
	case SUCCESS:
		break;
	default:
		return ret;
	};

	context->num_comp_vectors = num_comp_vectors;
	verbs_device = verbs_get_device(context->device);
	verbs_device->core_support = core_support;
	return 0;
}

int ibv_cmd_get_context(struct verbs_context *context_ex,
			struct ibv_get_context *cmd, size_t cmd_size,
			struct ib_uverbs_get_context_resp *resp,
			size_t resp_size)
{
	DECLARE_CMD_BUFFER_COMPAT(cmdb, UVERBS_OBJECT_DEVICE,
				  UVERBS_METHOD_GET_CONTEXT, cmd, cmd_size,
				  resp, resp_size);

	return cmd_get_context(context_ex, cmdb);
}

int ibv_cmd_query_context(struct ibv_context *context,
			  struct ibv_command_buffer *driver)
{
	DECLARE_COMMAND_BUFFER_LINK(cmd, UVERBS_OBJECT_DEVICE,
				    UVERBS_METHOD_QUERY_CONTEXT,
				    2,
				    driver);

	struct verbs_device *verbs_device;
	uint64_t core_support;
	int ret;

	fill_attr_out_ptr(cmd, UVERBS_ATTR_QUERY_CONTEXT_NUM_COMP_VECTORS,
			  &context->num_comp_vectors);
	fill_attr_out_ptr(cmd, UVERBS_ATTR_QUERY_CONTEXT_CORE_SUPPORT,
			  &core_support);

	ret = execute_ioctl(context, cmd);
	if (ret)
		return ret;

	verbs_device = verbs_get_device(context->device);
	verbs_device->core_support = core_support;

	return 0;
}

static int is_zero_gid(union ibv_gid *gid)
{
	const union ibv_gid zgid = {};

	return !memcmp(gid, &zgid, sizeof(*gid));
}

static int query_sysfs_gid_ndev_ifindex(struct ibv_context *context,
					uint8_t port_num, uint32_t gid_index,
					uint32_t *ndev_ifindex)
{
	struct verbs_device *verbs_device = verbs_get_device(context->device);
	char buff[IF_NAMESIZE];

	if (ibv_read_ibdev_sysfs_file(buff, sizeof(buff), verbs_device->sysfs,
				      "ports/%d/gid_attrs/ndevs/%d", port_num,
				      gid_index) <= 0) {
		*ndev_ifindex = 0;
		return 0;
	}

	*ndev_ifindex = if_nametoindex(buff);
	return *ndev_ifindex ? 0 : errno;
}

static int query_sysfs_gid(struct ibv_context *context, uint8_t port_num, int index,
			   union ibv_gid *gid)
{
	struct verbs_device *verbs_device = verbs_get_device(context->device);
	char attr[41];
	uint16_t val;
	int i;

	if (ibv_read_ibdev_sysfs_file(attr, sizeof(attr), verbs_device->sysfs,
				      "ports/%d/gids/%d", port_num, index) < 0)
		return -1;

	for (i = 0; i < 8; ++i) {
		if (sscanf(attr + i * 5, "%hx", &val) != 1)
			return -1;
		gid->raw[i * 2] = val >> 8;
		gid->raw[i * 2 + 1] = val & 0xff;
	}

	return 0;
}

/* GID types as appear in sysfs, no change is expected as of ABI
 * compatibility.
 */
#define V1_TYPE "IB/RoCE v1"
#define V2_TYPE "RoCE v2"
static int query_sysfs_gid_type(struct ibv_context *context, uint8_t port_num,
				unsigned int index, enum ibv_gid_type_sysfs *type)
{
	struct verbs_device *verbs_device = verbs_get_device(context->device);
	char buff[11];

	/* Reset errno so that we can rely on its value upon any error flow in
	 * ibv_read_sysfs_file.
	 */
	errno = 0;
	if (ibv_read_ibdev_sysfs_file(buff, sizeof(buff), verbs_device->sysfs,
				      "ports/%d/gid_attrs/types/%d", port_num,
				      index) <= 0) {
		char *dir_path;
		DIR *dir;

		if (errno == EINVAL) {
			/* In IB, this file doesn't exist and the kernel sets
			 * errno to -EINVAL.
			 */
			*type = IBV_GID_TYPE_SYSFS_IB_ROCE_V1;
			return 0;
		}
		if (asprintf(&dir_path, "%s/%s/%d/%s/",
			     verbs_device->sysfs->ibdev_path, "ports", port_num,
			     "gid_attrs") < 0)
			return -1;
		dir = opendir(dir_path);
		free(dir_path);
		if (!dir) {
			if (errno == ENOENT)
				/* Assuming that if gid_attrs doesn't exist,
				 * we have an old kernel and all GIDs are
				 * IB/RoCE v1
				 */
				*type = IBV_GID_TYPE_SYSFS_IB_ROCE_V1;
			else
				return -1;
		} else {
			closedir(dir);
			errno = EFAULT;
			return -1;
		}
	} else {
		if (!strcmp(buff, V1_TYPE)) {
			*type = IBV_GID_TYPE_SYSFS_IB_ROCE_V1;
		} else if (!strcmp(buff, V2_TYPE)) {
			*type = IBV_GID_TYPE_SYSFS_ROCE_V2;
		} else {
			errno = ENOTSUP;
			return -1;
		}
	}

	return 0;
}

static int query_sysfs_gid_entry(struct ibv_context *context, uint32_t port_num,
				 uint32_t gid_index,
				 struct ibv_gid_entry *entry,
				 uint32_t attr_mask)
{
	enum ibv_gid_type_sysfs gid_type;
	struct ibv_port_attr port_attr = {};
	int ret = 0;

	entry->gid_index = gid_index;
	entry->port_num = port_num;

	if (attr_mask & VERBS_QUERY_GID_ATTR_GID) {
		ret = query_sysfs_gid(context, port_num, gid_index, &entry->gid);
		if (ret)
			return EINVAL;
	}

	if (attr_mask & VERBS_QUERY_GID_ATTR_TYPE) {
		ret = query_sysfs_gid_type(context, port_num, gid_index, &gid_type);
		if (ret)
			return EINVAL;

		if (gid_type == IBV_GID_TYPE_SYSFS_IB_ROCE_V1) {
			ret = ibv_query_port(context, port_num, &port_attr);
			if (ret)
				goto out;

			if (port_attr.link_layer == IBV_LINK_LAYER_INFINIBAND) {
				entry->gid_type = IBV_GID_TYPE_IB;
			} else if (port_attr.link_layer ==
				   IBV_LINK_LAYER_ETHERNET) {
				entry->gid_type = IBV_GID_TYPE_ROCE_V1;
			} else {
				ret = EINVAL;
				goto out;
			}
		} else {
			entry->gid_type = IBV_GID_TYPE_ROCE_V2;
		}
	}

	if (attr_mask & VERBS_QUERY_GID_ATTR_NDEV_IFINDEX)
		ret = query_sysfs_gid_ndev_ifindex(context, port_num, gid_index,
						   &entry->ndev_ifindex);

out:
	return ret;
}

/* Using async_event cmd_name because query_gid_ex is not in
 * verbs_context_ops while async_event is and doesn't use ioctl.
 */
#define query_gid_kernel_cap async_event
int __ibv_query_gid_ex(struct ibv_context *context, uint32_t port_num,
			    uint32_t gid_index, struct ibv_gid_entry *entry,
			    uint32_t flags, size_t entry_size,
			    uint32_t fallback_attr_mask)
{
	DECLARE_COMMAND_BUFFER(cmdb, UVERBS_OBJECT_DEVICE,
			       UVERBS_METHOD_QUERY_GID_ENTRY, 4);
	int ret;

	fill_attr_const_in(cmdb, UVERBS_ATTR_QUERY_GID_ENTRY_PORT, port_num);
	fill_attr_const_in(cmdb, UVERBS_ATTR_QUERY_GID_ENTRY_GID_INDEX,
			   gid_index);
	fill_attr_in_uint32(cmdb, UVERBS_ATTR_QUERY_GID_ENTRY_FLAGS, flags);
	fill_attr_out(cmdb, UVERBS_ATTR_QUERY_GID_ENTRY_RESP_ENTRY, entry,
		      entry_size);

	switch (execute_ioctl_fallback(context, query_gid_kernel_cap, cmdb,
				       &ret)) {
	case TRY_WRITE:
		if (flags)
			return EOPNOTSUPP;

		ret = query_sysfs_gid_entry(context, port_num, gid_index,
					    entry, fallback_attr_mask);
		if (ret)
			return ret;

		if (fallback_attr_mask & VERBS_QUERY_GID_ATTR_GID &&
		    is_zero_gid(&entry->gid))
			return ENODATA;

		return 0;
	default:
		return ret;
	}
}

int _ibv_query_gid_ex(struct ibv_context *context, uint32_t port_num,
		      uint32_t gid_index, struct ibv_gid_entry *entry,
		      uint32_t flags, size_t entry_size)
{
	return __ibv_query_gid_ex(context, port_num, gid_index, entry,
				  flags, entry_size,
				  VERBS_QUERY_GID_ATTR_GID |
				  VERBS_QUERY_GID_ATTR_TYPE |
				  VERBS_QUERY_GID_ATTR_NDEV_IFINDEX);
}
