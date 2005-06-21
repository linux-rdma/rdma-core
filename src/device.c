/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
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
 * $Id$
 */

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <alloca.h>

#include "ibverbs.h"

struct dlist *ibv_get_devices(void)
{
	return device_list;
}

const char *ibv_get_device_name(struct ibv_device *device)
{
	return device->ibdev->name;
}

uint64_t ibv_get_device_guid(struct ibv_device *device)
{
	struct sysfs_attribute *attr;
	uint16_t guid[4];
	int i;

	attr = sysfs_get_classdev_attr(device->ibdev, "node_guid");
	if (!attr)
		return 0;

	if (sscanf(attr->value, "%hx:%hx:%hx:%hx",
		   guid, guid + 1, guid + 2, guid + 3) != 4)
		return 0;

	for (i = 0; i < 4; ++i)
		guid[i] = htons(guid[i]);

	return *(uint64_t *) guid;
}

struct ibv_context *ibv_open_device(struct ibv_device *device)
{
	char *devpath;
	int cmd_fd;
	struct ibv_context *context;
	struct ibv_query_params      cmd;
	struct ibv_query_params_resp resp;

	asprintf(&devpath, "/dev/infiniband/%s", device->dev->name);

	/*
	 * We'll only be doing writes, but we need O_RDWR in case the
	 * provider needs to mmap() the file.
	 */
	cmd_fd = open(devpath, O_RDWR);
	if (cmd_fd < 0)
		return NULL;

	IBV_INIT_CMD_RESP(&cmd, sizeof cmd, QUERY_PARAMS, &resp, sizeof resp);
	if (write(cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
		goto err;

	context = device->ops.alloc_context(device, resp.num_cq_events, cmd_fd);
	if (!context)
		goto err;

	context->device   = device;
	context->cmd_fd   = cmd_fd;
	context->num_comp = resp.num_cq_events;

	return context;

err:
	close(cmd_fd);

	return NULL;
}

int ibv_close_device(struct ibv_context *context)
{
	int i;

	close(context->async_fd);
	for (i = 0; i < context->num_comp; ++i)
		close(context->cq_fd[i]);
	close(context->cmd_fd);

	context->device->ops.free_context(context);

	return 0;
}

int ibv_get_async_event(struct ibv_context *context,
			struct ibv_async_event *event)
{
	struct ibv_kern_async_event ev;

	if (read(context->async_fd, &ev, sizeof ev) != sizeof ev)
		return -1;

	/* XXX convert CQ/QP handles back to pointers */
	event->element.port_num = ev.element;
	event->event_type       = ev.event_type;

	return 0;
}
