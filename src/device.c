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
	struct ibv_context *context, *tmp;
	char *devpath;
	struct ibv_get_context context_cmd;
	struct ibv_get_context_resp context_resp;
	struct ibv_get_event_fds event_fds_cmd;
	struct ibv_get_event_fds_resp *event_fds_resp;
	int i;

	context = malloc(sizeof *context);
	if (!context)
		return NULL;

	context->device = device;

	asprintf(&devpath, "/dev/infiniband/%s", device->dev->name);
	context->cmd_fd = open(devpath, O_WRONLY);

	if (context->cmd_fd < 0)
		goto err;

	context_cmd.command   = IB_USER_VERBS_CMD_GET_CONTEXT;
	context_cmd.in_words  = sizeof context_cmd / 4;
	context_cmd.out_words = sizeof context_resp / 4;
	context_cmd.response  = (unsigned long) &context_resp;

	if (write(context->cmd_fd, &context_cmd, sizeof context_cmd) != sizeof context_cmd)
		goto err_close;

	context->num_comp = context_resp.num_cq_events;

	if (context->num_comp > 1) {
		tmp = realloc(context, sizeof *context + context->num_comp * sizeof (int));
		if (!tmp)
			goto err_close;
		context = tmp;
	}

	event_fds_resp = alloca(sizeof *event_fds_resp + context->num_comp * 4);

	event_fds_cmd.command   = IB_USER_VERBS_CMD_GET_EVENT_FDS;
	event_fds_cmd.in_words  = sizeof event_fds_cmd / 4;
	event_fds_cmd.out_words = sizeof *event_fds_resp / 4 + context->num_comp;
	event_fds_cmd.response  = (unsigned long) event_fds_resp;

	if (write(context->cmd_fd, &event_fds_cmd, sizeof event_fds_cmd) !=
	    sizeof event_fds_cmd)
		goto err_close;

	context->async_fd = event_fds_resp->async_fd;
	for (i = 0; i < context->num_comp; ++i)
		context->cq_fd[i] = event_fds_resp->cq_fd[i];

	return context;

err_close:
	close(context->cmd_fd);

err:
	free(context);
	return NULL;
}

int ibv_close_device(struct ibv_context *context)
{
	int i;

	close(context->async_fd);
	for (i = 0; i < context->num_comp; ++i)
		close(context->cq_fd[i]);
	close(context->cmd_fd);

	free(context);

	return 0;
}

int ibv_get_async_event(struct ibv_context *context,
			struct ibv_async_event *event)
{
	struct ibv_kern_async_event ev;

	int ret = read(context->async_fd, &ev, sizeof ev);

	if (ret != sizeof ev)
		return -1;

	/* XXX convert CQ/QP handles back to pointers */
	event->element.port_num = ev.element;
	event->event_type       = ev.event_type;

	return 0;
}
