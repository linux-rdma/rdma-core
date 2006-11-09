/*
 * Copyright (c) 2004 Topspin Communications.  All rights reserved.
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

#include "ibverbs.h"

struct dlist *ibv_get_devices(void)
{
	return device_list;
}

const char *ibv_get_device_name(struct ibv_device *device)
{
	return device->dev->name;
}

uint64_t ibv_get_device_guid(struct ibv_device *device)
{
	struct sysfs_attribute *attr;
	uint16_t guid[4];
	int i;

	attr = sysfs_get_classdev_attr(device->dev, "node_guid");
	if (!attr)
		return 0;

	if (sscanf(attr->value, "%hx:%hx:%hx:%hx",
		   guid, guid + 1, guid + 2, guid + 3) != 4)
		return 0;

	for (i = 0; i < 4; ++i)
		guid[i] = htons(guid[i]);

	return *(uint64_t *) guid;
}
