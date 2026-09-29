/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2006 Cisco Systems, Inc.  All rights reserved.
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
#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <glob.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <assert.h>
#include <fnmatch.h>
#include <sys/sysmacros.h>

#include <rdma/rdma_netlink.h>

#include <util/util.h>
#include "driver.h"
#include "ibverbs.h"
#include <infiniband/cmd_write.h>

int setup_sysfs_uverbs(int uv_dirfd, const char *uverbs,
		       struct verbs_sysfs_dev *sysfs_dev)
{
	return 0;
}

int find_sysfs_devs(struct list_head *tmp_sysfs_dev_list)
{
	char class_path[IBV_SYSFS_PATH_MAX];
	char uverbs_path[IBV_SYSFS_PATH_MAX];
	struct verbs_sysfs_dev *sysfs_dev = NULL;
	const char *sysfs_path;
	char value[32];
	int i, ret;

	ret = 0;
	sysfs_path = ibv_get_sysfs_path();

	snprintf(class_path, sizeof class_path, "%s/class/infiniband_verbs",
	    sysfs_path);

	for (i = 0; i < 256; i++) {
		if (sysfs_dev == NULL) {
			sysfs_dev = calloc(1, sizeof *sysfs_dev);
			if (sysfs_dev == NULL) {
				ret = ENOMEM;
				goto out;
			}
		} else {
			memset(sysfs_dev, 0, sizeof(*sysfs_dev));
		}

		snprintf(sysfs_dev->sysfs_name, sizeof(sysfs_dev->sysfs_name),
		    "uverbs%d", i);

		snprintf(uverbs_path, sizeof(uverbs_path),
		    "%s/%s", class_path, sysfs_dev->sysfs_name);

		if (ibv_read_sysfs_file(uverbs_path, "ibdev",
		    sysfs_dev->ibdev_name, sizeof(sysfs_dev->ibdev_name)) < 0)
			continue;

		if (!check_snprintf(sysfs_dev->ibdev_path,
		    sizeof(sysfs_dev->ibdev_path), "%s/class/infiniband/%s",
		    ibv_get_sysfs_path(), sysfs_dev->ibdev_name))
			continue;

		if (ibv_read_sysfs_file(uverbs_path, "abi_version",
		    value, sizeof(value)) > 0)
			sysfs_dev->abi_ver = strtol(value, NULL, 10);

		if (ibv_read_sysfs_file(sysfs_dev->ibdev_path, "node_type",
		    value, sizeof(value)) > 0) {
			sysfs_dev->node_type =
			    decode_knode_type(strtoul(value, NULL, 10));
		} else {
			sysfs_dev->node_type = IBV_NODE_UNKNOWN;
		}
		// XXXKIB sysfs_dev->sysfs_cdev = XXX;
		sysfs_dev->ibdev_idx = -1;

		list_add(tmp_sysfs_dev_list, &sysfs_dev->entry);
		sysfs_dev = NULL;
	}

 out:
	if (sysfs_dev != NULL)
		free(sysfs_dev);

	return ret;
}
