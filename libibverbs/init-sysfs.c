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
	unsigned int major;
	unsigned int minor;
	struct stat buf;
	char value[32];

	if (!check_snprintf(sysfs_dev->sysfs_name,
			    sizeof(sysfs_dev->sysfs_name), "%s", uverbs))
		return -1;

	if (stat(sysfs_dev->ibdev_path, &buf))
		return -1;
	sysfs_dev->time_created = buf.st_mtim;

	if (ibv_read_sysfs_file_at(uv_dirfd, "dev", value,
				   sizeof(value)) < 0)
		return -1;
	if (sscanf(value, "%u:%u", &major, &minor) != 2)
		return -1;
	sysfs_dev->sysfs_cdev = makedev(major, minor);

	if (ibv_read_sysfs_file_at(uv_dirfd, "abi_version", value,
				   sizeof(value)) > 0)
		sysfs_dev->abi_ver = strtoul(value, NULL, 10);

	return 0;
}

static int setup_sysfs_dev(int dirfd, const char *uverbs,
			   struct list_head *tmp_sysfs_dev_list)
{
	struct verbs_sysfs_dev *sysfs_dev = NULL;
	char value[32];
	int uv_dirfd;

	sysfs_dev = calloc(1, sizeof(*sysfs_dev));
	if (!sysfs_dev)
		return ENOMEM;

	sysfs_dev->ibdev_idx = -1;

	uv_dirfd = openat(dirfd, uverbs, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (uv_dirfd == -1)
		goto err_alloc;

	if (ibv_read_sysfs_file_at(uv_dirfd, "ibdev", sysfs_dev->ibdev_name,
				   sizeof(sysfs_dev->ibdev_name)) < 0)
		goto err_fd;

	if (!check_snprintf(
		    sysfs_dev->ibdev_path, sizeof(sysfs_dev->ibdev_path),
		    "%s/class/infiniband/%s", ibv_get_sysfs_path(),
		    sysfs_dev->ibdev_name))
		goto err_fd;

	if (setup_sysfs_uverbs(uv_dirfd, uverbs, sysfs_dev))
		goto err_fd;

	if (ibv_read_ibdev_sysfs_file(value, sizeof(value), sysfs_dev,
				      "node_type") <= 0)
		sysfs_dev->node_type = IBV_NODE_UNKNOWN;
	else
		sysfs_dev->node_type =
			decode_knode_type(strtoul(value, NULL, 10));

	if (try_access_device(sysfs_dev))
		goto err_fd;

	close(uv_dirfd);
	list_add(tmp_sysfs_dev_list, &sysfs_dev->entry);
	return 0;

err_fd:
	close(uv_dirfd);
err_alloc:
	free(sysfs_dev);
	return 0;
}

int find_sysfs_devs(struct list_head *tmp_sysfs_dev_list)
{
	struct verbs_sysfs_dev *dev, *dev_tmp;
	char class_path[IBV_SYSFS_PATH_MAX];
	DIR *class_dir;
	struct dirent *dent;
	int ret = 0;

	if (!check_snprintf(class_path, sizeof(class_path),
			    "%s/class/infiniband_verbs", ibv_get_sysfs_path()))
		return ENOMEM;

	class_dir = opendir(class_path);
	if (!class_dir)
		return ENOSYS;

	while ((dent = readdir(class_dir))) {
		if (dent->d_name[0] == '.')
			continue;

		ret = setup_sysfs_dev(dirfd(class_dir), dent->d_name,
				      tmp_sysfs_dev_list);
		if (ret)
			break;
	}
	closedir(class_dir);

	if (ret) {
		list_for_each_safe (tmp_sysfs_dev_list, dev, dev_tmp, entry) {
			list_del(&dev->entry);
			free(dev);
		}
	}
	return ret;
}
