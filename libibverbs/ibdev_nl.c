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

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include <ccan/list.h>
#include <util/util.h>
#include <infiniband/driver.h>

#include "ibverbs.h"

/* Determine the name of the uverbsX class for the sysfs_dev using sysfs. */
static int find_uverbs_sysfs(struct verbs_sysfs_dev *sysfs_dev)
{
	char path[IBV_SYSFS_PATH_MAX];
	struct dirent *dent;
	DIR *class_dir;
	int ret = ENOENT;

	if (!check_snprintf(path, sizeof(path), "%s/device/infiniband_verbs",
			    sysfs_dev->ibdev_path))
		return ENOMEM;

	class_dir = opendir(path);
	if (!class_dir)
		return ENOSYS;

	while ((dent = readdir(class_dir))) {
		int uv_dirfd;
		bool failed;

		if (dent->d_name[0] == '.')
			continue;

		uv_dirfd = openat(dirfd(class_dir), dent->d_name,
				  O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (uv_dirfd == -1)
			break;
		failed = setup_sysfs_uverbs(uv_dirfd, dent->d_name, sysfs_dev);
		close(uv_dirfd);
		if (!failed)
			ret = 0;
		break;
	}
	closedir(class_dir);
	return ret;
}

static int find_sysfs_devs_nl_cb(struct nl_msg *msg, void *data)
{
	struct nlattr *tb[RDMA_NLDEV_ATTR_MAX];
	struct list_head *sysfs_list = data;
	struct verbs_sysfs_dev *sysfs_dev;
	int ret;

	ret = nlmsg_parse(nlmsg_hdr(msg), 0, tb, RDMA_NLDEV_ATTR_MAX - 1,
			  rdmanl_policy);
	if (ret < 0)
		return ret;
	if (!tb[RDMA_NLDEV_ATTR_DEV_NAME] || !tb[RDMA_NLDEV_ATTR_DEV_INDEX])
		return NLE_PARSE_ERR;

	sysfs_dev = calloc(1, sizeof(*sysfs_dev));
	if (!sysfs_dev)
		return NLE_NOMEM;

	sysfs_dev->ibdev_idx = nla_get_u32(tb[RDMA_NLDEV_ATTR_DEV_INDEX]);
	if (!check_snprintf(sysfs_dev->ibdev_name,
			    sizeof(sysfs_dev->ibdev_name), "%s",
			    nla_get_string(tb[RDMA_NLDEV_ATTR_DEV_NAME])))
		goto err;
	if (!check_snprintf(
		    sysfs_dev->ibdev_path, sizeof(sysfs_dev->ibdev_path),
		    "%s/class/infiniband/%s", ibv_get_sysfs_path(),
		    sysfs_dev->ibdev_name))
		goto err;

	if (find_uverbs_sysfs(sysfs_dev))
		goto err;

	/*
	 * We don't need to check the cdev as netlink only shows us devices in
	 * this namespace
	 */

	list_add(sysfs_list, &sysfs_dev->entry);
	return NL_OK;

err:
	free(sysfs_dev);
	return NLE_PARSE_ERR;
}

/* Fetch the list of IB devices and uverbs from netlink */
int find_sysfs_devs_nl(struct list_head *tmp_sysfs_dev_list)
{
	struct verbs_sysfs_dev *dev, *dev_tmp;
	struct nl_sock *nl;

	nl = rdmanl_socket_alloc();
	if (!nl)
		return -EOPNOTSUPP;

	if (rdmanl_get_devices(nl, find_sysfs_devs_nl_cb, tmp_sysfs_dev_list))
		goto err;

	nl_socket_free(nl);
	return 0;

err:
	list_for_each_safe (tmp_sysfs_dev_list, dev, dev_tmp, entry) {
		list_del(&dev->entry);
		free(dev);
	}
	nl_socket_free(nl);
	return EINVAL;
}
