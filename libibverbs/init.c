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
#include "ibverbs.h"
#include <infiniband/cmd_write.h>

int abi_ver;

struct ibv_driver {
	struct list_node	entry;
	const struct verbs_device_ops *ops;
};

static LIST_HEAD(driver_list);

static int try_access_device(const struct verbs_sysfs_dev *sysfs_dev)
{
	struct stat cdev_stat;
	char *devpath;
	int ret;

	if (asprintf(&devpath, RDMA_CDEV_DIR"/%s",
		     sysfs_dev->sysfs_name) < 0)
		return ENOMEM;

	ret = stat(devpath, &cdev_stat);
	free(devpath);
	return ret;
}

enum ibv_node_type decode_knode_type(unsigned int knode_type)
{
	switch (knode_type) {
	case RDMA_NODE_IB_CA:
		return IBV_NODE_CA;
	case RDMA_NODE_IB_SWITCH:
		return IBV_NODE_SWITCH;
	case RDMA_NODE_IB_ROUTER:
		return IBV_NODE_ROUTER;
	case RDMA_NODE_RNIC:
		return IBV_NODE_RNIC;
	case RDMA_NODE_USNIC:
		return IBV_NODE_USNIC;
	case RDMA_NODE_USNIC_UDP:
		return IBV_NODE_USNIC_UDP;
	case RDMA_NODE_UNSPECIFIED:
		return IBV_NODE_UNSPECIFIED;
	}
	return IBV_NODE_UNKNOWN;
}

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

static int find_sysfs_devs(struct list_head *tmp_sysfs_dev_list)
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

void verbs_register_driver(const struct verbs_device_ops *ops)
{
	struct ibv_driver *driver;

	driver = malloc(sizeof *driver);
	if (!driver) {
		fprintf(stderr,
			PFX "Warning: couldn't allocate driver for %s\n",
			ops->name);
		return;
	}

	driver->ops = ops;

	list_add_tail(&driver_list, &driver->entry);
}

/* Match a single modalias value */
static bool match_modalias(const struct verbs_match_ent *ent, const char *value)
{
	char pci_ma[100];

	switch (ent->kind) {
	case VERBS_MATCH_MODALIAS:
		return fnmatch(ent->u.modalias, value, 0) == 0;
	case VERBS_MATCH_PCI:
		snprintf(pci_ma, sizeof(pci_ma), "pci:v%08Xd%08Xsv*",
			 ent->vendor, ent->device);
		return fnmatch(pci_ma, value, 0) == 0;
	default:
		return false;
	}
}

/* Search a null terminated table of verbs_match_ent's and return the one
 * that matches the device the verbs sysfs device is bound to or NULL.
 */
static const struct verbs_match_ent *
match_modalias_device(const struct verbs_device_ops *ops,
		      struct verbs_sysfs_dev *sysfs_dev)
{
	const struct verbs_match_ent *i;

	if (!(sysfs_dev->flags & VSYSFS_READ_MODALIAS)) {
		sysfs_dev->flags |= VSYSFS_READ_MODALIAS;
		if (ibv_read_ibdev_sysfs_file(
			    sysfs_dev->modalias, sizeof(sysfs_dev->modalias),
			    sysfs_dev, "device/modalias") <= 0) {
			sysfs_dev->modalias[0] = 0;
			return NULL;
		}
	}

	for (i = ops->match_table; i->kind != VERBS_MATCH_SENTINEL; i++)
		if (match_modalias(i, sysfs_dev->modalias))
			return i;

	return NULL;
}

/* Match the device name itself */
static const struct verbs_match_ent *
match_name(const struct verbs_device_ops *ops,
		      struct verbs_sysfs_dev *sysfs_dev)
{
	char name_ma[100];
	const struct verbs_match_ent *i;

	if (!check_snprintf(name_ma, sizeof(name_ma),
			    "rdma_device:N%s", sysfs_dev->ibdev_name))
		return NULL;

	for (i = ops->match_table; i->kind != VERBS_MATCH_SENTINEL; i++)
		if (match_modalias(i, name_ma))
			return i;

	return NULL;
}

/* Match the driver id we get from netlink */
static const struct verbs_match_ent *
match_driver_id(const struct verbs_device_ops *ops,
		struct verbs_sysfs_dev *sysfs_dev)
{
	const struct verbs_match_ent *i;

	if (sysfs_dev->driver_id == RDMA_DRIVER_UNKNOWN)
		return NULL;

	for (i = ops->match_table; i->kind != VERBS_MATCH_SENTINEL; i++)
		if (i->kind == VERBS_MATCH_DRIVER_ID &&
		    i->u.driver_id == sysfs_dev->driver_id)
			return i;
	return NULL;
}

/* True if the provider matches the selected rdma sysfs device */
static bool match_device(const struct verbs_device_ops *ops,
			 struct verbs_sysfs_dev *sysfs_dev)
{
	if (ops->match_table) {
		sysfs_dev->match = match_driver_id(ops, sysfs_dev);
		if (!sysfs_dev->match)
			sysfs_dev->match = match_name(ops, sysfs_dev);
		if (!sysfs_dev->match)
			sysfs_dev->match =
			    match_modalias_device(ops, sysfs_dev);
	}

	if (ops->match_device) {
		/* If a matching function is provided then it is called
		 * unconditionally after the table match above, it is
		 * responsible for determining if the device matches based on
		 * the match pointer and any other internal information.
		 */
		if (!ops->match_device(sysfs_dev))
			return false;
	} else {
		/* With no match function, we must have a table match */
		if (!sysfs_dev->match)
			return false;
	}

	if (sysfs_dev->abi_ver < ops->match_min_abi_version ||
	    sysfs_dev->abi_ver > ops->match_max_abi_version) {
		fprintf(stderr, PFX
			"Warning: Driver %s does not support the kernel ABI of %u (supports %u to %u) for device %s\n",
			ops->name, sysfs_dev->abi_ver,
			ops->match_min_abi_version,
			ops->match_max_abi_version,
			sysfs_dev->ibdev_path);
		return false;
	}
	return true;
}

static struct verbs_device *try_driver(const struct verbs_device_ops *ops,
				       struct verbs_sysfs_dev *sysfs_dev)
{
	struct verbs_device *vdev;
	struct ibv_device *dev;

	if (!match_device(ops, sysfs_dev))
		return NULL;

	vdev = ops->alloc_device(sysfs_dev);
	if (!vdev) {
		fprintf(stderr, PFX "Fatal: couldn't allocate device for %s\n",
			sysfs_dev->ibdev_path);
		return NULL;
	}

	vdev->ops = ops;

	atomic_init(&vdev->refcount, 1);
	dev = &vdev->device;
	assert(dev->_ops._dummy1 == NULL);
	assert(dev->_ops._dummy2 == NULL);

	dev->node_type = sysfs_dev->node_type;
	switch (sysfs_dev->node_type) {
	case IBV_NODE_CA:
	case IBV_NODE_SWITCH:
	case IBV_NODE_ROUTER:
		dev->transport_type = IBV_TRANSPORT_IB;
		break;
	case IBV_NODE_RNIC:
		dev->transport_type = IBV_TRANSPORT_IWARP;
		break;
	case IBV_NODE_USNIC:
		dev->transport_type = IBV_TRANSPORT_USNIC;
		break;
	case IBV_NODE_USNIC_UDP:
		dev->transport_type = IBV_TRANSPORT_USNIC_UDP;
		break;
	case IBV_NODE_UNSPECIFIED:
		dev->transport_type = IBV_TRANSPORT_UNSPECIFIED;
		break;
	default:
		dev->transport_type = IBV_TRANSPORT_UNKNOWN;
		break;
	}

	strcpy(dev->dev_name,   sysfs_dev->sysfs_name);
	if (!check_snprintf(dev->dev_path, sizeof(dev->dev_path),
			    "%s/class/infiniband_verbs/%s",
			    ibv_get_sysfs_path(), sysfs_dev->sysfs_name))
		goto err;
	strcpy(dev->name,       sysfs_dev->ibdev_name);
	strcpy(dev->ibdev_path, sysfs_dev->ibdev_path);
	vdev->sysfs = sysfs_dev;

	return vdev;

err:
	ops->uninit_device(vdev);
	return NULL;
}

static struct verbs_device *try_drivers(struct verbs_sysfs_dev *sysfs_dev)
{
	struct ibv_driver *driver;
	struct verbs_device *dev;

	/*
	 * Matching by driver_id takes priority over other match types, do it
	 * first.
	 */
	if (sysfs_dev->driver_id != RDMA_DRIVER_UNKNOWN) {
		list_for_each (&driver_list, driver, entry) {
			if (match_driver_id(driver->ops, sysfs_dev)) {
				dev = try_driver(driver->ops, sysfs_dev);
				if (dev)
					return dev;
			}
		}
	}

	list_for_each(&driver_list, driver, entry) {
		dev = try_driver(driver->ops, sysfs_dev);
		if (dev)
			return dev;
	}

	return NULL;
}

static int check_abi_version(void)
{
	char value[8];

	if (abi_ver)
		return 0;

	if (ibv_read_sysfs_file(ibv_get_sysfs_path(),
				"class/infiniband_verbs/abi_version", value,
				sizeof(value)) < 0) {
		return ENOSYS;
	}

	abi_ver = strtol(value, NULL, 10);

	if (abi_ver < IB_USER_VERBS_MIN_ABI_VERSION ||
	    abi_ver > IB_USER_VERBS_MAX_ABI_VERSION) {
		fprintf(stderr, PFX "Fatal: kernel ABI version %d "
			"doesn't match library version %d.\n",
			abi_ver, IB_USER_VERBS_MAX_ABI_VERSION);
		return ENOSYS;
	}

	return 0;
}

static void check_memlock_limit(void)
{
	struct rlimit rlim;

	if (!geteuid())
		return;

	if (getrlimit(RLIMIT_MEMLOCK, &rlim)) {
		fprintf(stderr, PFX "Warning: getrlimit(RLIMIT_MEMLOCK) failed.");
		return;
	}

	if (rlim.rlim_cur <= 32768)
		fprintf(stderr, PFX "Warning: RLIMIT_MEMLOCK is %llu bytes.\n"
			"    This will severely limit memory registrations.\n",
			(unsigned long long)rlim.rlim_cur);
}

static int same_sysfs_dev(struct verbs_sysfs_dev *sysfs1,
			  struct verbs_sysfs_dev *sysfs2)
{
	if (strcmp(sysfs1->sysfs_name, sysfs2->sysfs_name) != 0)
		return 0;

	/* In netlink mode the idx is a globally unique ID */
	if (sysfs1->ibdev_idx != sysfs2->ibdev_idx)
		return 0;

	if (sysfs1->ibdev_idx == -1 &&
	    ts_cmp(&sysfs1->time_created, &sysfs2->time_created, !=))
		return 0;

	return 1;
}

/* Match every ibv_sysfs_dev in the sysfs_list to a driver and add a new entry
 * to device_list. Once matched to a driver the entry in sysfs_list is
 * removed.
 */
static void try_all_drivers(struct list_head *sysfs_list,
			    struct list_head *device_list,
			    unsigned int *num_devices)
{
	struct verbs_sysfs_dev *sysfs_dev;
	struct verbs_sysfs_dev *tmp;
	struct verbs_device *vdev;

	list_for_each_safe(sysfs_list, sysfs_dev, tmp, entry) {
		vdev = try_drivers(sysfs_dev);
		if (vdev) {
			list_del(&sysfs_dev->entry);
			/* Ownership of sysfs_dev moves into vdev->sysfs */
			list_add(device_list, &vdev->entry);
			(*num_devices)++;
		}
	}
}

int ibverbs_get_device_list(struct list_head *device_list)
{
	LIST_HEAD(sysfs_list);
	struct verbs_sysfs_dev *sysfs_dev, *next_dev;
	struct verbs_device *vdev, *tmp;
	static int drivers_loaded;
	unsigned int num_devices = 0;
	int ret;

	ret = find_sysfs_devs_nl(&sysfs_list);
	if (ret) {
		ret = find_sysfs_devs(&sysfs_list);
		if (ret)
			return -ret;
	}

	if (!list_empty(&sysfs_list)) {
		ret = check_abi_version();
		if (ret)
			return -ret;
	}

	/* Remove entries from the sysfs_list that are already preset in the
	 * device_list, and remove entries from the device_list that are not
	 * present in the sysfs_list.
	 */
	list_for_each_safe(device_list, vdev, tmp, entry) {
		struct verbs_sysfs_dev *old_sysfs = NULL;

		list_for_each(&sysfs_list, sysfs_dev, entry) {
			if (same_sysfs_dev(vdev->sysfs, sysfs_dev)) {
				old_sysfs = sysfs_dev;
				break;
			}
		}

		if (old_sysfs) {
			list_del(&old_sysfs->entry);
			free(old_sysfs);
			num_devices++;
		} else {
			list_del(&vdev->entry);
			ibverbs_device_put(&vdev->device);
		}
	}

	try_all_drivers(&sysfs_list, device_list, &num_devices);

	if (list_empty(&sysfs_list) || drivers_loaded)
		goto out;

	load_drivers();
	drivers_loaded = 1;

	try_all_drivers(&sysfs_list, device_list, &num_devices);

out:
	/* Anything left in sysfs_list was not assoicated with a
	 * driver.
	 */
	list_for_each_safe(&sysfs_list, sysfs_dev, next_dev, entry) {
		if (getenv("IBV_SHOW_WARNINGS")) {
			fprintf(stderr, PFX
				"Warning: no userspace device-specific driver found for %s\n",
				sysfs_dev->ibdev_name);
		}
		free(sysfs_dev);
	}

	return num_devices;
}

int ibverbs_init(void)
{
	char *env_value;

	if (getenv("RDMAV_FORK_SAFE") || getenv("IBV_FORK_SAFE"))
		if (ibv_fork_init())
			fprintf(stderr, PFX "Warning: fork()-safety requested "
				"but init failed\n");

	/* Backward compatibility for the mlx4 driver env */
	env_value = getenv("MLX4_DEVICE_FATAL_CLEANUP");
	if (env_value)
		verbs_allow_disassociate_destroy = strcmp(env_value, "0") != 0;

	if (getenv("RDMAV_ALLOW_DISASSOC_DESTROY"))
		verbs_allow_disassociate_destroy = true;

	if (!ibv_get_sysfs_path())
		return -errno;

	check_memlock_limit();

	return 0;
}

void ibverbs_device_hold(struct ibv_device *dev)
{
	struct verbs_device *verbs_device = verbs_get_device(dev);

	atomic_fetch_add(&verbs_device->refcount, 1);
}

void ibverbs_device_put(struct ibv_device *dev)
{
	struct verbs_device *verbs_device = verbs_get_device(dev);

	if (atomic_fetch_sub(&verbs_device->refcount, 1) == 1) {
		free(verbs_device->sysfs);
		if (verbs_device->ops->uninit_device)
			verbs_device->ops->uninit_device(verbs_device);
	}
}
