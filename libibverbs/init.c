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
#include <dirent.h>
#include <errno.h>
#include <assert.h>
#include <fnmatch.h>

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

static int find_sysfs_devs(struct list_head *tmp_sysfs_dev_list)
{
	char class_path[IBV_SYSFS_PATH_MAX];
	DIR *class_dir;
	struct dirent *dent;
	struct verbs_sysfs_dev *sysfs_dev = NULL;
	char value[8];
	int ret = 0;

	if (!check_snprintf(class_path, sizeof(class_path),
			    "%s/class/infiniband_verbs", ibv_get_sysfs_path()))
		return ENOMEM;

	class_dir = opendir(class_path);
	if (!class_dir)
		return ENOSYS;

	while ((dent = readdir(class_dir))) {
		struct stat buf;

		if (dent->d_name[0] == '.')
			continue;

		if (!sysfs_dev)
			sysfs_dev = calloc(1, sizeof(*sysfs_dev));
		if (!sysfs_dev) {
			ret = ENOMEM;
			goto out;
		}

		if (!check_snprintf(sysfs_dev->sysfs_path, sizeof sysfs_dev->sysfs_path,
				    "%s/%s", class_path, dent->d_name))
			continue;

		if (stat(sysfs_dev->sysfs_path, &buf)) {
			fprintf(stderr, PFX "Warning: couldn't stat '%s'.\n",
				sysfs_dev->sysfs_path);
			continue;
		}

		if (!S_ISDIR(buf.st_mode))
			continue;

		if (!check_snprintf(sysfs_dev->sysfs_name, sizeof sysfs_dev->sysfs_name,
				    "%s", dent->d_name))
			continue;

		if (ibv_read_sysfs_file(sysfs_dev->sysfs_path, "ibdev",
					sysfs_dev->ibdev_name,
					sizeof sysfs_dev->ibdev_name) < 0) {
			fprintf(stderr, PFX "Warning: no ibdev class attr for '%s'.\n",
				dent->d_name);
			continue;
		}

		if (!check_snprintf(
			sysfs_dev->ibdev_path, sizeof(sysfs_dev->ibdev_path),
			"%s/class/infiniband/%s", ibv_get_sysfs_path(),
			sysfs_dev->ibdev_name))
			continue;

		if (stat(sysfs_dev->ibdev_path, &buf)) {
			fprintf(stderr, PFX "Warning: couldn't stat '%s'.\n",
				sysfs_dev->ibdev_path);
			continue;
		}

		if (try_access_device(sysfs_dev))
			continue;

		sysfs_dev->time_created = buf.st_mtim;

		if (ibv_read_sysfs_file(sysfs_dev->sysfs_path, "abi_version",
					value, sizeof value) > 0)
			sysfs_dev->abi_ver = strtol(value, NULL, 10);

		if (ibv_read_sysfs_file(sysfs_dev->sysfs_path,
					"device/modalias", sysfs_dev->modalias,
					sizeof(sysfs_dev->modalias)) <= 0)
			sysfs_dev->modalias[0] = 0;

		list_add(tmp_sysfs_dev_list, &sysfs_dev->entry);
		sysfs_dev      = NULL;
	}

 out:
	if (sysfs_dev)
		free(sysfs_dev);

	closedir(class_dir);
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
		return fnmatch(ent->modalias, value, 0) == 0;
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

/* True if the provider matches the selected rdma sysfs device */
static bool match_device(const struct verbs_device_ops *ops,
			 struct verbs_sysfs_dev *sysfs_dev)
{
	if (ops->match_table) {
		/* The internally generated alias is checked first, since some
		 * devices like rxe can attach to a random modalias, including
		 * ones that match other providers.
		 */
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
	char value[16];

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

	if (ibv_read_sysfs_file(sysfs_dev->ibdev_path, "node_type", value, sizeof value) < 0) {
		fprintf(stderr, PFX "Warning: no node_type attr under %s.\n",
			sysfs_dev->ibdev_path);
			dev->node_type = IBV_NODE_UNKNOWN;
	} else {
		dev->node_type = strtol(value, NULL, 10);
		if (dev->node_type < IBV_NODE_CA || dev->node_type > IBV_NODE_USNIC_UDP)
			dev->node_type = IBV_NODE_UNKNOWN;
	}

	switch (dev->node_type) {
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
	default:
		dev->transport_type = IBV_TRANSPORT_UNKNOWN;
		break;
	}

	strcpy(dev->dev_name,   sysfs_dev->sysfs_name);
	strcpy(dev->dev_path,   sysfs_dev->sysfs_path);
	strcpy(dev->name,       sysfs_dev->ibdev_name);
	strcpy(dev->ibdev_path, sysfs_dev->ibdev_path);
	vdev->sysfs = sysfs_dev;

	return vdev;
}

static struct verbs_device *try_drivers(struct verbs_sysfs_dev *sysfs_dev)
{
	struct ibv_driver *driver;
	struct verbs_device *dev;

	list_for_each(&driver_list, driver, entry) {
		dev = try_driver(driver->ops, sysfs_dev);
		if (dev)
			return dev;
	}

	return NULL;
}

static int check_abi_version(const char *path)
{
	char value[8];

	if (ibv_read_sysfs_file(path, "class/infiniband_verbs/abi_version",
				value, sizeof value) < 0) {
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
	if (!strcmp(sysfs1->sysfs_name, sysfs2->sysfs_name) &&
	    ts_cmp(&sysfs1->time_created,
		   &sysfs2->time_created, ==))
		return 1;
	return 0;
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

	ret = find_sysfs_devs(&sysfs_list);
	if (ret)
		return -ret;

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
				sysfs_dev->sysfs_path);
		}
		free(sysfs_dev);
	}

	return num_devices;
}

int ibverbs_init(void)
{
	const char *sysfs_path;
	char *env_value;
	int ret;

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

	sysfs_path = ibv_get_sysfs_path();
	if (!sysfs_path)
		return -ENOSYS;

	ret = check_abi_version(sysfs_path);
	if (ret)
		return -ret;

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
