// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#define _GNU_SOURCE
#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/param.h>

#include "mlx5dv.h"
#include "mlx5_vfio.h"
#include "mlx5.h"

static struct verbs_context *
mlx5_vfio_alloc_context(struct ibv_device *ibdev,
			int cmd_fd, void *private_data)
{
	return NULL;
}

static void mlx5_vfio_uninit_device(struct verbs_device *verbs_device)
{
	struct mlx5_vfio_device *dev = to_mvfio_dev(&verbs_device->device);

	free(dev->pci_name);
	free(dev);
}

static const struct verbs_device_ops mlx5_vfio_dev_ops = {
	.name = "mlx5_vfio",
	.alloc_context = mlx5_vfio_alloc_context,
	.uninit_device = mlx5_vfio_uninit_device,
};

static bool is_mlx5_pci(const char *pci_path)
{
	const struct verbs_match_ent *ent;
	uint16_t vendor_id, device_id;
	char pci_info_path[256];
	char buff[128];
	int fd;

	snprintf(pci_info_path, sizeof(pci_info_path), "%s/vendor", pci_path);
	fd = open(pci_info_path, O_RDONLY);
	if (fd < 0)
		return false;

	if (read(fd, buff, sizeof(buff)) <= 0)
		goto err;

	vendor_id = strtoul(buff, NULL, 0);
	close(fd);

	snprintf(pci_info_path, sizeof(pci_info_path), "%s/device", pci_path);
	fd = open(pci_info_path, O_RDONLY);
	if (fd < 0)
		return false;

	if (read(fd, buff, sizeof(buff)) <= 0)
		goto err;

	device_id = strtoul(buff, NULL, 0);
	close(fd);

	for (ent = mlx5_hca_table; ent->kind != VERBS_MATCH_SENTINEL; ent++) {
		if (ent->kind != VERBS_MATCH_PCI)
			continue;
		if (ent->device == device_id && ent->vendor == vendor_id)
			return true;
	}

	return false;

err:
	close(fd);
	return false;
}

static int mlx5_vfio_get_iommu_group_id(const char *pci_name)
{
	int seg, bus, slot, func;
	int ret, groupid;
	char path[128], iommu_group_path[128], *group_name;
	struct stat st;
	ssize_t len;

	ret = sscanf(pci_name, "%04x:%02x:%02x.%d", &seg, &bus, &slot, &func);
	if (ret != 4)
		return -1;

	snprintf(path, sizeof(path),
		 "/sys/bus/pci/devices/%04x:%02x:%02x.%01x/",
		 seg, bus, slot, func);

	ret = stat(path, &st);
	if (ret < 0)
		return -1;

	if (!is_mlx5_pci(path))
		return -1;

	strncat(path, "iommu_group", sizeof(path) - strlen(path) - 1);

	len = readlink(path, iommu_group_path, sizeof(iommu_group_path));
	if (len <= 0)
		return -1;

	iommu_group_path[len] = 0;
	group_name = basename(iommu_group_path);

	if (sscanf(group_name, "%d", &groupid) != 1)
		return -1;

	snprintf(path, sizeof(path), "/dev/vfio/%d", groupid);
	ret = stat(path, &st);
	if (ret < 0)
		return -1;

	return groupid;
}

static int mlx5_vfio_get_handle(struct mlx5_vfio_device *vfio_dev,
			 struct mlx5dv_vfio_context_attr *attr)
{
	int iommu_group;

	iommu_group = mlx5_vfio_get_iommu_group_id(attr->pci_name);
	if (iommu_group < 0)
		return -1;

	sprintf(vfio_dev->vfio_path, "/dev/vfio/%d", iommu_group);
	vfio_dev->pci_name = strdup(attr->pci_name);

	return 0;
}

struct ibv_device **
mlx5dv_get_vfio_device_list(struct mlx5dv_vfio_context_attr *attr)
{
	struct mlx5_vfio_device *vfio_dev;
	struct ibv_device **list = NULL;
	int err;

	if (!check_comp_mask(attr->comp_mask, 0) ||
	    !check_comp_mask(attr->flags, MLX5DV_VFIO_CTX_FLAGS_INIT_LINK_DOWN)) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	list = calloc(1, sizeof(struct ibv_device *));
	if (!list) {
		errno = ENOMEM;
		return NULL;
	}

	vfio_dev = calloc(1, sizeof(*vfio_dev));
	if (!vfio_dev) {
		errno = ENOMEM;
		goto end;
	}

	vfio_dev->vdev.ops = &mlx5_vfio_dev_ops;
	atomic_init(&vfio_dev->vdev.refcount, 1);

	/* Find the vfio handle for attrs, store in mlx5_vfio_device */
	err = mlx5_vfio_get_handle(vfio_dev, attr);
	if (err)
		goto err_get;

	vfio_dev->flags = attr->flags;
	vfio_dev->page_size = sysconf(_SC_PAGESIZE);

	list[0] = &vfio_dev->vdev.device;
	return list;

err_get:
	free(vfio_dev);
end:
	free(list);
	return NULL;
}
