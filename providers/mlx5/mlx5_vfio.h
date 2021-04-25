// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#ifndef MLX5_VFIO_H
#define MLX5_VFIO_H

#include <stddef.h>
#include <stdio.h>

#include <infiniband/driver.h>

struct mlx5_vfio_device {
	struct verbs_device vdev;
	char *pci_name;
	char vfio_path[IBV_SYSFS_PATH_MAX];
	int page_size;
	uint32_t flags;
};

static inline struct mlx5_vfio_device *to_mvfio_dev(struct ibv_device *ibdev)
{
	return container_of(ibdev, struct mlx5_vfio_device, vdev.device);
}

#endif
