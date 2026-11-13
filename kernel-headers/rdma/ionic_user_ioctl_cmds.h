/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (C) 2026, Advanced Micro Devices, Inc */

#ifndef IONIC_USER_IOCTL_CMDS_H
#define IONIC_USER_IOCTL_CMDS_H

#include <linux/types.h>
#include <rdma/ib_user_ioctl_cmds.h>

enum ionic_ib_create_cq_attrs {
	IONIC_IB_ATTR_CREATE_CQ_BUF_UMEM_0 = UVERBS_ID_DRIVER_NS_WITH_UHW,
	IONIC_IB_ATTR_CREATE_CQ_BUF_UMEM_1,
};

#endif
