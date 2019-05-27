/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All rights reserved.
 */

#ifndef __EFADV_H__
#define __EFADV_H__

#include <stdio.h>
#include <sys/types.h>

#include <infiniband/verbs.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	/* Values must match the values in efa-abi.h */
	EFADV_QP_DRIVER_TYPE_SRD = 0,
};

struct ibv_qp *efadv_create_driver_qp(struct ibv_pd *ibvpd,
				      struct ibv_qp_init_attr *attr,
				      uint32_t driver_qp_type);

#ifdef __cplusplus
}
#endif

#endif /* __EFADV_H__ */
