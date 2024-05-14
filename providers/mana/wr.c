// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2024, Microsoft Corporation. All rights reserved.
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <util/compiler.h>
#include <util/util.h>
#include <sys/mman.h>

#include <infiniband/driver.h>

#include <infiniband/kern-abi.h>
#include <rdma/mana-abi.h>
#include <kernel-abi/mana-abi.h>

#include "mana.h"

int mana_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
		   struct ibv_recv_wr **bad)
{
	/* This version of driver supports RAW QP only.
	 * Posting WR is done directly in the application.
	 */
	return EOPNOTSUPP;
}

int mana_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
		   struct ibv_send_wr **bad)
{
	/* This version of driver supports RAW QP only.
	 * Posting WR is done directly in the application.
	 */
	return EOPNOTSUPP;
}
