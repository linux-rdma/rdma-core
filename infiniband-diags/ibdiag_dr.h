/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#ifndef _IBDIAG_DR_H_
#define _IBDIAG_DR_H_

#include <infiniband/mad.h>
#include "ibdiag_common.h"

/* Build a direct route to dest_lid by following switch forwarding tables via
 * live SMP queries.  "from" is the starting portid (LID- or DR-addressed,
 * e.g. {0} for the local node); on success its drpath is extended so SMPs
 * reach dest_lid.  Returns 0 on success, -1 on failure.
 */
int build_dr_path_to_lid(const struct ibmad_port *srcport, int timeout,
			 ib_portid_t *from, uint16_t dest_lid);

#endif				/* _IBDIAG_DR_H_ */
