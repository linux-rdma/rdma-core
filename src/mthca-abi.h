/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
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
 *
 * $Id$
 */

#ifndef MTHCA_ABI_H
#define MTHCA_ABI_H

#include <infiniband/kern-abi.h>

struct mthca_alloc_ucontext {
	struct ibv_get_context ibv_cmd;
	__u64                  respbuf;
};

struct mthca_alloc_ucontext_resp {
	__u32 qp_tab_size;
	__u32 uarc_size;
};

struct mthca_alloc_pd {
	struct ibv_alloc_pd ibv_cmd;
	__u64               pdnbuf;
};

struct mthca_alloc_pd_resp {
	__u32 pdn;
	__u32 reserved;
};

struct mthca_create_cq {
	struct ibv_create_cq ibv_cmd;
	__u64                cqnbuf;
	__u32                lkey;
	__u32                pdn;
	__u64 		     arm_db_page;
	__u64 		     set_db_page;
	__u32 		     arm_db_index;
	__u32 		     set_db_index;
};

struct mthca_create_cq_resp {
	__u32 cqn;
	__u32 reserved;
};

struct mthca_create_qp {
	struct ibv_create_qp ibv_cmd;
	__u32                lkey;
	__u32                reserved;
	__u64 		     sq_db_page;
	__u64 		     rq_db_page;
	__u32 		     sq_db_index;
	__u32 		     rq_db_index;
};

#endif /* MTHCA_ABI_H */
