/*
 * Copyright (c) 2015-2016  QLogic Corporation
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
 *        disclaimer in the documentation and /or other materials
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

#ifndef __RDMA_COMMON__
#define __RDMA_COMMON__

#include <linux/types.h>

/************************/
/* RDMA FW CONSTANTS */
/************************/

#define RDMA_RESERVED_LKEY			(0)			//Reserved lkey
#define RDMA_RING_PAGE_SIZE			(0x1000)	//4KB pages

#define	RDMA_MAX_SGE_PER_SQ_WQE		(4)		//max number of SGEs in a single request
#define	RDMA_MAX_SGE_PER_RQ_WQE		(4)		//max number of SGEs in a single request

#define RDMA_MAX_DATA_SIZE_IN_WQE	(0x7FFFFFFF)	//max size of data in single request

#define RDMA_REQ_RD_ATOMIC_ELM_SIZE		(0x50)
#define RDMA_RESP_RD_ATOMIC_ELM_SIZE	(0x20)

#define RDMA_MAX_CQS				(64*1024)
#define RDMA_MAX_TIDS				(128*1024-1)
#define RDMA_MAX_PDS				(64*1024)
#define RDMA_MAX_SRQS				(32*1024)

#define RDMA_NUM_STATISTIC_COUNTERS			MAX_NUM_VPORTS
#define RDMA_NUM_STATISTIC_COUNTERS_K2			MAX_NUM_VPORTS_K2
#define RDMA_NUM_STATISTIC_COUNTERS_BB			MAX_NUM_VPORTS_BB

#define RDMA_TASK_TYPE (PROTOCOLID_ROCE)


struct rdma_srq_id
{
	__le16 srq_idx /* SRQ index */;
	__le16 opaque_fid;
};


struct rdma_srq_producers
{
	__le32 sge_prod /* Current produced sge in SRQ */;
	__le32 wqe_prod /* Current produced WQE to SRQ */;
};

#endif /* __RDMA_COMMON__ */
