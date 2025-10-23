/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2018-2025 Advanced Micro Devices, Inc.  All rights reserved.
 */

#ifndef IONIC_FW_H
#define IONIC_FW_H

#include "ionic_fw_types.h"

static inline int to_ionic_mr_flags(int access)
{
	int flags = 0;

	if (access & IBV_ACCESS_LOCAL_WRITE)
		flags |= IONIC_MRF_LOCAL_WRITE;

	if (access & IBV_ACCESS_REMOTE_READ)
		flags |= IONIC_MRF_REMOTE_READ;

	if (access & IBV_ACCESS_REMOTE_WRITE)
		flags |= IONIC_MRF_REMOTE_WRITE;

	if (access & IBV_ACCESS_REMOTE_ATOMIC)
		flags |= IONIC_MRF_REMOTE_ATOMIC;

	if (access & IBV_ACCESS_MW_BIND)
		flags |= IONIC_MRF_MW_BIND;

	if (access & IBV_ACCESS_ZERO_BASED)
		flags |= IONIC_MRF_ZERO_BASED;

	return flags;
}

static inline int ionic_to_ibv_status(int sts)
{
	switch (sts) {
	case IONIC_STS_OK:
		return IBV_WC_SUCCESS;
	case IONIC_STS_LOCAL_LEN_ERR:
		return IBV_WC_LOC_LEN_ERR;
	case IONIC_STS_LOCAL_QP_OPER_ERR:
		return IBV_WC_LOC_QP_OP_ERR;
	case IONIC_STS_LOCAL_PROT_ERR:
		return IBV_WC_LOC_PROT_ERR;
	case IONIC_STS_WQE_FLUSHED_ERR:
		return IBV_WC_WR_FLUSH_ERR;
	case IONIC_STS_MEM_MGMT_OPER_ERR:
		return IBV_WC_MW_BIND_ERR;
	case IONIC_STS_BAD_RESP_ERR:
		return IBV_WC_BAD_RESP_ERR;
	case IONIC_STS_LOCAL_ACC_ERR:
		return IBV_WC_LOC_ACCESS_ERR;
	case IONIC_STS_REMOTE_INV_REQ_ERR:
		return IBV_WC_REM_INV_REQ_ERR;
	case IONIC_STS_REMOTE_ACC_ERR:
		return IBV_WC_REM_ACCESS_ERR;
	case IONIC_STS_REMOTE_OPER_ERR:
		return IBV_WC_REM_OP_ERR;
	case IONIC_STS_RETRY_EXCEEDED:
		return IBV_WC_RETRY_EXC_ERR;
	case IONIC_STS_RNR_RETRY_EXCEEDED:
		return IBV_WC_RNR_RETRY_EXC_ERR;
	case IONIC_STS_XRC_VIO_ERR:
	default:
		return IBV_WC_GENERAL_ERR;
	}
}

static inline bool ionic_v1_cqe_color(struct ionic_v1_cqe *cqe)
{
	return !!(cqe->qid_type_flags & htobe32(IONIC_V1_CQE_COLOR));
}

static inline bool ionic_v1_cqe_error(struct ionic_v1_cqe *cqe)
{
	return !!(cqe->qid_type_flags & htobe32(IONIC_V1_CQE_ERROR));
}

static inline bool ionic_v1_cqe_recv_is_ipv4(struct ionic_v1_cqe *cqe)
{
	return !!(cqe->recv.src_qpn_op &
		  htobe32(IONIC_V1_CQE_RECV_IS_IPV4));
}

static inline bool ionic_v1_cqe_recv_is_vlan(struct ionic_v1_cqe *cqe)
{
	return !!(cqe->recv.src_qpn_op &
		  htobe32(IONIC_V1_CQE_RECV_IS_VLAN));
}

static inline void ionic_v1_cqe_clean(struct ionic_v1_cqe *cqe)
{
	cqe->qid_type_flags |= htobe32(~0u << IONIC_V1_CQE_QID_SHIFT);
}

static inline uint32_t ionic_v1_cqe_qtf(struct ionic_v1_cqe *cqe)
{
	return be32toh(cqe->qid_type_flags);
}

static inline uint8_t ionic_v1_cqe_qtf_type(uint32_t qtf)
{
	return (qtf >> IONIC_V1_CQE_TYPE_SHIFT) & IONIC_V1_CQE_TYPE_MASK;
}

static inline uint32_t ionic_v1_cqe_qtf_qid(uint32_t qtf)
{
	return qtf >> IONIC_V1_CQE_QID_SHIFT;
}

static inline size_t ionic_v1_send_wqe_min_size(int min_sge, int min_data,
						int spec, bool expdb)
{
	size_t sz_wqe, sz_sgl, sz_data;

	if (spec > IONIC_V1_SPEC_FIRST_SGE)
		min_sge += IONIC_V1_SPEC_FIRST_SGE;

	if (expdb) {
		min_sge += 1;
		min_data += IONIC_EXP_DBELL_SZ;
	}

	sz_wqe = sizeof(struct ionic_v1_wqe);
	sz_sgl = offsetof(struct ionic_v1_wqe, common.pld.sgl[min_sge]);
	sz_data = offsetof(struct ionic_v1_wqe, common.pld.data[min_data]);

	if (sz_sgl > sz_wqe)
		sz_wqe = sz_sgl;

	if (sz_data > sz_wqe)
		sz_wqe = sz_data;

	return roundup_pow_of_two(sz_wqe);
}

static inline int ionic_v1_send_wqe_max_sge(uint8_t stride_log2, int spec, bool expdb)
{
	struct ionic_v1_wqe *wqe = (void *)0;
	struct ionic_sge *sge = (void *)(uintptr_t)(1ull << stride_log2);
	int num_sge = 0;

	if (expdb)
		sge -= 1;

	if (spec > IONIC_V1_SPEC_FIRST_SGE)
		num_sge = IONIC_V1_SPEC_FIRST_SGE;

	num_sge = sge - &wqe->common.pld.sgl[num_sge];

	if (spec && num_sge > spec)
		num_sge = spec;

	return num_sge;
}

static inline int ionic_v1_send_wqe_max_data(uint8_t stride_log2, bool expdb)
{
	struct ionic_v1_wqe *wqe = (void *)0;
	__u8 *data = (void *)(uintptr_t)(1ull << stride_log2);

	if (expdb)
		data -= IONIC_EXP_DBELL_SZ;

	return data - wqe->common.pld.data;
}

static inline size_t ionic_v1_recv_wqe_min_size(int min_sge, int spec, bool expdb)
{
	size_t sz_wqe, sz_sgl;

	if (spec > IONIC_V1_SPEC_FIRST_SGE)
		min_sge += IONIC_V1_SPEC_FIRST_SGE;

	if (expdb)
		min_sge += 1;

	sz_wqe = sizeof(struct ionic_v1_wqe);
	sz_sgl = offsetof(struct ionic_v1_wqe, recv.pld.sgl[min_sge]);

	if (sz_sgl > sz_wqe)
		sz_wqe = sz_sgl;

	return sz_wqe;
}

static inline int ionic_v1_recv_wqe_max_sge(uint8_t stride_log2, int spec, bool expdb)
{
	struct ionic_v1_wqe *wqe = (void *)0;
	struct ionic_sge *sge = (void *)(uintptr_t)(1ull << stride_log2);
	int num_sge = 0;

	if (expdb)
		sge -= 1;

	if (spec > IONIC_V1_SPEC_FIRST_SGE)
		num_sge = IONIC_V1_SPEC_FIRST_SGE;

	num_sge = sge - &wqe->recv.pld.sgl[num_sge];

	if (spec && num_sge > spec)
		num_sge = spec;

	return num_sge;
}

static inline int ionic_v1_use_spec_sge(int min_sge, int spec)
{
	if (!spec || min_sge > spec)
		return 0;

	if (min_sge <= IONIC_V1_SPEC_FIRST_SGE)
		return IONIC_V1_SPEC_FIRST_SGE;

	return spec;
}

#endif /* IONIC_FW_H */
