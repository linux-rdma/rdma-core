/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2017 - 2021 Intel Corporation */
#ifndef IRDMA_H
#define IRDMA_H

#define IRDMA_WQEALLOC_WQE_DESC_INDEX GENMASK(31, 20)

enum irdma_vers {
	IRDMA_GEN_RSVD,
	IRDMA_GEN_1,
	IRDMA_GEN_2,
};

struct irdma_uk_attrs {
	__u64 feature_flags;
	__u32 max_hw_wq_frags;
	__u32 max_hw_read_sges;
	__u32 max_hw_inline;
	__u32 max_hw_rq_quanta;
	__u32 max_hw_wq_quanta;
	__u32 min_hw_cq_size;
	__u32 max_hw_cq_size;
	__u16 max_hw_sq_chunk;
	__u8 hw_rev;
};

struct irdma_hw_attrs {
	struct irdma_uk_attrs uk_attrs;
	__u64 max_hw_outbound_msg_size;
	__u64 max_hw_inbound_msg_size;
	__u64 max_mr_size;
	__u32 min_hw_qp_id;
	__u32 min_hw_aeq_size;
	__u32 max_hw_aeq_size;
	__u32 min_hw_ceq_size;
	__u32 max_hw_ceq_size;
	__u32 max_hw_device_pages;
	__u32 max_hw_vf_fpm_id;
	__u32 first_hw_vf_fpm_id;
	__u32 max_hw_ird;
	__u32 max_hw_ord;
	__u32 max_hw_wqes;
	__u32 max_hw_pds;
	__u32 max_hw_ena_vf_count;
	__u32 max_qp_wr;
	__u32 max_pe_ready_count;
	__u32 max_done_count;
	__u32 max_sleep_count;
	__u32 max_cqp_compl_wait_time_ms;
	__u16 max_stat_inst;
};

#endif /* IRDMA_H*/
