/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright 2022-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#ifndef __HBL_H__
#define __HBL_H__

#include <infiniband/driver.h>

#include "hbl-abi.h"
#include "hbldv.h"

/**
 * struct hbl_dev - HBL device.
 * @vdev: Verbs device.
 */
struct hbl_dev {
	struct verbs_device vdev;
};

/**
 * struct hbl_context - HBL context.
 * @ibv_ctx: Verbs context.
 * @ports_mask: Mask of ports associated with this context.
 * @cap_mask: Capabilities mask.
 * @ref_cnt: number of refcounts of the context.
 * @core_fd: File descriptor of the core device.
 * @is_default_ctx: was the context created with default values.
 */
struct hbl_context {
	struct verbs_context ibv_ctx;
	uint64_t ports_mask;
	uint64_t cap_mask;
	uint32_t ref_cnt;
	int core_fd;
	uint8_t is_default_ctx;
};

/**
 * struct hbl_pd - HBL PD.
 * @ibvpd: IBV PD.
 * @pdn: PD number.
 */
struct hbl_pd {
	struct ibv_pd ibvpd;
	uint32_t pdn;
};

/**
 * struct hbl_qp - HBL QP.
 * @vqp: Verbs QP.
 * @swq_cpu_addr: Send WQ mmap address.
 * @rwq_cpu_addr: Receive WQ mmap address.
 * @swq_mem_handle: Send WQ mmap handle.
 * @rwq_mem_handle: Receive WQ mmap handle.
 * @swq_mem_size: Send WQ mmap size.
 * @rwq_mem_size: Receive WQ mmap size.
 * @max_send_wr: Max number of send WQEs.
 * @max_recv_wr: Max number of receive WQEs.
 * @qp_num: HBL QP ID.
 */
struct hbl_qp {
	struct verbs_qp vqp;
	void *swq_cpu_addr;
	void *rwq_cpu_addr;
	uint64_t swq_mem_handle;
	uint64_t rwq_mem_handle;
	uint32_t swq_mem_size;
	uint32_t rwq_mem_size;
	uint32_t max_send_wr;
	uint32_t max_recv_wr;
	uint32_t qp_num;
};

/**
 * struct hbl_cq - HBL CQ
 * @ibvcq: Verbs CQ.
 * @mem_cpu_addr: CQ buffer address.
 * @pi_cpu_addr: CQ PI memory address.
 * @regs_cpu_addr: CQ UMR address.
 * @cq_size: Size of the CQ.
 * @cq_num: CQ id that is allocated.
 * @regs_offset: CQ UMR reg offset.
 * @is_native: to identify if CQ is created via ibv_create_cq().
 * @cq_type: Type of CQ resource.
 * @port_cq: pointer to array of CQ for all available ports.
 */
struct hbl_cq {
	struct ibv_cq ibvcq;
	void *mem_cpu_addr;
	void *pi_cpu_addr;
	void *regs_cpu_addr;
	uint32_t cq_size;
	uint32_t cq_num;
	uint32_t regs_offset;
	uint8_t is_native;
	enum hbldv_cq_type cq_type;
	struct hbl_cq *port_cq;
};

/**
 * struct hbl_usr_fifo_obj - HBL user FIFO object.
 * @dv_usr_fifo: DV user FIFO data.
 * @context: IBV context.
 * @handle: User fifo IDR handle.
 */
struct hbl_usr_fifo_obj {
	struct hbldv_usr_fifo dv_usr_fifo;
	struct ibv_context *context;
	uint32_t handle;
};

/**
 * struct hbl_encap - HBL encapsulation data.
 * @dv_encap: HBL DV encapsulation data.
 * @context: IBV context.
 * @handle: Encap IDR handle.
 */
struct hbl_encap {
	struct hbldv_encap dv_encap;
	struct ibv_context *context;
	uint32_t handle;
};

bool is_hbl_dev(struct ibv_device *device);

static inline struct hbl_dev *to_hbl_dev(struct ibv_device *ibvdev)
{
	return container_of(ibvdev, struct hbl_dev, vdev.device);
}

static inline struct hbl_context *to_hbl_ctx(struct ibv_context *ibctx)
{
	return container_of(ibctx, struct hbl_context, ibv_ctx.context);
}

static inline struct hbl_pd *to_hbl_pd(struct ibv_pd *ibvpd)
{
	return container_of(ibvpd, struct hbl_pd, ibvpd);
}

static inline struct hbl_qp *to_hbl_qp(struct verbs_qp *vqp)
{
	return container_of(vqp, struct hbl_qp, vqp);
}

static inline struct hbl_cq *to_hbl_cq(struct ibv_cq *ibvcq)
{
	return container_of(ibvcq, struct hbl_cq, ibvcq);
}

#endif /* __HBL_H__ */
