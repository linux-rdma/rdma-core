/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 - 2022, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSCALE_H
#define XSCALE_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdatomic.h>
#include <util/compiler.h>

#include <infiniband/driver.h>
#include <util/udma_barrier.h>
#include <ccan/list.h>
#include <ccan/minmax.h>
#include <valgrind/memcheck.h>

#include "xsc-abi.h"

typedef uint8_t   u8;
typedef uint16_t  u16;
typedef uint32_t  u32;
typedef uint64_t  u64;

enum {
	XSC_DBG_QP = 1 << 0,
	XSC_DBG_CQ = 1 << 1,
	XSC_DBG_QP_SEND = 1 << 2,
	XSC_DBG_QP_SEND_ERR = 1 << 3,
	XSC_DBG_CQ_CQE = 1 << 4,
	XSC_DBG_CONTIG = 1 << 5,
	XSC_DBG_DR = 1 << 6,
	XSC_DBG_CTX = 1 << 7,
	XSC_DBG_PD = 1 << 8,
	XSC_DBG_MR = 1 << 9,
};

extern u32 xsc_debug_mask;

#define xsc_dbg(fp, mask, fmt, args...)                                        \
	do {                                                                   \
		if (xsc_debug_mask & (mask)) {                                 \
			char host[256];                                        \
			char timestr[32];                                      \
			struct tm now_tm;                                      \
			time_t now_time;                                       \
			time(&now_time);                                       \
			localtime_r(&now_time, &now_tm);                       \
			strftime(timestr, sizeof(timestr), "%Y-%m-%d %X",      \
				 &now_tm);                                     \
			gethostname(host, 256);                                \
			fprintf(fp, "[%s %s %s %d] " fmt, timestr, host,       \
				__func__, __LINE__, ##args);                   \
		}                                                              \
	} while (0)

#define xsc_err(fmt, args...)                                                  \
	do {                                                                   \
		char host[256];                                                \
		char timestr[32];                                              \
		struct tm now_tm;                                              \
		time_t now_time;                                               \
		time(&now_time);                                               \
		localtime_r(&now_time, &now_tm);                               \
		strftime(timestr, sizeof(timestr), "%Y-%m-%d %X", &now_tm);    \
		gethostname(host, 256);                                        \
		printf("[%s %s %s %d] " fmt, timestr, host, __func__,          \
		       __LINE__, ##args);                                      \
	} while (0)

enum {
	XSC_QP_TABLE_SHIFT = 12,
	XSC_QP_TABLE_MASK = (1 << XSC_QP_TABLE_SHIFT) - 1,
	XSC_QP_TABLE_SIZE = 1 << (24 - XSC_QP_TABLE_SHIFT),
};

struct xsc_device {
	struct verbs_device verbs_dev;
	int page_size;
};

#define NAME_BUFFER_SIZE 64

struct xsc_context {
	struct verbs_context ibv_ctx;
	int max_num_qps;
	struct {
		struct xsc_qp **table;
		int refcnt;
	} qp_table[XSC_QP_TABLE_SIZE];
	pthread_mutex_t qp_table_mutex;

	int max_sq_desc_sz;
	int max_rq_desc_sz;
	int max_send_wr;
	int max_recv_wr;
	int num_ports;
	char hostname[NAME_BUFFER_SIZE];
	u32 max_cqe;
	void *sqm_reg_va;
	void *rqm_reg_va;
	void *cqm_reg_va;
	void *cqm_armdb_va;
	int db_mmap_size;
	u32 page_size;
	u64 qpm_tx_db;
	u64 qpm_rx_db;
	u64 cqm_next_cid_reg;
	u64 cqm_armdb;
	u32 send_ds_num;
	u32 recv_ds_num;
	u32 send_ds_shift;
	u32 recv_ds_shift;
	FILE *dbg_fp;
	struct xsc_hw_ops *hw_ops;
};

union xsc_ib_fw_ver {
	u64 data;
	struct {
		u8 ver_major;
		u8 ver_minor;
		u16 ver_patch;
		u32 ver_tweak;
	} s;
};

static inline int xsc_ilog2(int n)
{
	int t;

	if (n <= 0)
		return -1;

	t = 0;
	while ((1 << t) < n)
		++t;

	return t;
}

static inline struct xsc_device *to_xdev(struct ibv_device *ibdev)
{
	return container_of(ibdev, struct xsc_device, verbs_dev.device);
}

static inline struct xsc_context *to_xctx(struct ibv_context *ibctx)
{
	return container_of(ibctx, struct xsc_context, ibv_ctx.context);
}

int xsc_query_device(struct ibv_context *context, struct ibv_device_attr *attr);
int xsc_query_device_ex(struct ibv_context *context,
			const struct ibv_query_device_ex_input *input,
			struct ibv_device_attr_ex *attr, size_t attr_size);
int xsc_query_port(struct ibv_context *context, u8 port,
		   struct ibv_port_attr *attr);

#endif /* XSC_H */
