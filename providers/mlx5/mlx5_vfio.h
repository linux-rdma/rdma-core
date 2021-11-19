// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#ifndef MLX5_VFIO_H
#define MLX5_VFIO_H

#include <stddef.h>
#include <stdio.h>
#include "mlx5.h"
#include "mlx5_ifc.h"

#include <infiniband/driver.h>
#include <util/interval_set.h>
#include "mlx5_ifc.h"

#define FW_INIT_WAIT_MS 2
#define FW_PRE_INIT_TIMEOUT_MILI 120000

enum {
	MLX5_MAX_COMMANDS = 32,
	MLX5_CMD_DATA_BLOCK_SIZE = 512,
	MLX5_PCI_CMD_XPORT = 7,
};

enum mlx5_ib_mtt_access_flags {
	MLX5_MTT_READ  = (1 << 0),
	MLX5_MTT_WRITE = (1 << 1),
};

enum {
	MLX5_MAX_PAGE_SHIFT = 31,
};

#define MLX5_MTT_PRESENT (MLX5_MTT_READ | MLX5_MTT_WRITE)

enum {
	MLX5_VFIO_BLOCK_SIZE = 2 * 1024 * 1024,
	MLX5_VFIO_BLOCK_NUM_PAGES = MLX5_VFIO_BLOCK_SIZE / MLX5_ADAPTER_PAGE_SIZE,
};

struct mlx5_vfio_mr {
	struct verbs_mr vmr;
	uint64_t iova;
	uint64_t iova_page_size;
	uint64_t iova_aligned_offset;
	uint64_t iova_reg_size;
};

struct mlx5_vfio_devx_umem {
	struct mlx5dv_devx_umem dv_devx_umem;
	struct ibv_context *context;
	void *addr;
	size_t size;
	uint64_t iova;
	uint64_t iova_size;
	uint64_t iova_reg_size;
};

struct mlx5_vfio_device {
	struct verbs_device vdev;
	char *pci_name;
	char vfio_path[IBV_SYSFS_PATH_MAX];
	int page_size;
	uint32_t flags;
	atomic_int mkey_var;
};

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define MLX5_SET_HOST_ENDIANNESS 0
#elif __BYTE_ORDER == __BIG_ENDIAN
#define MLX5_SET_HOST_ENDIANNESS 0x80
#else
#error Host endianness not defined
#endif

/* GET Dev Caps macros */
#define MLX5_VFIO_CAP_GEN(ctx, cap) \
	DEVX_GET(cmd_hca_cap, ctx->caps.hca_cur[MLX5_CAP_GENERAL], cap)

#define MLX5_VFIO_CAP_GEN_64(mdev, cap) \
	DEVX_GET64(cmd_hca_cap, mdev->caps.hca_cur[MLX5_CAP_GENERAL], cap)

#define MLX5_VFIO_CAP_GEN_MAX(ctx, cap) \
	DEVX_GET(cmd_hca_cap, ctx->caps.hca_max[MLX5_CAP_GENERAL], cap)

#define MLX5_VFIO_CAP_ROCE(ctx, cap) \
	DEVX_GET(roce_cap, ctx->caps.hca_cur[MLX5_CAP_ROCE], cap)

#define MLX5_VFIO_CAP_ROCE_MAX(ctx, cap) \
	DEVX_GET(roce_cap, ctx->caps.hca_max[MLX5_CAP_ROCE], cap)

struct mlx5_vfio_context;

struct mlx5_reg_host_endianness {
	uint8_t he;
	uint8_t rsvd[15];
};

struct health_buffer {
	__be32		assert_var[5];
	__be32		rsvd0[3];
	__be32		assert_exit_ptr;
	__be32		assert_callra;
	__be32		rsvd1[2];
	__be32		fw_ver;
	__be32		hw_id;
	__be32		rfr;
	uint8_t		irisc_index;
	uint8_t		synd;
	__be16		ext_synd;
};

struct mlx5_init_seg {
	__be32			fw_rev;
	__be32			cmdif_rev_fw_sub;
	__be32			rsvd0[2];
	__be32			cmdq_addr_h;
	__be32			cmdq_addr_l_sz;
	__be32			cmd_dbell;
	__be32			rsvd1[120];
	__be32			initializing;
	struct health_buffer	health;
	__be32			rsvd2[880];
	__be32			internal_timer_h;
	__be32			internal_timer_l;
	__be32			rsvd3[2];
	__be32			health_counter;
	__be32			rsvd4[1019];
	__be64			ieee1588_clk;
	__be32			ieee1588_clk_type;
	__be32			clr_intx;
};

struct mlx5_cmd_layout {
	uint8_t		type;
	uint8_t		rsvd0[3];
	__be32		ilen;
	__be64		iptr;
	__be32		in[4];
	__be32		out[4];
	__be64		optr;
	__be32		olen;
	uint8_t		token;
	uint8_t		sig;
	uint8_t		rsvd1;
	uint8_t		status_own;
};

struct mlx5_cmd_block {
	uint8_t		data[MLX5_CMD_DATA_BLOCK_SIZE];
	uint8_t		rsvd0[48];
	__be64		next;
	__be32		block_num;
	uint8_t		rsvd1;
	uint8_t		token;
	uint8_t		ctrl_sig;
	uint8_t		sig;
};

struct page_block {
	void *page_ptr;
	uint64_t iova;
	struct list_node next_block;
	BITMAP_DECLARE(free_pages, MLX5_VFIO_BLOCK_NUM_PAGES);
};

struct vfio_mem_allocator {
	struct list_head block_list;
	pthread_mutex_t block_list_mutex;
};

struct mlx5_cmd_mailbox {
	void *buf;
	uint64_t iova;
	struct mlx5_cmd_mailbox *next;
};

struct mlx5_cmd_msg {
	uint32_t len;
	struct mlx5_cmd_mailbox *next;
};


typedef int (*vfio_cmd_slot_comp)(struct mlx5_vfio_context *ctx,
				  unsigned long slot);

struct cmd_async_data {
	void *buff_in;
	int ilen;
	void *buff_out;
	int olen;
};

struct mlx5_vfio_cmd_slot {
	struct mlx5_cmd_layout *lay;
	struct mlx5_cmd_msg in;
	struct mlx5_cmd_msg out;
	pthread_mutex_t lock;
	int completion_event_fd;
	vfio_cmd_slot_comp comp_func;
	/* async cmd caller data */
	bool in_use;
	struct cmd_async_data curr;
	bool is_pending;
	struct cmd_async_data pending;
};

struct mlx5_vfio_cmd {
	void *vaddr; /* cmd page address */
	uint64_t iova;
	uint8_t log_sz;
	uint8_t log_stride;
	struct mlx5_vfio_cmd_slot cmds[MLX5_MAX_COMMANDS];
};

struct mlx5_eq_param {
	uint8_t irq_index;
	int nent;
	uint64_t mask[4];
};

struct mlx5_eq {
	__be32 *doorbell;
	uint32_t cons_index;
	unsigned int vecidx;
	uint8_t eqn;
	int nent;
	void *vaddr;
	uint64_t iova;
	uint64_t iova_size;
};

struct mlx5_eqe_cmd {
	__be32 vector;
	__be32 rsvd[6];
};

struct mlx5_eqe_page_req {
	__be16 ec_function;
	__be16 func_id;
	__be32 num_pages;
	__be32 rsvd1[5];
};

union ev_data {
	__be32 raw[7];
	struct mlx5_eqe_cmd cmd;
	struct mlx5_eqe_page_req req_pages;
};

struct mlx5_eqe {
	uint8_t rsvd0;
	uint8_t type;
	uint8_t rsvd1;
	uint8_t sub_type;
	__be32 rsvd2[7];
	union ev_data data;
	__be16 rsvd3;
	uint8_t signature;
	uint8_t owner;
};

#define MLX5_EQE_SIZE (sizeof(struct mlx5_eqe))
#define MLX5_NUM_CMD_EQE   (32)
#define MLX5_NUM_SPARE_EQE (0x80)

struct mlx5_vfio_eqs_uar {
	uint32_t uarn;
	uint64_t iova;
};

#define POLL_HEALTH_INTERVAL 1000 /* ms */
#define MAX_MISSES 3
struct mlx5_vfio_health_state {
	uint64_t prev_time; /* ms */
	uint32_t prev_count;
	uint32_t miss_counter;
};

struct mlx5_vfio_context {
	struct verbs_context vctx;
	int container_fd;
	int group_fd;
	int device_fd;
	int cmd_comp_fd; /* command completion FD */
	struct iset *iova_alloc;
	uint64_t iova_min_page_size;
	FILE *dbg_fp;
	struct vfio_mem_allocator mem_alloc;
	struct mlx5_init_seg *bar_map;
	size_t bar_map_size;
	struct mlx5_vfio_cmd cmd;
	bool have_eq;
	struct {
		uint32_t hca_cur[MLX5_CAP_NUM][DEVX_UN_SZ_DW(hca_cap_union)];
		uint32_t hca_max[MLX5_CAP_NUM][DEVX_UN_SZ_DW(hca_cap_union)];
	} caps;
	struct mlx5_vfio_health_state health_state;
	struct mlx5_eq async_eq;
	struct mlx5_vfio_eqs_uar eqs_uar;
	pthread_mutex_t eq_lock;
	struct mlx5_dv_context_ops *dv_ctx_ops;
};

#define MLX5_MAX_DESTROY_INBOX_SIZE_DW	DEVX_ST_SZ_DW(delete_fte_in)
struct mlx5_devx_obj {
	struct mlx5dv_devx_obj dv_obj;
	uint32_t dinbox[MLX5_MAX_DESTROY_INBOX_SIZE_DW];
	uint32_t dinlen;
};

static inline struct mlx5_vfio_device *to_mvfio_dev(struct ibv_device *ibdev)
{
	return container_of(ibdev, struct mlx5_vfio_device, vdev.device);
}

static inline struct mlx5_vfio_context *to_mvfio_ctx(struct ibv_context *ibctx)
{
	return container_of(ibctx, struct mlx5_vfio_context, vctx.context);
}

static inline struct mlx5_vfio_mr *to_mvfio_mr(struct ibv_mr *ibmr)
{
	return container_of(ibmr, struct mlx5_vfio_mr, vmr.ibv_mr);
}

#endif
