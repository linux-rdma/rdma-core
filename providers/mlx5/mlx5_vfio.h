// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#ifndef MLX5_VFIO_H
#define MLX5_VFIO_H

#include <stddef.h>
#include <stdio.h>
#include "mlx5.h"

#include <infiniband/driver.h>
#include <util/interval_set.h>

#define FW_INIT_WAIT_MS 2
#define FW_PRE_INIT_TIMEOUT_MILI 120000

enum {
	MLX5_MAX_COMMANDS = 32,
	MLX5_CMD_DATA_BLOCK_SIZE = 512,
	MLX5_PCI_CMD_XPORT = 7,
};

enum {
	MLX5_VFIO_BLOCK_SIZE = 2 * 1024 * 1024,
	MLX5_VFIO_BLOCK_NUM_PAGES = MLX5_VFIO_BLOCK_SIZE / MLX5_ADAPTER_PAGE_SIZE,
};

struct mlx5_vfio_device {
	struct verbs_device vdev;
	char *pci_name;
	char vfio_path[IBV_SYSFS_PATH_MAX];
	int page_size;
	uint32_t flags;
};

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define MLX5_SET_HOST_ENDIANNESS 0
#elif __BYTE_ORDER == __BIG_ENDIAN
#define MLX5_SET_HOST_ENDIANNESS 0x80
#else
#error Host endianness not defined
#endif

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

struct mlx5_vfio_cmd_slot {
	struct mlx5_cmd_layout *lay;
	struct mlx5_cmd_msg in;
	struct mlx5_cmd_msg out;
	pthread_mutex_t lock;
	int completion_event_fd;
};

struct mlx5_vfio_cmd {
	void *vaddr; /* cmd page address */
	uint64_t iova;
	uint8_t log_sz;
	uint8_t log_stride;
	struct mlx5_vfio_cmd_slot cmds[MLX5_MAX_COMMANDS];
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
};

static inline struct mlx5_vfio_device *to_mvfio_dev(struct ibv_device *ibdev)
{
	return container_of(ibdev, struct mlx5_vfio_device, vdev.device);
}

static inline struct mlx5_vfio_context *to_mvfio_ctx(struct ibv_context *ibctx)
{
	return container_of(ibctx, struct mlx5_vfio_context, vctx.context);
}

#endif
