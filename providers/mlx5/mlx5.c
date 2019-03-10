/*
 * Copyright (c) 2012 Mellanox Technologies, Inc.  All rights reserved.
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
 */
#define _GNU_SOURCE
#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <string.h>
#include <sched.h>
#include <sys/param.h>

#include <util/symver.h>

#include "mlx5.h"
#include "mlx5-abi.h"
#include "wqe.h"

#ifndef PCI_VENDOR_ID_MELLANOX
#define PCI_VENDOR_ID_MELLANOX			0x15b3
#endif

#ifndef CPU_OR
#define CPU_OR(x, y, z) do {} while (0)
#endif

#ifndef CPU_EQUAL
#define CPU_EQUAL(x, y) 1
#endif

#define HCA(v, d) VERBS_PCI_MATCH(PCI_VENDOR_ID_##v, d, NULL)
static const struct verbs_match_ent hca_table[] = {
	HCA(MELLANOX, 0x1011),	/* MT4113 Connect-IB */
	HCA(MELLANOX, 0x1012),	/* Connect-IB Virtual Function */
	HCA(MELLANOX, 0x1013),	/* ConnectX-4 */
	HCA(MELLANOX, 0x1014),	/* ConnectX-4 Virtual Function */
	HCA(MELLANOX, 0x1015),	/* ConnectX-4LX */
	HCA(MELLANOX, 0x1016),	/* ConnectX-4LX Virtual Function */
	HCA(MELLANOX, 0x1017),	/* ConnectX-5, PCIe 3.0 */
	HCA(MELLANOX, 0x1018),	/* ConnectX-5 Virtual Function */
	HCA(MELLANOX, 0x1019),    /* ConnectX-5 Ex */
	HCA(MELLANOX, 0x101a),	/* ConnectX-5 Ex VF */
	HCA(MELLANOX, 0x101b),    /* ConnectX-6 */
	HCA(MELLANOX, 0x101c),	/* ConnectX-6 VF */
	HCA(MELLANOX, 0x101d),	/* ConnectX-6 DX */
	HCA(MELLANOX, 0x101e),	/* ConnectX family mlx5Gen Virtual Function */
	HCA(MELLANOX, 0xa2d2),	/* BlueField integrated ConnectX-5 network controller */
	HCA(MELLANOX, 0xa2d3),	/* BlueField integrated ConnectX-5 network controller VF */
	{}
};

uint32_t mlx5_debug_mask = 0;
int mlx5_freeze_on_error_cqe;

static const struct verbs_context_ops mlx5_ctx_common_ops = {
	.query_device  = mlx5_query_device,
	.query_port    = mlx5_query_port,
	.alloc_pd      = mlx5_alloc_pd,
	.dealloc_pd    = mlx5_free_pd,
	.reg_mr	       = mlx5_reg_mr,
	.rereg_mr      = mlx5_rereg_mr,
	.dereg_mr      = mlx5_dereg_mr,
	.alloc_mw      = mlx5_alloc_mw,
	.dealloc_mw    = mlx5_dealloc_mw,
	.bind_mw       = mlx5_bind_mw,
	.create_cq     = mlx5_create_cq,
	.poll_cq       = mlx5_poll_cq,
	.req_notify_cq = mlx5_arm_cq,
	.cq_event      = mlx5_cq_event,
	.resize_cq     = mlx5_resize_cq,
	.destroy_cq    = mlx5_destroy_cq,
	.create_srq    = mlx5_create_srq,
	.modify_srq    = mlx5_modify_srq,
	.query_srq     = mlx5_query_srq,
	.destroy_srq   = mlx5_destroy_srq,
	.post_srq_recv = mlx5_post_srq_recv,
	.create_qp     = mlx5_create_qp,
	.query_qp      = mlx5_query_qp,
	.modify_qp     = mlx5_modify_qp,
	.destroy_qp    = mlx5_destroy_qp,
	.post_send     = mlx5_post_send,
	.post_recv     = mlx5_post_recv,
	.create_ah     = mlx5_create_ah,
	.destroy_ah    = mlx5_destroy_ah,
	.attach_mcast  = mlx5_attach_mcast,
	.detach_mcast  = mlx5_detach_mcast,

	.advise_mr = mlx5_advise_mr,
	.alloc_dm = mlx5_alloc_dm,
	.alloc_parent_domain = mlx5_alloc_parent_domain,
	.alloc_td = mlx5_alloc_td,
	.attach_counters_point_flow = mlx5_attach_counters_point_flow,
	.close_xrcd = mlx5_close_xrcd,
	.create_counters = mlx5_create_counters,
	.create_cq_ex = mlx5_create_cq_ex,
	.create_flow = mlx5_create_flow,
	.create_flow_action_esp = mlx5_create_flow_action_esp,
	.create_qp_ex = mlx5_create_qp_ex,
	.create_rwq_ind_table = mlx5_create_rwq_ind_table,
	.create_srq_ex = mlx5_create_srq_ex,
	.create_wq = mlx5_create_wq,
	.dealloc_td = mlx5_dealloc_td,
	.destroy_counters = mlx5_destroy_counters,
	.destroy_flow = mlx5_destroy_flow,
	.destroy_flow_action = mlx5_destroy_flow_action,
	.destroy_rwq_ind_table = mlx5_destroy_rwq_ind_table,
	.destroy_wq = mlx5_destroy_wq,
	.free_dm = mlx5_free_dm,
	.get_srq_num = mlx5_get_srq_num,
	.modify_cq = mlx5_modify_cq,
	.modify_flow_action_esp = mlx5_modify_flow_action_esp,
	.modify_qp_rate_limit = mlx5_modify_qp_rate_limit,
	.modify_wq = mlx5_modify_wq,
	.open_xrcd = mlx5_open_xrcd,
	.post_srq_ops = mlx5_post_srq_ops,
	.query_device_ex = mlx5_query_device_ex,
	.query_rt_values = mlx5_query_rt_values,
	.read_counters = mlx5_read_counters,
	.reg_dm_mr = mlx5_reg_dm_mr,
	.alloc_null_mr = mlx5_alloc_null_mr,
};

static const struct verbs_context_ops mlx5_ctx_cqev1_ops = {
	.poll_cq = mlx5_poll_cq_v1,
};

static int read_number_from_line(const char *line, int *value)
{
	const char *ptr;

	ptr = strchr(line, ':');
	if (!ptr)
		return 1;

	++ptr;

	*value = atoi(ptr);
	return 0;
}
/**
 * The function looks for the first free user-index in all the
 * user-index tables. If all are used, returns -1, otherwise
 * a valid user-index.
 * In case the reference count of the table is zero, it means the
 * table is not in use and wasn't allocated yet, therefore the
 * mlx5_store_uidx allocates the table, and increment the reference
 * count on the table.
 */
static int32_t get_free_uidx(struct mlx5_context *ctx)
{
	int32_t tind;
	int32_t i;

	for (tind = 0; tind < MLX5_UIDX_TABLE_SIZE; tind++) {
		if (ctx->uidx_table[tind].refcnt < MLX5_UIDX_TABLE_MASK)
			break;
	}

	if (tind == MLX5_UIDX_TABLE_SIZE)
		return -1;

	if (!ctx->uidx_table[tind].refcnt)
		return tind << MLX5_UIDX_TABLE_SHIFT;

	for (i = 0; i < MLX5_UIDX_TABLE_MASK + 1; i++) {
		if (!ctx->uidx_table[tind].table[i])
			break;
	}

	return (tind << MLX5_UIDX_TABLE_SHIFT) | i;
}

int32_t mlx5_store_uidx(struct mlx5_context *ctx, void *rsc)
{
	int32_t tind;
	int32_t ret = -1;
	int32_t uidx;

	pthread_mutex_lock(&ctx->uidx_table_mutex);
	uidx = get_free_uidx(ctx);
	if (uidx < 0)
		goto out;

	tind = uidx >> MLX5_UIDX_TABLE_SHIFT;

	if (!ctx->uidx_table[tind].refcnt) {
		ctx->uidx_table[tind].table = calloc(MLX5_UIDX_TABLE_MASK + 1,
						     sizeof(struct mlx5_resource *));
		if (!ctx->uidx_table[tind].table)
			goto out;
	}

	++ctx->uidx_table[tind].refcnt;
	ctx->uidx_table[tind].table[uidx & MLX5_UIDX_TABLE_MASK] = rsc;
	ret = uidx;

out:
	pthread_mutex_unlock(&ctx->uidx_table_mutex);
	return ret;
}

void mlx5_clear_uidx(struct mlx5_context *ctx, uint32_t uidx)
{
	int tind = uidx >> MLX5_UIDX_TABLE_SHIFT;

	pthread_mutex_lock(&ctx->uidx_table_mutex);

	if (!--ctx->uidx_table[tind].refcnt)
		free(ctx->uidx_table[tind].table);
	else
		ctx->uidx_table[tind].table[uidx & MLX5_UIDX_TABLE_MASK] = NULL;

	pthread_mutex_unlock(&ctx->uidx_table_mutex);
}

static int mlx5_is_sandy_bridge(int *num_cores)
{
	char line[128];
	FILE *fd;
	int rc = 0;
	int cur_cpu_family = -1;
	int cur_cpu_model = -1;

	fd = fopen("/proc/cpuinfo", "r");
	if (!fd)
		return 0;

	*num_cores = 0;

	while (fgets(line, 128, fd)) {
		int value;

		/* if this is information on new processor */
		if (!strncmp(line, "processor", 9)) {
			++*num_cores;

			cur_cpu_family = -1;
			cur_cpu_model  = -1;
		} else if (!strncmp(line, "cpu family", 10)) {
			if ((cur_cpu_family < 0) && (!read_number_from_line(line, &value)))
				cur_cpu_family = value;
		} else if (!strncmp(line, "model", 5)) {
			if ((cur_cpu_model < 0) && (!read_number_from_line(line, &value)))
				cur_cpu_model = value;
		}

		/* if this is a Sandy Bridge CPU */
		if ((cur_cpu_family == 6) &&
		    (cur_cpu_model == 0x2A || (cur_cpu_model == 0x2D) ))
			rc = 1;
	}

	fclose(fd);
	return rc;
}

/*
man cpuset

  This format displays each 32-bit word in hexadecimal (using ASCII characters "0" - "9" and "a" - "f"); words
  are filled with leading zeros, if required. For masks longer than one word, a comma separator is used between
  words. Words are displayed in big-endian order, which has the most significant bit first. The hex digits
  within a word are also in big-endian order.

  The number of 32-bit words displayed is the minimum number needed to display all bits of the bitmask, based on
  the size of the bitmask.

  Examples of the Mask Format:

     00000001                        # just bit 0 set
     40000000,00000000,00000000      # just bit 94 set
     000000ff,00000000               # bits 32-39 set
     00000000,000E3862               # 1,5,6,11-13,17-19 set

  A mask with bits 0, 1, 2, 4, 8, 16, 32, and 64 set displays as:

     00000001,00000001,00010117

  The first "1" is for bit 64, the second for bit 32, the third for bit 16, the fourth for bit 8, the fifth for
  bit 4, and the "7" is for bits 2, 1, and 0.
*/
static void mlx5_local_cpu_set(struct ibv_device *ibdev, cpu_set_t *cpu_set)
{
	char *p, buf[1024] = {};
	char *env_value;
	uint32_t word;
	int i, k;

	env_value = getenv("MLX5_LOCAL_CPUS");
	if (env_value)
		strncpy(buf, env_value, sizeof(buf) - 1);
	else {
		char fname[MAXPATHLEN];
		FILE *fp;

		snprintf(fname, MAXPATHLEN, "/sys/class/infiniband/%s/device/local_cpus",
			 ibv_get_device_name(ibdev));

		fp = fopen(fname, "r");
		if (!fp) {
			fprintf(stderr, PFX "Warning: can not get local cpu set: failed to open %s\n", fname);
			return;
		}
		if (!fgets(buf, sizeof(buf), fp)) {
			fprintf(stderr, PFX "Warning: can not get local cpu set: failed to read cpu mask\n");
			fclose(fp);
			return;
		}
		fclose(fp);
	}

	p = strrchr(buf, ',');
	if (!p)
		p = buf;

	i = 0;
	do {
		if (*p == ',') {
			*p = 0;
			p ++;
		}

		word = strtoul(p, NULL, 16);

		for (k = 0; word; ++k, word >>= 1)
			if (word & 1)
				CPU_SET(k+i, cpu_set);

		if (p == buf)
			break;

		p = strrchr(buf, ',');
		if (!p)
			p = buf;

		i += 32;
	} while (i < CPU_SETSIZE);
}

static int mlx5_enable_sandy_bridge_fix(struct ibv_device *ibdev)
{
	cpu_set_t my_cpus, dev_local_cpus, result_set;
	int stall_enable;
	int ret;
	int num_cores;

	if (!mlx5_is_sandy_bridge(&num_cores))
		return 0;

	/* by default enable stall on sandy bridge arch */
	stall_enable = 1;

	/*
	 * check if app is bound to cpu set that is inside
	 * of device local cpu set. Disable stalling if true
	 */

	/* use static cpu set - up to CPU_SETSIZE (1024) cpus/node */
	CPU_ZERO(&my_cpus);
	CPU_ZERO(&dev_local_cpus);
	CPU_ZERO(&result_set);
	ret = sched_getaffinity(0, sizeof(my_cpus), &my_cpus);
	if (ret == -1) {
		if (errno == EINVAL)
			fprintf(stderr, PFX "Warning: my cpu set is too small\n");
		else
			fprintf(stderr, PFX "Warning: failed to get my cpu set\n");
		goto out;
	}

	/* get device local cpu set */
	mlx5_local_cpu_set(ibdev, &dev_local_cpus);

	/* check if my cpu set is in dev cpu */
	CPU_OR(&result_set, &my_cpus, &dev_local_cpus);
	stall_enable = CPU_EQUAL(&result_set, &dev_local_cpus) ? 0 : 1;

out:
	return stall_enable;
}

static void mlx5_read_env(struct ibv_device *ibdev, struct mlx5_context *ctx)
{
	char *env_value;

	env_value = getenv("MLX5_STALL_CQ_POLL");
	if (env_value)
		/* check if cq stall is enforced by user */
		ctx->stall_enable = (strcmp(env_value, "0")) ? 1 : 0;
	else
		/* autodetect if we need to do cq polling */
		ctx->stall_enable = mlx5_enable_sandy_bridge_fix(ibdev);

	env_value = getenv("MLX5_STALL_NUM_LOOP");
	if (env_value)
		mlx5_stall_num_loop = atoi(env_value);

	env_value = getenv("MLX5_STALL_CQ_POLL_MIN");
	if (env_value)
		mlx5_stall_cq_poll_min = atoi(env_value);

	env_value = getenv("MLX5_STALL_CQ_POLL_MAX");
	if (env_value)
		mlx5_stall_cq_poll_max = atoi(env_value);

	env_value = getenv("MLX5_STALL_CQ_INC_STEP");
	if (env_value)
		mlx5_stall_cq_inc_step = atoi(env_value);

	env_value = getenv("MLX5_STALL_CQ_DEC_STEP");
	if (env_value)
		mlx5_stall_cq_dec_step = atoi(env_value);

	ctx->stall_adaptive_enable = 0;
	ctx->stall_cycles = 0;

	if (mlx5_stall_num_loop < 0) {
		ctx->stall_adaptive_enable = 1;
		ctx->stall_cycles = mlx5_stall_cq_poll_min;
	}

}

static int get_total_uuars(int page_size)
{
	int size = MLX5_DEF_TOT_UUARS;
	int uuars_in_page;
	char *env;

	env = getenv("MLX5_TOTAL_UUARS");
	if (env)
		size = atoi(env);

	if (size < 1)
		return -EINVAL;

	uuars_in_page = page_size / MLX5_ADAPTER_PAGE_SIZE * MLX5_NUM_NON_FP_BFREGS_PER_UAR;
	size = max(uuars_in_page, size);
	size = align(size, MLX5_NUM_NON_FP_BFREGS_PER_UAR);
	if (size > MLX5_MAX_BFREGS)
		return -ENOMEM;

	return size;
}

static void open_debug_file(struct mlx5_context *ctx)
{
	char *env;

	env = getenv("MLX5_DEBUG_FILE");
	if (!env) {
		ctx->dbg_fp = stderr;
		return;
	}

	ctx->dbg_fp = fopen(env, "aw+");
	if (!ctx->dbg_fp) {
		fprintf(stderr, "Failed opening debug file %s, using stderr\n", env);
		ctx->dbg_fp = stderr;
		return;
	}
}

static void close_debug_file(struct mlx5_context *ctx)
{
	if (ctx->dbg_fp && ctx->dbg_fp != stderr)
		fclose(ctx->dbg_fp);
}

static void set_debug_mask(void)
{
	char *env;

	env = getenv("MLX5_DEBUG_MASK");
	if (env)
		mlx5_debug_mask = strtol(env, NULL, 0);
}

static void set_freeze_on_error(void)
{
	char *env;

	env = getenv("MLX5_FREEZE_ON_ERROR_CQE");
	if (env)
		mlx5_freeze_on_error_cqe = strtol(env, NULL, 0);
}

static int get_always_bf(void)
{
	char *env;

	env = getenv("MLX5_POST_SEND_PREFER_BF");
	if (!env)
		return 1;

	return strcmp(env, "0") ? 1 : 0;
}

static int get_shut_up_bf(void)
{
	char *env;

	env = getenv("MLX5_SHUT_UP_BF");
	if (!env)
		return 0;

	return strcmp(env, "0") ? 1 : 0;
}

static int get_num_low_lat_uuars(int tot_uuars)
{
	char *env;
	int num = 4;

	env = getenv("MLX5_NUM_LOW_LAT_UUARS");
	if (env)
		num = atoi(env);

	if (num < 0)
		return -EINVAL;

	num = max(num, tot_uuars - MLX5_MED_BFREGS_TSHOLD);
	return num;
}

/* The library allocates an array of uuar contexts. The one in index zero does
 * not to execersize odd/even policy so it can avoid a lock but it may not use
 * blue flame. The upper ones, low_lat_uuars can use blue flame with no lock
 * since they are assigned to one QP only. The rest can use blue flame but since
 * they are shared they need a lock
 */
static int need_uuar_lock(struct mlx5_context *ctx, int uuarn)
{
	int i;

	if (uuarn == 0 || mlx5_single_threaded)
		return 0;

	i = (uuarn / 2) + (uuarn % 2);
	if (i >= ctx->tot_uuars - ctx->low_lat_uuars)
		return 0;

	return 1;
}

static int single_threaded_app(void)
{

	char *env;

	env = getenv("MLX5_SINGLE_THREADED");
	if (env)
		return strcmp(env, "1") ? 0 : 1;

	return 0;
}

static int mlx5_cmd_get_context(struct mlx5_context *context,
				struct mlx5_alloc_ucontext *req,
				size_t req_len,
				struct mlx5_alloc_ucontext_resp *resp,
				size_t resp_len)
{
	struct verbs_context *verbs_ctx = &context->ibv_ctx;

	if (!ibv_cmd_get_context(verbs_ctx, &req->ibv_cmd,
				 req_len, &resp->ibv_resp, resp_len))
		return 0;

	/* The ibv_cmd_get_context fails in older kernels when passing
	 * a request length that the kernel doesn't know.
	 * To avoid breaking compatibility of new libmlx5 and older
	 * kernels, when ibv_cmd_get_context fails with the full
	 * request length, we try once again with the legacy length.
	 * We repeat this process while reducing requested size based
	 * on the feature input size. To avoid this in the future, we
	 * will remove the check in kernel that requires fields unknown
	 * to the kernel to be cleared. This will require that any new
	 * feature that involves extending struct mlx5_alloc_ucontext
	 * will be accompanied by an indication in the form of one or
	 * more fields in struct mlx5_alloc_ucontext_resp. If the
	 * response value can be interpreted as feature not supported
	 * when the returned value is zero, this will suffice to
	 * indicate to the library that the request was ignored by the
	 * kernel, either because it is unaware or because it decided
	 * to do so. If zero is a valid response, we will add a new
	 * field that indicates whether the request was handled.
	 */
	if (!ibv_cmd_get_context(verbs_ctx, &req->ibv_cmd,
				 offsetof(struct mlx5_alloc_ucontext, lib_caps),
				 &resp->ibv_resp, resp_len))
		return 0;

	return ibv_cmd_get_context(verbs_ctx, &req->ibv_cmd,
				   offsetof(struct mlx5_alloc_ucontext,
					    max_cqe_version),
				   &resp->ibv_resp, resp_len);
}

static int mlx5_map_internal_clock(struct mlx5_device *mdev,
				   struct ibv_context *ibv_ctx)
{
	struct mlx5_context *context = to_mctx(ibv_ctx);
	void *hca_clock_page;
	off_t offset = 0;

	set_command(MLX5_IB_MMAP_CORE_CLOCK, &offset);
	hca_clock_page = mmap(NULL, mdev->page_size,
			      PROT_READ, MAP_SHARED, ibv_ctx->cmd_fd,
			      mdev->page_size * offset);

	if (hca_clock_page == MAP_FAILED) {
		fprintf(stderr, PFX
			"Warning: Timestamp available,\n"
			"but failed to mmap() hca core clock page.\n");
		return -1;
	}

	context->hca_core_clock = hca_clock_page +
		(context->core_clock.offset & (mdev->page_size - 1));
	return 0;
}

static void mlx5_map_clock_info(struct mlx5_device *mdev,
				struct ibv_context *ibv_ctx)
{
	struct mlx5_context *context = to_mctx(ibv_ctx);
	void *clock_info_page;
	off_t offset = 0;

	set_command(MLX5_IB_MMAP_CLOCK_INFO, &offset);
	set_index(MLX5_IB_CLOCK_INFO_V1, &offset);
	clock_info_page = mmap(NULL, mdev->page_size,
			       PROT_READ, MAP_SHARED, ibv_ctx->cmd_fd,
			       offset * mdev->page_size);

	if (clock_info_page != MAP_FAILED)
		context->clock_info_page = clock_info_page;
}

int mlx5dv_query_device(struct ibv_context *ctx_in,
			 struct mlx5dv_context *attrs_out)
{
	struct mlx5_context *mctx = to_mctx(ctx_in);
	uint64_t comp_mask_out = 0;

	if (!is_mlx5_dev(ctx_in->device))
		return EOPNOTSUPP;

	attrs_out->version   = 0;
	attrs_out->flags     = 0;

	if (mctx->cqe_version == MLX5_CQE_VERSION_V1)
		attrs_out->flags |= MLX5DV_CONTEXT_FLAGS_CQE_V1;

	if (mctx->vendor_cap_flags & MLX5_VENDOR_CAP_FLAGS_MPW_ALLOWED)
		attrs_out->flags |= MLX5DV_CONTEXT_FLAGS_MPW_ALLOWED;

	if (mctx->vendor_cap_flags & MLX5_VENDOR_CAP_FLAGS_CQE_128B_COMP)
		attrs_out->flags |= MLX5DV_CONTEXT_FLAGS_CQE_128B_COMP;

	if (mctx->vendor_cap_flags & MLX5_VENDOR_CAP_FLAGS_CQE_128B_PAD)
		attrs_out->flags |= MLX5DV_CONTEXT_FLAGS_CQE_128B_PAD;

	if (attrs_out->comp_mask & MLX5DV_CONTEXT_MASK_CQE_COMPRESION) {
		attrs_out->cqe_comp_caps = mctx->cqe_comp_caps;
		comp_mask_out |= MLX5DV_CONTEXT_MASK_CQE_COMPRESION;
	}

	if (mctx->vendor_cap_flags & MLX5_VENDOR_CAP_FLAGS_ENHANCED_MPW)
		attrs_out->flags |= MLX5DV_CONTEXT_FLAGS_ENHANCED_MPW;

	if (mctx->vendor_cap_flags &
		MLX5_VENDOR_CAP_FLAGS_PACKET_BASED_CREDIT_MODE)
		attrs_out->flags |= MLX5DV_CONTEXT_FLAGS_PACKET_BASED_CREDIT_MODE;

	if (attrs_out->comp_mask & MLX5DV_CONTEXT_MASK_SWP) {
		attrs_out->sw_parsing_caps = mctx->sw_parsing_caps;
		comp_mask_out |= MLX5DV_CONTEXT_MASK_SWP;
	}

	if (attrs_out->comp_mask & MLX5DV_CONTEXT_MASK_STRIDING_RQ) {
		attrs_out->striding_rq_caps = mctx->striding_rq_caps;
		comp_mask_out |= MLX5DV_CONTEXT_MASK_STRIDING_RQ;
	}

	if (attrs_out->comp_mask & MLX5DV_CONTEXT_MASK_TUNNEL_OFFLOADS) {
		attrs_out->tunnel_offloads_caps = mctx->tunnel_offloads_caps;
		comp_mask_out |= MLX5DV_CONTEXT_MASK_TUNNEL_OFFLOADS;
	}

	if (attrs_out->comp_mask & MLX5DV_CONTEXT_MASK_DYN_BFREGS) {
		attrs_out->max_dynamic_bfregs = mctx->num_dyn_bfregs;
		comp_mask_out |= MLX5DV_CONTEXT_MASK_DYN_BFREGS;
	}

	if (attrs_out->comp_mask & MLX5DV_CONTEXT_MASK_CLOCK_INFO_UPDATE) {
		if (mctx->clock_info_page) {
			attrs_out->max_clock_info_update_nsec =
					mctx->clock_info_page->overflow_period;
			comp_mask_out |= MLX5DV_CONTEXT_MASK_CLOCK_INFO_UPDATE;
		}
	}

	if (attrs_out->comp_mask & MLX5DV_CONTEXT_MASK_FLOW_ACTION_FLAGS) {
		attrs_out->flow_action_flags = mctx->flow_action_flags;
		comp_mask_out |= MLX5DV_CONTEXT_MASK_FLOW_ACTION_FLAGS;
	}

	attrs_out->comp_mask = comp_mask_out;

	return 0;
}

static int mlx5dv_get_qp(struct ibv_qp *qp_in,
			 struct mlx5dv_qp *qp_out)
{
	struct mlx5_qp *mqp = to_mqp(qp_in);
	uint64_t mask_out = 0;

	if (!is_mlx5_dev(qp_in->context->device))
		return EOPNOTSUPP;

	qp_out->dbrec     = mqp->db;

	if (mqp->sq_buf_size)
		/* IBV_QPT_RAW_PACKET */
		qp_out->sq.buf = (void *)((uintptr_t)mqp->sq_buf.buf);
	else
		qp_out->sq.buf = (void *)((uintptr_t)mqp->buf.buf + mqp->sq.offset);
	qp_out->sq.wqe_cnt = mqp->sq.wqe_cnt;
	qp_out->sq.stride  = 1 << mqp->sq.wqe_shift;

	qp_out->rq.buf     = (void *)((uintptr_t)mqp->buf.buf + mqp->rq.offset);
	qp_out->rq.wqe_cnt = mqp->rq.wqe_cnt;
	qp_out->rq.stride  = 1 << mqp->rq.wqe_shift;

	qp_out->bf.reg	   = mqp->bf->reg;

	if (qp_out->comp_mask & MLX5DV_QP_MASK_UAR_MMAP_OFFSET) {
		qp_out->uar_mmap_offset = mqp->bf->uar_mmap_offset;
		mask_out |= MLX5DV_QP_MASK_UAR_MMAP_OFFSET;
	}

	if (qp_out->comp_mask & MLX5DV_QP_MASK_RAW_QP_HANDLES) {
		qp_out->tirn = mqp->tirn;
		qp_out->tisn = mqp->tisn;
		qp_out->rqn = mqp->rqn;
		qp_out->sqn = mqp->sqn;
		mask_out |= MLX5DV_QP_MASK_RAW_QP_HANDLES;
	}

	if (mqp->bf->uuarn > 0)
		qp_out->bf.size = mqp->bf->buf_size;
	else
		qp_out->bf.size = 0;

	qp_out->comp_mask = mask_out;

	return 0;
}

static int mlx5dv_get_cq(struct ibv_cq *cq_in,
			 struct mlx5dv_cq *cq_out)
{
	struct mlx5_cq *mcq = to_mcq(cq_in);
	struct mlx5_context *mctx = to_mctx(cq_in->context);

	if (!is_mlx5_dev(cq_in->context->device))
		return EOPNOTSUPP;

	cq_out->comp_mask = 0;
	cq_out->cqn       = mcq->cqn;
	cq_out->cqe_cnt   = mcq->ibv_cq.cqe + 1;
	cq_out->cqe_size  = mcq->cqe_sz;
	cq_out->buf       = mcq->active_buf->buf;
	cq_out->dbrec     = mcq->dbrec;
	cq_out->cq_uar	  = mctx->uar[0].reg;

	mcq->flags	 |= MLX5_CQ_FLAGS_DV_OWNED;

	return 0;
}

static int mlx5dv_get_rwq(struct ibv_wq *wq_in,
			  struct mlx5dv_rwq *rwq_out)
{
	struct mlx5_rwq *mrwq = to_mrwq(wq_in);

	if (!is_mlx5_dev(wq_in->context->device))
		return EOPNOTSUPP;

	rwq_out->comp_mask = 0;
	rwq_out->buf       = mrwq->pbuff;
	rwq_out->dbrec     = mrwq->recv_db;
	rwq_out->wqe_cnt   = mrwq->rq.wqe_cnt;
	rwq_out->stride    = 1 << mrwq->rq.wqe_shift;

	return 0;
}

static int mlx5dv_get_srq(struct ibv_srq *srq_in,
			  struct mlx5dv_srq *srq_out)
{
	struct mlx5_srq *msrq;
	uint64_t mask_out = 0;

	if (!is_mlx5_dev(srq_in->context->device))
		return EOPNOTSUPP;

	msrq = container_of(srq_in, struct mlx5_srq, vsrq.srq);

	srq_out->buf       = msrq->buf.buf;
	srq_out->dbrec     = msrq->db;
	srq_out->stride    = 1 << msrq->wqe_shift;
	srq_out->head      = msrq->head;
	srq_out->tail      = msrq->tail;

	if (srq_out->comp_mask & MLX5DV_SRQ_MASK_SRQN) {
		srq_out->srqn = msrq->srqn;
		mask_out |= MLX5DV_SRQ_MASK_SRQN;
	}

	srq_out->comp_mask = mask_out;
	return 0;
}

static int mlx5dv_get_dm(struct ibv_dm *dm_in,
			  struct mlx5dv_dm *dm_out)
{
	struct mlx5_dm *mdm = to_mdm(dm_in);

	if (!is_mlx5_dev(dm_in->context->device))
		return EOPNOTSUPP;

	dm_out->comp_mask = 0;
	dm_out->buf       = mdm->start_va;
	dm_out->length    = mdm->length;

	return 0;
}

static int mlx5dv_get_av(struct ibv_ah *ah_in,
			 struct mlx5dv_ah *ah_out)
{
	struct mlx5_ah *mah = to_mah(ah_in);

	if (!is_mlx5_dev(ah_in->context->device))
		return EOPNOTSUPP;

	ah_out->comp_mask = 0;
	ah_out->av	  = &mah->av;

	return 0;
}

static int mlx5dv_get_pd(struct ibv_pd *pd_in,
			 struct mlx5dv_pd *pd_out)
{
	struct mlx5_pd *mpd = to_mpd(pd_in);

	if (!is_mlx5_dev(pd_in->context->device))
		return EOPNOTSUPP;

	pd_out->comp_mask = 0;
	pd_out->pdn = mpd->pdn;

	return 0;
}

LATEST_SYMVER_FUNC(mlx5dv_init_obj, 1_2, "MLX5_1.2",
		   int,
		   struct mlx5dv_obj *obj, uint64_t obj_type)
{
	int ret = 0;

	if (obj_type & MLX5DV_OBJ_QP)
		ret = mlx5dv_get_qp(obj->qp.in, obj->qp.out);
	if (!ret && (obj_type & MLX5DV_OBJ_CQ))
		ret = mlx5dv_get_cq(obj->cq.in, obj->cq.out);
	if (!ret && (obj_type & MLX5DV_OBJ_SRQ))
		ret = mlx5dv_get_srq(obj->srq.in, obj->srq.out);
	if (!ret && (obj_type & MLX5DV_OBJ_RWQ))
		ret = mlx5dv_get_rwq(obj->rwq.in, obj->rwq.out);
	if (!ret && (obj_type & MLX5DV_OBJ_DM))
		ret = mlx5dv_get_dm(obj->dm.in, obj->dm.out);
	if (!ret && (obj_type & MLX5DV_OBJ_AH))
		ret = mlx5dv_get_av(obj->ah.in, obj->ah.out);
	if (!ret && (obj_type & MLX5DV_OBJ_PD))
		ret = mlx5dv_get_pd(obj->pd.in, obj->pd.out);

	return ret;
}

COMPAT_SYMVER_FUNC(mlx5dv_init_obj, 1_0, "MLX5_1.0",
		   int,
		   struct mlx5dv_obj *obj, uint64_t obj_type)
{
	int ret = 0;

	ret = __mlx5dv_init_obj_1_2(obj, obj_type);
	if (!ret && (obj_type & MLX5DV_OBJ_CQ)) {
		/* ABI version 1.0 returns the void ** in this memory
		 * location
		 */
		obj->cq.out->cq_uar = to_mctx(obj->cq.in->context)->uar;
	}
	return ret;
}

static off_t get_uar_mmap_offset(int idx, int page_size, int command)
{
	off_t offset = 0;

	set_command(command, &offset);

	if (command == MLX5_IB_MMAP_ALLOC_WC &&
	    idx >= (1 << MLX5_IB_MMAP_CMD_SHIFT))
		set_extended_index(idx, &offset);
	else
		set_index(idx, &offset);

	return offset * page_size;
}

static off_t uar_type_to_cmd(int uar_type)
{
	return (uar_type == MLX5_UAR_TYPE_NC) ? MLX5_MMAP_GET_NC_PAGES_CMD :
		MLX5_MMAP_GET_REGULAR_PAGES_CMD;
}

void *mlx5_mmap(struct mlx5_uar_info *uar, int index, int cmd_fd, int page_size,
		int uar_type)
{
	off_t offset;

	if (uar_type == MLX5_UAR_TYPE_NC) {
		offset = get_uar_mmap_offset(index, page_size,
					     MLX5_MMAP_GET_NC_PAGES_CMD);
		uar->reg = mmap(NULL, page_size, PROT_WRITE, MAP_SHARED,
				       cmd_fd, offset);
		if (uar->reg != MAP_FAILED) {
			uar->type = MLX5_UAR_TYPE_NC;
			goto out;
		}
	}

	/* Backward compatibility for legacy kernels that don't support
	 * MLX5_MMAP_GET_NC_PAGES_CMD mmap command.
	 */
	offset = get_uar_mmap_offset(index, page_size,
				     (uar_type == MLX5_UAR_TYPE_REGULAR_DYN) ?
				     MLX5_IB_MMAP_ALLOC_WC :
				     MLX5_MMAP_GET_REGULAR_PAGES_CMD);
	uar->reg = mmap(NULL, page_size, PROT_WRITE, MAP_SHARED,
			cmd_fd, offset);
	if (uar->reg != MAP_FAILED)
		uar->type = MLX5_UAR_TYPE_REGULAR;

out:
	return uar->reg;
}

int mlx5dv_set_context_attr(struct ibv_context *ibv_ctx,
			enum mlx5dv_set_ctx_attr_type type, void *attr)
{
	struct mlx5_context *ctx = to_mctx(ibv_ctx);

	if (!is_mlx5_dev(ibv_ctx->device))
		return EOPNOTSUPP;

	switch (type) {
	case MLX5DV_CTX_ATTR_BUF_ALLOCATORS:
		ctx->extern_alloc = *((struct mlx5dv_ctx_allocators *)attr);
		break;
	default:
		return ENOTSUP;
	}

	return 0;
}

int mlx5dv_get_clock_info(struct ibv_context *ctx_in,
			  struct mlx5dv_clock_info *clock_info)
{
	struct mlx5_context *ctx = to_mctx(ctx_in);
	const struct mlx5_ib_clock_info *ci = ctx->clock_info_page;
	uint32_t retry, tmp_sig;
	atomic_uint32_t *sig;

	if (!ci)
		return EINVAL;

	sig = (atomic_uint32_t *)&ci->sign;

	do {
		retry = 10;
repeat:
		tmp_sig = atomic_load(sig);
		if (unlikely(tmp_sig &
			     MLX5_IB_CLOCK_INFO_KERNEL_UPDATING)) {
			if (--retry)
				goto repeat;
			return EBUSY;
		}
		clock_info->nsec   = ci->nsec;
		clock_info->last_cycles = ci->cycles;
		clock_info->frac   = ci->frac;
		clock_info->mult   = ci->mult;
		clock_info->shift  = ci->shift;
		clock_info->mask   = ci->mask;
	} while (unlikely(tmp_sig != atomic_load(sig)));

	return 0;
}

static void adjust_uar_info(struct mlx5_device *mdev,
			    struct mlx5_context *context,
			    struct mlx5_alloc_ucontext_resp resp)
{
	if (!resp.log_uar_size && !resp.num_uars_per_page) {
		/* old kernel */
		context->uar_size = mdev->page_size;
		context->num_uars_per_page = 1;
		return;
	}

	context->uar_size = 1 << resp.log_uar_size;
	context->num_uars_per_page = resp.num_uars_per_page;
}

bool mlx5dv_is_supported(struct ibv_device *device)
{
	return is_mlx5_dev(device);
}

struct ibv_context *
mlx5dv_open_device(struct ibv_device *device, struct mlx5dv_context_attr *attr)
{
	if (!is_mlx5_dev(device)) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	return verbs_open_device(device, attr);
}

static struct verbs_context *mlx5_alloc_context(struct ibv_device *ibdev,
						int cmd_fd,
						void *private_data)
{
	struct mlx5_context	       *context;
	struct mlx5_alloc_ucontext	req;
	struct mlx5_alloc_ucontext_resp resp;
	int				i;
	int				page_size;
	int				tot_uuars;
	int				low_lat_uuars;
	int				gross_uuars;
	int				j;
	struct mlx5_device	       *mdev = to_mdev(ibdev);
	struct verbs_context	       *v_ctx;
	struct ibv_port_attr		port_attr;
	struct ibv_device_attr_ex	device_attr;
	int				k;
	int				bfi;
	int				num_sys_page_map;
	struct mlx5dv_context_attr      *ctx_attr = private_data;

	if (ctx_attr && ctx_attr->comp_mask) {
		errno = EINVAL;
		return NULL;
	}

	context = verbs_init_and_alloc_context(ibdev, cmd_fd, context, ibv_ctx,
					       RDMA_DRIVER_MLX5);
	if (!context)
		return NULL;

	v_ctx = &context->ibv_ctx;
	page_size = mdev->page_size;
	mlx5_single_threaded = single_threaded_app();

	open_debug_file(context);
	set_debug_mask();
	set_freeze_on_error();
	if (gethostname(context->hostname, sizeof(context->hostname)))
		strcpy(context->hostname, "host_unknown");

	tot_uuars = get_total_uuars(page_size);
	if (tot_uuars < 0) {
		errno = -tot_uuars;
		goto err_free;
	}

	low_lat_uuars = get_num_low_lat_uuars(tot_uuars);
	if (low_lat_uuars < 0) {
		errno = -low_lat_uuars;
		goto err_free;
	}

	if (low_lat_uuars > tot_uuars - 1) {
		errno = ENOMEM;
		goto err_free;
	}

	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));

	req.total_num_bfregs = tot_uuars;
	req.num_low_latency_bfregs = low_lat_uuars;
	req.max_cqe_version = MLX5_CQE_VERSION_V1;
	req.lib_caps |= MLX5_LIB_CAP_4K_UAR;
	if (ctx_attr && ctx_attr->flags) {

		if (!check_comp_mask(ctx_attr->flags,
				     MLX5DV_CONTEXT_FLAGS_DEVX)) {
			errno = EINVAL;
			goto err_free;
		}

		req.flags = MLX5_IB_ALLOC_UCTX_DEVX;
	}

	if (mlx5_cmd_get_context(context, &req, sizeof(req), &resp,
				 sizeof(resp)))
		goto err_free;

	context->max_num_qps		= resp.qp_tab_size;
	context->bf_reg_size		= resp.bf_reg_size;
	context->tot_uuars		= resp.tot_bfregs;
	context->low_lat_uuars		= low_lat_uuars;
	context->cache_line_size	= resp.cache_line_size;
	context->max_sq_desc_sz = resp.max_sq_desc_sz;
	context->max_rq_desc_sz = resp.max_rq_desc_sz;
	context->max_send_wqebb	= resp.max_send_wqebb;
	context->num_ports	= resp.num_ports;
	context->max_recv_wr	= resp.max_recv_wr;
	context->max_srq_recv_wr = resp.max_srq_recv_wr;
	context->num_dyn_bfregs = resp.num_dyn_bfregs;

	if (resp.comp_mask & MLX5_IB_ALLOC_UCONTEXT_RESP_MASK_DUMP_FILL_MKEY) {
		context->dump_fill_mkey = resp.dump_fill_mkey;
		/* Have the BE value ready to be used in data path */
		context->dump_fill_mkey_be = htobe32(resp.dump_fill_mkey);
	} else {
		/* kernel driver will never return MLX5_INVALID_LKEY for
		 * dump_fill_mkey
		 */
		context->dump_fill_mkey = MLX5_INVALID_LKEY;
		context->dump_fill_mkey_be = htobe32(MLX5_INVALID_LKEY);
	}

	if (context->num_dyn_bfregs) {
		context->count_dyn_bfregs = calloc(context->num_dyn_bfregs,
						   sizeof(*context->count_dyn_bfregs));
		if (!context->count_dyn_bfregs) {
			errno = ENOMEM;
			goto err_free;
		}
	}

	context->cqe_version = resp.cqe_version;

	adjust_uar_info(mdev, context, resp);

	gross_uuars = context->tot_uuars / MLX5_NUM_NON_FP_BFREGS_PER_UAR * NUM_BFREGS_PER_UAR;
	context->bfs = calloc(gross_uuars + context->num_dyn_bfregs, sizeof(*context->bfs));

	if (!context->bfs) {
		errno = ENOMEM;
		goto err_free;
	}

	context->cmds_supp_uhw = resp.cmds_supp_uhw;
	context->vendor_cap_flags = 0;
	context->start_dyn_bfregs_index = gross_uuars;

	if (resp.eth_min_inline)
		context->eth_min_inline_size = (resp.eth_min_inline == MLX5_USER_INLINE_MODE_NONE) ?
						0 : MLX5_ETH_L2_INLINE_HEADER_SIZE;
	else
		context->eth_min_inline_size = MLX5_ETH_L2_INLINE_HEADER_SIZE;

	pthread_mutex_init(&context->qp_table_mutex, NULL);
	pthread_mutex_init(&context->srq_table_mutex, NULL);
	pthread_mutex_init(&context->uidx_table_mutex, NULL);
	pthread_mutex_init(&context->dyn_bfregs_mutex, NULL);
	for (i = 0; i < MLX5_QP_TABLE_SIZE; ++i)
		context->qp_table[i].refcnt = 0;

	for (i = 0; i < MLX5_QP_TABLE_SIZE; ++i)
		context->uidx_table[i].refcnt = 0;

	context->db_list = NULL;

	pthread_mutex_init(&context->db_list_mutex, NULL);

	context->prefer_bf = get_always_bf();
	context->shut_up_bf = get_shut_up_bf();

	num_sys_page_map = context->tot_uuars / (context->num_uars_per_page * MLX5_NUM_NON_FP_BFREGS_PER_UAR);
	for (i = 0; i < num_sys_page_map; ++i) {
		if (mlx5_mmap(&context->uar[i], i, cmd_fd, page_size,
			      context->shut_up_bf ? MLX5_UAR_TYPE_NC :
			      MLX5_UAR_TYPE_REGULAR) == MAP_FAILED) {
			context->uar[i].reg = NULL;
			goto err_free_bf;
		}
	}

	for (i = 0; i < num_sys_page_map; i++) {
		for (j = 0; j < context->num_uars_per_page; j++) {
			for (k = 0; k < NUM_BFREGS_PER_UAR; k++) {
				bfi = (i * context->num_uars_per_page + j) * NUM_BFREGS_PER_UAR + k;
				context->bfs[bfi].reg = context->uar[i].reg + MLX5_ADAPTER_PAGE_SIZE * j +
							MLX5_BF_OFFSET + k * context->bf_reg_size;
				context->bfs[bfi].need_lock = need_uuar_lock(context, bfi);
				mlx5_spinlock_init(&context->bfs[bfi].lock, context->bfs[bfi].need_lock);
				context->bfs[bfi].offset = 0;
				if (bfi)
					context->bfs[bfi].buf_size = context->bf_reg_size / 2;
				context->bfs[bfi].uuarn = bfi;
				context->bfs[bfi].uar_mmap_offset = get_uar_mmap_offset(i,
											page_size,
											uar_type_to_cmd(context->uar[i].type));
			}
		}
	}
	context->hca_core_clock = NULL;
	if (resp.response_length + sizeof(resp.ibv_resp) >=
	    offsetof(struct mlx5_alloc_ucontext_resp, hca_core_clock_offset) +
	    sizeof(resp.hca_core_clock_offset) &&
	    resp.comp_mask & MLX5_IB_ALLOC_UCONTEXT_RESP_MASK_CORE_CLOCK_OFFSET) {
		context->core_clock.offset = resp.hca_core_clock_offset;
		mlx5_map_internal_clock(mdev, &v_ctx->context);
	}

	context->clock_info_page = NULL;
	if (resp.response_length + sizeof(resp.ibv_resp) >=
	    offsetof(struct mlx5_alloc_ucontext_resp, clock_info_versions) +
	    sizeof(resp.clock_info_versions) &&
	    (resp.clock_info_versions & (1 << MLX5_IB_CLOCK_INFO_V1))) {
		mlx5_map_clock_info(mdev, &v_ctx->context);
	}

	context->flow_action_flags = resp.flow_action_flags;

	mlx5_read_env(ibdev, context);

	mlx5_spinlock_init(&context->hugetlb_lock, !mlx5_single_threaded);
	list_head_init(&context->hugetlb_list);

	verbs_set_ops(v_ctx, &mlx5_ctx_common_ops);
	if (context->cqe_version) {
		if (context->cqe_version == MLX5_CQE_VERSION_V1)
			verbs_set_ops(v_ctx, &mlx5_ctx_cqev1_ops);
		else
			goto err_free;
	}

	memset(&device_attr, 0, sizeof(device_attr));
	if (!mlx5_query_device_ex(&v_ctx->context, NULL, &device_attr,
				  sizeof(struct ibv_device_attr_ex))) {
		context->cached_device_cap_flags =
			device_attr.orig_attr.device_cap_flags;
		context->atomic_cap = device_attr.orig_attr.atomic_cap;
		context->cached_tso_caps = device_attr.tso_caps;
		context->max_dm_size = device_attr.max_dm_size;
	}

	for (j = 0; j < min(MLX5_MAX_PORTS_NUM, context->num_ports); ++j) {
		memset(&port_attr, 0, sizeof(port_attr));
		if (!mlx5_query_port(&v_ctx->context, j + 1, &port_attr)) {
			context->cached_link_layer[j] = port_attr.link_layer;
			context->cached_port_flags[j] = port_attr.flags;
		}
	}

	return v_ctx;

err_free_bf:
	free(context->bfs);

err_free:
	free(context->count_dyn_bfregs);
	for (i = 0; i < MLX5_MAX_UARS; ++i) {
		if (context->uar[i].reg)
			munmap(context->uar[i].reg, page_size);
	}
	close_debug_file(context);

	verbs_uninit_context(&context->ibv_ctx);
	free(context);
	return NULL;
}

static void mlx5_free_context(struct ibv_context *ibctx)
{
	struct mlx5_context *context = to_mctx(ibctx);
	int page_size = to_mdev(ibctx->device)->page_size;
	int i;

	for (i = context->start_dyn_bfregs_index;
	      i < context->start_dyn_bfregs_index + context->num_dyn_bfregs; i++) {
		if (context->bfs[i].uar)
			munmap(context->bfs[i].uar, page_size);
	}

	free(context->count_dyn_bfregs);
	free(context->bfs);
	for (i = 0; i < MLX5_MAX_UARS; ++i) {
		if (context->uar[i].reg)
			munmap(context->uar[i].reg, page_size);
	}
	if (context->hca_core_clock)
		munmap(context->hca_core_clock - context->core_clock.offset,
		       page_size);
	if (context->clock_info_page)
		munmap((void *)context->clock_info_page, page_size);
	close_debug_file(context);

	verbs_uninit_context(&context->ibv_ctx);
	free(context);
}

static void mlx5_uninit_device(struct verbs_device *verbs_device)
{
	struct mlx5_device *dev = to_mdev(&verbs_device->device);

	free(dev);
}

static struct verbs_device *mlx5_device_alloc(struct verbs_sysfs_dev *sysfs_dev)
{
	struct mlx5_device *dev;

	dev = calloc(1, sizeof *dev);
	if (!dev)
		return NULL;

	dev->page_size   = sysconf(_SC_PAGESIZE);
	dev->driver_abi_ver = sysfs_dev->abi_ver;

	return &dev->verbs_dev;
}

static const struct verbs_device_ops mlx5_dev_ops = {
	.name = "mlx5",
	.match_min_abi_version = MLX5_UVERBS_MIN_ABI_VERSION,
	.match_max_abi_version = MLX5_UVERBS_MAX_ABI_VERSION,
	.match_table = hca_table,
	.alloc_device = mlx5_device_alloc,
	.uninit_device = mlx5_uninit_device,
	.alloc_context = mlx5_alloc_context,
	.free_context = mlx5_free_context,
};

bool is_mlx5_dev(struct ibv_device *device)
{
	struct verbs_device *verbs_device = verbs_get_device(device);

	return verbs_device->ops == &mlx5_dev_ops;
}
PROVIDER_DRIVER(mlx5, mlx5_dev_ops);
