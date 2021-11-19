/*
 * Copyright (c) 2012 Mellanox Technologies, Inc.  All rights reserved.
 * Copyright (c) 2020 Intel Corporation.  All rights reserved.
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
#include <rdma/mlx5_user_ioctl_cmds.h>

#include "mlx5.h"
#include "mlx5-abi.h"
#include "wqe.h"
#include "mlx5_ifc.h"
#include "mlx5_vfio.h"

static void mlx5_free_context(struct ibv_context *ibctx);
static bool is_mlx5_dev(struct ibv_device *device);

#ifndef CPU_OR
#define CPU_OR(x, y, z) do {} while (0)
#endif

#ifndef CPU_EQUAL
#define CPU_EQUAL(x, y) 1
#endif

#define HCA(v, d) VERBS_PCI_MATCH(PCI_VENDOR_ID_##v, d, NULL)
const struct verbs_match_ent mlx5_hca_table[] = {
	VERBS_DRIVER_ID(RDMA_DRIVER_MLX5),
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
	HCA(MELLANOX, 0x101f),	/* ConnectX-6 LX */
	HCA(MELLANOX, 0x1021),  /* ConnectX-7 */
	HCA(MELLANOX, 0xa2d2),	/* BlueField integrated ConnectX-5 network controller */
	HCA(MELLANOX, 0xa2d3),	/* BlueField integrated ConnectX-5 network controller VF */
	HCA(MELLANOX, 0xa2d6),  /* BlueField-2 integrated ConnectX-6 Dx network controller */
	HCA(MELLANOX, 0xa2dc),  /* BlueField-3 integrated ConnectX-7 network controller */
	{}
};

uint32_t mlx5_debug_mask = 0;
int mlx5_freeze_on_error_cqe;

static const struct verbs_context_ops mlx5_ctx_common_ops = {
	.query_port    = mlx5_query_port,
	.alloc_pd      = mlx5_alloc_pd,
	.async_event   = mlx5_async_event,
	.dealloc_pd    = mlx5_free_pd,
	.reg_mr	       = mlx5_reg_mr,
	.reg_dmabuf_mr = mlx5_reg_dmabuf_mr,
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
	.import_dm = mlx5_import_dm,
	.import_mr = mlx5_import_mr,
	.import_pd = mlx5_import_pd,
	.modify_cq = mlx5_modify_cq,
	.modify_flow_action_esp = mlx5_modify_flow_action_esp,
	.modify_qp_rate_limit = mlx5_modify_qp_rate_limit,
	.modify_wq = mlx5_modify_wq,
	.open_qp = mlx5_open_qp,
	.open_xrcd = mlx5_open_xrcd,
	.post_srq_ops = mlx5_post_srq_ops,
	.query_device_ex = mlx5_query_device_ex,
	.query_ece = mlx5_query_ece,
	.query_rt_values = mlx5_query_rt_values,
	.read_counters = mlx5_read_counters,
	.reg_dm_mr = mlx5_reg_dm_mr,
	.alloc_null_mr = mlx5_alloc_null_mr,
	.free_context = mlx5_free_context,
	.set_ece = mlx5_set_ece,
	.unimport_dm = mlx5_unimport_dm,
	.unimport_mr = mlx5_unimport_mr,
	.unimport_pd = mlx5_unimport_pd,
	.query_qp_data_in_order = mlx5_query_qp_data_in_order,
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

struct mlx5_mkey *mlx5_find_mkey(struct mlx5_context *ctx, uint32_t mkey)
{
	int tind = mkey >> MLX5_MKEY_TABLE_SHIFT;

	if (ctx->mkey_table[tind].refcnt)
		return ctx->mkey_table[tind].table[mkey & MLX5_MKEY_TABLE_MASK];
	else
		return NULL;
}

int mlx5_store_mkey(struct mlx5_context *ctx, uint32_t mkey,
		    struct mlx5_mkey *mlx5_mkey)
{
	int tind = mkey >> MLX5_MKEY_TABLE_SHIFT;
	int ret = 0;

	pthread_mutex_lock(&ctx->mkey_table_mutex);

	if (!ctx->mkey_table[tind].refcnt) {
		ctx->mkey_table[tind].table = calloc(MLX5_MKEY_TABLE_MASK + 1,
				sizeof(struct mlx5_mkey *));
		if (!ctx->mkey_table[tind].table) {
			ret = -1;
			goto out;
		}
	}

	++ctx->mkey_table[tind].refcnt;
	ctx->mkey_table[tind].table[mkey & MLX5_MKEY_TABLE_MASK] = mlx5_mkey;

out:
	pthread_mutex_unlock(&ctx->mkey_table_mutex);
	return ret;
}

void mlx5_clear_mkey(struct mlx5_context *ctx, uint32_t mkey)
{
	int tind = mkey >> MLX5_MKEY_TABLE_SHIFT;

	pthread_mutex_lock(&ctx->mkey_table_mutex);

	if (!--ctx->mkey_table[tind].refcnt)
		free(ctx->mkey_table[tind].table);
	else
		ctx->mkey_table[tind].table[mkey & MLX5_MKEY_TABLE_MASK] = NULL;

	pthread_mutex_unlock(&ctx->mkey_table_mutex);
}

struct mlx5_psv *mlx5_create_psv(struct ibv_pd *pd)
{
	uint32_t out[DEVX_ST_SZ_DW(create_psv_out)] = {};
	uint32_t in[DEVX_ST_SZ_DW(create_psv_in)] = {};
	struct mlx5_psv *psv;

	psv = calloc(1, sizeof(*psv));
	if (!psv) {
		errno = ENOMEM;
		return NULL;
	}

	DEVX_SET(create_psv_in, in, opcode, MLX5_CMD_OP_CREATE_PSV);
	DEVX_SET(create_psv_in, in, pd, to_mpd(pd)->pdn);
	DEVX_SET(create_psv_in, in, num_psv, 1);

	psv->devx_obj = mlx5dv_devx_obj_create(pd->context, in, sizeof(in),
					       out, sizeof(out));
	if (!psv->devx_obj)
		goto err_free_psv;

	psv->index = DEVX_GET(create_psv_out, out, psv0_index);

	return psv;
err_free_psv:
	free(psv);
	return NULL;
}

int mlx5_destroy_psv(struct mlx5_psv *psv)
{
	int ret;

	ret = mlx5dv_devx_obj_destroy(psv->devx_obj);
	if (!ret)
		free(psv);

	return ret;
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
static void mlx5_local_cpu_set(struct ibv_device *ibdev, struct mlx5_context *mctx,
			       cpu_set_t *cpu_set)
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
			mlx5_err(mctx->dbg_fp, PFX "Warning: can not get local cpu set: failed to open %s\n", fname);
			return;
		}
		if (!fgets(buf, sizeof(buf), fp)) {
			mlx5_err(mctx->dbg_fp, PFX "Warning: can not get local cpu set: failed to read cpu mask\n");
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

static int mlx5_enable_sandy_bridge_fix(struct ibv_device *ibdev, struct mlx5_context *mctx)
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
			mlx5_err(mctx->dbg_fp, PFX "Warning: my cpu set is too small\n");
		else
			mlx5_err(mctx->dbg_fp, PFX "Warning: failed to get my cpu set\n");
		goto out;
	}

	/* get device local cpu set */
	mlx5_local_cpu_set(ibdev, mctx, &dev_local_cpus);

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
		ctx->stall_enable = mlx5_enable_sandy_bridge_fix(ibdev, ctx);

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

void mlx5_open_debug_file(FILE **dbg_fp)
{
	char *env;
	FILE *default_dbg_fp = NULL;

#ifdef MLX5_DEBUG
	default_dbg_fp = stderr;
#endif

	env = getenv("MLX5_DEBUG_FILE");
	if (!env) {
		*dbg_fp = default_dbg_fp;
		return;
	}

	*dbg_fp = fopen(env, "aw+");
	if (!*dbg_fp) {
		*dbg_fp = default_dbg_fp;
		mlx5_err(*dbg_fp, "Failed opening debug file %s\n", env);
		return;
	}
}

void mlx5_close_debug_file(FILE *dbg_fp)
{
	if (dbg_fp && dbg_fp != stderr)
		fclose(dbg_fp);
}

void mlx5_set_debug_mask(void)
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
		mlx5_err(context->dbg_fp, PFX
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

static uint32_t get_dc_odp_caps(struct ibv_context *ctx)
{
	uint32_t in[DEVX_ST_SZ_DW(query_hca_cap_in)] = {};
	uint32_t out[DEVX_ST_SZ_DW(query_hca_cap_out)] = {};
	uint16_t opmod = (MLX5_CAP_ODP << 1) | HCA_CAP_OPMOD_GET_CUR;
	uint32_t ret;

	DEVX_SET(query_hca_cap_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_CAP);
	DEVX_SET(query_hca_cap_in, in, op_mod, opmod);

	ret = mlx5dv_devx_general_cmd(ctx, in, sizeof(in), out, sizeof(out));
	if (ret)
		return 0;

	if (DEVX_GET(query_hca_cap_out, out,
		     capability.odp_cap.dc_odp_caps.send))
		ret |= IBV_ODP_SUPPORT_SEND;
	if (DEVX_GET(query_hca_cap_out, out,
		     capability.odp_cap.dc_odp_caps.receive))
		ret |= IBV_ODP_SUPPORT_RECV;
	if (DEVX_GET(query_hca_cap_out, out,
		     capability.odp_cap.dc_odp_caps.write))
		ret |= IBV_ODP_SUPPORT_WRITE;
	if (DEVX_GET(query_hca_cap_out, out,
		     capability.odp_cap.dc_odp_caps.read))
		ret |= IBV_ODP_SUPPORT_READ;
	if (DEVX_GET(query_hca_cap_out, out,
		     capability.odp_cap.dc_odp_caps.atomic))
		ret |= IBV_ODP_SUPPORT_ATOMIC;
	if (DEVX_GET(query_hca_cap_out, out,
		     capability.odp_cap.dc_odp_caps.srq_receive))
		ret |= IBV_ODP_SUPPORT_SRQ_RECV;

	return ret;
}

static int _mlx5dv_query_device(struct ibv_context *ctx_in,
				struct mlx5dv_context *attrs_out)
{
	struct mlx5_context *mctx = to_mctx(ctx_in);
	uint64_t comp_mask_out = 0;

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

	if (mctx->flags & MLX5_CTX_FLAGS_REAL_TIME_TS_SUPPORTED)
		attrs_out->flags |= MLX5DV_CONTEXT_FLAGS_REAL_TIME_TS;

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

	if (attrs_out->comp_mask & MLX5DV_CONTEXT_MASK_DCI_STREAMS) {
		attrs_out->dci_streams_caps = mctx->dci_streams_caps;
		comp_mask_out |= MLX5DV_CONTEXT_MASK_DCI_STREAMS;
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

	if (attrs_out->comp_mask & MLX5DV_CONTEXT_MASK_DC_ODP_CAPS) {
		attrs_out->dc_odp_caps = get_dc_odp_caps(ctx_in);
		comp_mask_out |= MLX5DV_CONTEXT_MASK_DC_ODP_CAPS;
	}

	if (attrs_out->comp_mask & MLX5DV_CONTEXT_MASK_HCA_CORE_CLOCK) {
		if (mctx->hca_core_clock) {
			attrs_out->hca_core_clock = mctx->hca_core_clock;
			comp_mask_out |= MLX5DV_CONTEXT_MASK_HCA_CORE_CLOCK;
		}
	}

	if (attrs_out->comp_mask & MLX5DV_CONTEXT_MASK_NUM_LAG_PORTS) {
		if (mctx->entropy_caps.num_lag_ports) {
			attrs_out->num_lag_ports =
				mctx->entropy_caps.num_lag_ports;
			comp_mask_out |= MLX5DV_CONTEXT_MASK_NUM_LAG_PORTS;
		}
	}

	if (attrs_out->comp_mask & MLX5DV_CONTEXT_MASK_SIGNATURE_OFFLOAD) {
		attrs_out->sig_caps = mctx->sig_caps;
		comp_mask_out |= MLX5DV_CONTEXT_MASK_SIGNATURE_OFFLOAD;
	}

	if (attrs_out->comp_mask & MLX5DV_CONTEXT_MASK_WR_MEMCPY_LENGTH) {
		attrs_out->max_wr_memcpy_length =
			mctx->dma_mmo_caps.dma_max_size;
		comp_mask_out |= MLX5DV_CONTEXT_MASK_WR_MEMCPY_LENGTH;
	}

	if (attrs_out->comp_mask & MLX5DV_CONTEXT_MASK_CRYPTO_OFFLOAD) {
		attrs_out->crypto_caps = mctx->crypto_caps;
		comp_mask_out |= MLX5DV_CONTEXT_MASK_CRYPTO_OFFLOAD;
	}

	attrs_out->comp_mask = comp_mask_out;

	return 0;
}

int mlx5dv_query_device(struct ibv_context *ctx_in,
			struct mlx5dv_context *attrs_out)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(ctx_in);

	if (!dvops || !dvops->query_device)
		return EOPNOTSUPP;

	return dvops->query_device(ctx_in, attrs_out);
}

static int mlx5dv_get_qp(struct ibv_qp *qp_in,
			 struct mlx5dv_qp *qp_out)
{
	struct mlx5_qp *mqp = to_mqp(qp_in);
	uint64_t mask_out = 0;

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

	if (qp_out->comp_mask & MLX5DV_QP_MASK_RAW_QP_TIR_ADDR) {
		qp_out->tir_icm_addr = mqp->tir_icm_addr;
		mask_out |= MLX5DV_QP_MASK_RAW_QP_TIR_ADDR;
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

	cq_out->comp_mask = 0;
	cq_out->cqn       = mcq->cqn;
	cq_out->cqe_cnt   = mcq->verbs_cq.cq.cqe + 1;
	cq_out->cqe_size  = mcq->cqe_sz;
	cq_out->buf       = mcq->active_buf->buf;
	cq_out->dbrec     = mcq->dbrec;
	cq_out->cq_uar	  = mctx->cq_uar_reg;

	mcq->flags	 |= MLX5_CQ_FLAGS_DV_OWNED;

	return 0;
}

static int mlx5dv_get_rwq(struct ibv_wq *wq_in,
			  struct mlx5dv_rwq *rwq_out)
{
	struct mlx5_rwq *mrwq = to_mrwq(wq_in);

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
	uint64_t mask_out = 0;

	dm_out->buf       = mdm->start_va;
	dm_out->length    = mdm->length;

	if (dm_out->comp_mask & MLX5DV_DM_MASK_REMOTE_VA) {
		dm_out->remote_va = mdm->remote_va;
		mask_out |= MLX5DV_DM_MASK_REMOTE_VA;
	}

	dm_out->comp_mask = mask_out;

	return 0;
}

static int mlx5dv_get_av(struct ibv_ah *ah_in,
			 struct mlx5dv_ah *ah_out)
{
	struct mlx5_ah *mah = to_mah(ah_in);

	ah_out->comp_mask = 0;
	ah_out->av	  = &mah->av;

	return 0;
}

static int mlx5dv_get_pd(struct ibv_pd *pd_in,
			 struct mlx5dv_pd *pd_out)
{
	struct mlx5_pd *mpd = to_mpd(pd_in);

	pd_out->comp_mask = 0;
	pd_out->pdn = mpd->pdn;

	return 0;
}

static int query_lag(struct ibv_context *ctx, uint8_t *lag_state,
		     uint8_t *tx_remap_affinity_1,
		     uint8_t *tx_remap_affinity_2)
{
	uint32_t out_lag[DEVX_ST_SZ_DW(query_lag_out)] = {};
	uint32_t in_lag[DEVX_ST_SZ_DW(query_lag_in)] = {};
	int ret;

	DEVX_SET(query_lag_in, in_lag, opcode, MLX5_CMD_OP_QUERY_LAG);
	ret = mlx5dv_devx_general_cmd(ctx, in_lag, sizeof(in_lag), out_lag,
				      sizeof(out_lag));
	if (ret)
		return ret;

	*lag_state = DEVX_GET(query_lag_out, out_lag, ctx.lag_state);
	if (tx_remap_affinity_1)
		*tx_remap_affinity_1 = DEVX_GET(query_lag_out, out_lag,
						ctx.tx_remap_affinity_1);
	if (tx_remap_affinity_2)
		*tx_remap_affinity_2 = DEVX_GET(query_lag_out, out_lag,
						ctx.tx_remap_affinity_2);

	return 0;
}

static bool lag_operation_supported(struct ibv_qp *qp)
{
	struct mlx5_context *mctx = to_mctx(qp->context);
	struct mlx5_qp *mqp = to_mqp(qp);

	if (mctx->entropy_caps.num_lag_ports <= 1)
		return false;

	if ((qp->qp_type == IBV_QPT_RC) ||
	    (qp->qp_type == IBV_QPT_UD) ||
	    (qp->qp_type == IBV_QPT_UC) ||
	    (qp->qp_type == IBV_QPT_RAW_PACKET) ||
	    (qp->qp_type == IBV_QPT_XRC_SEND) ||
	    ((qp->qp_type == IBV_QPT_DRIVER) &&
	     (mqp->dc_type == MLX5DV_DCTYPE_DCI)))
		return true;

	return false;
}


static int _mlx5dv_query_qp_lag_port(struct ibv_qp *qp, uint8_t *port_num,
				     uint8_t *active_port_num)
{
	uint8_t lag_state, tx_remap_affinity_1, tx_remap_affinity_2;
	uint32_t in_tis[DEVX_ST_SZ_DW(query_tis_in)] = {};
	uint32_t out_tis[DEVX_ST_SZ_DW(query_tis_out)] = {};
	uint32_t in_qp[DEVX_ST_SZ_DW(query_qp_in)] = {};
	uint32_t out_qp[DEVX_ST_SZ_DW(query_qp_out)] = {};
	struct mlx5_context *mctx = to_mctx(qp->context);
	struct mlx5_qp *mqp = to_mqp(qp);
	int ret;

	if (!lag_operation_supported(qp))
		return EOPNOTSUPP;

	ret = query_lag(qp->context, &lag_state,
			&tx_remap_affinity_1, &tx_remap_affinity_2);
	if (ret)
		return ret;

	if (!lag_state && !mctx->entropy_caps.lag_tx_port_affinity)
		return EOPNOTSUPP;

	switch (qp->qp_type) {
	case IBV_QPT_RAW_PACKET:
		DEVX_SET(query_tis_in, in_tis, opcode, MLX5_CMD_OP_QUERY_TIS);
		DEVX_SET(query_tis_in, in_tis, tisn, mqp->tisn);
		ret = mlx5dv_devx_qp_query(qp, in_tis, sizeof(in_tis), out_tis,
					   sizeof(out_tis));
		if (ret)
			return ret;

		*port_num = DEVX_GET(query_tis_out, out_tis,
				     tis_context.lag_tx_port_affinity);
		break;

	default:
		DEVX_SET(query_qp_in, in_qp, opcode, MLX5_CMD_OP_QUERY_QP);
		DEVX_SET(query_qp_in, in_qp, qpn, qp->qp_num);
		ret = mlx5dv_devx_qp_query(qp, in_qp, sizeof(in_qp), out_qp,
					   sizeof(out_qp));
		if (ret)
			return ret;

		*port_num = DEVX_GET(query_qp_out, out_qp,
				     qpc.lag_tx_port_affinity);
		break;
	}

	switch (*port_num) {
	case 1:
		*active_port_num = tx_remap_affinity_1;
		break;

	case 2:
		*active_port_num = tx_remap_affinity_2;
		break;

	default:
		return EOPNOTSUPP;
	}

	return 0;
}

int mlx5dv_query_qp_lag_port(struct ibv_qp *qp, uint8_t *port_num,
			     uint8_t *active_port_num)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(qp->context);

	if (!dvops || !dvops->query_qp_lag_port)
		return EOPNOTSUPP;

	return dvops->query_qp_lag_port(qp, port_num,
					active_port_num);
}

static int modify_tis_lag_port(struct ibv_qp *qp, uint8_t port_num)
{
	uint32_t out[DEVX_ST_SZ_DW(modify_tis_out)] = {};
	uint32_t in[DEVX_ST_SZ_DW(modify_tis_in)] = {};
	struct mlx5_qp *mqp = to_mqp(qp);

	DEVX_SET(modify_tis_in, in, opcode, MLX5_CMD_OP_MODIFY_TIS);
	DEVX_SET(modify_tis_in, in, tisn, mqp->tisn);
	DEVX_SET(modify_tis_in, in, bitmask.lag_tx_port_affinity, 1);
	DEVX_SET(modify_tis_in, in, ctx.lag_tx_port_affinity, port_num);
	return mlx5dv_devx_qp_modify(qp, in, sizeof(in), out, sizeof(out));
}

static int modify_qp_lag_port(struct ibv_qp *qp, uint8_t port_num)
{
	uint32_t out[DEVX_ST_SZ_DW(rts2rts_qp_out)] = {};
	uint32_t in[DEVX_ST_SZ_DW(rts2rts_qp_in)] = {};
	struct mlx5_context *mctx = to_mctx(qp->context);

	if (!mctx->entropy_caps.rts2rts_lag_tx_port_affinity ||
	    qp->state != IBV_QPS_RTS)
		return EOPNOTSUPP;

	DEVX_SET(rts2rts_qp_in, in, opcode, MLX5_CMD_OP_RTS2RTS_QP);
	DEVX_SET(rts2rts_qp_in, in, qpn, qp->qp_num);
	DEVX_SET(rts2rts_qp_in, in, opt_param_mask,
		 MLX5_QPC_OPT_MASK_RTS2RTS_LAG_TX_PORT_AFFINITY);
	DEVX_SET(rts2rts_qp_in, in, qpc.lag_tx_port_affinity, port_num);
	return mlx5dv_devx_qp_modify(qp, in, sizeof(in), out, sizeof(out));
}

static int _mlx5dv_modify_qp_lag_port(struct ibv_qp *qp, uint8_t port_num)
{
	uint8_t curr_configured, curr_active;
	struct mlx5_qp *mqp = to_mqp(qp);
	int ret;

	/* Query lag port to see if we are at all in lag mode, otherwise FW
	 * might return success and ignore the modification.
	 */
	ret = mlx5dv_query_qp_lag_port(qp, &curr_configured, &curr_active);
	if (ret)
		return ret;

	switch (qp->qp_type) {
	case IBV_QPT_RAW_PACKET:
		return modify_tis_lag_port(qp, port_num);

	case IBV_QPT_DRIVER:
		if (mqp->dc_type != MLX5DV_DCTYPE_DCI)
			return EOPNOTSUPP;
		SWITCH_FALLTHROUGH;
	case IBV_QPT_RC:
	case IBV_QPT_UD:
	case IBV_QPT_UC:
		return modify_qp_lag_port(qp, port_num);

	default:
		return EOPNOTSUPP;
	}
}

int mlx5dv_modify_qp_lag_port(struct ibv_qp *qp, uint8_t port_num)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(qp->context);

	if (!dvops || !dvops->modify_qp_lag_port)
		return EOPNOTSUPP;

	return dvops->modify_qp_lag_port(qp, port_num);

}

static int _mlx5dv_modify_qp_udp_sport(struct ibv_qp *qp, uint16_t udp_sport)
{
	uint32_t in[DEVX_ST_SZ_DW(rts2rts_qp_in)] = {};
	uint32_t out[DEVX_ST_SZ_DW(rts2rts_qp_out)] = {};
	struct mlx5_context *mctx = to_mctx(qp->context);

	switch (qp->qp_type) {
	case IBV_QPT_RC:
	case IBV_QPT_UC:
		if (qp->state != IBV_QPS_RTS ||
		    !mctx->entropy_caps.rts2rts_qp_udp_sport)
			return EOPNOTSUPP;
		break;
	default:
		return EOPNOTSUPP;
	}
	DEVX_SET(rts2rts_qp_in, in, opcode, MLX5_CMD_OP_RTS2RTS_QP);
	DEVX_SET(rts2rts_qp_in, in, qpn, qp->qp_num);
	DEVX_SET64(rts2rts_qp_in, in, opt_param_mask_95_32,
		   MLX5_QPC_OPT_MASK_32_UDP_SPORT);
	DEVX_SET(rts2rts_qp_in, in, qpc.primary_address_path.udp_sport,
		 udp_sport);

	return mlx5dv_devx_qp_modify(qp, in, sizeof(in), out,
				     sizeof(out));
}

int mlx5dv_modify_qp_udp_sport(struct ibv_qp *qp, uint16_t udp_sport)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(qp->context);

	if (!dvops || !dvops->modify_qp_udp_sport)
		return EOPNOTSUPP;

	return dvops->modify_qp_udp_sport(qp, udp_sport);
}

int mlx5dv_dci_stream_id_reset(struct ibv_qp *qp, uint16_t stream_id)
{
	uint32_t out[DEVX_ST_SZ_DW(rts2rts_qp_out)] = {};
	uint32_t in[DEVX_ST_SZ_DW(rts2rts_qp_in)] = {};
	struct mlx5_context *mctx = to_mctx(qp->context);
	struct mlx5_qp *mqp = to_mqp(qp);
	void *qpce = DEVX_ADDR_OF(rts2rts_qp_in, in, qpc_data_ext);

	if (!is_mlx5_dev(qp->context->device) ||
	    !mctx->dci_streams_caps.max_log_num_errored ||
	    !mctx->qpc_extension_cap ||
	    qp->state != IBV_QPS_RTS)
		return EOPNOTSUPP;

	if ((mqp->dc_type != MLX5DV_DCTYPE_DCI) || (qp->qp_type != IBV_QPT_DRIVER))
		return EINVAL;

	DEVX_SET(rts2rts_qp_in, in, opcode, MLX5_CMD_OP_RTS2RTS_QP);
	DEVX_SET(rts2rts_qp_in, in, qpn, qp->qp_num);
	DEVX_SET(rts2rts_qp_in, in, qpc_ext, 1);
	DEVX_SET64(rts2rts_qp_in, in, opt_param_mask_95_32,
		   MLX5_QPC_OPT_MASK_32_DCI_STREAM_CHANNEL_ID);

	DEVX_SET(qpc_ext, qpce, dci_stream_channel_id, stream_id);

	return mlx5dv_devx_qp_modify(qp, in, sizeof(in), out, sizeof(out));
}

static bool sched_supported(struct ibv_context *ctx)
{
	struct mlx5_qos_caps *qc = &to_mctx(ctx)->qos_caps;

	return (qc->qos &&
		(qc->nic_element_type & ELEMENT_TYPE_CAP_MASK_TASR) &&
		(qc->nic_element_type & ELEMENT_TYPE_CAP_MASK_QUEUE_GROUP) &&
		(qc->nic_tsar_type & TSAR_TYPE_CAP_MASK_DWRR));
}

static struct mlx5dv_devx_obj *
mlx5dv_sched_nic_create(struct ibv_context *ctx,
			const struct mlx5dv_sched_attr *sched_attr,
			int elem_type)
{
	uint32_t out[DEVX_ST_SZ_DW(general_obj_out_cmd_hdr)] = {};
	uint32_t in[DEVX_ST_SZ_DW(create_sched_elem_in)] = {};
	uint32_t parent_id;
	void *attr;

	attr = DEVX_ADDR_OF(create_sched_elem_in, in, hdr);
	DEVX_SET(general_obj_in_cmd_hdr,
		 attr, opcode, MLX5_CMD_OP_CREATE_GENERAL_OBJECT);
	DEVX_SET(general_obj_in_cmd_hdr,
		 attr, obj_type, MLX5_OBJ_TYPE_SCHEDULING_ELEMENT);

	attr = DEVX_ADDR_OF(create_sched_elem_in, in, sched_elem);
	DEVX_SET64(sched_elem, attr, modify_field_select, sched_attr->flags);
	DEVX_SET(sched_elem, attr,
		 scheduling_hierarchy, MLX5_SCHED_HIERARCHY_NIC);

	attr = DEVX_ADDR_OF(create_sched_elem_in, in, sched_elem.sched_context);
	DEVX_SET(sched_context, attr, element_type, elem_type);

	parent_id = sched_attr->parent ? sched_attr->parent->obj->object_id : 0;
	DEVX_SET(sched_context, attr, parent_element_id, parent_id);
	if (sched_attr->flags & MLX5DV_SCHED_ELEM_ATTR_FLAGS_BW_SHARE)
		DEVX_SET(sched_context, attr, bw_share, sched_attr->bw_share);
	if (sched_attr->flags & MLX5DV_SCHED_ELEM_ATTR_FLAGS_MAX_AVG_BW)
		DEVX_SET(sched_context, attr,
			 max_average_bw, sched_attr->max_avg_bw);

	attr = DEVX_ADDR_OF(create_sched_elem_in, in,
			    sched_elem.sched_context.sched_elem_attr);
	DEVX_SET(sched_elem_attr_tsar, attr, tsar_type,
		 MLX5_SCHED_TSAR_TYPE_DWRR);

	return mlx5dv_devx_obj_create(ctx, in, sizeof(in), out, sizeof(out));
}

static int
mlx5dv_sched_nic_modify(struct mlx5dv_devx_obj *obj,
			const struct mlx5dv_sched_attr *sched_attr,
			int elem_type)
{
	uint32_t out[DEVX_ST_SZ_DW(general_obj_out_cmd_hdr)] = {};
	uint32_t in[DEVX_ST_SZ_DW(create_sched_elem_in)] = {};
	void *attr;

	attr = DEVX_ADDR_OF(create_sched_elem_in, in, hdr);
	DEVX_SET(general_obj_in_cmd_hdr,
		 attr, opcode, MLX5_CMD_OP_MODIFY_GENERAL_OBJECT);
	DEVX_SET(general_obj_in_cmd_hdr,
		 attr, obj_type, MLX5_OBJ_TYPE_SCHEDULING_ELEMENT);
	DEVX_SET(general_obj_in_cmd_hdr, in, obj_id, obj->object_id);

	attr = DEVX_ADDR_OF(create_sched_elem_in, in, sched_elem);
	DEVX_SET64(sched_elem, attr, modify_field_select, sched_attr->flags);
	DEVX_SET(sched_elem, attr,
		 scheduling_hierarchy, MLX5_SCHED_HIERARCHY_NIC);

	attr = DEVX_ADDR_OF(create_sched_elem_in, in, sched_elem.sched_context);
	DEVX_SET(sched_context, attr, element_type, elem_type);
	if (sched_attr->flags & MLX5DV_SCHED_ELEM_ATTR_FLAGS_BW_SHARE)
		DEVX_SET(sched_context, attr, bw_share, sched_attr->bw_share);
	if (sched_attr->flags & MLX5DV_SCHED_ELEM_ATTR_FLAGS_MAX_AVG_BW)
		DEVX_SET(sched_context, attr,
			 max_average_bw, sched_attr->max_avg_bw);

	attr = DEVX_ADDR_OF(create_sched_elem_in, in,
			    sched_elem.sched_context.sched_elem_attr);
	DEVX_SET(sched_elem_attr_tsar, attr, tsar_type,
		 MLX5_SCHED_TSAR_TYPE_DWRR);

	return mlx5dv_devx_obj_modify(obj, in, sizeof(in), out, sizeof(out));
}

#define MLX5DV_SCHED_ELEM_ATTR_ALL_FLAGS \
	(MLX5DV_SCHED_ELEM_ATTR_FLAGS_BW_SHARE |	\
	 MLX5DV_SCHED_ELEM_ATTR_FLAGS_MAX_AVG_BW)

static bool attr_supported(struct ibv_context *ctx,
			   const struct mlx5dv_sched_attr *attr)
{
	struct mlx5_qos_caps *qc = &to_mctx(ctx)->qos_caps;

	if ((attr->flags & MLX5DV_SCHED_ELEM_ATTR_FLAGS_BW_SHARE) &&
	    !qc->nic_bw_share)
		return false;
	if ((attr->flags & MLX5DV_SCHED_ELEM_ATTR_FLAGS_MAX_AVG_BW) &&
	    !qc->nic_rate_limit)
		return false;

	return true;
}

static bool sched_attr_valid(const struct mlx5dv_sched_attr *attr, bool node)
{
	if (!attr || attr->comp_mask ||
	    !check_comp_mask(attr->flags, MLX5DV_SCHED_ELEM_ATTR_ALL_FLAGS))
		return false;
	if (node && (!attr->parent && attr->flags))
		return false;
	if (!node && !attr->parent)
		return false;

	return true;
}

static struct mlx5dv_sched_node *
_mlx5dv_sched_node_create(struct ibv_context *ctx,
			   const struct mlx5dv_sched_attr *attr)
{
	struct mlx5dv_sched_node *node;
	struct mlx5dv_devx_obj *obj;

	if (!sched_attr_valid(attr, true)) {
		errno = EINVAL;
		return NULL;
	}

	if (!sched_supported(ctx) || !attr_supported(ctx, attr)) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	node = calloc(1, sizeof(*node));
	if (!node) {
		errno = ENOMEM;
		return NULL;
	}

	obj = mlx5dv_sched_nic_create(ctx, attr, MLX5_SCHED_ELEM_TYPE_TSAR);
	if (!obj)
		goto err_sched_nic_create;

	node->obj = obj;
	node->parent = attr->parent;
	return node;

err_sched_nic_create:
	free(node);
	return NULL;
}

struct mlx5dv_sched_node *
mlx5dv_sched_node_create(struct ibv_context *ctx,
			 const struct mlx5dv_sched_attr *attr)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(ctx);

	if (!dvops || !dvops->sched_node_create) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	return dvops->sched_node_create(ctx, attr);
}

static struct mlx5dv_sched_leaf *
_mlx5dv_sched_leaf_create(struct ibv_context *ctx,
			   const struct mlx5dv_sched_attr *attr)
{
	struct mlx5dv_sched_leaf *leaf;
	struct mlx5dv_devx_obj *obj;

	if (!sched_attr_valid(attr, false)) {
		errno = EINVAL;
		return NULL;
	}

	if (!attr_supported(ctx, attr)) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	leaf = calloc(1, sizeof(*leaf));
	if (!leaf) {
		errno = ENOMEM;
		return NULL;
	}

	obj = mlx5dv_sched_nic_create(ctx, attr,
				      MLX5_SCHED_ELEM_TYPE_QUEUE_GROUP);
	if (!obj)
		goto err_sched_nic_create;

	leaf->obj = obj;
	leaf->parent = attr->parent;
	return leaf;

err_sched_nic_create:
	free(leaf);
	return NULL;
}

struct mlx5dv_sched_leaf *
mlx5dv_sched_leaf_create(struct ibv_context *ctx,
			 const struct mlx5dv_sched_attr *attr)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(ctx);

	if (!dvops || !dvops->sched_leaf_create) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	return dvops->sched_leaf_create(ctx, attr);
}

static int _mlx5dv_sched_node_modify(struct mlx5dv_sched_node *node,
				     const struct mlx5dv_sched_attr *attr)
{
	if (!node || !sched_attr_valid(attr, true)) {
		errno = EINVAL;
		return errno;
	}

	if (!attr_supported(node->obj->context, attr)) {
		errno = EOPNOTSUPP;
		return errno;
	}

	return mlx5dv_sched_nic_modify(node->obj, attr,
				       MLX5_SCHED_ELEM_TYPE_TSAR);
}

int mlx5dv_sched_node_modify(struct mlx5dv_sched_node *node,
			     const struct mlx5dv_sched_attr *attr)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(node->obj->context);

	if (!dvops || !dvops->sched_node_modify)
		return EOPNOTSUPP;

	return dvops->sched_node_modify(node, attr);
}

static int _mlx5dv_sched_leaf_modify(struct mlx5dv_sched_leaf *leaf,
				     const struct mlx5dv_sched_attr *attr)
{
	if (!leaf || !sched_attr_valid(attr, false)) {
		errno = EINVAL;
		return errno;
	}

	if (!attr_supported(leaf->obj->context, attr)) {
		errno = EOPNOTSUPP;
		return errno;
	}

	return mlx5dv_sched_nic_modify(leaf->obj, attr,
				       MLX5_SCHED_ELEM_TYPE_QUEUE_GROUP);
}

int mlx5dv_sched_leaf_modify(struct mlx5dv_sched_leaf *leaf,
			     const struct mlx5dv_sched_attr *attr)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(leaf->obj->context);

	if (!dvops || !dvops->sched_leaf_modify)
		return EOPNOTSUPP;

	return dvops->sched_leaf_modify(leaf, attr);
}

static int _mlx5dv_sched_node_destroy(struct mlx5dv_sched_node *node)
{
	int ret;

	ret = mlx5dv_devx_obj_destroy(node->obj);
	if (ret)
		return ret;

	free(node);
	return 0;
}

int mlx5dv_sched_node_destroy(struct mlx5dv_sched_node *node)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(node->obj->context);

	if (!dvops || !dvops->sched_node_destroy)
		return EOPNOTSUPP;

	return dvops->sched_node_destroy(node);
}

static int _mlx5dv_sched_leaf_destroy(struct mlx5dv_sched_leaf *leaf)
{
	int ret;

	ret = mlx5dv_devx_obj_destroy(leaf->obj);
	if (ret)
		return ret;

	free(leaf);
	return 0;
}

int mlx5dv_sched_leaf_destroy(struct mlx5dv_sched_leaf *leaf)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(leaf->obj->context);

	if (!dvops || !dvops->sched_leaf_destroy)
		return EOPNOTSUPP;

	return dvops->sched_leaf_destroy(leaf);
}

static int modify_ib_qp_sched_elem_init(struct ibv_qp *qp,
					uint32_t req_id, uint32_t resp_id)
{
	uint64_t mask = MLX5_QPC_OPT_MASK_32_QOS_QUEUE_GROUP_ID;
	uint32_t in[DEVX_ST_SZ_DW(init2init_qp_in)] = {};
	uint32_t out[DEVX_ST_SZ_DW(init2init_qp_out)] = {};
	void *qpce = DEVX_ADDR_OF(init2init_qp_in, in, qpc_data_ext);

	DEVX_SET(init2init_qp_in, in, opcode, MLX5_CMD_OP_INIT2INIT_QP);
	DEVX_SET(init2init_qp_in, in, qpc_ext, 1);
	DEVX_SET(init2init_qp_in, in, qpn, qp->qp_num);
	DEVX_SET64(init2init_qp_in, in, opt_param_mask_95_32, mask);

	DEVX_SET(qpc_ext, qpce, qos_queue_group_id_requester, req_id);
	DEVX_SET(qpc_ext, qpce, qos_queue_group_id_responder, resp_id);

	return mlx5dv_devx_qp_modify(qp, in, sizeof(in), out, sizeof(out));
}

static int modify_ib_qp_sched_elem_rts(struct ibv_qp *qp,
				       uint32_t req_id, uint32_t resp_id)
{
	uint64_t mask = MLX5_QPC_OPT_MASK_32_QOS_QUEUE_GROUP_ID;
	uint32_t in[DEVX_ST_SZ_DW(rts2rts_qp_in)] = {};
	uint32_t out[DEVX_ST_SZ_DW(rts2rts_qp_out)] = {};
	void *qpce = DEVX_ADDR_OF(rts2rts_qp_in, in, qpc_data_ext);

	DEVX_SET(rts2rts_qp_in, in, opcode, MLX5_CMD_OP_RTS2RTS_QP);
	DEVX_SET(rts2rts_qp_in, in, qpc_ext, 1);
	DEVX_SET(rts2rts_qp_in, in, qpn, qp->qp_num);
	DEVX_SET64(rts2rts_qp_in, in, opt_param_mask_95_32, mask);

	DEVX_SET(qpc_ext, qpce, qos_queue_group_id_requester, req_id);
	DEVX_SET(qpc_ext, qpce, qos_queue_group_id_responder, resp_id);

	return mlx5dv_devx_qp_modify(qp, in, sizeof(in), out, sizeof(out));
}

static int modify_ib_qp_sched_elem(struct ibv_qp *qp,
				   uint32_t req_id, uint32_t resp_id)
{
	int ret;

	switch (qp->state) {
	case IBV_QPS_INIT:
		ret = modify_ib_qp_sched_elem_init(qp, req_id, resp_id);
		break;

	case IBV_QPS_RTS:
		ret = modify_ib_qp_sched_elem_rts(qp, req_id, resp_id);
		break;

	default:
		return EOPNOTSUPP;
	};

	return ret;
}

static int modify_raw_qp_sched_elem(struct ibv_qp *qp, uint32_t qos_id)
{
	struct mlx5_qos_caps *qc = &to_mctx(qp->context)->qos_caps;
	uint32_t mout[DEVX_ST_SZ_DW(modify_sq_out)] = {};
	uint32_t min[DEVX_ST_SZ_DW(modify_sq_in)] = {};
	struct mlx5_qp *mqp = to_mqp(qp);
	void *sqc;

	if (qp->state != IBV_QPS_RTS || !qc->nic_sq_scheduling)
		return EOPNOTSUPP;

	DEVX_SET(modify_sq_in, min, opcode, MLX5_CMD_OP_MODIFY_SQ);
	DEVX_SET(modify_sq_in, min, sq_state, MLX5_SQC_STATE_RDY);
	DEVX_SET(modify_sq_in, min, sqn, mqp->sqn);
	DEVX_SET64(modify_sq_in, min, modify_bitmask,
		   MLX5_MODIFY_SQ_BITMASK_QOS_QUEUE_GROUP_ID);
	sqc = DEVX_ADDR_OF(modify_sq_in, min, sq_context);
	DEVX_SET(sqc, sqc, state, MLX5_SQC_STATE_RDY);
	DEVX_SET(sqc, sqc, qos_queue_group_id, qos_id);

	return mlx5dv_devx_qp_modify(qp, min, sizeof(min), mout, sizeof(mout));
}

static int _mlx5dv_modify_qp_sched_elem(struct ibv_qp *qp,
					const struct mlx5dv_sched_leaf *requestor,
					const struct mlx5dv_sched_leaf *responder)
{
	struct mlx5_qos_caps *qc = &to_mctx(qp->context)->qos_caps;

	switch (qp->qp_type) {
	case IBV_QPT_UC:
	case IBV_QPT_UD:
		if (responder)
			return EINVAL;
		SWITCH_FALLTHROUGH;
	case IBV_QPT_RC:
		if ((!to_mctx(qp->context)->qpc_extension_cap) ||
		    !(qc->nic_qp_scheduling))
			return EOPNOTSUPP;
		return modify_ib_qp_sched_elem(qp,
					       requestor ? requestor->obj->object_id : 0,
					       responder ? responder->obj->object_id : 0);
	case IBV_QPT_RAW_PACKET:
		if (responder)
			return EINVAL;
		return modify_raw_qp_sched_elem(qp,
						requestor ? requestor->obj->object_id : 0);
	default:
		return EOPNOTSUPP;
	}
}

int mlx5dv_modify_qp_sched_elem(struct ibv_qp *qp,
				const struct mlx5dv_sched_leaf *requestor,
				const struct mlx5dv_sched_leaf *responder)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(qp->context);

	if (!dvops || !dvops->modify_qp_sched_elem)
		return EOPNOTSUPP;

	return dvops->modify_qp_sched_elem(qp, requestor, responder);
}

int mlx5_modify_qp_drain_sigerr(struct ibv_qp *qp)
{
	uint64_t mask = MLX5_QPC_OPT_MASK_INIT2INIT_DRAIN_SIGERR;
	uint32_t in[DEVX_ST_SZ_DW(init2init_qp_in)] = {};
	uint32_t out[DEVX_ST_SZ_DW(init2init_qp_out)] = {};
	void *qpc = DEVX_ADDR_OF(init2init_qp_in, in, qpc);

	DEVX_SET(init2init_qp_in, in, opcode, MLX5_CMD_OP_INIT2INIT_QP);
	DEVX_SET(init2init_qp_in, in, qpn, qp->qp_num);
	DEVX_SET(init2init_qp_in, in, opt_param_mask, mask);

	DEVX_SET(qpc, qpc, drain_sigerr, 1);

	return mlx5dv_devx_qp_modify(qp, in, sizeof(in), out, sizeof(out));
}

static struct reserved_qpn_blk *reserved_qpn_blk_alloc(struct mlx5_context *mctx)
{
	uint32_t out[DEVX_ST_SZ_DW(general_obj_out_cmd_hdr)] = {};
	uint32_t in[DEVX_ST_SZ_DW(create_reserved_qpn_in)] = {};
	struct reserved_qpn_blk *blk;
	void *attr;

	blk = calloc(1, sizeof(*blk));
	if (!blk) {
		errno = ENOMEM;
		return NULL;
	}

	blk->bmp = bitmap_alloc0(1 << mctx->hca_cap_2_caps.log_reserved_qpns_per_obj);
	if (!blk->bmp) {
		errno = ENOMEM;
		goto bmp_alloc_fail;
	}

	attr = DEVX_ADDR_OF(create_reserved_qpn_in, in, hdr);
	DEVX_SET(general_obj_in_cmd_hdr,
		 attr, opcode, MLX5_CMD_OP_CREATE_GENERAL_OBJECT);
	DEVX_SET(general_obj_in_cmd_hdr,
		 attr, obj_type, MLX5_OBJ_TYPE_RESERVED_QPN);
	DEVX_SET(general_obj_in_cmd_hdr,
		 attr, log_obj_range, mctx->hca_cap_2_caps.log_reserved_qpns_per_obj);

	blk->obj = mlx5dv_devx_obj_create(&mctx->ibv_ctx.context,
					  in, sizeof(in), out, sizeof(out));
	if (!blk->obj)
		goto obj_alloc_fail;

	blk->first_qpn = blk->obj->object_id;
	blk->next_avail_slot = 0;

	return blk;

obj_alloc_fail:
	free(blk->bmp);

bmp_alloc_fail:
	free(blk);
	return NULL;
}

static void reserved_qpn_blk_dealloc(struct reserved_qpn_blk *blk)
{
	if (mlx5dv_devx_obj_destroy(blk->obj))
		assert(false);

	free(blk->bmp);
	free(blk);
}

static void reserved_qpn_blks_free(struct mlx5_context *mctx)
{
	struct reserved_qpn_blk *blk, *tmp;

	pthread_mutex_lock(&mctx->reserved_qpns.mutex);

	list_for_each_safe(&mctx->reserved_qpns.blk_list,
			   blk, tmp, entry) {
		list_del(&blk->entry);
		reserved_qpn_blk_dealloc(blk);
	}

	pthread_mutex_unlock(&mctx->reserved_qpns.mutex);
}

/**
 * Allocate a reserved QPN either from the last FW object allocated,
 * or by allocating a new one. When find a free QPN in an object, it
 * always starts from last allocation position, to make sure the QPN
 * always move forward to prevent stale QPN.
 */
static int _mlx5dv_reserved_qpn_alloc(struct ibv_context *ctx, uint32_t *qpn)
{
	struct mlx5_context *mctx = to_mctx(ctx);
	struct reserved_qpn_blk *blk;
	uint32_t qpns_per_obj;
	int ret = 0;

	if (!(mctx->general_obj_types_caps & (1ULL << MLX5_OBJ_TYPE_RESERVED_QPN)))
		return EOPNOTSUPP;

	qpns_per_obj = 1 << mctx->hca_cap_2_caps.log_reserved_qpns_per_obj;

	pthread_mutex_lock(&mctx->reserved_qpns.mutex);

	blk = list_tail(&mctx->reserved_qpns.blk_list,
			struct reserved_qpn_blk, entry);
	if (!blk ||
	    (blk->next_avail_slot >= qpns_per_obj)) {
		blk = reserved_qpn_blk_alloc(mctx);
		if (!blk) {
			ret = errno;
			goto end;
		}
		list_add_tail(&mctx->reserved_qpns.blk_list, &blk->entry);
	}

	*qpn = blk->first_qpn + blk->next_avail_slot;
	bitmap_set_bit(blk->bmp, blk->next_avail_slot);
	blk->next_avail_slot++;

end:
	pthread_mutex_unlock(&mctx->reserved_qpns.mutex);
	return ret;
}

int mlx5dv_reserved_qpn_alloc(struct ibv_context *ctx, uint32_t *qpn)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(ctx);

	if (!dvops || !dvops->reserved_qpn_alloc)
		return EOPNOTSUPP;

	return dvops->reserved_qpn_alloc(ctx, qpn);
}

/**
 * Deallocate a reserved QPN. The FW object is destroyed only when all QPNs
 * in this object were used and freed.
 */
static int _mlx5dv_reserved_qpn_dealloc(struct ibv_context *ctx, uint32_t qpn)
{
	struct mlx5_context *mctx = to_mctx(ctx);
	struct reserved_qpn_blk *blk, *tmp;
	uint32_t qpns_per_obj;
	bool found = false;
	int ret = 0;

	qpns_per_obj = 1 << mctx->hca_cap_2_caps.log_reserved_qpns_per_obj;

	pthread_mutex_lock(&mctx->reserved_qpns.mutex);

	list_for_each_safe(&mctx->reserved_qpns.blk_list,
			   blk, tmp, entry) {
		if ((qpn >= blk->first_qpn) &&
		    (qpn < blk->first_qpn + qpns_per_obj)) {
			found = true;
			break;
		}
	}

	if (!found || !bitmap_test_bit(blk->bmp, qpn - blk->first_qpn)) {
		errno = EINVAL;
		ret = errno;
		goto end;
	}

	bitmap_clear_bit(blk->bmp, qpn - blk->first_qpn);
	if ((blk->next_avail_slot >= qpns_per_obj) &&
	    (bitmap_empty(blk->bmp, qpns_per_obj))) {
		list_del(&blk->entry);
		reserved_qpn_blk_dealloc(blk);
	}

end:
	pthread_mutex_unlock(&mctx->reserved_qpns.mutex);
	return ret;
}

int mlx5dv_reserved_qpn_dealloc(struct ibv_context *ctx, uint32_t qpn)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(ctx);

	if (!dvops || !dvops->reserved_qpn_dealloc)
		return EOPNOTSUPP;

	return dvops->reserved_qpn_dealloc(ctx, qpn);
}

static int _mlx5dv_init_obj(struct mlx5dv_obj *obj, uint64_t obj_type)
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

static struct ibv_context *
get_context_from_obj(struct mlx5dv_obj *obj, uint64_t obj_type)
{
	if (obj_type & MLX5DV_OBJ_QP)
		return obj->qp.in->context;
	if (obj_type & MLX5DV_OBJ_CQ)
		return obj->cq.in->context;
	if (obj_type & MLX5DV_OBJ_SRQ)
		return obj->srq.in->context;
	if (obj_type & MLX5DV_OBJ_RWQ)
		return obj->rwq.in->context;
	if (obj_type & MLX5DV_OBJ_DM)
		return obj->dm.in->context;
	if (obj_type & MLX5DV_OBJ_AH)
		return obj->ah.in->context;
	if (obj_type & MLX5DV_OBJ_PD)
		return obj->pd.in->context;

	return NULL;
}

LATEST_SYMVER_FUNC(mlx5dv_init_obj, 1_2, "MLX5_1.2",
		   int,
		   struct mlx5dv_obj *obj, uint64_t obj_type)
{
	struct mlx5_dv_context_ops *dvops;
	struct ibv_context *ctx;

	ctx = get_context_from_obj(obj, obj_type);
	if (!ctx)
		return EINVAL;

	dvops = mlx5_get_dv_ops(ctx);

	if (!dvops || !dvops->init_obj)
		return EOPNOTSUPP;

	return dvops->init_obj(obj, obj_type);
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
		obj->cq.out->cq_uar = &(to_mctx(obj->cq.in->context)->cq_uar_reg);
	}
	return ret;
}

off_t get_uar_mmap_offset(int idx, int page_size, int command)
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

static int _mlx5dv_set_context_attr(struct ibv_context *ibv_ctx,
				    enum mlx5dv_set_ctx_attr_type type,
				    void *attr)
{
	struct mlx5_context *ctx = to_mctx(ibv_ctx);

	switch (type) {
	case MLX5DV_CTX_ATTR_BUF_ALLOCATORS:
		ctx->extern_alloc = *((struct mlx5dv_ctx_allocators *)attr);
		break;
	default:
		return ENOTSUP;
	}

	return 0;
}

int mlx5dv_set_context_attr(struct ibv_context *ibv_ctx,
			    enum mlx5dv_set_ctx_attr_type type, void *attr)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(ibv_ctx);

	if (!dvops || !dvops->set_context_attr)
		return EOPNOTSUPP;

	return dvops->set_context_attr(ibv_ctx, type, attr);
}

static int _mlx5dv_get_clock_info(struct ibv_context *ctx_in,
				  struct mlx5dv_clock_info *clock_info)
{
	struct mlx5_context *ctx = to_mctx(ctx_in);
	const struct mlx5_ib_clock_info *ci;
	uint32_t retry, tmp_sig;
	atomic_uint32_t *sig;

	if (!is_mlx5_dev(ctx_in->device))
		return EOPNOTSUPP;

	ci = ctx->clock_info_page;

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

int mlx5dv_get_clock_info(struct ibv_context *ctx_in,
			  struct mlx5dv_clock_info *clock_info)
{
	struct mlx5_dv_context_ops *dvops = mlx5_get_dv_ops(ctx_in);

	if (!dvops || !dvops->get_clock_info)
		return EOPNOTSUPP;

	return dvops->get_clock_info(ctx_in, clock_info);
}

static struct mlx5_dv_context_ops mlx5_dv_ctx_ops = {
	.query_device = _mlx5dv_query_device,

	.query_qp_lag_port = _mlx5dv_query_qp_lag_port,
	.modify_qp_lag_port = _mlx5dv_modify_qp_lag_port,

	.modify_qp_udp_sport = _mlx5dv_modify_qp_udp_sport,

	.sched_node_create = _mlx5dv_sched_node_create,
	.sched_leaf_create = _mlx5dv_sched_leaf_create,
	.sched_node_modify = _mlx5dv_sched_node_modify,
	.sched_leaf_modify = _mlx5dv_sched_leaf_modify,
	.sched_node_destroy = _mlx5dv_sched_node_destroy,
	.sched_leaf_destroy = _mlx5dv_sched_leaf_destroy,
	.modify_qp_sched_elem = _mlx5dv_modify_qp_sched_elem,

	.reserved_qpn_alloc = _mlx5dv_reserved_qpn_alloc,
	.reserved_qpn_dealloc = _mlx5dv_reserved_qpn_dealloc,

	.set_context_attr = _mlx5dv_set_context_attr,
	.get_clock_info = _mlx5dv_get_clock_info,
	.init_obj = _mlx5dv_init_obj,
};

static void adjust_uar_info(struct mlx5_device *mdev,
			    struct mlx5_context *context,
			    struct mlx5_ib_alloc_ucontext_resp *resp)
{
	if (!resp->log_uar_size && !resp->num_uars_per_page) {
		/* old kernel */
		context->uar_size = mdev->page_size;
		context->num_uars_per_page = 1;
		return;
	}

	context->uar_size = 1 << resp->log_uar_size;
	context->num_uars_per_page = resp->num_uars_per_page;
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

static int get_uar_info(struct mlx5_device *mdev,
			int *tot_uuars, int *low_lat_uuars)
{
	*tot_uuars = get_total_uuars(mdev->page_size);
	if (*tot_uuars < 0) {
		errno = -*tot_uuars;
		return -1;
	}

	*low_lat_uuars = get_num_low_lat_uuars(*tot_uuars);
	if (*low_lat_uuars < 0) {
		errno = -*low_lat_uuars;
		return -1;
	}

	if (*low_lat_uuars > *tot_uuars - 1) {
		errno = ENOMEM;
		return -1;
	}

	return 0;
}

static void mlx5_uninit_context(struct mlx5_context *context)
{
	mlx5_close_debug_file(context->dbg_fp);

	verbs_uninit_context(&context->ibv_ctx);
	free(context);
}

static struct mlx5_context *mlx5_init_context(struct ibv_device *ibdev,
						int cmd_fd)
{
	struct mlx5_device *mdev = to_mdev(ibdev);
	struct mlx5_context *context;
	int low_lat_uuars;
	int tot_uuars;
	int ret;

	context = verbs_init_and_alloc_context(ibdev, cmd_fd, context, ibv_ctx,
					       RDMA_DRIVER_MLX5);
	if (!context)
		return NULL;

	mlx5_open_debug_file(&context->dbg_fp);
	mlx5_set_debug_mask();
	set_freeze_on_error();
	if (gethostname(context->hostname, sizeof(context->hostname)))
		strcpy(context->hostname, "host_unknown");

	mlx5_single_threaded = single_threaded_app();

	ret = get_uar_info(mdev, &tot_uuars, &low_lat_uuars);
	if (ret) {
		mlx5_uninit_context(context);
		return NULL;
	}
	context->tot_uuars = tot_uuars;
	context->low_lat_uuars = low_lat_uuars;

	return context;
}

static int mlx5_set_context(struct mlx5_context *context,
			    struct mlx5_ib_alloc_ucontext_resp *resp,
			    bool is_import)
{
	struct verbs_context *v_ctx = &context->ibv_ctx;
	struct ibv_port_attr port_attr = {};
	int cmd_fd = v_ctx->context.cmd_fd;
	struct mlx5_device *mdev = to_mdev(v_ctx->context.device);
	struct ibv_device *ibdev = v_ctx->context.device;
	int page_size = mdev->page_size;
	int num_sys_page_map;
	int gross_uuars;
	int bfi;
	int i, k, j;

	context->max_num_qps = resp->qp_tab_size;
	context->bf_reg_size = resp->bf_reg_size;
	context->cache_line_size = resp->cache_line_size;
	context->max_sq_desc_sz = resp->max_sq_desc_sz;
	context->max_rq_desc_sz = resp->max_rq_desc_sz;
	context->max_send_wqebb	= resp->max_send_wqebb;
	context->num_ports = resp->num_ports;
	context->max_recv_wr = resp->max_recv_wr;
	context->max_srq_recv_wr = resp->max_srq_recv_wr;
	context->num_dyn_bfregs = resp->num_dyn_bfregs;

	if (resp->comp_mask & MLX5_IB_ALLOC_UCONTEXT_RESP_MASK_ECE)
		context->flags |= MLX5_CTX_FLAGS_ECE_SUPPORTED;

	if (resp->comp_mask & MLX5_IB_ALLOC_UCONTEXT_RESP_MASK_SQD2RTS)
		context->flags |= MLX5_CTX_FLAGS_SQD2RTS_SUPPORTED;

	if (resp->comp_mask & MLX5_IB_ALLOC_UCONTEXT_RESP_MASK_REAL_TIME_TS)
		context->flags |= MLX5_CTX_FLAGS_REAL_TIME_TS_SUPPORTED;

	if (resp->comp_mask & MLX5_IB_ALLOC_UCONTEXT_RESP_MASK_DUMP_FILL_MKEY) {
		context->dump_fill_mkey = resp->dump_fill_mkey;
		/* Have the BE value ready to be used in data path */
		context->dump_fill_mkey_be = htobe32(resp->dump_fill_mkey);
	} else {
		/* kernel driver will never return MLX5_INVALID_LKEY for
		 * dump_fill_mkey
		 */
		context->dump_fill_mkey = MLX5_INVALID_LKEY;
		context->dump_fill_mkey_be = htobe32(MLX5_INVALID_LKEY);
	}

	context->cqe_version = resp->cqe_version;
	adjust_uar_info(mdev, context, resp);

	context->cmds_supp_uhw = resp->cmds_supp_uhw;
	context->vendor_cap_flags = 0;
	list_head_init(&context->dyn_uar_bf_list);
	list_head_init(&context->dyn_uar_qp_shared_list);
	list_head_init(&context->dyn_uar_qp_dedicated_list);

	if (resp->eth_min_inline)
		context->eth_min_inline_size = (resp->eth_min_inline == MLX5_USER_INLINE_MODE_NONE) ?
						0 : MLX5_ETH_L2_INLINE_HEADER_SIZE;
	else
		context->eth_min_inline_size = MLX5_ETH_L2_INLINE_HEADER_SIZE;

	pthread_mutex_init(&context->qp_table_mutex, NULL);
	pthread_mutex_init(&context->srq_table_mutex, NULL);
	pthread_mutex_init(&context->uidx_table_mutex, NULL);
	pthread_mutex_init(&context->mkey_table_mutex, NULL);
	pthread_mutex_init(&context->dyn_bfregs_mutex, NULL);
	pthread_mutex_init(&context->crypto_login_mutex, NULL);
	for (i = 0; i < MLX5_QP_TABLE_SIZE; ++i)
		context->qp_table[i].refcnt = 0;

	for (i = 0; i < MLX5_QP_TABLE_SIZE; ++i)
		context->uidx_table[i].refcnt = 0;

	for (i = 0; i < MLX5_MKEY_TABLE_SIZE; ++i)
		context->mkey_table[i].refcnt = 0;

	context->db_list = NULL;

	pthread_mutex_init(&context->db_list_mutex, NULL);

	context->prefer_bf = get_always_bf();
	context->shut_up_bf = get_shut_up_bf();

	if (resp->tot_bfregs) {
		if (is_import) {
			errno = EINVAL;
			return EINVAL;
		}
		context->tot_uuars = resp->tot_bfregs;
		gross_uuars = context->tot_uuars / MLX5_NUM_NON_FP_BFREGS_PER_UAR * NUM_BFREGS_PER_UAR;
		context->bfs = calloc(gross_uuars, sizeof(*context->bfs));
		if (!context->bfs) {
			errno = ENOMEM;
			goto err_free;
		}
		context->flags |= MLX5_CTX_FLAGS_NO_KERN_DYN_UAR;
	} else {
		context->qp_max_dedicated_uuars = context->low_lat_uuars;
		context->qp_max_shared_uuars = context->tot_uuars - context->low_lat_uuars;
		goto bf_done;
	}

	context->max_num_legacy_dyn_uar_sys_page = context->num_dyn_bfregs /
			(context->num_uars_per_page * MLX5_NUM_NON_FP_BFREGS_PER_UAR);
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
				context->bfs[bfi].uar_mmap_offset =
					get_uar_mmap_offset(i, page_size,
							uar_type_to_cmd(context->uar[i].type));
			}
		}
	}

bf_done:

	context->hca_core_clock = NULL;
	if (resp->comp_mask & MLX5_IB_ALLOC_UCONTEXT_RESP_MASK_CORE_CLOCK_OFFSET) {
		context->core_clock.offset = resp->hca_core_clock_offset;
		mlx5_map_internal_clock(mdev, &v_ctx->context);
	}

	context->clock_info_page = NULL;
	if ((resp->clock_info_versions & (1 << MLX5_IB_CLOCK_INFO_V1)))
		mlx5_map_clock_info(mdev, &v_ctx->context);

	context->flow_action_flags = resp->flow_action_flags;

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
	context->dv_ctx_ops = &mlx5_dv_ctx_ops;

	mlx5_query_device_ctx(context);

	for (j = 0; j < min(MLX5_MAX_PORTS_NUM, context->num_ports); ++j) {
		memset(&port_attr, 0, sizeof(port_attr));
		if (!mlx5_query_port(&v_ctx->context, j + 1, &port_attr)) {
			context->cached_link_layer[j] = port_attr.link_layer;
			context->cached_port_flags[j] = port_attr.flags;
		}
	}

	mlx5_set_singleton_nc_uar(&v_ctx->context);
	context->cq_uar_reg = context->nc_uar ? context->nc_uar->uar : context->uar[0].reg;

	pthread_mutex_init(&context->reserved_qpns.mutex, NULL);
	list_head_init(&context->reserved_qpns.blk_list);

	return 0;

err_free_bf:
	free(context->bfs);

err_free:
	for (i = 0; i < MLX5_MAX_UARS; ++i) {
		if (context->uar[i].reg)
			munmap(context->uar[i].reg, page_size);
	}

	return -1;
}

static struct verbs_context *mlx5_alloc_context(struct ibv_device *ibdev,
						int cmd_fd,
						void *private_data)
{
	struct mlx5_context	       *context;
	struct mlx5_alloc_ucontext	req = {};
	struct mlx5_alloc_ucontext_resp resp = {};
	struct mlx5dv_context_attr      *ctx_attr = private_data;
	bool				always_devx = false;
	int ret;

	context = mlx5_init_context(ibdev, cmd_fd);
	if (!context)
		return NULL;

	if (ctx_attr && ctx_attr->comp_mask) {
		errno = EINVAL;
		goto err;
	}

	req.total_num_bfregs = context->tot_uuars;
	req.num_low_latency_bfregs = context->low_lat_uuars;
	req.max_cqe_version = MLX5_CQE_VERSION_V1;
	req.lib_caps |= (MLX5_LIB_CAP_4K_UAR | MLX5_LIB_CAP_DYN_UAR);
	if (ctx_attr && ctx_attr->flags) {

		if (!check_comp_mask(ctx_attr->flags,
				     MLX5DV_CONTEXT_FLAGS_DEVX)) {
			errno = EINVAL;
			goto err;
		}

		req.flags = MLX5_IB_ALLOC_UCTX_DEVX;
	} else {
		req.flags = MLX5_IB_ALLOC_UCTX_DEVX;
		always_devx = true;
	}

retry_open:
	if (mlx5_cmd_get_context(context, &req, sizeof(req), &resp,
				 sizeof(resp))) {
		if (always_devx) {
			req.flags &= ~MLX5_IB_ALLOC_UCTX_DEVX;
			always_devx = false;
			memset(&resp, 0, sizeof(resp));
			goto retry_open;
		} else {
			goto err;
		}
	}

	ret = mlx5_set_context(context, &resp.drv_payload, false);
	if (ret)
		goto err;

	return &context->ibv_ctx;

err:
	mlx5_uninit_context(context);
	return NULL;
}

static struct verbs_context *mlx5_import_context(struct ibv_device *ibdev,
						int cmd_fd)

{
	struct mlx5_ib_alloc_ucontext_resp resp = {};
	DECLARE_COMMAND_BUFFER_LINK(driver_attr, UVERBS_OBJECT_DEVICE,
				    UVERBS_METHOD_QUERY_CONTEXT, 1,
				    NULL);
	struct ibv_context *context;
	struct mlx5_context *mctx;
	int ret;

	mctx = mlx5_init_context(ibdev, cmd_fd);
	if (!mctx)
		return NULL;

	context = &mctx->ibv_ctx.context;

	fill_attr_out_ptr(driver_attr, MLX5_IB_ATTR_QUERY_CONTEXT_RESP_UCTX, &resp);
	ret = ibv_cmd_query_context(context, driver_attr);
	if (ret)
		goto err;

	ret = mlx5_set_context(mctx, &resp, true);
	if (ret)
		goto err;

	return &mctx->ibv_ctx;

err:
	mlx5_uninit_context(mctx);
	return NULL;
}

static void mlx5_free_context(struct ibv_context *ibctx)
{
	struct mlx5_context *context = to_mctx(ibctx);
	int page_size = to_mdev(ibctx->device)->page_size;
	int i;

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
	mlx5_close_debug_file(context->dbg_fp);
	clean_dyn_uars(ibctx);
	reserved_qpn_blks_free(context);

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

	mlx5_set_dv_ctx_ops(&mlx5_dv_ctx_ops);
	return &dev->verbs_dev;
}

static const struct verbs_device_ops mlx5_dev_ops = {
	.name = "mlx5",
	.match_min_abi_version = MLX5_UVERBS_MIN_ABI_VERSION,
	.match_max_abi_version = MLX5_UVERBS_MAX_ABI_VERSION,
	.match_table = mlx5_hca_table,
	.alloc_device = mlx5_device_alloc,
	.uninit_device = mlx5_uninit_device,
	.alloc_context = mlx5_alloc_context,
	.import_context = mlx5_import_context,
};

static bool is_mlx5_dev(struct ibv_device *device)
{
	struct verbs_device *verbs_device = verbs_get_device(device);

	return verbs_device->ops == &mlx5_dev_ops;
}

struct mlx5_dv_context_ops *mlx5_get_dv_ops(struct ibv_context *ibctx)
{
	if (is_mlx5_dev(ibctx->device))
		return to_mctx(ibctx)->dv_ctx_ops;
	else if (is_mlx5_vfio_dev(ibctx->device))
		return to_mvfio_ctx(ibctx)->dv_ctx_ops;
	else
		return NULL;
}
PROVIDER_DRIVER(mlx5, mlx5_dev_ops);
