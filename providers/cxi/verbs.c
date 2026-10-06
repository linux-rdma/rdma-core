// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright 2025 HPE. All rights reserved.
 */

#include <config.h>
#include <assert.h>
#include <stdio.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>

#include <infiniband/driver.h>
#include <util/util.h>
#include <infiniband/verbs.h>
#include <infiniband/cmd_write.h>
#include <util/util.h>
#include <util/mmio.h>
#include <util/udma_barrier.h>
#include <kernel-abi/cxiverbs-abi.h>
#include <rdma/cxiverbs-abi.h>

#include "cxiverbs-abi.h"
#include "cxi.h"
#include "cxi_le.h"
#include "cxi_verbs.h"
#include "cxidv.h"

static int cxi_resolve_addr(struct ibv_job *job, unsigned int addr_idx, struct cxi_ah *address);

static int cxi_parse_env_u32(const char *name, uint32_t max, uint32_t *out, bool *present)
{
	const char *value = getenv(name);
	char *end;
	unsigned long parsed;

	*present = false;
	if (!value || !*value)
		return 0;

	errno = 0;
	parsed = strtoul(value, &end, 0);
	if (errno || *end || parsed > max)
		return EINVAL;

	*out = parsed;
	*present = true;
	return 0;
}

int cxi_query_device(struct ibv_context *context, const struct ibv_query_device_ex_input *input,
		     struct ibv_device_attr_ex *attr, size_t attr_size)
{
	struct ib_uverbs_ex_query_device_resp resp;
	size_t resp_size = sizeof(resp);
	uint64_t raw_fw_ver;
	unsigned int major, minor, sub_minor;
	int ret;

	ret = ibv_cmd_query_device_any(context, input, attr, attr_size, &resp, &resp_size);
	if (ret)
		return ret;

	raw_fw_ver = resp.base.fw_ver;
	major = (raw_fw_ver >> 32) & 0xffff;
	minor = (raw_fw_ver >> 16) & 0xffff;
	sub_minor = raw_fw_ver & 0xffff;

	snprintf(attr->orig_attr.fw_ver, sizeof(attr->orig_attr.fw_ver), "%d.%d.%d", major, minor,
		 sub_minor);

	return 0;
}

int cxi_query_port(struct ibv_context *context, uint8_t port, struct ibv_port_attr *attr)
{
	struct ibv_query_port cmd;

	return ibv_cmd_query_port(context, port, attr, &cmd, sizeof(cmd));
}

struct ibv_job *cxi_alloc_job(struct ibv_context *context, struct ibv_job_attr *attr,
			      void *user_context)
{
	struct ibv_job *job;
	struct ib_uverbs_attr *handle;
	int ret;

	if (!attr || attr->comp_mask & ~(IBV_JOB_ATTR_ID | IBV_JOB_ATTR_MAX_ADDR_ENTRIES |
					 IBV_JOB_ATTR_PORT_NUM | IBV_JOB_ATTR_SGID_INDEX)) {
		errno = EINVAL;
		return NULL;
	}

	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_JOB, UVERBS_METHOD_JOB_ALLOC, 7);

	handle = fill_attr_out_obj(cmd, UVERBS_ATTR_ALLOC_JOB_HANDLE);
	if (attr->comp_mask & IBV_JOB_ATTR_ID)
		fill_attr_in_uint32(cmd, UVERBS_ATTR_ALLOC_JOB_ID, attr->id);
	fill_attr_in_uint32(cmd, UVERBS_ATTR_ALLOC_JOB_MAX_ADDR_ENTRIES,
			    attr->comp_mask & IBV_JOB_ATTR_MAX_ADDR_ENTRIES ?
			    attr->max_addr_entries : 0);
	if (attr->comp_mask & IBV_JOB_ATTR_PORT_NUM)
		fill_attr_in_uint32(cmd, UVERBS_ATTR_ALLOC_JOB_PORT_NUM, attr->port_num);
	if (attr->comp_mask & IBV_JOB_ATTR_SGID_INDEX)
		fill_attr_in_ptr(cmd, UVERBS_ATTR_ALLOC_JOB_SGID_INDEX, &attr->sgid_index);

	job = calloc(1, sizeof(*job));
	if (!job) {
		errno = ENOMEM;
		return NULL;
	}

	ret = execute_ioctl(context, cmd);
	if (ret) {
		free(job);
		errno = ret;
		return NULL;
	}

	job->handle = read_attr_obj(UVERBS_ATTR_ALLOC_JOB_HANDLE, handle);
	job->context = context;
	job->user_context = user_context;
	return job;
}

int cxi_dealloc_job(struct ibv_job *job)
{
	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_JOB, UVERBS_METHOD_JOB_DEALLOC, 1);
	int ret;

	fill_attr_in_obj(cmd, UVERBS_ATTR_DEALLOC_JOB_HANDLE, job->handle);
	ret = execute_ioctl(job->context, cmd);
	if (ret) {
		errno = ret;
		return -1;
	}

	free(job);
	return 0;
}

int cxi_query_job(struct ibv_job *job, struct ibv_job_attr *attr)
{
	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_JOB, UVERBS_METHOD_JOB_QUERY, 6);
	struct ibv_job_attr result = {};
	int ret;

	if (!job || !attr)
		return EINVAL;
	fill_attr_in_obj(cmd, UVERBS_ATTR_QUERY_JOB_HANDLE, job->handle);
	fill_attr_out_ptr(cmd, UVERBS_ATTR_QUERY_JOB_ID, &result.id);
	fill_attr_out_ptr(cmd, UVERBS_ATTR_QUERY_JOB_MAX_ADDR_ENTRIES, &result.max_addr_entries);
	fill_attr_out_ptr(cmd, UVERBS_ATTR_QUERY_JOB_PORT_NUM, &result.port_num);
	fill_attr_out_ptr(cmd, UVERBS_ATTR_QUERY_JOB_SGID_INDEX, &result.sgid_index);
	ret = execute_ioctl(job->context, cmd);
	if (!ret) {
		result.comp_mask = IBV_JOB_ATTR_ID | IBV_JOB_ATTR_MAX_ADDR_ENTRIES |
				   IBV_JOB_ATTR_PORT_NUM | IBV_JOB_ATTR_SGID_INDEX;
		*attr = result;
	}
	return ret;
}

static void cxi_ah_attr_to_uverbs(struct ib_uverbs_ah_attr_ex *dst,
				  const struct ibv_ah_attr_ex *src)
{
	const struct ibv_ah_attr *attr = &src->ah_attr;

	memcpy(dst->ah_attr.grh.dgid, attr->grh.dgid.raw, sizeof(dst->ah_attr.grh.dgid));
	dst->ah_attr.grh.flow_label = attr->grh.flow_label;
	dst->ah_attr.grh.sgid_index = attr->grh.sgid_index;
	dst->ah_attr.grh.hop_limit = attr->grh.hop_limit;
	dst->ah_attr.grh.traffic_class = attr->grh.traffic_class;
	dst->ah_attr.dlid = attr->dlid;
	dst->ah_attr.sl = attr->sl;
	dst->ah_attr.src_path_bits = attr->src_path_bits;
	dst->ah_attr.static_rate = attr->static_rate;
	dst->ah_attr.is_global = attr->is_global;
	dst->ah_attr.port_num = attr->port_num;
	dst->remote_qpn = src->remote_qpn;
}

static void cxi_ah_attr_from_uverbs(struct ibv_ah_attr_ex *dst,
				    const struct ib_uverbs_ah_attr_ex *src)
{
	struct ibv_ah_attr *attr = &dst->ah_attr;

	memcpy(attr->grh.dgid.raw, src->ah_attr.grh.dgid, sizeof(attr->grh.dgid.raw));
	attr->grh.flow_label = src->ah_attr.grh.flow_label;
	attr->grh.sgid_index = src->ah_attr.grh.sgid_index;
	attr->grh.hop_limit = src->ah_attr.grh.hop_limit;
	attr->grh.traffic_class = src->ah_attr.grh.traffic_class;
	attr->dlid = src->ah_attr.dlid;
	attr->sl = src->ah_attr.sl;
	attr->src_path_bits = src->ah_attr.src_path_bits;
	attr->static_rate = src->ah_attr.static_rate;
	attr->is_global = src->ah_attr.is_global;
	attr->port_num = src->ah_attr.port_num;
	dst->remote_qpn = src->remote_qpn;
}

int cxi_insert_addr(struct ibv_job *job, struct ibv_ah_attr_ex *ah_attr, unsigned int addr_idx)
{
	struct ib_uverbs_ah_attr_ex uah = {};

	if (!job || !ah_attr)
		return EINVAL;
	cxi_ah_attr_to_uverbs(&uah, ah_attr);
	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_JOB, UVERBS_METHOD_JOB_ADDR_INSERT, 3);

	fill_attr_in_obj(cmd, UVERBS_ATTR_JOB_ADDR_INSERT_HANDLE, job->handle);
	fill_attr_in_uint32(cmd, UVERBS_ATTR_JOB_ADDR_INSERT_INDEX, addr_idx);
	fill_attr_in(cmd, UVERBS_ATTR_JOB_ADDR_INSERT_AH_ATTR_EX, &uah, sizeof(uah));
	return execute_ioctl(job->context, cmd);
}

int cxi_remove_addr(struct ibv_job *job, unsigned int addr_idx)
{
	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_JOB, UVERBS_METHOD_JOB_ADDR_REMOVE, 2);

	if (!job)
		return EINVAL;
	fill_attr_in_obj(cmd, UVERBS_ATTR_JOB_ADDR_REMOVE_HANDLE, job->handle);
	fill_attr_in_uint32(cmd, UVERBS_ATTR_JOB_ADDR_REMOVE_INDEX, addr_idx);
	return execute_ioctl(job->context, cmd);
}

int cxi_query_addr(struct ibv_job *job, unsigned int addr_idx, struct ibv_ah_attr_ex *ah_attr)
{
	struct ib_uverbs_ah_attr_ex uah = {};
	int ret;

	if (!job || !ah_attr)
		return EINVAL;
	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_JOB, UVERBS_METHOD_JOB_ADDR_QUERY, 3);

	fill_attr_in_obj(cmd, UVERBS_ATTR_JOB_ADDR_QUERY_HANDLE, job->handle);
	fill_attr_in_uint32(cmd, UVERBS_ATTR_JOB_ADDR_QUERY_INDEX, addr_idx);
	fill_attr_out_ptr(cmd, UVERBS_ATTR_JOB_ADDR_QUERY_AH_ATTR_EX, &uah);
	ret = execute_ioctl(job->context, cmd);
	if (!ret)
		cxi_ah_attr_from_uverbs(ah_attr, &uah);
	return ret;
}

int cxi_export_job(struct ibv_job *job, int *fd)
{
	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_JOB, UVERBS_METHOD_JOB_EXPORT, 2);
	struct ib_uverbs_attr *handle;
	int ret;

	fill_attr_in_obj(cmd, UVERBS_ATTR_EXPORT_JOB_HANDLE, job->handle);
	handle = fill_attr_out_fd(cmd, UVERBS_ATTR_EXPORT_JOB_FD, 0);

	ret = execute_ioctl(job->context, cmd);
	if (ret) {
		errno = ret;
		return -1;
	}

	*fd = read_attr_fd(UVERBS_ATTR_EXPORT_JOB_FD, handle);
	return 0;
}

int cxi_import_job(struct ibv_context *context, int fd, struct ibv_job **job_out)
{
	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_JOB, UVERBS_METHOD_JOB_IMPORT, 2);
	struct ib_uverbs_attr *handle;
	struct ibv_job *job;
	int ret;

	handle = fill_attr_out_obj(cmd, UVERBS_ATTR_IMPORT_JOB_HANDLE);
	fill_attr_in_fd(cmd, UVERBS_ATTR_IMPORT_JOB_FD, fd);

	job = calloc(1, sizeof(*job));
	if (!job) {
		errno = ENOMEM;
		return -1;
	}

	ret = execute_ioctl(context, cmd);
	if (ret) {
		free(job);
		errno = ret;
		return -1;
	}

	job->handle = read_attr_obj(UVERBS_ATTR_IMPORT_JOB_HANDLE, handle);
	job->context = context;
	*job_out = job;
	return 0;
}

struct ibv_job_key *cxi_create_jkey(struct ibv_pd *pd, struct ibv_job *job)
{
	struct ibv_job_key *job_key;
	struct cxi_job_key *provider_key;
	struct cxi_pd *provider_pd = to_cxi_pd(pd);
	struct ibv_job_attr job_attr = {};
	struct ib_uverbs_attr *handle;
	uint32_t jkey;
	struct cxi_ibv_create_jkey_cmd profile = {
		.tc = CXIDV_TC_BEST_EFFORT,
	};
	const char *traffic_class = getenv("UET_TC");
	int ret;

	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_JKEY, UVERBS_METHOD_JKEY_CREATE, 6);

	if (traffic_class) {
		char *end;
		unsigned long value;

		errno = 0;
		value = strtoul(traffic_class, &end, 0);
		if (errno || *end || value > CXIDV_TC_ETH) {
			errno = EINVAL;
			return NULL;
		}
		profile.tc = value;
	}

	handle = fill_attr_out_obj(cmd, UVERBS_ATTR_CREATE_JKEY_HANDLE);
	fill_attr_in_obj(cmd, UVERBS_ATTR_CREATE_JKEY_PD_HANDLE, pd->handle);
	fill_attr_in_obj(cmd, UVERBS_ATTR_CREATE_JKEY_JOB_HANDLE, job->handle);
	fill_attr_out_ptr(cmd, UVERBS_ATTR_CREATE_JKEY_JKEY, &jkey);
	fill_attr_in(cmd, UVERBS_ATTR_UHW_IN, &profile, sizeof(profile));

	provider_key = calloc(1, sizeof(*provider_key));
	if (!provider_key) {
		errno = ENOMEM;
		return NULL;
	}
	job_key = &provider_key->key;
	provider_key->job = job;
	if (ibv_query_job(job, &job_attr)) {
		free(provider_key);
		return NULL;
	}
	provider_key->job_id = job_attr.id;

	ret = execute_ioctl(pd->context, cmd);
	if (ret) {
		free(provider_key);
		errno = ret;
		return NULL;
	}

	job_key->handle = read_attr_obj(UVERBS_ATTR_CREATE_JKEY_HANDLE, handle);
	job_key->jkey = jkey;
	job_key->pd = pd;
	pthread_spin_lock(&provider_pd->jkey_lock);
	provider_key->next = provider_pd->jkeys;
	provider_pd->jkeys = provider_key;
	pthread_spin_unlock(&provider_pd->jkey_lock);
	return job_key;
}

int cxi_destroy_jkey(struct ibv_job_key *job_key)
{
	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_JKEY, UVERBS_METHOD_JKEY_DESTROY, 1);
	struct cxi_pd *pd = to_cxi_pd(job_key->pd);
	struct cxi_job_key **entry;
	int ret;

	fill_attr_in_obj(cmd, UVERBS_ATTR_DESTROY_JKEY_HANDLE, job_key->handle);
	ret = execute_ioctl(job_key->pd->context, cmd);
	if (ret) {
		errno = ret;
		return -1;
	}

	pthread_spin_lock(&pd->jkey_lock);
	for (entry = &pd->jkeys; *entry; entry = &(*entry)->next) {
		if (&(*entry)->key == job_key) {
			*entry = (*entry)->next;
			break;
		}
	}
	pthread_spin_unlock(&pd->jkey_lock);
	free(job_key);
	return 0;
}

int cxidv_query_device(struct ibv_context *ibvctx, struct cxidv_devinfo *attr)
{
	struct cxi_context *ctx = to_cxi_ctx(ibvctx);
	const struct cxi_ibv_devinfo *di = &ctx->devinfo;

	if (!is_cxi_dev(ibvctx->device))
		return EOPNOTSUPP;

	/* di is all-zero if cxi_alloc_context()'s query_device call failed */
	if (!di->pid_bits && !di->nid && !di->vendor_id)
		return EOPNOTSUPP;

	memset(attr, 0, sizeof(*attr));
	attr->nid = di->nid;
	attr->pid_bits = di->pid_bits;
	attr->pid_count = di->pid_count;
	attr->pid_granule = di->pid_granule;
	attr->min_free_shift = di->min_free_shift;
	attr->rdzv_get_idx = di->rdzv_get_idx;
	attr->vendor_id = di->vendor_id;
	attr->device_id = di->device_id;
	attr->device_rev = di->device_rev;
	attr->device_proto = di->device_proto;
	attr->device_platform = di->device_platform;
	attr->pct_eq = di->pct_eq;
	attr->uc_nic = di->uc_nic;
	attr->link_mtu = di->link_mtu;
	attr->link_speed = di->link_speed;
	attr->link_state = di->link_state;
	attr->num_ptes = di->num_ptes;
	attr->num_txqs = di->num_txqs;
	attr->num_tgqs = di->num_tgqs;
	attr->num_eqs = di->num_eqs;
	attr->num_cts = di->num_cts;
	attr->num_acs = di->num_acs;
	attr->num_tles = di->num_tles;
	attr->num_les = di->num_les;
	attr->cassini_version = di->cassini_version;
	attr->system_type_identifier = di->system_type_identifier;
	memcpy(attr->fru_description, di->fru_description, sizeof(attr->fru_description));

	return 0;
}

int cxidv_cq_from_ibv_cq(struct ibv_cq *ibvcq, struct cxidv_cq *attr)
{
	struct cxi_ibv_cq *cq = to_cxi_ibv_cq(ibvcq);

	if (!is_cxi_dev(ibvcq->context->device))
		return EOPNOTSUPP;

	memset(attr, 0, sizeof(*attr));
	attr->eq_buf = cq->eq_buf;
	attr->eq_buf_size = cq->eq_buf_size;
	attr->eq_db = cq->eq_db;
	attr->eq_db_size = cq->eq_db_size;
	attr->eqn = cq->eqn;

	return 0;
}

int cxidv_qp_from_ibv_qp(struct ibv_qp *ibvqp, struct cxidv_qp *attr)
{
	struct cxi_qp *qp = to_cxi_qp(ibvqp);

	if (!is_cxi_dev(ibvqp->context->device))
		return EOPNOTSUPP;

	memset(attr, 0, sizeof(*attr));
	attr->txq_cmds = qp->txq_cmds;
	attr->txq_cmds_size = qp->txq_cmds_size;
	attr->txq_db = qp->txq_db;
	attr->txq_db_size = qp->txq_db_size;
	attr->txq_idx = qp->txq_idx;
	attr->lcid = qp->lcid;
	attr->tgq_cmds = qp->tgq_cmds;
	attr->tgq_cmds_size = qp->tgq_cmds_size;
	attr->tgq_db = qp->tgq_db;
	attr->tgq_db_size = qp->tgq_db_size;
	attr->tgq_idx = qp->tgq_idx;
	attr->pte_index = qp->pte_index;

	return 0;
}

/*
 * Change the src_id (see IBV_RU_ATTR_SRC_ID) this QP reports to its peers.
 * Purely a local relabeling: nothing about it is known to the kernel or the
 * wire beyond the initiator field of each command this QP builds from here
 * on, so there is no round trip. Serialized against post_send/wr_* via
 * sq_lock so a send never mixes half of an old and half of a new value.
 */
int cxidv_modify_qp_src_id(struct ibv_qp *ibvqp, uint32_t src_id)
{
	struct cxi_qp *qp = to_cxi_qp(ibvqp);

	if (!is_cxi_dev(ibvqp->context->device))
		return EOPNOTSUPP;

	pthread_spin_lock(&qp->sq_lock);
	qp->src_id = src_id;
	pthread_spin_unlock(&qp->sq_lock);

	return 0;
}

static void cxi_tc_cache_update(struct cxi_context *ctx, uint32_t tc, uint32_t svc_id,
				bool update_svc_id)
{
	pthread_mutex_lock(&ctx->tc_lock);
	ctx->tc = tc;
	ctx->tc_valid = true;
	if (update_svc_id)
		ctx->preferred_svc_id = svc_id;
	pthread_mutex_unlock(&ctx->tc_lock);
}

static bool cxi_tc_cache_read(struct cxi_context *ctx, uint32_t *tc, uint32_t *svc_id)
{
	bool valid;

	pthread_mutex_lock(&ctx->tc_lock);
	valid = ctx->tc_valid;
	if (valid) {
		if (tc)
			*tc = ctx->tc;
		if (svc_id)
			*svc_id = ctx->preferred_svc_id;
	}
	pthread_mutex_unlock(&ctx->tc_lock);

	return valid;
}

static void cxi_fill_job_tc_limit(struct ibv_command_buffer *cmd, int max_attr, int res_attr,
				  const struct cxidv_limits *limit)
{
	fill_attr_in(cmd, max_attr, &limit->max, sizeof(limit->max));
	fill_attr_in(cmd, res_attr, &limit->res, sizeof(limit->res));
}

int cxidv_bind_job_tc(struct ibv_context *ibvctx, struct cxidv_job_tc_attr *attr)
{
	struct cxi_context *ctx = to_cxi_ctx(ibvctx);
	uint32_t bound_svc_id;
	int ret;

	if (!is_cxi_dev(ibvctx->device))
		return EOPNOTSUPP;
	if (!attr)
		return EINVAL;
	if (attr->flags & ~CXIDV_JOB_TC_F_CREATE)
		return EINVAL;

	DECLARE_COMMAND_BUFFER(cmd, CXI_IB_OBJECT_JOB_TC, CXI_IB_METHOD_JOB_TC_BIND, 22);

	fill_attr_in_uint32(cmd, CXI_IB_ATTR_JOB_TC_BIND_FLAGS, attr->flags);
	fill_attr_in_uint32(cmd, CXI_IB_ATTR_JOB_TC_BIND_JOB_ID, attr->job_id);
	fill_attr_in_uint32(cmd, CXI_IB_ATTR_JOB_TC_BIND_TC, attr->tc);
	fill_attr_in_uint32(cmd, CXI_IB_ATTR_JOB_TC_BIND_TC_TYPE, attr->tc_type);
	if (attr->svc_id)
		fill_attr_in_uint32(cmd, CXI_IB_ATTR_JOB_TC_BIND_SVC_ID, attr->svc_id);
	cxi_fill_job_tc_limit(cmd, CXI_IB_ATTR_JOB_TC_BIND_PTES_MAX,
			      CXI_IB_ATTR_JOB_TC_BIND_PTES_RES, &attr->ptes);
	cxi_fill_job_tc_limit(cmd, CXI_IB_ATTR_JOB_TC_BIND_TXQS_MAX,
			      CXI_IB_ATTR_JOB_TC_BIND_TXQS_RES, &attr->txqs);
	cxi_fill_job_tc_limit(cmd, CXI_IB_ATTR_JOB_TC_BIND_TGQS_MAX,
			      CXI_IB_ATTR_JOB_TC_BIND_TGQS_RES, &attr->tgqs);
	cxi_fill_job_tc_limit(cmd, CXI_IB_ATTR_JOB_TC_BIND_EQS_MAX, CXI_IB_ATTR_JOB_TC_BIND_EQS_RES,
			      &attr->eqs);
	cxi_fill_job_tc_limit(cmd, CXI_IB_ATTR_JOB_TC_BIND_CTS_MAX, CXI_IB_ATTR_JOB_TC_BIND_CTS_RES,
			      &attr->cts);
	cxi_fill_job_tc_limit(cmd, CXI_IB_ATTR_JOB_TC_BIND_LES_MAX, CXI_IB_ATTR_JOB_TC_BIND_LES_RES,
			      &attr->les);
	cxi_fill_job_tc_limit(cmd, CXI_IB_ATTR_JOB_TC_BIND_TLES_MAX,
			      CXI_IB_ATTR_JOB_TC_BIND_TLES_RES, &attr->tles);
	cxi_fill_job_tc_limit(cmd, CXI_IB_ATTR_JOB_TC_BIND_ACS_MAX, CXI_IB_ATTR_JOB_TC_BIND_ACS_RES,
			      &attr->acs);
	fill_attr_out_ptr(cmd, CXI_IB_ATTR_JOB_TC_BIND_RESP_SVC_ID, &bound_svc_id);

	ret = execute_ioctl(ibvctx, cmd);
	if (ret)
		return ret;

	attr->bound_svc_id = bound_svc_id;
	cxi_tc_cache_update(ctx, attr->tc, bound_svc_id, true);

	return 0;
}

int cxidv_set_default_tc(struct ibv_context *ibvctx, uint32_t tc)
{
	struct cxi_context *ctx = to_cxi_ctx(ibvctx);

	if (!is_cxi_dev(ibvctx->device))
		return EOPNOTSUPP;
	if (tc >= CXI_IBV_TC_MAX)
		return EINVAL;

	cxi_tc_cache_update(ctx, tc, 0, false);

	return 0;
}

int cxidv_clear_job_tc(struct ibv_context *ibvctx, uint32_t tc, uint32_t tc_type)
{
	int ret;

	if (!is_cxi_dev(ibvctx->device))
		return EOPNOTSUPP;

	DECLARE_COMMAND_BUFFER(cmd, CXI_IB_OBJECT_JOB_TC, CXI_IB_METHOD_JOB_TC_CLEAR, 2);

	fill_attr_in_uint32(cmd, CXI_IB_ATTR_JOB_TC_CLEAR_TC, tc);
	fill_attr_in_uint32(cmd, CXI_IB_ATTR_JOB_TC_CLEAR_TC_TYPE, tc_type);

	ret = execute_ioctl(ibvctx, cmd);
	return ret;
}

int cxidv_query_tcs(struct ibv_context *ibvctx, struct cxidv_tc_entry *entries,
		    uint32_t max_entries, uint32_t *count)
{
	struct cxi_ibv_tc_entry *kentries;
	uint32_t kcount = 0;
	uint32_t copied;
	int ret;
	uint32_t i;

	if (!is_cxi_dev(ibvctx->device))
		return EOPNOTSUPP;
	if (!count || (max_entries && !entries))
		return EINVAL;

	kentries = calloc(max_entries ? max_entries : 1, sizeof(*kentries));
	if (!kentries)
		return ENOMEM;

	DECLARE_COMMAND_BUFFER(cmd, CXI_IB_OBJECT_JOB_TC, CXI_IB_METHOD_JOB_TC_QUERY, 3);

	fill_attr_in_uint32(cmd, CXI_IB_ATTR_JOB_TC_QUERY_MAX_ENTRIES, max_entries);
	fill_attr_out_ptr(cmd, CXI_IB_ATTR_JOB_TC_QUERY_RESP_COUNT, &kcount);
	fill_attr_out_ptr_array(cmd, CXI_IB_ATTR_JOB_TC_QUERY_RESP_ENTRIES, kentries, max_entries);

	ret = execute_ioctl(ibvctx, cmd);
	if (ret) {
		free(kentries);
		return ret;
	}

	*count = kcount;
	copied = kcount < max_entries ? kcount : max_entries;
	for (i = 0; i < copied; i++) {
		entries[i].tc = kentries[i].tc;
		entries[i].tc_type = kentries[i].tc_type;
		entries[i].res_req_dscp = kentries[i].res_req_dscp;
		entries[i].unres_req_dscp = kentries[i].unres_req_dscp;
		entries[i].res_rsp_dscp = kentries[i].res_rsp_dscp;
		entries[i].unres_rsp_dscp = kentries[i].unres_rsp_dscp;
		entries[i].req_pcp = kentries[i].req_pcp;
		entries[i].rsp_pcp = kentries[i].rsp_pcp;
		entries[i].ocuset = kentries[i].ocuset;
		entries[i].cq_tc = kentries[i].cq_tc;
		entries[i].req_bc = kentries[i].req_bc;
		entries[i].flags = kentries[i].flags;
	}

	free(kentries);
	return 0;
}

static int validate_svc_vni_policy(const struct cxidv_svc_attr *attr)
{
	uint32_t index;
	uint32_t previous;

	if (attr->is_system_svc > 1 || attr->is_range > 1 || attr->vni_min || attr->vni_max ||
	    attr->flags & ~(CXIDV_SVC_LIMITS | CXIDV_SVC_CREATE_TC))
		return EINVAL;
	if (attr->is_range) {
		if (attr->is_system_svc || attr->vni_count || !attr->vnis[0] ||
		    attr->vnis[0] > attr->vnis[1] || attr->vnis[2] || attr->vnis[3])
			return EINVAL;
		return 0;
	}
	if (attr->is_system_svc) {
		if (attr->svc_id || attr->vni_count || attr->tc_mask ||
		    (attr->flags & CXIDV_SVC_CREATE_TC) || !(attr->flags & CXIDV_SVC_LIMITS))
			return EINVAL;
		for (index = 0; index < CXIDV_SVC_RSRC_COUNT; index++) {
			uint16_t expected =
				index == CXIDV_SVC_EQS || index == CXIDV_SVC_ACS ? 1 : 0;

			if (attr->maximum[index] != expected || attr->reserved[index] != expected)
				return EINVAL;
		}
		for (index = 0; index < CXIDV_SVC_MAX_VNIS; index++)
			if (attr->vnis[index])
				return EINVAL;
		return 0;
	}
	if (!attr->vni_count || attr->vni_count > CXIDV_SVC_MAX_VNIS || !attr->tc_mask)
		return EINVAL;
	for (index = 0; index < CXIDV_SVC_MAX_VNIS; index++) {
		if (index >= attr->vni_count) {
			if (attr->vnis[index])
				return EINVAL;
			continue;
		}
		if (!attr->vnis[index])
			return EINVAL;
		for (previous = 0; previous < index; previous++)
			if (attr->vnis[index] == attr->vnis[previous])
				return EINVAL;
	}
	return 0;
}

int cxidv_alloc_svc(struct ibv_context *context, const struct cxidv_svc_attr *attr,
		    uint32_t *svc_id)
{
	DECLARE_COMMAND_BUFFER(cmd, CXI_IB_OBJECT_SVC, CXI_IB_METHOD_SVC_ALLOC, 2);
	struct cxi_ibv_svc_config config;

	static_assert(CXIDV_SVC_MAX_VNIS == CXI_IB_SVC_MAX_VNIS, "service VNI limit");
	static_assert(sizeof(config) == sizeof(*attr), "service ABI layout");
	if (!context || !attr || !svc_id)
		return EINVAL;
	if (validate_svc_vni_policy(attr))
		return EINVAL;
	if (!is_cxi_dev(context->device))
		return EOPNOTSUPP;
	memcpy(&config, attr, sizeof(config));
	fill_attr_in(cmd, CXI_IB_ATTR_SVC_CONFIG, &config, sizeof(config));
	fill_attr_out_ptr(cmd, CXI_IB_ATTR_SVC_ID, svc_id);
	return execute_ioctl(context, cmd);
}

int cxidv_query_svc(struct ibv_context *context, uint32_t svc_id, struct cxidv_svc_attr *attr)
{
	DECLARE_COMMAND_BUFFER(cmd, CXI_IB_OBJECT_SVC, CXI_IB_METHOD_SVC_QUERY, 2);
	struct cxi_ibv_svc_config config = {};
	int ret;

	if (!context || !attr)
		return EINVAL;
	if (!is_cxi_dev(context->device))
		return EOPNOTSUPP;
	fill_attr_in_uint32(cmd, CXI_IB_ATTR_SVC_ID, svc_id);
	fill_attr_out_ptr(cmd, CXI_IB_ATTR_SVC_CONFIG, &config);
	ret = execute_ioctl(context, cmd);
	if (!ret)
		memcpy(attr, &config, sizeof(config));
	return ret;
}

int cxidv_svc_is_enabled(struct ibv_context *context, uint32_t svc_id, int *enable)
{
	DECLARE_COMMAND_BUFFER(cmd, CXI_IB_OBJECT_SVC, CXI_IB_METHOD_SVC_QUERY, 2);
	uint32_t flags = 0;
	int ret;

	if (!context || !enable)
		return EINVAL;
	if (!is_cxi_dev(context->device))
		return EOPNOTSUPP;
	fill_attr_in_uint32(cmd, CXI_IB_ATTR_SVC_ID, svc_id);
	fill_attr_out_ptr(cmd, CXI_IB_ATTR_SVC_FLAGS, &flags);
	ret = execute_ioctl(context, cmd);
	if (!ret)
		*enable = !!(flags & CXI_IB_SVC_ENABLED);
	return ret;
}

int cxidv_get_svc_rsrc_use(struct ibv_context *context, uint32_t svc_id,
			   struct cxidv_svc_rsrc_use *usage)
{
	DECLARE_COMMAND_BUFFER(cmd, CXI_IB_OBJECT_SVC, CXI_IB_METHOD_SVC_QUERY, 2);
	struct cxi_ibv_svc_rsrc_use response;
	int ret;

	if (!context || !usage)
		return EINVAL;
	if (!is_cxi_dev(context->device))
		return EOPNOTSUPP;
	static_assert(sizeof(response) == sizeof(*usage), "service usage layout");
	fill_attr_in_uint32(cmd, CXI_IB_ATTR_SVC_ID, svc_id);
	fill_attr_out_ptr(cmd, CXI_IB_ATTR_SVC_USAGE, &response);
	ret = execute_ioctl(context, cmd);
	if (!ret)
		memcpy(usage, &response, sizeof(response));
	return ret;
}

int cxidv_get_svc_lpr(struct ibv_context *context, uint32_t svc_id, uint32_t *lpr)
{
	DECLARE_COMMAND_BUFFER(cmd, CXI_IB_OBJECT_SVC, CXI_IB_METHOD_SVC_QUERY, 2);

	if (!context || !lpr)
		return EINVAL;
	if (!is_cxi_dev(context->device))
		return EOPNOTSUPP;
	fill_attr_in_uint32(cmd, CXI_IB_ATTR_SVC_ID, svc_id);
	fill_attr_out_ptr(cmd, CXI_IB_ATTR_SVC_LPR, lpr);
	return execute_ioctl(context, cmd);
}

int cxidv_destroy_svc(struct ibv_context *context, uint32_t svc_id)
{
	DECLARE_COMMAND_BUFFER(cmd, CXI_IB_OBJECT_SVC, CXI_IB_METHOD_SVC_DESTROY, 1);

	if (!context)
		return EINVAL;
	if (!is_cxi_dev(context->device))
		return EOPNOTSUPP;
	fill_attr_in_uint32(cmd, CXI_IB_ATTR_SVC_ID, svc_id);
	return execute_ioctl(context, cmd);
}

int cxidv_enable_svc(struct ibv_context *context, uint32_t svc_id, int enable)
{
	DECLARE_COMMAND_BUFFER(cmd, CXI_IB_OBJECT_SVC, CXI_IB_METHOD_SVC_ENABLE, 2);

	if (!context || (enable != 0 && enable != 1))
		return EINVAL;
	if (!is_cxi_dev(context->device))
		return EOPNOTSUPP;
	fill_attr_in_uint32(cmd, CXI_IB_ATTR_SVC_ID, svc_id);
	fill_attr_in_uint32(cmd, CXI_IB_ATTR_SVC_FLAGS, enable);
	return execute_ioctl(context, cmd);
}

int cxidv_alloc_lni(struct ibv_context *context, uint32_t svc_id, struct cxidv_lni **out)
{
	DECLARE_COMMAND_BUFFER(cmd, CXI_IB_OBJECT_LNI, CXI_IB_METHOD_LNI_ALLOC, 3);
	struct ib_uverbs_attr *handle;
	struct cxidv_lni *lni;
	int ret;

	if (!context || !out || !svc_id)
		return EINVAL;
	if (!is_cxi_dev(context->device))
		return EOPNOTSUPP;
	*out = NULL;
	lni = calloc(1, sizeof(*lni));
	if (!lni)
		return ENOMEM;
	handle = fill_attr_out_obj(cmd, CXI_IB_ATTR_LNI_ALLOC_HANDLE);
	fill_attr_in_uint32(cmd, CXI_IB_ATTR_LNI_ALLOC_SVC_ID, svc_id);
	fill_attr_out_ptr(cmd, CXI_IB_ATTR_LNI_ALLOC_ID, &lni->id);
	ret = execute_ioctl(context, cmd);
	if (ret) {
		free(lni);
		return ret;
	}
	lni->context = context;
	lni->handle = read_attr_obj(CXI_IB_ATTR_LNI_ALLOC_HANDLE, handle);
	lni->svc_id = svc_id;
	*out = lni;
	return 0;
}

int cxidv_alloc_cp(struct cxidv_lni *lni, uint32_t vni, uint32_t tc, uint32_t type,
		   struct cxidv_cp **out)
{
	DECLARE_COMMAND_BUFFER(cmd, CXI_IB_OBJECT_CP, CXI_IB_METHOD_CP_ALLOC, 6);
	struct ib_uverbs_attr *handle;
	struct cxi_ibv_cp_info info;
	struct cxidv_cp *cp;
	int ret;

	if (!lni || !out)
		return EINVAL;
	cp = calloc(1, sizeof(*cp));
	if (!cp)
		return ENOMEM;
	handle = fill_attr_out_obj(cmd, CXI_IB_ATTR_CP_HANDLE);
	fill_attr_in_uint32(cmd, CXI_IB_ATTR_CP_LNI, lni->handle);
	fill_attr_in_uint32(cmd, CXI_IB_ATTR_CP_VNI, vni);
	fill_attr_in_uint32(cmd, CXI_IB_ATTR_CP_TC, tc);
	fill_attr_in_uint32(cmd, CXI_IB_ATTR_CP_TYPE, type);
	fill_attr_out_ptr(cmd, CXI_IB_ATTR_CP_INFO, &info);
	ret = execute_ioctl(lni->context, cmd);
	if (ret) {
		free(cp);
		return ret;
	}
	cp->lni = lni;
	cp->handle = read_attr_obj(CXI_IB_ATTR_CP_HANDLE, handle);
	cp->vni = info.vni;
	cp->tc = info.tc;
	cp->type = info.type;
	cp->lcid = info.lcid;
	*out = cp;
	return 0;
}

int cxidv_destroy_cp(struct cxidv_cp *cp)
{
	DECLARE_COMMAND_BUFFER(cmd, CXI_IB_OBJECT_CP, CXI_IB_METHOD_CP_DESTROY, 1);
	int ret;

	if (!cp)
		return EINVAL;
	fill_attr_in_obj(cmd, CXI_IB_ATTR_CP_HANDLE, cp->handle);
	ret = execute_ioctl(cp->lni->context, cmd);
	if (!ret)
		free(cp);
	return ret;
}

int cxidv_destroy_cmdq(struct cxidv_cmdq *cmdq)
{
	DECLARE_COMMAND_BUFFER(cmd, CXI_IB_OBJECT_CMDQ, CXI_IB_METHOD_CMDQ_DESTROY, 1);
	int ret;

	if (!cmdq)
		return EINVAL;
	fill_attr_in_obj(cmd, CXI_IB_ATTR_CMDQ_HANDLE, cmdq->handle);
	/* Kernel CMDQ cleanup cannot fail, so there is nothing to retry. */
	ret = execute_ioctl(cmdq->lni->context, cmd);
	if (cmdq->doorbell && munmap(cmdq->doorbell, cmdq->doorbell_size) && !ret)
		ret = errno;
	if (cmdq->commands && munmap(cmdq->commands, cmdq->commands_size) && !ret)
		ret = errno;
	free(cmdq);
	return ret;
}

static int cxidv_alloc_cmdq_flags(struct cxidv_lni *lni, uint32_t count, uint32_t flags,
				  struct cxidv_cmdq **out)
{
	DECLARE_COMMAND_BUFFER(cmd, CXI_IB_OBJECT_CMDQ, CXI_IB_METHOD_CMDQ_ALLOC, 5);
	struct cxi_ibv_cmdq_info info = {};
	struct ib_uverbs_attr *handle;
	struct cxidv_cmdq *cmdq;
	int ret;

	if (!lni || !out)
		return EINVAL;
	*out = NULL;
	if (!count)
		return EINVAL;
	cmdq = calloc(1, sizeof(*cmdq));
	if (!cmdq)
		return ENOMEM;
	handle = fill_attr_out_obj(cmd, CXI_IB_ATTR_CMDQ_HANDLE);
	fill_attr_in_uint32(cmd, CXI_IB_ATTR_CMDQ_LNI, lni->handle);
	fill_attr_in_uint32(cmd, CXI_IB_ATTR_CMDQ_COUNT, count);
	fill_attr_in_uint32(cmd, CXI_IB_ATTR_CMDQ_FLAGS, flags);
	fill_attr_out_ptr(cmd, CXI_IB_ATTR_CMDQ_INFO, &info);
	ret = execute_ioctl(lni->context, cmd);
	if (ret) {
		free(cmdq);
		return ret;
	}
	cmdq->lni = lni;
	cmdq->handle = read_attr_obj(CXI_IB_ATTR_CMDQ_HANDLE, handle);
	if (!info.commands_length || !info.doorbell_length || !info.count ||
	    info.commands_length > SIZE_MAX || info.doorbell_length > SIZE_MAX ||
	    (uint64_t)info.count * sizeof(struct cxi_cmd64) > info.commands_length) {
		ret = EPROTO;
		goto fail;
	}
	cmdq->count = info.count;
	cmdq->index = info.index;
	cmdq->commands_size = info.commands_length;
	cmdq->commands_offset = info.commands_offset;
	cmdq->doorbell_size = info.doorbell_length;
	cmdq->commands = mmap(NULL, cmdq->commands_size, PROT_READ | PROT_WRITE, MAP_SHARED,
			      lni->context->cmd_fd, info.commands_offset);
	if (cmdq->commands == MAP_FAILED) {
		ret = errno;
		cmdq->commands = NULL;
		goto fail;
	}
	cmdq->doorbell = mmap(NULL, cmdq->doorbell_size, PROT_READ | PROT_WRITE, MAP_SHARED,
			      lni->context->cmd_fd, info.doorbell_offset);
	if (cmdq->doorbell == MAP_FAILED) {
		ret = errno;
		cmdq->doorbell = NULL;
		goto fail;
	}
	*out = cmdq;
	return 0;
fail:
	cxidv_destroy_cmdq(cmdq);
	return ret;
}

int cxidv_alloc_cmdq(struct cxidv_lni *lni, uint32_t count, struct cxidv_cmdq **out)
{
	return cxidv_alloc_cmdq_flags(lni, count, 0, out);
}

int cxidv_alloc_trigger_cmdq(struct cxidv_lni *lni, uint32_t count, struct cxidv_cmdq **out)
{
	return cxidv_alloc_cmdq_flags(lni, count, CXI_IB_CMDQ_TRIGGER, out);
}

int cxidv_inbound_wait(struct ibv_context *context)
{
	DECLARE_COMMAND_BUFFER(cmd, CXI_IB_OBJECT_CSR, CXI_IB_METHOD_CSR_INBOUND_WAIT, 0);

	if (!context)
		return EINVAL;
	return execute_ioctl(context, cmd);
}

int cxidv_destroy_ct(struct cxidv_ct *ct)
{
	DECLARE_COMMAND_BUFFER(cmd, CXI_IB_OBJECT_CT, CXI_IB_METHOD_CT_DESTROY, 1);
	int ret;

	if (!ct)
		return EINVAL;
	fill_attr_in_obj(cmd, CXI_IB_ATTR_CT_DESTROY_HANDLE, ct->handle);
	/* Kernel CT cleanup cannot fail, so there is nothing to retry. */
	ret = execute_ioctl(ct->lni->context, cmd);
	if (ct->doorbell && munmap(ct->doorbell, ct->doorbell_size) && !ret)
		ret = errno;
	if (ct->writeback && munmap(ct->writeback, ct->writeback_size) && !ret)
		ret = errno;
	free(ct);
	return ret;
}

static int cxidv_alloc_ct_address(struct cxidv_lni *lni, void *writeback, struct cxidv_ct **out)
{
	DECLARE_COMMAND_BUFFER(cmd, CXI_IB_OBJECT_CT, CXI_IB_METHOD_CT_ALLOC, 8);
	struct ib_uverbs_attr *handle;
	long page_size = sysconf(_SC_PAGESIZE);
	void *source;
	uint64_t source_address;
	uint64_t writeback_size = 0;
	uint64_t doorbell_size = 0;
	uint64_t doorbell_offset = 0;
	struct cxidv_ct *ct;
	int ret;

	if (!lni || !out || page_size <= 0)
		return EINVAL;
	*out = NULL;
	if (writeback && (uintptr_t)writeback % page_size)
		return EINVAL;
	ct = calloc(1, sizeof(*ct));
	if (!ct)
		return ENOMEM;
	source = writeback;
	if (!source) {
		source = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
			      -1, 0);
		if (source == MAP_FAILED) {
			ret = errno;
			free(ct);
			return ret;
		}
	}
	source_address = (uint64_t)(uintptr_t)source;
	handle = fill_attr_out_obj(cmd, CXI_IB_ATTR_CT_ALLOC_HANDLE);
	fill_attr_in(cmd, CXI_IB_ATTR_CT_ALLOC_WB_ADDRESS, &source_address, sizeof(source_address));
	fill_attr_in_uint32(cmd, CXI_IB_ATTR_CT_ALLOC_LNI_HANDLE, lni->handle);
	fill_attr_out_ptr(cmd, CXI_IB_ATTR_CT_ALLOC_CTN, &ct->ctn);
	fill_attr_out_ptr(cmd, CXI_IB_ATTR_CT_ALLOC_WB_MMAP_OFFSET, &ct->writeback_offset);
	fill_attr_out_ptr(cmd, CXI_IB_ATTR_CT_ALLOC_WB_MMAP_LENGTH, &writeback_size);
	fill_attr_out_ptr(cmd, CXI_IB_ATTR_CT_ALLOC_DB_MMAP_OFFSET, &doorbell_offset);
	fill_attr_out_ptr(cmd, CXI_IB_ATTR_CT_ALLOC_DB_MMAP_LENGTH, &doorbell_size);
	ret = execute_ioctl(lni->context, cmd);
	if (!writeback)
		munmap(source, page_size);
	if (ret) {
		free(ct);
		return ret;
	}
	ct->lni = lni;
	ct->handle = read_attr_obj(CXI_IB_ATTR_CT_ALLOC_HANDLE, handle);
	if (!writeback_size || !doorbell_size || writeback_size > SIZE_MAX ||
	    doorbell_size > SIZE_MAX) {
		ret = EPROTO;
		goto fail;
	}
	ct->writeback_size = writeback_size;
	ct->doorbell_size = doorbell_size;
	ct->writeback = mmap(NULL, ct->writeback_size, PROT_READ | PROT_WRITE, MAP_SHARED,
			     lni->context->cmd_fd, ct->writeback_offset);
	if (ct->writeback == MAP_FAILED) {
		ret = errno;
		ct->writeback = NULL;
		goto fail;
	}
	ct->doorbell = mmap(NULL, ct->doorbell_size, PROT_READ | PROT_WRITE, MAP_SHARED,
			    lni->context->cmd_fd, doorbell_offset);
	if (ct->doorbell == MAP_FAILED) {
		ret = errno;
		ct->doorbell = NULL;
		goto fail;
	}
	*out = ct;
	return 0;
fail:
	cxidv_destroy_ct(ct);
	return ret;
}

int cxidv_alloc_ct(struct cxidv_lni *lni, struct cxidv_ct **out)
{
	return cxidv_alloc_ct_address(lni, NULL, out);
}

int cxidv_alloc_ct_writeback(struct cxidv_lni *lni, void *writeback, struct cxidv_ct **out)
{
	if (!writeback) {
		if (out)
			*out = NULL;
		return EINVAL;
	}
	return cxidv_alloc_ct_address(lni, writeback, out);
}

static bool cxi_csr_range(const struct cxidv_csr *csr, uint64_t offset, size_t length)
{
	return csr && csr->address && csr->address != MAP_FAILED && length &&
	       offset < csr->length && length <= csr->length - offset;
}

int cxidv_read_csr(const struct cxidv_csr *csr, uint64_t offset, void *value, size_t length)
{
	size_t index;
	uint64_t word;

	if (!value || !cxi_csr_range(csr, offset, length) || offset % sizeof(word) ||
	    length % sizeof(word) || (uintptr_t)csr->address % sizeof(word))
		return EINVAL;
#if SIZEOF_LONG == 8
	mmio_flush_writes();
	for (index = 0; index < length; index += sizeof(word)) {
		word = le64toh(mmio_read64_le((char *)csr->address + offset + index));
		udma_from_device_barrier();
		memcpy((char *)value + index, &word, sizeof(word));
	}
	return 0;
#else
	return EOPNOTSUPP;
#endif
}

int cxidv_write_csr(const struct cxidv_csr *csr, uint64_t offset, const void *value, size_t length)
{
	size_t index;
	uint64_t word;

	if (!value || !cxi_csr_range(csr, offset, length) || offset % sizeof(word) ||
	    length % sizeof(word) || (uintptr_t)csr->address % sizeof(word))
		return EINVAL;
#if SIZEOF_LONG == 8
	udma_to_device_barrier();
	for (index = 0; index < length; index += sizeof(word)) {
		memcpy(&word, (const char *)value + index, sizeof(word));
		mmio_write64_le((char *)csr->address + offset + index, htole64(word));
	}
	mmio_flush_writes();
	return 0;
#else
	return EOPNOTSUPP;
#endif
}

int cxidv_write8_csr(const struct cxidv_csr *csr, uint64_t offset, uint8_t value)
{
	if (!cxi_csr_range(csr, offset, sizeof(value)))
		return EINVAL;
	udma_to_device_barrier();
	mmio_write8((char *)csr->address + offset, value);
	mmio_flush_writes();
	return 0;
}

int cxidv_unmap_csrs(struct cxidv_csr *csr)
{
	DECLARE_COMMAND_BUFFER(cmd, CXI_IB_OBJECT_CSR, CXI_IB_METHOD_CSR_UNMAP, 1);
	int ret;

	if (!csr)
		return EINVAL;
	if (csr->address && munmap(csr->address, csr->length))
		return errno;
	csr->address = NULL;
	fill_attr_in_obj(cmd, CXI_IB_ATTR_CSR_HANDLE, csr->handle);
	ret = execute_ioctl(csr->context, cmd);
	free(csr);
	return ret;
}

int cxidv_map_csrs(struct ibv_context *context, struct cxidv_csr **out)
{
	DECLARE_COMMAND_BUFFER(cmd, CXI_IB_OBJECT_CSR, CXI_IB_METHOD_CSR_MAP, 2);
	struct cxi_ibv_csr_info info = {};
	struct ib_uverbs_attr *handle;
	struct cxidv_csr *csr;
	int ret;

	if (!context || !out || !is_cxi_dev(context->device))
		return EINVAL;
	csr = calloc(1, sizeof(*csr));
	if (!csr)
		return ENOMEM;
	handle = fill_attr_out_obj(cmd, CXI_IB_ATTR_CSR_HANDLE);
	fill_attr_out_ptr(cmd, CXI_IB_ATTR_CSR_INFO, &info);
	ret = execute_ioctl(context, cmd);
	if (ret) {
		free(csr);
		return ret;
	}
	csr->context = context;
	csr->handle = read_attr_obj(CXI_IB_ATTR_CSR_HANDLE, handle);
	csr->length = info.length;
	csr->mmap_offset = info.offset;
	csr->address = mmap(NULL, csr->length, PROT_READ | PROT_WRITE, MAP_SHARED, context->cmd_fd,
			    csr->mmap_offset);
	if (csr->address == MAP_FAILED) {
		ret = errno;
		csr->address = NULL;
		cxidv_unmap_csrs(csr);
		return ret;
	}
	*out = csr;
	return 0;
}

int cxidv_alloc_wait(struct cxidv_lni *lni, struct cxidv_wait **out)
{
	DECLARE_COMMAND_BUFFER(cmd, CXI_IB_OBJECT_WAIT, CXI_IB_METHOD_WAIT_ALLOC, 2);
	struct ib_uverbs_attr *handle;
	struct cxidv_wait *wait;
	int ret;

	if (!lni || !out)
		return EINVAL;
	wait = calloc(1, sizeof(*wait));
	if (!wait)
		return ENOMEM;
	handle = fill_attr_out_fd(cmd, CXI_IB_ATTR_WAIT_FD, 0);
	fill_attr_in_uint32(cmd, CXI_IB_ATTR_WAIT_LNI, lni->handle);
	ret = execute_ioctl(lni->context, cmd);
	if (ret) {
		free(wait);
		return ret;
	}
	wait->fd = read_attr_fd(CXI_IB_ATTR_WAIT_FD, handle);
	wait->lni = lni;
	*out = wait;
	return 0;
}

#define CXI_WAIT_USERS_MASK (UINT_MAX >> 1)
#define CXI_WAIT_DESTROYING_BIT (UINT_MAX & ~CXI_WAIT_USERS_MASK)

static int cxi_wait_ref_get(struct cxidv_wait *wait)
{
	unsigned int users;

	if (!wait)
		return 0;

	for (;;) {
		users = __atomic_load_n(&wait->users, __ATOMIC_ACQUIRE);
		if (users & CXI_WAIT_DESTROYING_BIT)
			return EBUSY;
		if ((users & CXI_WAIT_USERS_MASK) == CXI_WAIT_USERS_MASK)
			return EOVERFLOW;
		if (__atomic_compare_exchange_n(&wait->users, &users, users + 1, false,
						__ATOMIC_ACQ_REL,
						__ATOMIC_ACQUIRE))
			return 0;
	}
}

static void cxi_wait_ref_put(struct cxidv_wait *wait)
{
	unsigned int users;

	if (!wait)
		return;

	users = __atomic_fetch_sub(&wait->users, 1, __ATOMIC_ACQ_REL);
	assert((users & CXI_WAIT_USERS_MASK) > 0);
	(void)users;
}

int cxidv_destroy_wait(struct cxidv_wait *wait)
{
	unsigned int users = 0;

	if (!wait)
		return EINVAL;
	if (!__atomic_compare_exchange_n(&wait->users, &users,
					 CXI_WAIT_DESTROYING_BIT, false,
					 __ATOMIC_ACQ_REL,
					 __ATOMIC_ACQUIRE))
		return EBUSY;
	if (close(wait->fd)) {
		__atomic_store_n(&wait->users, 0, __ATOMIC_RELEASE);
		return errno;
	}
	free(wait);
	return 0;
}

int cxidv_destroy_eq(struct cxidv_eq *eq)
{
	DECLARE_COMMAND_BUFFER(cmd, CXI_IB_OBJECT_EQ, CXI_IB_METHOD_EQ_DESTROY, 1);
	int ret;

	if (!eq)
		return EINVAL;
	fill_attr_in_obj(cmd, CXI_IB_ATTR_EQ_HANDLE, eq->handle);
	ret = execute_ioctl(eq->lni->context, cmd);
	if (ret)
		return ret;
	if (eq->doorbell && munmap(eq->doorbell, eq->doorbell_size))
		ret = errno;
	cxi_wait_ref_put(eq->event_wait);
	cxi_wait_ref_put(eq->status_wait);
	free(eq);
	return ret;
}

int cxidv_alloc_eq(struct cxidv_lni *lni, struct ibv_mr *mr, const struct cxidv_eq_attr *attr,
		   struct cxidv_eq **out)
{
	DECLARE_COMMAND_BUFFER(cmd, CXI_IB_OBJECT_EQ, CXI_IB_METHOD_EQ_ALLOC, 8);
	struct cxi_ibv_eq_config config;
	struct cxi_ibv_eq_info info;
	struct ib_uverbs_attr *handle;
	struct cxidv_eq *eq;
	int ret;

	static_assert((unsigned int)CXIDV_EQ_REGISTER_PCT == (unsigned int)CXI_IB_EQ_REGISTER_PCT,
		      "EQ flag ABI");
	static_assert((unsigned int)CXIDV_EQ_PASSTHROUGH == (unsigned int)CXI_IB_EQ_PASSTHROUGH,
		      "EQ bypass ABI");
	if (!lni || !attr || !out ||
	    (attr->flags & ~(CXIDV_EQ_REGISTER_PCT | CXIDV_EQ_PASSTHROUGH)) ||
	    ((attr->flags & CXIDV_EQ_PASSTHROUGH) ? (mr || !(attr->flags & CXIDV_EQ_REGISTER_PCT)) :
						    (!mr || mr->context != lni->context)) ||
	    (attr->event_wait && attr->event_wait->lni != lni) ||
	    (attr->status_wait && attr->status_wait->lni != lni))
		return EINVAL;
	eq = calloc(1, sizeof(*eq));
	if (!eq)
		return ENOMEM;
	ret = cxi_wait_ref_get(attr->event_wait);
	if (ret) {
		free(eq);
		return ret;
	}
	ret = cxi_wait_ref_get(attr->status_wait);
	if (ret) {
		cxi_wait_ref_put(attr->event_wait);
		free(eq);
		return ret;
	}
	config.address = (uint64_t)(uintptr_t)attr->queue;
	config.length = attr->length;
	config.threshold_base = attr->threshold_base;
	config.threshold_delta = attr->threshold_delta;
	config.threshold_count = attr->threshold_count;
	config.ec_delay = attr->ec_delay;
	config.cpu = attr->cpu;
	config.reserved_slots = attr->reserved_slots;
	handle = fill_attr_out_obj(cmd, CXI_IB_ATTR_EQ_HANDLE);
	fill_attr_in_uint32(cmd, CXI_IB_ATTR_EQ_LNI, lni->handle);
	if (mr)
		fill_attr_in_obj(cmd, CXI_IB_ATTR_EQ_MR, mr->handle);
	fill_attr_in(cmd, CXI_IB_ATTR_EQ_CONFIG, &config, sizeof(config));
	fill_attr_out_ptr(cmd, CXI_IB_ATTR_EQ_INFO, &info);
	if (attr->flags)
		fill_attr_in_uint32(cmd, CXI_IB_ATTR_EQ_FLAGS, attr->flags);
	if (attr->event_wait)
		fill_attr_in_fd(cmd, CXI_IB_ATTR_EQ_EVENT_WAIT, attr->event_wait->fd);
	if (attr->status_wait)
		fill_attr_in_fd(cmd, CXI_IB_ATTR_EQ_STATUS_WAIT, attr->status_wait->fd);
	ret = execute_ioctl(lni->context, cmd);
	if (ret) {
		cxi_wait_ref_put(attr->status_wait);
		cxi_wait_ref_put(attr->event_wait);
		free(eq);
		return ret;
	}
	eq->lni = lni;
	eq->event_wait = attr->event_wait;
	eq->status_wait = attr->status_wait;
	eq->handle = read_attr_obj(CXI_IB_ATTR_EQ_HANDLE, handle);
	eq->eqn = info.eqn;
	eq->doorbell_size = info.doorbell_size;
	eq->doorbell = mmap(NULL, eq->doorbell_size, PROT_READ | PROT_WRITE, MAP_SHARED,
			    lni->context->cmd_fd, info.doorbell_offset);
	if (eq->doorbell == MAP_FAILED) {
		ret = errno;
		eq->doorbell = NULL;
		if (cxidv_destroy_eq(eq))
			free(eq);
		return ret;
	}
	*out = eq;
	return 0;
}

int cxidv_destroy_lni(struct cxidv_lni *lni)
{
	DECLARE_COMMAND_BUFFER(cmd, CXI_IB_OBJECT_LNI, CXI_IB_METHOD_LNI_DESTROY, 1);
	int ret;

	if (!lni)
		return EINVAL;
	fill_attr_in_obj(cmd, CXI_IB_ATTR_LNI_DESTROY_HANDLE, lni->handle);
	ret = execute_ioctl(lni->context, cmd);
	if (!ret)
		free(lni);
	return ret;
}

int cxidv_alloc_pid(struct ibv_pd *ibpd, uint32_t flags, uint32_t *pid)
{
	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_PD, CXI_IB_METHOD_PD_PID_ALLOC, 3);
	struct cxi_pd *pd;
	int ret;

	if (!ibpd || !pid)
		return EINVAL;
	if (!is_cxi_dev(ibpd->context->device))
		return EOPNOTSUPP;
	fill_attr_in_obj(cmd, CXI_IB_ATTR_PD_PID_HANDLE, ibpd->handle);
	fill_attr_in_uint32(cmd, CXI_IB_ATTR_PD_PID_FLAGS, flags);
	fill_attr_out_ptr(cmd, CXI_IB_ATTR_PD_PID_VALUE, pid);
	ret = execute_ioctl(ibpd->context, cmd);
	if (!ret) {
		pd = to_cxi_pd(ibpd);
		pd->pidonfep = *pid;
		pd->pid_valid = true;
	}
	return ret;
}

int cxidv_query_pid(struct ibv_pd *ibpd, uint32_t *pid)
{
	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_PD, CXI_IB_METHOD_PD_PID_QUERY, 2);

	if (!ibpd || !pid)
		return EINVAL;
	if (!is_cxi_dev(ibpd->context->device))
		return EOPNOTSUPP;
	fill_attr_in_obj(cmd, CXI_IB_ATTR_PD_PID_HANDLE, ibpd->handle);
	fill_attr_out_ptr(cmd, CXI_IB_ATTR_PD_PID_VALUE, pid);
	return execute_ioctl(ibpd->context, cmd);
}

static struct ibv_pd *cxi_alloc_pd_for_lni(struct ibv_context *context, u32 lni_handle)
{
	struct cxi_alloc_pd_resp resp = {};
	struct cxi_alloc_pd cmd = {};
	struct cxi_pd *pd;
	int ret;

	pd = calloc(1, sizeof(*pd));
	if (!pd)
		return NULL;
	ret = pthread_spin_init(&pd->jkey_lock, PTHREAD_PROCESS_PRIVATE);
	if (ret) {
		free(pd);
		errno = ret;
		return NULL;
	}

	cmd.drv_payload.lni_handle = lni_handle;
	cmd.drv_payload.comp_mask = CXI_IBV_ALLOC_PD_LNI;

	ret = ibv_cmd_alloc_pd(context, &pd->ibv_pd, &cmd.ibv_cmd, sizeof(cmd), &resp.ibv_resp,
			       sizeof(resp));
	if (ret) {
		pthread_spin_destroy(&pd->jkey_lock);
		free(pd);
		return NULL;
	}

	pd->pd_id = resp.pd_id;

	return &pd->ibv_pd;
}

struct ibv_pd *cxi_alloc_pd(struct ibv_context *context)
{
	return cxi_alloc_pd_for_lni(context, CXI_IBV_LNI_ANY);
}

struct ibv_pd *cxidv_alloc_pd(struct cxidv_lni *lni)
{
	if (!lni) {
		errno = EINVAL;
		return NULL;
	}
	return cxi_alloc_pd_for_lni(lni->context, lni->handle);
}

int cxi_dealloc_pd(struct ibv_pd *pd)
{
	struct cxi_pd *cxi_pd = to_cxi_pd(pd);
	int ret;

	ret = ibv_cmd_dealloc_pd(pd);
	if (!ret) {
		struct cxi_job_key *entry;

		while ((entry = cxi_pd->jkeys)) {
			cxi_pd->jkeys = entry->next;
			free(entry);
		}
		pthread_spin_destroy(&cxi_pd->jkey_lock);
		free(cxi_pd);
	}

	return ret;
}

/* Shared by the plain and extended registration paths. */
static struct ibv_mr *cxi_do_reg_mr(struct ibv_pd *pd, void *addr, size_t length, uint64_t hca_va,
				    int access, uint64_t user_rkey, uint32_t native_flags)
{
	struct cxi_context *ctx = to_cxi_ctx(pd->context);
	struct cxi_reg_mr_resp resp = {};
	struct cxi_reg_mr cmd = {};
	struct cxi_mr *mr;
	int ret;

	mr = calloc(1, sizeof(*mr));
	if (!mr)
		return NULL;

	if (user_rkey) {
		cmd.rkey64 = user_rkey;
		cmd.flags = CXI_REG_MR_USER_RKEY;
	}
	if (native_flags) {
		cmd.flags |= CXI_REG_MR_NATIVE_MAP;
		cmd.native_flags = native_flags;
	}

	ret = ibv_cmd_reg_mr(pd, addr, length, hca_va, access, &mr->vmr, &cmd.ibv_cmd, sizeof(cmd),
			     &resp.ibv_resp, sizeof(resp));
	if (ret) {
		free(mr);
		return NULL;
	}

	mr->vmr.ibv_mr.lkey64 = resp.lkey64;
	mr->vmr.ibv_mr.rkey64 = resp.rkey64;
	mr->lkey64 = resp.lkey64;
	mr->rkey64 = resp.rkey64;
	mr->info = resp.info;
	mr->va = (uint64_t)(uintptr_t)addr;
	mr->iova = resp.iova;
	mr->len = length;

	pthread_spin_lock(&ctx->mr_list_lock);
	mr->next = ctx->mr_list;
	ctx->mr_list = mr;
	pthread_spin_unlock(&ctx->mr_list_lock);

	return &mr->vmr.ibv_mr;
}

struct ibv_mr *cxi_reg_mr(struct ibv_pd *pd, void *addr, size_t length, uint64_t hca_va, int access)
{
	return cxi_do_reg_mr(pd, addr, length, hca_va, access, 0, 0);
}

struct ibv_mr *cxidv_reg_native_mr(struct ibv_pd *pd, void *address, size_t length, uint32_t flags)
{
	if (!pd || !is_cxi_dev(pd->context->device) || !flags) {
		errno = EINVAL;
		return NULL;
	}
	return cxi_do_reg_mr(pd, address, length, (uintptr_t)address,
			     (flags & (1U << 2)) ? IBV_ACCESS_LOCAL_WRITE : 0, 0, flags);
}

struct ibv_mr *cxi_reg_mr_ex(struct ibv_pd *pd, struct ibv_mr_init_attr *attr)
{
	uint64_t comp_mask = attr->comp_mask;

	/* Only the pieces the driver can honour today. */
	if (comp_mask & ~(IBV_REG_MR_MASK_ADDR | IBV_REG_MR_MASK_IOVA | IBV_REG_MR_MASK_RKEY)) {
		errno = EOPNOTSUPP;
		return NULL;
	}
	if (!(comp_mask & IBV_REG_MR_MASK_ADDR)) {
		errno = EINVAL;
		return NULL;
	}
	if ((comp_mask & IBV_REG_MR_MASK_RKEY) && !attr->rkey) {
		errno = EINVAL;
		return NULL;
	}

	return cxi_do_reg_mr(pd, attr->addr, attr->length,
			     (comp_mask & IBV_REG_MR_MASK_IOVA) ? attr->iova :
								  (uintptr_t)attr->addr,
			     attr->access, (comp_mask & IBV_REG_MR_MASK_RKEY) ? attr->rkey : 0, 0);
}

/*
 * Resolve an SGE against its memory region: the ATU assigns each descriptor
 * its own IOVA range, so a command cannot use the process virtual address an
 * SGE carries, and the LAC lives in the key rather than the command. Returns
 * 0 when the SGE does not fall inside a registered region.
 *
 * An SGE only carries the narrow key, which aliases the low word of the wide
 * one, so it is enough to find the region; the full key comes from there.
 */
static int cxi_sge_resolve(struct cxi_context *ctx, const struct ibv_sge *sge, uint64_t *iova,
			   uint8_t *lac)
{
	struct cxi_mr *mr;
	int found = 0;

	pthread_spin_lock(&ctx->mr_list_lock);
	for (mr = ctx->mr_list; mr; mr = mr->next) {
		uint64_t offset;

		if (mr->vmr.ibv_mr.lkey != sge->lkey)
			continue;
		if (sge->addr < mr->va || sge->length > mr->len ||
		    sge->addr - mr->va > mr->len - sge->length ||
		    sge->length > UINT64_MAX - sge->addr)
			break;
		offset = sge->addr - mr->va;
		if (offset > UINT64_MAX - mr->iova)
			break;
		*iova = mr->iova + offset;
		*lac = mr->lkey64 & CXI_LKEY64_LAC_MASK;
		found = 1;
		break;
	}
	pthread_spin_unlock(&ctx->mr_list_lock);

	return found;
}

static int cxi_sge64_to_sge(struct cxi_context *ctx, struct ibv_pd *pd,
			    const struct ibv_sge64 *wide, struct ibv_sge *narrow)
{
	struct cxi_mr *mr;
	int ret = EINVAL;

	pthread_spin_lock(&ctx->mr_list_lock);
	for (mr = ctx->mr_list; mr; mr = mr->next) {
		if (mr->vmr.ibv_mr.pd != pd || mr->lkey64 != wide->lkey64)
			continue;
		if (wide->addr < mr->va || wide->length > mr->len ||
		    wide->addr - mr->va > mr->len - wide->length)
			break;
		*narrow = (struct ibv_sge){
			.addr = wide->addr,
			.length = wide->length,
			.lkey = mr->vmr.ibv_mr.lkey,
		};
		ret = 0;
		break;
	}
	pthread_spin_unlock(&ctx->mr_list_lock);
	return ret;
}

int cxidv_mr_from_ibv_mr(struct ibv_mr *ibmr, struct cxidv_mr_info *info)
{
	struct cxi_mr *mr;

	if (!ibmr || !info)
		return EINVAL;
	if (!is_cxi_dev(ibmr->context->device))
		return EOPNOTSUPP;
	mr = to_cxi_mr(ibmr);
	info->va = mr->info.va;
	info->iova = mr->info.iova;
	info->length = mr->info.length;
	info->page_shift = mr->info.page_shift;
	info->huge_shift = mr->info.huge_shift;
	info->id = mr->info.id;
	info->lac = mr->info.lac;
	return 0;
}

int cxi_dereg_mr(struct verbs_mr *vmr)
{
	struct cxi_context *ctx = to_cxi_ctx(vmr->ibv_mr.context);
	struct cxi_mr *mr = to_cxi_mr(&vmr->ibv_mr);
	struct cxi_mr **pp;
	int ret;

	ret = ibv_cmd_dereg_mr(vmr);
	if (!ret) {
		pthread_spin_lock(&ctx->mr_list_lock);
		for (pp = &ctx->mr_list; *pp; pp = &(*pp)->next) {
			if (*pp == mr) {
				*pp = mr->next;
				break;
			}
		}
		pthread_spin_unlock(&ctx->mr_list_lock);
		free(mr);
	}

	return ret;
}

/*
 * Map the EQ ring and doorbell the kernel just allocated and prime the ring
 * state. Shared by the classic and extended create paths.
 */
static int cxi_cq_map_eq(struct cxi_ibv_cq *cq, struct ibv_context *context, uint32_t eqn,
			 uint64_t buf_offset, size_t buf_size, uint64_t db_offset, size_t db_size)
{
	int ret;

	cq->eqn = eqn;
	cq->eq_buf_size = buf_size;
	cq->eq_db_size = db_size;

	cq->eq_buf = mmap(NULL, cq->eq_buf_size, PROT_READ | PROT_WRITE, MAP_SHARED,
			  context->cmd_fd, buf_offset);
	if (cq->eq_buf == MAP_FAILED) {
		cq->eq_buf = NULL;
		return errno;
	}

	cq->eq_db = mmap(NULL, cq->eq_db_size, PROT_READ | PROT_WRITE, MAP_SHARED, context->cmd_fd,
			 db_offset);
	if (cq->eq_db == MAP_FAILED) {
		munmap(cq->eq_buf, cq->eq_buf_size);
		cq->eq_buf = NULL;
		cq->eq_db = NULL;
		return errno;
	}

	cxi_eq_init(&cq->hw_eq, cq->eq_buf, cq->eq_buf_size, cq->eqn, cq->eq_db);
	ret = pthread_spin_init(&cq->lock, PTHREAD_PROCESS_PRIVATE);
	if (ret) {
		munmap(cq->eq_db, cq->eq_db_size);
		munmap(cq->eq_buf, cq->eq_buf_size);
		cq->eq_db = NULL;
		cq->eq_buf = NULL;
		return ret;
	}

	return 0;
}

struct ibv_cq *cxi_create_cq(struct ibv_context *context, int cqe, struct ibv_comp_channel *channel,
			     int comp_vector)
{
	struct cxi_create_cq_resp resp = {};
	struct cxi_create_cq cmd = {};
	struct cxi_ibv_cq *cq;
	int ret;

	if (cqe > 65536) {
		errno = EINVAL;
		return NULL;
	}

	cq = calloc(1, sizeof(*cq));
	if (!cq)
		return NULL;

	cmd.n_entries = cqe;
	cmd.cpu_affinity = 0;
	cmd.lni_handle = CXI_IBV_LNI_ANY;

	ret = ibv_cmd_create_cq(context, cqe, channel, comp_vector, &cq->verbs_cq.cq, &cmd.ibv_cmd,
				sizeof(cmd), &resp.ibv_resp, sizeof(resp));
	if (ret) {
		free(cq);
		return NULL;
	}

	cq->cqe = cq->verbs_cq.cq.cqe;

	ret = cxi_cq_map_eq(cq, context, resp.eqn, resp.eq_buf_offset, resp.eq_buf_size,
			    resp.eq_db_offset, resp.eq_db_size);
	if (ret) {
		ibv_cmd_destroy_cq(&cq->verbs_cq.cq);
		free(cq);
		errno = ret;
		return NULL;
	}

	return &cq->verbs_cq.cq;
}

int cxi_destroy_cq(struct ibv_cq *cq)
{
	struct cxi_ibv_cq *cxi_cq = to_cxi_ibv_cq(cq);
	int ret;

	ret = ibv_cmd_destroy_cq(cq);
	if (!ret) {
		if (cxi_cq->eq_db)
			munmap(cxi_cq->eq_db, cxi_cq->eq_db_size);
		if (cxi_cq->eq_buf)
			munmap(cxi_cq->eq_buf, cxi_cq->eq_buf_size);
		pthread_spin_destroy(&cxi_cq->lock);
		free(cxi_cq);
	}

	return ret;
}

/*
 * Translate a CXI return code to an IB work completion status. Mirrors the
 * kernel's cxi_rc_to_wc_status() in cxi_ib_main.c.
 */
static enum ibv_wc_status cxi_rc_to_wc_status(int rc)
{
	switch (rc) {
	case C_RC_OK:
		return IBV_WC_SUCCESS;
	case C_RC_PERM_VIOLATION:
	case C_RC_OP_VIOLATION:
		return IBV_WC_REM_ACCESS_ERR;
	case C_RC_NO_MATCH:
		return IBV_WC_REM_OP_ERR;
	case C_RC_NO_TRANSLATION:
	case C_RC_PAGE_PERM_ERROR:
		return IBV_WC_LOC_PROT_ERR;
	case C_RC_DROPPED:
	case C_RC_UNDELIVERABLE:
		return IBV_WC_RETRY_EXC_ERR;
	case C_RC_AMO_INVAL_OP_ERROR:
	case C_RC_AMO_ALIGN_ERROR:
	case C_RC_AMO_FP_INVALID:
		return IBV_WC_LOC_QP_OP_ERR;
	default:
		return IBV_WC_GENERAL_ERR;
	}
}

static bool cxi_sq_find_free_slot(struct cxi_qp *qp, uint32_t *slot)
{
	uint32_t candidate;

	if (!qp->sq_size || qp->send_count >= qp->sq_size || !qp->send_slot_valid)
		return false;

	candidate = qp->send_tail < qp->sq_size ? qp->send_tail : 0;
	for (uint32_t searched = 0; searched < qp->sq_size; searched++) {
		if (!qp->send_slot_valid[candidate]) {
			*slot = candidate;
			return true;
		}
		candidate++;
		if (candidate == qp->sq_size)
			candidate = 0;
	}

	return false;
}

static int cxi_sq_make_cookie(struct cxi_qp *qp, uint32_t slot, uint64_t *cookie)
{
	struct cxi_context *ctx = to_cxi_ctx(qp->vqp.qp.context);
	uint_fast64_t generation;

	if (qp->qp_slot >= CXI_MAX_QPS || slot >= qp->sq_size ||
	    qp->sq_size > CXI_SEND_COOKIE_SLOT_MASK + 1)
		return EINVAL;

	generation = atomic_load_explicit(&ctx->send_cookie_seq, memory_order_relaxed);
	for (;;) {
		if (generation >= CXI_SEND_COOKIE_GENERATION_MAX)
			return EOVERFLOW;
		if (atomic_compare_exchange_weak_explicit(&ctx->send_cookie_seq, &generation,
							  generation + 1, memory_order_relaxed,
							  memory_order_relaxed))
			break;
	}
	generation++;

	*cookie = (generation << CXI_SEND_COOKIE_INDEX_BITS) |
		  (qp->qp_slot << CXI_SEND_COOKIE_SLOT_BITS) | slot;
	return 0;
}

static struct cxi_qp *
cxi_sq_cookie_qp(struct cxi_context *ctx, uint64_t cookie, uint32_t *slot)
{
	uint32_t qp_slot;

	if (!(cookie >> CXI_SEND_COOKIE_INDEX_BITS))
		return NULL;

	qp_slot = (cookie >> CXI_SEND_COOKIE_SLOT_BITS) & CXI_QP_SLOT_MASK;
	*slot = cookie & CXI_SEND_COOKIE_SLOT_MASK;
	return ctx->qp_slots[qp_slot];
}

static int cxi_qp_insert_pte_locked(struct cxi_context *ctx, struct cxi_qp *qp)
{
	uint32_t position = 0;

	if (qp->pte_index < 0 || ctx->qp_count >= CXI_MAX_QPS)
		return EINVAL;
	while (position < ctx->qp_count &&
	       ctx->qp_by_pte[position]->pte_index < qp->pte_index)
		position++;
	if (position < ctx->qp_count &&
	    ctx->qp_by_pte[position]->pte_index == qp->pte_index)
		return EEXIST;
	memmove(&ctx->qp_by_pte[position + 1], &ctx->qp_by_pte[position],
		(ctx->qp_count - position) * sizeof(ctx->qp_by_pte[0]));
	ctx->qp_by_pte[position] = qp;
	ctx->qp_count++;
	return 0;
}

static struct cxi_qp *cxi_qp_find_pte_locked(struct cxi_context *ctx, uint32_t pte_index)
{
	uint32_t low = 0;
	uint32_t high = ctx->qp_count;

	while (low < high) {
		uint32_t middle = low + (high - low) / 2;
		struct cxi_qp *qp = ctx->qp_by_pte[middle];

		if ((uint32_t)qp->pte_index < pte_index)
			low = middle + 1;
		else if ((uint32_t)qp->pte_index > pte_index)
			high = middle;
		else
			return qp;
	}

	return NULL;
}

static bool cxi_qp_remove_pte_locked(struct cxi_context *ctx, struct cxi_qp *qp)
{
	for (uint32_t position = 0; position < ctx->qp_count; position++) {
		if (ctx->qp_by_pte[position] != qp)
			continue;
		memmove(&ctx->qp_by_pte[position], &ctx->qp_by_pte[position + 1],
			(ctx->qp_count - position - 1) * sizeof(ctx->qp_by_pte[0]));
		ctx->qp_count--;
		return true;
	}

	return false;
}

static int cxi_qp_register_locked(struct cxi_context *ctx, struct cxi_qp *qp)
{
	uint32_t qp_slot;
	int ret;

	for (qp_slot = 0; qp_slot < CXI_MAX_QPS; qp_slot++)
		if (!ctx->qp_slots[qp_slot])
			break;
	if (qp_slot == CXI_MAX_QPS)
		return ENOSPC;

	qp->qp_slot = qp_slot;
	ret = cxi_qp_insert_pte_locked(ctx, qp);
	if (ret) {
		qp->qp_slot = UINT32_MAX;
		return ret;
	}
	ctx->qp_slots[qp_slot] = qp;
	return 0;
}

static void cxi_qp_unregister_locked(struct cxi_context *ctx, struct cxi_qp *qp)
{
	if (qp->qp_slot < CXI_MAX_QPS && ctx->qp_slots[qp->qp_slot] == qp)
		ctx->qp_slots[qp->qp_slot] = NULL;
	cxi_qp_remove_pte_locked(ctx, qp);
	qp->qp_slot = UINT32_MAX;
}

static int cxi_qp_update_pte_locked(struct cxi_context *ctx, struct cxi_qp *qp,
				    int pte_index)
{
	int previous = qp->pte_index;
	int ret;

	if (previous == pte_index)
		return 0;
	if (!cxi_qp_remove_pte_locked(ctx, qp))
		return ENOENT;
	qp->pte_index = pte_index;
	ret = cxi_qp_insert_pte_locked(ctx, qp);
	if (!ret)
		return 0;
	qp->pte_index = previous;
	cxi_qp_insert_pte_locked(ctx, qp);
	return ret;
}

static void cxi_sq_record_send(struct cxi_qp *qp, uint32_t slot, uint64_t cookie,
			       uint64_t wr_id, uint8_t opcode, uint32_t job_id)
{
	qp->send_wrids[slot] = wr_id;
	qp->send_opcodes[slot] = opcode;
	qp->send_job_ids[slot] = job_id;
	qp->send_cookies[slot] = cookie;
	qp->send_slot_valid[slot] = true;
	qp->send_tail = slot + 1 == qp->sq_size ? 0 : slot + 1;
	qp->send_count++;
}

/*
 * Decode one hardware event into a work completion. Returns 1 when @wc was
 * filled, 0 when the event queue is empty. Caller holds cq->lock.
 */
static int cxi_poll_one(struct cxi_ibv_cq *cxi_cq, struct ibv_wc *wc)
{
	struct cxi_context *ctx = to_cxi_ctx(cxi_cq->verbs_cq.cq.context);

	for (;;) {
		const union c_event *ev = cxi_eq_get_event(&cxi_cq->hw_eq);

		if (!ev)
			return 0;

		memset(wc, 0, sizeof(*wc));
		cxi_cq->cur_job_id = 0;
		cxi_cq->cur_src_id = 0;

		switch (ev->hdr.event_type) {
		case C_EVENT_SEND:
		case C_EVENT_ACK:
		case C_EVENT_REPLY: {
			struct cxi_qp *qp;
			uint32_t slot;
			uint64_t user_ptr = ev->init_short.user_ptr;

			pthread_spin_lock(&ctx->qp_table_lock);
			qp = cxi_sq_cookie_qp(ctx, user_ptr, &slot);
			if (qp && (qp->send_cq != cxi_cq || slot >= qp->sq_size))
				qp = NULL;
			if (qp) {
				pthread_spin_lock(&qp->sq_lock);
				if (!qp->send_slot_valid[slot] ||
				    qp->send_cookies[slot] != user_ptr) {
					pthread_spin_unlock(&qp->sq_lock);
					qp = NULL;
				}
			}

			if (!qp) {
				pthread_spin_unlock(&ctx->qp_table_lock);
				continue;
			}

			wc->wr_id = qp->send_wrids[slot];
			cxi_cq->cur_job_id = qp->send_job_ids[slot];
			/* An ACK alone cannot say what was sent. */
			switch (qp->send_opcodes[slot]) {
			case IBV_WR_RDMA_WRITE:
			case IBV_WR_RDMA_WRITE_WITH_IMM:
			case CXI_WR_RDMA_WRITE_WITH_IMM64:
			case CXI_WR_RDMA_WRITE64_WITH_IMM:
			case CXI_WR_RDMA_WRITE64_WITH_IMM64:
				wc->opcode = IBV_WC_RDMA_WRITE;
				break;
			case IBV_WR_RDMA_READ:
				wc->opcode = IBV_WC_RDMA_READ;
				break;
			default:
				wc->opcode = IBV_WC_SEND;
				break;
			}
			qp->send_slot_valid[slot] = false;
			qp->send_cookies[slot] = 0;
			qp->send_count--;
			wc->qp_num = qp->vqp.qp.qp_num;
			pthread_spin_unlock(&qp->sq_lock);
			pthread_spin_unlock(&ctx->qp_table_lock);

			wc->status = cxi_rc_to_wc_status(cxi_init_event_rc(ev));
			if (wc->status == IBV_WC_SUCCESS &&
			    ev->hdr.event_size == C_EVENT_SIZE_16_BYTE)
				wc->byte_len = ev->init_short.mlength;
			return 1;
		}

		case C_EVENT_PUT:
		case C_EVENT_GET: {
			struct cxi_qp *qp = NULL;
			uint64_t match_bits = 0;
			uint64_t header_data = 0;

			if (cxi_tgt_event_rc(ev) == C_RC_ENTRY_NOT_FOUND)
				continue;

			if (ev->hdr.event_size >= C_EVENT_SIZE_32_BYTE) {
				match_bits = ev->tgt_short.match_bits;
				header_data = ev->tgt_short.header_data;
				/*
				 * The sender's src_id (echoed back in the
				 * initiator field) and JobID (the VNI its QP
				 * was created under).
				 */
				cxi_cq->cur_src_id = ev->tgt_short.initiator;
				cxi_cq->cur_job_id = ev->tgt_short.vni;
			}

			/*
			 * Non-zero match bits mean the operation landed on an
			 * attached region rather than a receive buffer. A plain
			 * write or a served read raises no completion here, so
			 * only an immediate turns one into a receive.
			 */
			if ((match_bits & ~CXI_LE_VNI_MASK) && !header_data)
				break;

			pthread_spin_lock(&ctx->qp_table_lock);
			qp = cxi_qp_find_pte_locked(ctx, ev->tgt_short.ptlte_index);

			if (qp) {
				pthread_spin_lock(&qp->rq_lock);
				if (qp->recv_count) {
					wc->wr_id = qp->recv_wrids[qp->recv_head];
					qp->recv_head = (qp->recv_head + 1) % qp->rq_size;
					qp->recv_count--;
				}
				pthread_spin_unlock(&qp->rq_lock);
				wc->qp_num = qp->vqp.qp.qp_num;
			}
			pthread_spin_unlock(&ctx->qp_table_lock);

			wc->status = cxi_rc_to_wc_status(cxi_tgt_event_rc(ev));
			if (header_data) {
				wc->opcode = IBV_WC_RECV_RDMA_WITH_IMM;
				wc->imm_data = htobe32((uint32_t)header_data);
				wc->wc_flags |= IBV_WC_WITH_IMM;
				/*
				 * The classic struct ibv_wc has no room for a
				 * wide immediate; ibv_wc_read_imm64_data()
				 * reads it back out of here instead.
				 */
				cxi_cq->cur_imm64 = htobe64(header_data);
			} else {
				wc->opcode = IBV_WC_RECV;
			}
			if (wc->status == IBV_WC_SUCCESS &&
			    ev->hdr.event_size >= C_EVENT_SIZE_32_BYTE)
				wc->byte_len = ev->tgt_short.length;
			return 1;
		}

		case C_EVENT_ATOMIC:
		case C_EVENT_FETCH_ATOMIC:
			wc->wr_id = ev->init_short.user_ptr;
			wc->status = cxi_rc_to_wc_status(cxi_init_event_rc(ev));
			wc->opcode = IBV_WC_FETCH_ADD;
			return 1;

		case C_EVENT_COMMAND_FAILURE:
			wc->status = IBV_WC_LOC_QP_OP_ERR;
			wc->vendor_err = ev->cmd_fail.return_code;
			wc->opcode = IBV_WC_SEND;
			return 1;

		default:
			/* Administrative/unknown event: already consumed, skip it */
			break;
		}
	}
}

int cxi_poll_cq(struct ibv_cq *cq, int ne, struct ibv_wc *wc)
{
	struct cxi_ibv_cq *cxi_cq = to_cxi_ibv_cq(cq);
	int npolled = 0;

	pthread_spin_lock(&cxi_cq->lock);

	while (npolled < ne && cxi_poll_one(cxi_cq, &wc[npolled]))
		npolled++;

	/* Reclaim the slots of everything consumed above, errors included. */
	cxi_eq_ack_events(&cxi_cq->hw_eq);

	pthread_spin_unlock(&cxi_cq->lock);

	return npolled;
}

int cxi_arm_cq(struct ibv_cq *cq, int solicited)
{
	(void)cq;
	return solicited ? EOPNOTSUPP : 0;
}

/*
 * Extended CQ polling. start_poll takes the CQ lock and end_poll drops it, so
 * the cursor stays valid across the read_* accessors in between.
 */
static int cxi_cq_ex_advance(struct cxi_ibv_cq *cq)
{
	if (!cxi_poll_one(cq, &cq->cur_wc))
		return ENOENT;

	cq->verbs_cq.cq_ex.status = cq->cur_wc.status;
	cq->verbs_cq.cq_ex.wr_id = cq->cur_wc.wr_id;

	return 0;
}

static int cxi_start_poll(struct ibv_cq_ex *cq_ex, struct ibv_poll_cq_attr *attr)
{
	struct cxi_ibv_cq *cq = to_cxi_ibv_cq_ex(cq_ex);
	int ret;

	if (attr->comp_mask)
		return EINVAL;

	pthread_spin_lock(&cq->lock);

	ret = cxi_cq_ex_advance(cq);
	if (ret) {
		cxi_eq_ack_events(&cq->hw_eq);
		pthread_spin_unlock(&cq->lock);
	}

	return ret;
}

static int cxi_next_poll(struct ibv_cq_ex *cq_ex)
{
	return cxi_cq_ex_advance(to_cxi_ibv_cq_ex(cq_ex));
}

static void cxi_end_poll(struct ibv_cq_ex *cq_ex)
{
	struct cxi_ibv_cq *cq = to_cxi_ibv_cq_ex(cq_ex);

	cxi_eq_ack_events(&cq->hw_eq);
	pthread_spin_unlock(&cq->lock);
}

static enum ibv_wc_opcode cxi_wc_read_opcode(struct ibv_cq_ex *cq_ex)
{
	return to_cxi_ibv_cq_ex(cq_ex)->cur_wc.opcode;
}

static uint32_t cxi_wc_read_vendor_err(struct ibv_cq_ex *cq_ex)
{
	return to_cxi_ibv_cq_ex(cq_ex)->cur_wc.vendor_err;
}

static uint32_t cxi_wc_read_byte_len(struct ibv_cq_ex *cq_ex)
{
	return to_cxi_ibv_cq_ex(cq_ex)->cur_wc.byte_len;
}

static unsigned int cxi_wc_read_wc_flags(struct ibv_cq_ex *cq_ex)
{
	return to_cxi_ibv_cq_ex(cq_ex)->cur_wc.wc_flags;
}

static uint32_t cxi_wc_read_qp_num(struct ibv_cq_ex *cq_ex)
{
	return to_cxi_ibv_cq_ex(cq_ex)->cur_wc.qp_num;
}

static uint32_t cxi_wc_read_src_qp(struct ibv_cq_ex *cq_ex)
{
	return to_cxi_ibv_cq_ex(cq_ex)->cur_wc.src_qp;
}

static __be32 cxi_wc_read_imm_data(struct ibv_cq_ex *cq_ex)
{
	/* Already network order in the completion. */
	return to_cxi_ibv_cq_ex(cq_ex)->cur_wc.imm_data;
}

static __be64 cxi_wc_read_imm64_data(struct ibv_cq_ex *cq_ex)
{
	return to_cxi_ibv_cq_ex(cq_ex)->cur_imm64;
}

static uint32_t cxi_wc_read_job_id(struct ibv_cq_ex *cq_ex)
{
	return to_cxi_ibv_cq_ex(cq_ex)->cur_job_id;
}

static uint32_t cxi_wc_read_src_id(struct ibv_cq_ex *cq_ex)
{
	return to_cxi_ibv_cq_ex(cq_ex)->cur_src_id;
}

static void cxi_cq_fill_pfns(struct cxi_ibv_cq *cq, const struct ibv_cq_init_attr_ex *attr)
{
	struct ibv_cq_ex *cq_ex = &cq->verbs_cq.cq_ex;

	cq_ex->start_poll = cxi_start_poll;
	cq_ex->next_poll = cxi_next_poll;
	cq_ex->end_poll = cxi_end_poll;
	cq_ex->read_opcode = cxi_wc_read_opcode;
	cq_ex->read_vendor_err = cxi_wc_read_vendor_err;
	cq_ex->read_wc_flags = cxi_wc_read_wc_flags;

	if (attr->wc_flags & IBV_WC_EX_WITH_BYTE_LEN)
		cq_ex->read_byte_len = cxi_wc_read_byte_len;
	if (attr->wc_flags & IBV_WC_EX_WITH_QP_NUM)
		cq_ex->read_qp_num = cxi_wc_read_qp_num;
	if (attr->wc_flags & IBV_WC_EX_WITH_SRC_QP)
		cq_ex->read_src_qp = cxi_wc_read_src_qp;
	if (attr->wc_flags & IBV_WC_EX_WITH_IMM)
		cq_ex->read_imm_data = cxi_wc_read_imm_data;
	if (attr->wc_flags & IBV_WC_EX_WITH_IMM64)
		cq_ex->read_imm64_data = cxi_wc_read_imm64_data;
	if (attr->wc_flags & IBV_WC_EX_WITH_JOB_ID)
		cq_ex->read_job_id = cxi_wc_read_job_id;
	if (attr->wc_flags & IBV_WC_EX_WITH_SRC_ID)
		cq_ex->read_src_id = cxi_wc_read_src_id;
}

struct ibv_cq_ex *cxi_create_cq_ex(struct ibv_context *context, struct ibv_cq_init_attr_ex *attr)
{
	struct verbs_create_cq_prov_attr prov_attr = {};
	struct cxi_create_cq_ex_resp resp = {};
	struct cxi_create_cq_ex cmd = { .lni_handle = CXI_IBV_LNI_ANY };
	struct cxi_ibv_cq *cq;
	int ret;

	if (attr->cqe > 65536) {
		errno = EINVAL;
		return NULL;
	}

	/* Timestamps and flow tags have no CXI event-queue equivalent. */
	if (attr->wc_flags & ~(IBV_WC_EX_WITH_BYTE_LEN | IBV_WC_EX_WITH_IMM | IBV_WC_EX_WITH_IMM64 |
			       IBV_WC_EX_WITH_QP_NUM | IBV_WC_EX_WITH_SRC_QP |
			       IBV_WC_EX_WITH_JOB_ID | IBV_WC_EX_WITH_SRC_ID)) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	cq = calloc(1, sizeof(*cq));
	if (!cq)
		return NULL;

	cmd.drv_payload.n_entries = attr->cqe;

	ret = ibv_cmd_create_cq_ex(context, attr, &prov_attr, &cq->verbs_cq, &cmd.ibv_cmd,
				   sizeof(cmd), &resp.ibv_resp, sizeof(resp), 0);
	if (ret) {
		free(cq);
		errno = ret;
		return NULL;
	}

	cq->cqe = cq->verbs_cq.cq.cqe;

	ret = cxi_cq_map_eq(cq, context, resp.drv_payload.eqn, resp.drv_payload.eq_buf_offset,
			    resp.drv_payload.eq_buf_size, resp.drv_payload.eq_db_offset,
			    resp.drv_payload.eq_db_size);
	if (ret) {
		ibv_cmd_destroy_cq(&cq->verbs_cq.cq);
		free(cq);
		errno = ret;
		return NULL;
	}

	cxi_cq_fill_pfns(cq, attr);

	return &cq->verbs_cq.cq_ex;
}

static int cxi_qp_init_locks(struct cxi_qp *qp)
{
	int ret;

	ret = pthread_spin_init(&qp->sq_lock, PTHREAD_PROCESS_PRIVATE);
	if (ret)
		return ret;
	ret = pthread_spin_init(&qp->rq_lock, PTHREAD_PROCESS_PRIVATE);
	if (ret)
		goto destroy_sq;
	ret = pthread_mutex_init(&qp->builder_lock, NULL);
	if (!ret)
		return 0;
	pthread_spin_destroy(&qp->rq_lock);
destroy_sq:
	pthread_spin_destroy(&qp->sq_lock);
	return ret;
}

struct ibv_qp *cxi_create_qp(struct ibv_pd *pd, struct ibv_qp_init_attr *attr)
{
	(void)pd;
	(void)attr;
	errno = EOPNOTSUPP;
	return NULL;
}

/* Populates qp->vqp.qp_ex; defined below, alongside cxi_post_send(). */
static void cxi_qp_fill_wr_pfns(struct cxi_qp *qp, struct ibv_qp_init_attr_ex *attr_ex);

struct ibv_qp *cxi_create_qp_ex(struct ibv_context *context, struct ibv_qp_init_attr_ex *attr)
{
	struct cxi_create_qp_ex_resp resp = {};
	struct cxi_create_qp_ex cmd = {};
	struct cxi_context *ctx = to_cxi_ctx(context);
	struct cxi_qp *qp;
	uint32_t tc;
	bool present;
	int err = 0;
	int ret;

	if (attr->qp_type != IBV_QPT_RU) {
		errno = EOPNOTSUPP;
		return NULL;
	}
	if (!(attr->comp_mask & IBV_QP_INIT_ATTR_JKEY) || !attr->job_key) {
		errno = EINVAL;
		return NULL;
	}

	if (cxi_tc_cache_read(ctx, &tc, NULL)) {
		cmd.drv_payload.tc = tc;
		cmd.drv_payload.comp_mask |= CXI_IBV_CREATE_QP_TC;
	} else {
		ret = cxi_parse_env_u32("UET_TC", CXI_IBV_TC_MAX - 1, &tc, &present);
		if (ret) {
			errno = ret;
			return NULL;
		}
		if (present) {
			cmd.drv_payload.tc = tc;
			cmd.drv_payload.comp_mask |= CXI_IBV_CREATE_QP_TC;
		}
	}

	qp = calloc(1, sizeof(*qp));
	if (!qp)
		return NULL;
	qp->qp_slot = UINT32_MAX;

	ret = ibv_cmd_create_qp_ex2(context, &qp->vqp, attr, &cmd.ibv_cmd, sizeof(cmd),
				    &resp.ibv_resp, sizeof(resp), NULL);
	if (ret) {
		free(qp);
		return NULL;
	}

	qp->vqp.comp_mask |= VERBS_QP_EX;
	if (attr->comp_mask & IBV_QP_INIT_ATTR_SEND_OPS_FLAGS)
		cxi_qp_fill_wr_pfns(qp, attr);
	if (attr->comp_mask & IBV_QP_INIT_ATTR_SRC_ID)
		qp->src_id = attr->src_id;
	qp->job = container_of(attr->job_key, struct cxi_job_key, key)->job;
	qp->sq_size = attr->cap.max_send_wr;
	qp->rq_size = attr->cap.max_recv_wr;
	qp->send_cq = to_cxi_ibv_cq(attr->send_cq);
	qp->pte_index = resp.pte_index;
	qp->send_wrids = calloc(qp->sq_size ? qp->sq_size : 1, sizeof(*qp->send_wrids));
	if (!qp->send_wrids)
		goto err_destroy_qp;
	qp->send_opcodes = calloc(qp->sq_size ? qp->sq_size : 1, sizeof(*qp->send_opcodes));
	if (!qp->send_opcodes)
		goto err_destroy_qp;
	qp->send_job_ids = calloc(qp->sq_size ? qp->sq_size : 1, sizeof(*qp->send_job_ids));
	if (!qp->send_job_ids)
		goto err_destroy_qp;
	qp->send_cookies = calloc(qp->sq_size ? qp->sq_size : 1, sizeof(*qp->send_cookies));
	if (!qp->send_cookies)
		goto err_destroy_qp;
	qp->send_slot_valid = calloc(qp->sq_size ? qp->sq_size : 1,
				     sizeof(*qp->send_slot_valid));
	if (!qp->send_slot_valid)
		goto err_destroy_qp;
	qp->recv_wrids = calloc(qp->rq_size ? qp->rq_size : 1, sizeof(*qp->recv_wrids));
	if (!qp->recv_wrids)
		goto err_destroy_qp;
	qp->txq_idx = resp.txq_idx;
	qp->job_id = resp.job_id;
	qp->lcid = resp.lcid;
	qp->txq_cmds_size = resp.txq_cmds_size;
	qp->txq_db_size = resp.txq_db_size;

	qp->txq_cmds = mmap(NULL, qp->txq_cmds_size, PROT_READ | PROT_WRITE, MAP_SHARED,
			    context->cmd_fd, resp.txq_cmds_offset);
	if (qp->txq_cmds == MAP_FAILED)
		goto err_destroy_qp;

	qp->txq_db = mmap(NULL, qp->txq_db_size, PROT_READ | PROT_WRITE, MAP_SHARED,
			  context->cmd_fd, resp.txq_db_offset);
	if (qp->txq_db == MAP_FAILED)
		goto err_unmap_cmds;

	cxi_cq_init(&qp->hw_txq, qp->txq_cmds, qp->txq_cmds_size / sizeof(struct cxi_cmd64),
		    qp->txq_db, qp->txq_idx);

	qp->tgq_idx = resp.tgq_idx;
	qp->tgq_cmds_size = resp.tgq_cmds_size;
	qp->tgq_db_size = resp.tgq_db_size;

	qp->tgq_cmds = mmap(NULL, qp->tgq_cmds_size, PROT_READ | PROT_WRITE, MAP_SHARED,
			    context->cmd_fd, resp.tgq_cmds_offset);
	if (qp->tgq_cmds == MAP_FAILED)
		goto err_unmap_txq_db;

	qp->tgq_db = mmap(NULL, qp->tgq_db_size, PROT_READ | PROT_WRITE, MAP_SHARED,
			  context->cmd_fd, resp.tgq_db_offset);
	if (qp->tgq_db == MAP_FAILED)
		goto err_unmap_tgq_cmds;

	cxi_cq_init(&qp->hw_tgq, qp->tgq_cmds, qp->tgq_cmds_size / sizeof(struct cxi_cmd64),
		    qp->tgq_db, qp->tgq_idx);

	err = cxi_qp_init_locks(qp);
	if (err)
		goto err_unmap_tgq_db;
	pthread_spin_lock(&ctx->qp_table_lock);
	err = cxi_qp_register_locked(ctx, qp);
	pthread_spin_unlock(&ctx->qp_table_lock);
	if (err)
		goto err_destroy_locks;

	{
		union c_cmdu target_cmd = {};

		target_cmd.set_state.command.opcode = C_CMD_TGT_SETSTATE;
		target_cmd.set_state.ptlte_index = qp->pte_index;
		target_cmd.set_state.ptlte_state = C_PTLTE_ENABLED;
		ret = cxi_cq_emit_target(&qp->hw_tgq, &target_cmd);
		if (ret) {
			err = -ret;
			goto err_destroy_locks;
		}
		cxi_cq_ring(&qp->hw_tgq);
		qp->vqp.qp.state = IBV_QPS_RTS;
	}

	return &qp->vqp.qp;

err_destroy_locks:
	pthread_spin_lock(&ctx->qp_table_lock);
	if (qp->qp_slot < CXI_MAX_QPS)
		cxi_qp_unregister_locked(ctx, qp);
	pthread_spin_unlock(&ctx->qp_table_lock);
	pthread_mutex_destroy(&qp->builder_lock);
	pthread_spin_destroy(&qp->rq_lock);
	pthread_spin_destroy(&qp->sq_lock);
err_unmap_tgq_db:
	if (qp->tgq_db)
		munmap(qp->tgq_db, qp->tgq_db_size);
err_unmap_tgq_cmds:
	munmap(qp->tgq_cmds, qp->tgq_cmds_size);
err_unmap_txq_db:
	munmap(qp->txq_db, qp->txq_db_size);
err_unmap_cmds:
	munmap(qp->txq_cmds, qp->txq_cmds_size);
err_destroy_qp:
	free(qp->recv_wrids);
	free(qp->send_wrids);
	free(qp->send_opcodes);
	free(qp->send_job_ids);
	free(qp->send_cookies);
	free(qp->send_slot_valid);
	ibv_cmd_destroy_qp(&qp->vqp.qp);
	free(qp);
	if (err)
		errno = err;
	return NULL;
}

int cxi_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask)
{
	struct cxi_qp *cxi_qp = to_cxi_qp(qp);
	struct cxi_modify_qp_ex cmd = {};
	struct cxi_modify_qp_ex_resp resp = {};
	int ret;

	ret = ibv_cmd_modify_qp_ex(qp, attr, attr_mask, &cmd.ibv_cmd, sizeof(cmd), &resp.ibv_resp,
				   sizeof(resp));
	if (ret)
		return ret;

	if ((attr_mask & IBV_QP_STATE) && attr->qp_state == IBV_QPS_RTR) {
		struct cxi_context *ctx = to_cxi_ctx(qp->context);
		union c_cmdu tgt_cmd = {};
		int update_ret;

		pthread_spin_lock(&ctx->qp_table_lock);
		pthread_spin_lock(&cxi_qp->rq_lock);
		update_ret = cxi_qp_update_pte_locked(ctx, cxi_qp, resp.pte_index);
		if (update_ret) {
			pthread_spin_unlock(&cxi_qp->rq_lock);
			pthread_spin_unlock(&ctx->qp_table_lock);
			return update_ret;
		}

		/*
		 * A freshly mapped PtlTE comes up disabled and drops every
		 * inbound packet. Userspace owns the TGQ ring, so the enable
		 * has to be emitted here rather than from the kernel.
		 */
		tgt_cmd.set_state.command.opcode = C_CMD_TGT_SETSTATE;
		tgt_cmd.set_state.ptlte_index = (uint16_t)cxi_qp->pte_index;
		tgt_cmd.set_state.ptlte_state = C_PTLTE_ENABLED;

		ret = cxi_cq_emit_target(&cxi_qp->hw_tgq, &tgt_cmd);
		if (!ret)
			cxi_cq_ring(&cxi_qp->hw_tgq);
		pthread_spin_unlock(&cxi_qp->rq_lock);
		pthread_spin_unlock(&ctx->qp_table_lock);
		if (ret)
			return -ret;
	}

	return 0;
}

int cxi_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask,
		 struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd;

	return ibv_cmd_query_qp(qp, attr, attr_mask, init_attr, &cmd, sizeof(cmd));
}

int cxi_destroy_qp(struct ibv_qp *qp)
{
	struct cxi_qp *cxi_qp = to_cxi_qp(qp);
	struct cxi_context *ctx = to_cxi_ctx(qp->context);
	int ret;

	ret = ibv_cmd_destroy_qp(qp);
	if (ret)
		return ret;

	pthread_spin_lock(&ctx->qp_table_lock);
	cxi_qp_unregister_locked(ctx, cxi_qp);
	pthread_spin_unlock(&ctx->qp_table_lock);

	if (!ret) {
		if (cxi_qp->tgq_db)
			munmap(cxi_qp->tgq_db, cxi_qp->tgq_db_size);
		if (cxi_qp->tgq_cmds)
			munmap(cxi_qp->tgq_cmds, cxi_qp->tgq_cmds_size);
		if (cxi_qp->txq_db)
			munmap(cxi_qp->txq_db, cxi_qp->txq_db_size);
		if (cxi_qp->txq_cmds)
			munmap(cxi_qp->txq_cmds, cxi_qp->txq_cmds_size);
		free(cxi_qp->recv_wrids);
		free(cxi_qp->send_wrids);
		free(cxi_qp->send_opcodes);
		free(cxi_qp->send_job_ids);
		free(cxi_qp->send_cookies);
		free(cxi_qp->send_slot_valid);
		pthread_mutex_destroy(&cxi_qp->builder_lock);
		free(cxi_qp->pending_wrs);
		pthread_spin_destroy(&cxi_qp->sq_lock);
		pthread_spin_destroy(&cxi_qp->rq_lock);
		free(cxi_qp);
	}

	return ret;
}

/*
 * ibv_qp_ex work-request builder support.
 *
 * Each wr_* setter stages fields into cxi_qp->wr_build. Finished requests
 * are retained until wr_complete() emits the batch under sq_lock, so address
 * lookups and allocation never run under the SQ spinlock. This mirrors cxi_post_send()
 * closely enough that the two are kept as separate implementations rather
 * than factored together -- ibv_post_send() and the qp_ex builder have
 * different error/locking conventions, and this way neither one has to bend
 * to accommodate the other.
 */

static struct cxi_qp *to_cxi_qp_ex(struct ibv_qp_ex *ibvqpx)
{
	return container_of(ibvqpx, struct cxi_qp, vqp.qp_ex);
}

/* Emit the work request staged in cxi_qp->wr_build, if any. */
static void cxi_wr_emit_pending(struct cxi_qp *cxi_qp)
{
	struct cxi_context *ctx = to_cxi_ctx(cxi_qp->vqp.qp.context);
	struct cxi_ibv_cq *scq = to_cxi_ibv_cq(cxi_qp->vqp.qp.send_cq);
	struct cxi_wr_build *b = &cxi_qp->wr_build;
	struct c_full_dma_cmd cmd = {};
	struct ibv_sge sge;
	uint32_t send_slot;
	uint64_t send_cookie;
	union c_fab_addr dfa;
	uint8_t dfa_ext = 0;
	uint32_t remote_pid;
	uint64_t iova;
	uint64_t wire_rkey = 0;
	uint8_t lac;
	int ret;

	if (!b->have_wr)
		return;
	b->have_wr = false;

	if (b->err)
		return;

	if (!cxi_sq_find_free_slot(cxi_qp, &send_slot)) {
		b->err = ENOSPC;
		return;
	}
	ret = cxi_sq_make_cookie(cxi_qp, send_slot, &send_cookie);
	if (ret) {
		b->err = ret;
		return;
	}

	if (!b->has_addr || !b->has_sge) {
		b->err = EOPNOTSUPP;
		return;
	}

	sge.addr = b->local_addr;
	sge.length = b->length;
	sge.lkey = (uint32_t)b->lkey;
	if (b->sge64) {
		struct ibv_sge64 wide = {
			.addr = b->local_addr,
			.length = b->length,
			.lkey64 = b->lkey,
		};

		b->err = cxi_sge64_to_sge(ctx, cxi_qp->vqp.qp.pd, &wide, &sge);
		if (b->err)
			return;
	}

	if (!cxi_sge_resolve(ctx, &sge, &iova, &lac)) {
		b->err = EINVAL;
		return;
	}

	if (b->opcode != IBV_WR_SEND && b->opcode != IBV_WR_SEND_WITH_IMM &&
	    b->opcode != CXI_WR_SEND_WITH_IMM64) {
		b->err = b->rkey64 ? -cxi_le_wire_key(b->rkey64, &wire_rkey) : EINVAL;
		if (b->err)
			return;
	}
	remote_pid = b->remote_qpn & CXI_QPN_PID_MASK;
	cxi_build_dfa(b->remote_nid, remote_pid, ctx->pid_bits, CXI_QPN_RI(b->remote_qpn), &dfa,
		      &dfa_ext);

	if (b->jkey != cxi_qp->lcid) {
		ret = cxi_cq_emit_cq_lcid(&cxi_qp->hw_txq, b->jkey);
		if (ret) {
			b->err = ret < 0 ? -ret : ret;
			return;
		}
	}

	if (b->opcode == IBV_WR_SEND || b->opcode == IBV_WR_SEND_WITH_IMM ||
	    b->opcode == CXI_WR_SEND_WITH_IMM64) {
		cmd.command.opcode = C_CMD_PUT;
		cmd.remote_offset = 0;
	} else {
		cmd.command.opcode = (b->opcode == IBV_WR_RDMA_READ) ? C_CMD_GET : C_CMD_PUT;
		cmd.remote_offset = b->remote_addr;
		cmd.match_bits = wire_rkey;
	}
	cmd.lac = lac;
	cmd.dfa = dfa;
	cmd.index_ext = dfa_ext;
	cmd.local_addr = iova;
	cmd.request_len = b->length;
	cmd.user_ptr = send_cookie;
	cmd.eq = scq->eqn;
	cmd.event_send_disable = 1;
	cmd.initiator = cxi_qp->src_id;
	if (b->has_imm)
		cmd.header_data = b->imm_is64 ? be64toh(b->imm64) : be32toh(b->imm32);

	ret = cxi_cq_emit_dma(&cxi_qp->hw_txq, &cmd);

	if (!ret && b->jkey != cxi_qp->lcid)
		ret = cxi_cq_emit_cq_lcid(&cxi_qp->hw_txq, cxi_qp->lcid);
	if (ret) {
		b->err = ret < 0 ? -ret : ret;
		return;
	}

	cxi_sq_record_send(cxi_qp, send_slot, send_cookie, b->wr_id, b->opcode, b->job_id);
	b->send_slot = send_slot;
}

static void cxi_wr_flush_pending(struct cxi_qp *qp)
{
	struct cxi_wr_build *build = &qp->wr_build;

	if (!build->have_wr || build->err)
		return;
	if (qp->pending_count == qp->pending_capacity) {
		size_t capacity = qp->pending_capacity ? qp->pending_capacity * 2 : 16;
		struct cxi_wr_build *pending;

		if (capacity < qp->pending_capacity || capacity > SIZE_MAX / sizeof(*pending)) {
			build->err = ENOMEM;
			return;
		}
		pending = realloc(qp->pending_wrs, capacity * sizeof(*pending));
		if (!pending) {
			build->err = ENOMEM;
			return;
		}
		qp->pending_wrs = pending;
		qp->pending_capacity = capacity;
	}
	qp->pending_wrs[qp->pending_count++] = *build;
	build->have_wr = false;
}

static void cxi_wr_new(struct ibv_qp_ex *ibvqpx, unsigned int opcode)
{
	struct cxi_qp *cxi_qp = to_cxi_qp_ex(ibvqpx);
	struct cxi_wr_build *b = &cxi_qp->wr_build;

	cxi_wr_flush_pending(cxi_qp);

	*b = (struct cxi_wr_build){
		.err = b->err,
		.have_wr = true,
		.wr_id = ibvqpx->wr_id,
		.opcode = opcode,
		.jkey = cxi_qp->lcid,
		.job_id = cxi_qp->job_id,
	};
}

static void cxi_wr_send(struct ibv_qp_ex *ibvqpx)
{
	cxi_wr_new(ibvqpx, IBV_WR_SEND);
}

static void cxi_wr_send_imm(struct ibv_qp_ex *ibvqpx, __be32 imm_data)
{
	cxi_wr_new(ibvqpx, IBV_WR_SEND_WITH_IMM);
	to_cxi_qp_ex(ibvqpx)->wr_build.has_imm = true;
	to_cxi_qp_ex(ibvqpx)->wr_build.imm32 = imm_data;
}

static void cxi_wr_send_imm64(struct ibv_qp_ex *ibvqpx, __be64 imm_data)
{
	cxi_wr_new(ibvqpx, CXI_WR_SEND_WITH_IMM64);
	to_cxi_qp_ex(ibvqpx)->wr_build.has_imm = true;
	to_cxi_qp_ex(ibvqpx)->wr_build.imm_is64 = true;
	to_cxi_qp_ex(ibvqpx)->wr_build.imm64 = imm_data;
}

static void cxi_wr_rdma_write_op(struct ibv_qp_ex *ibvqpx, unsigned int opcode, uint64_t rkey,
				 uint64_t remote_addr)
{
	cxi_wr_new(ibvqpx, opcode);
	to_cxi_qp_ex(ibvqpx)->wr_build.remote_addr = remote_addr;
	to_cxi_qp_ex(ibvqpx)->wr_build.rkey64 = rkey;
}

static void cxi_wr_rdma_write(struct ibv_qp_ex *ibvqpx, uint32_t rkey, uint64_t remote_addr)
{
	cxi_wr_rdma_write_op(ibvqpx, IBV_WR_RDMA_WRITE, rkey, remote_addr);
}

static void cxi_wr_rdma_write64(struct ibv_qp_ex *ibvqpx, uint64_t rkey, uint64_t remote_addr)
{
	cxi_wr_rdma_write_op(ibvqpx, IBV_WR_RDMA_WRITE, rkey, remote_addr);
}

static void cxi_wr_rdma_write_imm(struct ibv_qp_ex *ibvqpx, uint32_t rkey, uint64_t remote_addr,
				  __be32 imm_data)
{
	cxi_wr_rdma_write_op(ibvqpx, IBV_WR_RDMA_WRITE_WITH_IMM, rkey, remote_addr);
	to_cxi_qp_ex(ibvqpx)->wr_build.has_imm = true;
	to_cxi_qp_ex(ibvqpx)->wr_build.imm32 = imm_data;
}

static void cxi_wr_rdma_write_imm64(struct ibv_qp_ex *ibvqpx, uint32_t rkey, uint64_t remote_addr,
				    __be64 imm_data)
{
	cxi_wr_rdma_write_op(ibvqpx, CXI_WR_RDMA_WRITE_WITH_IMM64, rkey, remote_addr);
	to_cxi_qp_ex(ibvqpx)->wr_build.has_imm = true;
	to_cxi_qp_ex(ibvqpx)->wr_build.imm_is64 = true;
	to_cxi_qp_ex(ibvqpx)->wr_build.imm64 = imm_data;
}

static void cxi_wr_rdma_write64_imm(struct ibv_qp_ex *ibvqpx, uint64_t rkey, uint64_t remote_addr,
				    __be32 imm_data)
{
	cxi_wr_rdma_write_op(ibvqpx, CXI_WR_RDMA_WRITE64_WITH_IMM, rkey, remote_addr);
	to_cxi_qp_ex(ibvqpx)->wr_build.has_imm = true;
	to_cxi_qp_ex(ibvqpx)->wr_build.imm32 = imm_data;
}

static void cxi_wr_rdma_write64_imm64(struct ibv_qp_ex *ibvqpx, uint64_t rkey, uint64_t remote_addr,
				      __be64 imm_data)
{
	cxi_wr_rdma_write_op(ibvqpx, CXI_WR_RDMA_WRITE64_WITH_IMM64, rkey, remote_addr);
	to_cxi_qp_ex(ibvqpx)->wr_build.has_imm = true;
	to_cxi_qp_ex(ibvqpx)->wr_build.imm_is64 = true;
	to_cxi_qp_ex(ibvqpx)->wr_build.imm64 = imm_data;
}

static void cxi_wr_rdma_read(struct ibv_qp_ex *ibvqpx, uint32_t rkey, uint64_t remote_addr)
{
	cxi_wr_new(ibvqpx, IBV_WR_RDMA_READ);
	to_cxi_qp_ex(ibvqpx)->wr_build.remote_addr = remote_addr;
	to_cxi_qp_ex(ibvqpx)->wr_build.rkey64 = rkey;
}

static void cxi_wr_rdma_read64(struct ibv_qp_ex *ibvqpx, uint64_t rkey, uint64_t remote_addr)
{
	cxi_wr_new(ibvqpx, IBV_WR_RDMA_READ);
	to_cxi_qp_ex(ibvqpx)->wr_build.remote_addr = remote_addr;
	to_cxi_qp_ex(ibvqpx)->wr_build.rkey64 = rkey;
}

static void cxi_wr_set_sge64(struct ibv_qp_ex *ibvqpx, uint64_t lkey, uint64_t addr,
			     uint32_t length)
{
	struct cxi_wr_build *b = &to_cxi_qp_ex(ibvqpx)->wr_build;

	if (!b->have_wr) {
		b->err = EINVAL;
		return;
	}

	b->local_addr = addr;
	b->lkey = lkey;
	b->sge64 = true;
	b->length = length;
	b->has_sge = true;
}

static void cxi_wr_set_sge_list(struct ibv_qp_ex *ibvqpx, size_t num_sge,
				const struct ibv_sge *sg_list)
{
	struct cxi_wr_build *b = &to_cxi_qp_ex(ibvqpx)->wr_build;

	if (!b->have_wr)
		return;

	if (num_sge != 1) {
		b->err = EINVAL;
		return;
	}

	b->local_addr = sg_list[0].addr;
	b->lkey = sg_list[0].lkey;
	b->sge64 = false;
	b->length = sg_list[0].length;
	b->has_sge = true;
}

static void cxi_wr_set_sge32(struct ibv_qp_ex *ibvqpx, uint32_t lkey, uint64_t addr,
			     uint32_t length)
{
	struct ibv_sge sge = {
		.addr = addr,
		.length = length,
		.lkey = lkey,
	};

	cxi_wr_set_sge_list(ibvqpx, 1, &sge);
}

static void cxi_wr_set_sge64_list(struct ibv_qp_ex *ibvqpx, size_t count,
				  const struct ibv_sge64 *list)
{
	if (count != 1 || !list) {
		to_cxi_qp_ex(ibvqpx)->wr_build.err = EINVAL;
		return;
	}
	cxi_wr_set_sge64(ibvqpx, list[0].lkey64, list[0].addr, list[0].length);
}

static void cxi_wr_set_ru_addr(struct ibv_qp_ex *ibvqpx, struct ibv_ah_ex *ah,
			       unsigned int addr_idx)
{
	struct cxi_qp *qp = to_cxi_qp_ex(ibvqpx);
	struct cxi_wr_build *b = &qp->wr_build;
	struct cxi_ah resolved = {};
	int ret;

	if (!b->have_wr)
		return;

	if (!ah) {
		ret = cxi_resolve_addr(qp->job, addr_idx, &resolved);
		if (ret) {
			b->err = ret;
			return;
		}
		b->remote_nid = resolved.nid;
		b->remote_qpn = resolved.ah_ex.remote_qpn;
	} else {
		b->ah = to_cxi_ah_ex(ah);
		b->remote_nid = b->ah->nid;
		b->remote_qpn = ah->remote_qpn;
	}
	b->has_addr = true;
}

static void cxi_wr_set_job_key(struct ibv_qp_ex *ibvqpx, uint32_t jkey)
{
	struct cxi_qp *qp = to_cxi_qp_ex(ibvqpx);
	struct cxi_wr_build *build = &qp->wr_build;
	struct cxi_pd *pd = to_cxi_pd(qp->vqp.qp.pd);
	struct cxi_job_key *entry;
	bool found = false;

	if (!build->have_wr) {
		build->err = EINVAL;
		return;
	}
	pthread_spin_lock(&pd->jkey_lock);
	for (entry = pd->jkeys; entry; entry = entry->next) {
		if (entry->key.jkey == jkey && jkey <= UINT8_MAX) {
			build->job_id = entry->job_id;
			found = true;
			break;
		}
	}
	pthread_spin_unlock(&pd->jkey_lock);
	if (!found) {
		build->err = EINVAL;
		return;
	}
	build->jkey = jkey;
}

static void cxi_wr_start(struct ibv_qp_ex *ibvqpx)
{
	struct cxi_qp *cxi_qp = to_cxi_qp_ex(ibvqpx);

	pthread_mutex_lock(&cxi_qp->builder_lock);
	cxi_qp->pending_count = 0;
	cxi_qp->wr_build = (struct cxi_wr_build){};
}

static int cxi_wr_complete(struct ibv_qp_ex *ibvqpx)
{
	struct cxi_qp *cxi_qp = to_cxi_qp_ex(ibvqpx);
	struct cxi_wr_build *b = &cxi_qp->wr_build;
	uint64_t saved_wp32;
	uint32_t saved_send_tail, saved_send_count;
	size_t emitted = 0;
	int ret;

	cxi_wr_flush_pending(cxi_qp);
	ret = b->err;
	if (ret) {
		pthread_mutex_unlock(&cxi_qp->builder_lock);
		return ret;
	}
	pthread_spin_lock(&cxi_qp->sq_lock);
	saved_wp32 = cxi_qp->hw_txq.wp32;
	saved_send_tail = cxi_qp->send_tail;
	saved_send_count = cxi_qp->send_count;
	for (size_t index = 0; index < cxi_qp->pending_count; index++) {
		*b = cxi_qp->pending_wrs[index];
		cxi_wr_emit_pending(cxi_qp);
		ret = b->err;
		if (ret)
			break;
		cxi_qp->pending_wrs[index].send_slot = b->send_slot;
		emitted++;
	}
	if (ret) {
		cxi_qp->hw_txq.wp32 = saved_wp32;
		cxi_qp->send_tail = saved_send_tail;
		cxi_qp->send_count = saved_send_count;
		for (size_t index = 0; index < emitted; index++) {
			cxi_qp->send_slot_valid[cxi_qp->pending_wrs[index].send_slot] = false;
			cxi_qp->send_cookies[cxi_qp->pending_wrs[index].send_slot] = 0;
		}
	} else {
		cxi_cq_ring(&cxi_qp->hw_txq);
	}

	pthread_spin_unlock(&cxi_qp->sq_lock);
	pthread_mutex_unlock(&cxi_qp->builder_lock);

	return ret;
}

static void cxi_wr_abort(struct ibv_qp_ex *ibvqpx)
{
	struct cxi_qp *cxi_qp = to_cxi_qp_ex(ibvqpx);

	cxi_qp->pending_count = 0;
	pthread_mutex_unlock(&cxi_qp->builder_lock);
}

/* Populate the ibv_qp_ex ops requested via IBV_QP_INIT_ATTR_SEND_OPS_FLAGS. */
static void cxi_qp_fill_wr_pfns(struct cxi_qp *qp, struct ibv_qp_init_attr_ex *attr_ex)
{
	struct ibv_qp_ex *ibvqpx = &qp->vqp.qp_ex;
	uint64_t flags = attr_ex->send_ops_flags;

	ibvqpx->wr_start = cxi_wr_start;
	ibvqpx->wr_complete = cxi_wr_complete;
	ibvqpx->wr_abort = cxi_wr_abort;

	if (flags & IBV_QP_EX_WITH_SEND)
		ibvqpx->wr_send = cxi_wr_send;
	if (flags & IBV_QP_EX_WITH_SEND_WITH_IMM)
		ibvqpx->wr_send_imm = cxi_wr_send_imm;
	if (flags & IBV_QP_EX_WITH_SEND_WITH_IMM64)
		ibvqpx->wr_send_imm64 = cxi_wr_send_imm64;
	if (flags & IBV_QP_EX_WITH_RDMA_WRITE) {
		ibvqpx->wr_rdma_write = cxi_wr_rdma_write;
		ibvqpx->wr_rdma_write64 = cxi_wr_rdma_write64;
	}
	if (flags & IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM)
		ibvqpx->wr_rdma_write_imm = cxi_wr_rdma_write_imm;
	if (flags & IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM64)
		ibvqpx->wr_rdma_write_imm64 = cxi_wr_rdma_write_imm64;
	if (flags & IBV_QP_EX_WITH_RDMA_WRITE64_WITH_IMM)
		ibvqpx->wr_rdma_write64_imm = cxi_wr_rdma_write64_imm;
	if (flags & IBV_QP_EX_WITH_RDMA_WRITE64_WITH_IMM64)
		ibvqpx->wr_rdma_write64_imm64 = cxi_wr_rdma_write64_imm64;
	if (flags & IBV_QP_EX_WITH_RDMA_READ) {
		ibvqpx->wr_rdma_read = cxi_wr_rdma_read;
		ibvqpx->wr_rdma_read64 = cxi_wr_rdma_read64;
	}

	ibvqpx->wr_set_sge64 = cxi_wr_set_sge64;
	ibvqpx->wr_set_sge = cxi_wr_set_sge32;
	ibvqpx->wr_set_sge64_list = cxi_wr_set_sge64_list;
	ibvqpx->wr_set_sge_list = cxi_wr_set_sge_list;
	ibvqpx->wr_set_ru_addr = cxi_wr_set_ru_addr;
	ibvqpx->wr_set_job_key = cxi_wr_set_job_key;
}

static int cxi_post_send_resolved(struct ibv_qp *qp, struct ibv_send_wr *wr,
				  struct ibv_send_wr **bad_wr)
{
	struct cxi_qp *cxi_qp = to_cxi_qp(qp);
	struct cxi_context *ctx = to_cxi_ctx(qp->context);
	struct cxi_ibv_cq *scq = to_cxi_ibv_cq(qp->send_cq);
	struct ibv_send_wr *original = NULL;
	struct ibv_send_wr converted;
	struct ibv_sge narrow;
	uint32_t send_slot;
	uint64_t send_cookie;
	int ret = 0;

	pthread_spin_lock(&cxi_qp->sq_lock);

	for (; wr; wr = wr->next) {
		original = wr;
		converted = *wr;
		wr = &converted;
		if (wr->send_flags & IBV_SEND_SGE64) {
			if (wr->num_sge != 1 || !wr->sg64_list) {
				ret = EINVAL;
				break;
			}
			ret = cxi_sge64_to_sge(ctx, qp->pd, wr->sg64_list, &narrow);
			if (ret)
				break;
			converted = *wr;
			converted.sg_list = &narrow;
			converted.send_flags &= ~IBV_SEND_SGE64;
			wr = &converted;
		}
		if (wr->opcode == IBV_WR_SEND || wr->opcode == IBV_WR_SEND_WITH_IMM) {
			struct ibv_ah_ex *address = original->wr.ru.ah;

			if (!address) {
				ret = EINVAL;
				break;
			}
			converted.wr.ud.ah = &address->ah_base;
			converted.wr.ud.remote_qpn = address->remote_qpn;
			converted.wr.ud.remote_qkey = original->wr.ru.jkey;
		}
		union c_fab_addr dfa;
		uint8_t dfa_ext = 0;
		uint64_t iova;
		uint8_t lac;

		if (!cxi_sq_find_free_slot(cxi_qp, &send_slot)) {
			ret = ENOSPC;
			*bad_wr = wr;
			break;
		}
		ret = cxi_sq_make_cookie(cxi_qp, send_slot, &send_cookie);
		if (ret) {
			*bad_wr = wr;
			break;
		}

		/* No room in ibv_send_wr for a 64-bit immediate; see ibv_wr_post(3). */
		if (wr->opcode > IBV_WR_ATOMIC_WRITE) {
			ret = EINVAL;
			*bad_wr = wr;
			break;
		}

		if (wr->opcode == IBV_WR_SEND || wr->opcode == IBV_WR_SEND_WITH_IMM) {
			struct c_full_dma_cmd cmd = {};
			struct cxi_ah *ah;

			if (!wr->num_sge || !wr->sg_list || !wr->wr.ud.ah) {
				ret = EOPNOTSUPP;
				*bad_wr = wr;
				break;
			}

			/* No CXI command carries a gather list. */
			if (wr->num_sge > 1) {
				ret = EINVAL;
				*bad_wr = wr;
				break;
			}

			if (!cxi_sge_resolve(ctx, &wr->sg_list[0], &iova, &lac)) {
				ret = EINVAL;
				*bad_wr = wr;
				break;
			}

			ah = to_cxi_ah(wr->wr.ud.ah);
			cxi_build_dfa(ah->nid, wr->wr.ud.remote_qpn & CXI_QPN_PID_MASK,
				      ctx->pid_bits, CXI_QPN_RI(wr->wr.ud.remote_qpn), &dfa,
				      &dfa_ext);

			/*
			 * cxi_cq_emit_nomatch_dma() forces restricted=1, which
			 * suppresses the target PUT event the receiver needs to
			 * complete its recv WR, and c_nomatch_dma_cmd has no
			 * user_ptr to carry wr_id. Use an unrestricted full DMA
			 * put instead; the destination PtlTE is non-matching, so
			 * match_bits are ignored.
			 */
			cmd.command.opcode = C_CMD_PUT;
			cmd.lac = lac;
			cmd.dfa = dfa;
			cmd.index_ext = dfa_ext;
			cmd.remote_offset = 0;
			cmd.local_addr = iova;
			cmd.request_len = wr->sg_list[0].length;
			cmd.user_ptr = send_cookie;
			cmd.eq = scq->eqn;
			/* One completion per WR: ACK only, not SEND. */
			cmd.event_send_disable = 1;
			cmd.initiator = cxi_qp->src_id;
			if (wr->opcode == IBV_WR_SEND_WITH_IMM)
				cmd.header_data = be32toh(wr->imm_data);

			ret = cxi_cq_emit_dma(&cxi_qp->hw_txq, &cmd);
			if (ret) {
				*bad_wr = wr;
				break;
			}
		} else if (wr->opcode == IBV_WR_RDMA_WRITE ||
			   wr->opcode == IBV_WR_RDMA_WRITE_WITH_IMM ||
			   wr->opcode == IBV_WR_RDMA_READ) {
			struct c_full_dma_cmd cmd = {};
			struct cxi_ah *ah;
			struct ibv_ah_ex *address = original->wr.ru_rdma.ah;
			uint32_t remote_pid;

			if (!wr->num_sge || !wr->sg_list) {
				ret = EOPNOTSUPP;
				*bad_wr = wr;
				break;
			}
			if (!address) {
				ret = EINVAL;
				break;
			}

			if (wr->num_sge > 1) {
				ret = EINVAL;
				*bad_wr = wr;
				break;
			}

			if (!cxi_sge_resolve(ctx, &wr->sg_list[0], &iova, &lac)) {
				ret = EINVAL;
				*bad_wr = wr;
				break;
			}

			ah = to_cxi_ah_ex(address);
			remote_pid = address->remote_qpn & CXI_QPN_PID_MASK;

			cxi_build_dfa(ah->nid, remote_pid, ctx->pid_bits,
				      CXI_QPN_RI(address->remote_qpn), &dfa, &dfa_ext);

			cmd.command.opcode =
				(wr->opcode == IBV_WR_RDMA_READ) ? C_CMD_GET : C_CMD_PUT;
			cmd.lac = lac;
			cmd.dfa = dfa;
			cmd.index_ext = dfa_ext;
			cmd.remote_offset = wr->wr.ru_rdma.remote_addr;
			cmd.local_addr = iova;
			cmd.request_len = wr->sg_list[0].length;
			{
				uint64_t wire_key;

				ret = wr->wr.ru_rdma.rkey64 ?
					      -cxi_le_wire_key(wr->wr.ru_rdma.rkey64, &wire_key) :
					      EINVAL;
				if (!ret)
					cmd.match_bits = wire_key;
			}
			if (ret) {
				*bad_wr = wr;
				break;
			}
			cmd.user_ptr = send_cookie;
			cmd.eq = scq->eqn;
			cmd.initiator = cxi_qp->src_id;
			/*
			 * One completion per WR: the ack for a put and the
			 * reply for a get already report it, so drop the send
			 * event that would otherwise arrive as well.
			 */
			cmd.event_send_disable = 1;
			/*
			 * Immediate data rides in the header, which the target
			 * reports in its PUT event.
			 */
			if (wr->opcode == IBV_WR_RDMA_WRITE_WITH_IMM)
				cmd.header_data = be32toh(wr->imm_data);

			ret = cxi_cq_emit_dma(&cxi_qp->hw_txq, &cmd);
			if (ret) {
				*bad_wr = wr;
				break;
			}
		} else {
			ret = EOPNOTSUPP;
			*bad_wr = wr;
			break;
		}

		cxi_sq_record_send(cxi_qp, send_slot, send_cookie, wr->wr_id, wr->opcode,
				   cxi_qp->job_id);
	}

	if (!ret)
		cxi_cq_ring(&cxi_qp->hw_txq);

	if (ret && bad_wr)
		*bad_wr = original;
	pthread_spin_unlock(&cxi_qp->sq_lock);

	return ret < 0 ? -ret : ret;
}

static bool cxi_wr_is_indexed(const struct ibv_send_wr *request)
{
	switch (request->opcode) {
	case IBV_WR_SEND:
	case IBV_WR_SEND_WITH_IMM:
		return !request->wr.ru.ah;
	case IBV_WR_RDMA_WRITE:
	case IBV_WR_RDMA_WRITE_WITH_IMM:
	case IBV_WR_RDMA_READ:
		return !request->wr.ru_rdma.ah;
	default:
		return false;
	}
}

int cxi_post_send(struct ibv_qp *qp, struct ibv_send_wr *wr, struct ibv_send_wr **bad_wr)
{
	struct cxi_prepared_wr {
		struct ibv_send_wr request;
		struct cxi_ah address;
		struct ibv_send_wr *original;
	} *prepared;
	struct ibv_send_wr *request, *failed = NULL, *lookup_failed = NULL;
	size_t count = 0, ready = 0;
	bool indexed = false;
	int ret, lookup_error = 0;

	for (request = wr; request; request = request->next) {
		indexed |= cxi_wr_is_indexed(request);
		count++;
	}
	if (!indexed)
		return cxi_post_send_resolved(qp, wr, bad_wr);
	prepared = calloc(count, sizeof(*prepared));
	if (!prepared) {
		if (bad_wr)
			*bad_wr = wr;
		return ENOMEM;
	}
	for (request = wr; request; request = request->next) {
		struct ibv_send_wr *copy = &prepared[ready].request;

		*copy = *request;
		copy->next = NULL;
		prepared[ready].original = request;
		if (cxi_wr_is_indexed(request)) {
			bool send = request->opcode == IBV_WR_SEND ||
				    request->opcode == IBV_WR_SEND_WITH_IMM;
			unsigned int index =
				send ? request->wr.ru.addr_idx : request->wr.ru_rdma.addr_idx;

			lookup_error = cxi_resolve_addr(to_cxi_qp(qp)->job, index,
							&prepared[ready].address);
			if (lookup_error) {
				lookup_failed = request;
				break;
			}
			if (send)
				copy->wr.ru.ah = &prepared[ready].address.ah_ex;
			else
				copy->wr.ru_rdma.ah = &prepared[ready].address.ah_ex;
		}
		if (ready)
			prepared[ready - 1].request.next = copy;
		ready++;
	}
	ret = ready ? cxi_post_send_resolved(qp, &prepared[0].request, &failed) : 0;
	if (ret && bad_wr) {
		for (size_t index = 0; index < ready; index++)
			if (failed == &prepared[index].request) {
				*bad_wr = prepared[index].original;
				break;
			}
	} else if (!ret && lookup_error) {
		ret = lookup_error;
		if (bad_wr)
			*bad_wr = lookup_failed;
	}
	free(prepared);
	return ret;
}

int cxi_post_recv64(struct ibv_qp *qp, struct ibv_recv_wr64 *wr, struct ibv_recv_wr64 **bad_wr)
{
	struct cxi_context *ctx = to_cxi_ctx(qp->context);

	for (; wr; wr = wr->next) {
		struct ibv_recv_wr converted = {
			.wr_id = wr->wr_id,
			.num_sge = 1,
		};
		struct ibv_recv_wr *failed;
		struct ibv_sge narrow;
		int ret;

		if (wr->num_sge != 1 || !wr->sg_list) {
			*bad_wr = wr;
			return EINVAL;
		}
		ret = cxi_sge64_to_sge(ctx, qp->pd, wr->sg_list, &narrow);
		if (!ret) {
			converted.sg_list = &narrow;
			ret = cxi_post_recv(qp, &converted, &failed);
		}
		if (ret) {
			*bad_wr = wr;
			return ret;
		}
	}
	return 0;
}

int cxi_post_recv(struct ibv_qp *qp, struct ibv_recv_wr *wr, struct ibv_recv_wr **bad_wr)
{
	struct cxi_qp *cxi_qp = to_cxi_qp(qp);
	int ret = 0;

	pthread_spin_lock(&cxi_qp->rq_lock);

	for (; wr; wr = wr->next) {
		union c_cmdu cmd = {};
		uint64_t iova;
		uint8_t lac;

		if (!wr->num_sge || !wr->sg_list || cxi_qp->pte_index < 0 ||
		    cxi_qp->recv_count == cxi_qp->rq_size) {
			ret = EINVAL;
			*bad_wr = wr;
			break;
		}

		/* A list entry describes one buffer. */
		if (wr->num_sge > 1) {
			ret = EINVAL;
			*bad_wr = wr;
			break;
		}

		if (!cxi_sge_resolve(to_cxi_ctx(qp->context), &wr->sg_list[0], &iova, &lac)) {
			ret = EINVAL;
			*bad_wr = wr;
			break;
		}

		cxi_le_recv(&cmd, (uint16_t)cxi_qp->pte_index, lac, iova, wr->sg_list[0].length);
		ret = -cxi_le_set_vni(&cmd, 0, cxi_qp->job_id);
		if (ret) {
			*bad_wr = wr;
			break;
		}

		ret = cxi_cq_emit_target(&cxi_qp->hw_tgq, &cmd);
		if (ret) {
			*bad_wr = wr;
			break;
		}

		cxi_qp->recv_wrids[cxi_qp->recv_tail] = wr->wr_id;
		cxi_qp->recv_tail = (cxi_qp->recv_tail + 1) % cxi_qp->rq_size;
		cxi_qp->recv_count++;
	}

	if (!ret)
		cxi_cq_ring(&cxi_qp->hw_tgq);

	pthread_spin_unlock(&cxi_qp->rq_lock);
	return ret < 0 ? -ret : ret;
}

/*
 * Expose a region to remote operations on this QP by giving it a list entry
 * of its own, matched on the region's rkey. Nothing else makes a registered
 * region reachable: registration only builds the ATU mapping.
 */
int cxi_attach_mr(struct ibv_qp *qp, struct ibv_mr *ibmr)
{
	struct cxi_qp *cxi_qp = to_cxi_qp(qp);
	struct cxi_mr *mr = to_cxi_mr(ibmr);
	union c_cmdu cmd = {};
	int ret;

	if (qp->pd != ibmr->pd)
		return EINVAL;
	if (cxi_qp->pte_index < 0)
		return EINVAL;

	cxi_le_region(&cmd, (uint16_t)cxi_qp->pte_index, mr->lkey64, mr->rkey64, mr->iova, mr->len);
	ret = -cxi_le_set_vni(&cmd, mr->rkey64, cxi_qp->job_id);
	if (ret)
		return ret;

	pthread_spin_lock(&cxi_qp->rq_lock);
	ret = cxi_cq_emit_target(&cxi_qp->hw_tgq, &cmd);
	if (!ret)
		cxi_cq_ring(&cxi_qp->hw_tgq);
	pthread_spin_unlock(&cxi_qp->rq_lock);

	return ret ? -ret : 0;
}

int cxi_detach_mr(struct ibv_qp *qp, struct ibv_mr *ibmr)
{
	struct cxi_qp *cxi_qp = to_cxi_qp(qp);
	struct cxi_mr *mr = to_cxi_mr(ibmr);
	union c_cmdu cmd = {};
	int ret;

	if (cxi_qp->pte_index < 0)
		return EINVAL;

	cxi_le_region_unlink(&cmd, (uint16_t)cxi_qp->pte_index, mr->rkey64);

	pthread_spin_lock(&cxi_qp->rq_lock);
	ret = cxi_cq_emit_target(&cxi_qp->hw_tgq, &cmd);
	if (!ret)
		cxi_cq_ring(&cxi_qp->hw_tgq);
	pthread_spin_unlock(&cxi_qp->rq_lock);

	return ret ? -ret : 0;
}

/*
 * A Slingshot GID carries the 20-bit NID and nothing else, so a GID with any
 * bit outside CXI_IBV_NID_MASK names a node this device cannot reach. Reject
 * it here rather than truncating it into a different node's address.
 */
static int cxi_gid_to_nid(const union ibv_gid *gid, uint32_t *nid)
{
	uint64_t id = be64toh(gid->global.interface_id);

	if (gid->global.subnet_prefix || (id & ~CXI_IBV_NID_MASK)) {
		errno = EINVAL;
		return -1;
	}

	*nid = (uint32_t)id;
	return 0;
}

static int cxi_resolve_addr(struct ibv_job *job, unsigned int addr_idx, struct cxi_ah *address)
{
	struct ibv_ah_attr_ex attr = {};
	int ret;

	if (!job)
		return EINVAL;
	ret = ibv_query_addr(job, addr_idx, &attr);
	if (ret)
		return ret;
	if (cxi_gid_to_nid(&attr.ah_attr.grh.dgid, &address->nid))
		return errno;
	address->ah_ex.remote_qpn = attr.remote_qpn;
	return 0;
}

struct ibv_ah *cxi_create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr)
{
	struct ib_uverbs_create_ah_resp resp;
	struct cxi_ah *ah;

	ah = calloc(1, sizeof(*ah));
	if (!ah)
		return NULL;

	if (ibv_cmd_create_ah(pd, &ah->ah_ex.ah_base, attr, &resp, sizeof(resp))) {
		free(ah);
		return NULL;
	}

	if (cxi_gid_to_nid(&attr->grh.dgid, &ah->nid)) {
		ibv_cmd_destroy_ah(&ah->ah_ex.ah_base);
		free(ah);
		return NULL;
	}

	return &ah->ah_ex.ah_base;
}

struct ibv_ah *cxi_create_ah_ex(struct ibv_pd *pd, struct ibv_ah_attr_ex *attr)
{
	struct ib_uverbs_create_ah_resp resp;
	struct cxi_ah *ah;

	ah = calloc(1, sizeof(*ah));
	if (!ah)
		return NULL;

	if (ibv_cmd_create_ah(pd, &ah->ah_ex.ah_base, &attr->ah_attr, &resp, sizeof(resp))) {
		free(ah);
		return NULL;
	}

	if (cxi_gid_to_nid(&attr->ah_attr.grh.dgid, &ah->nid)) {
		ibv_cmd_destroy_ah(&ah->ah_ex.ah_base);
		free(ah);
		return NULL;
	}
	ah->ah_ex.remote_qpn = attr->remote_qpn;

	return &ah->ah_ex.ah_base;
}

int cxi_destroy_ah(struct ibv_ah *ah)
{
	struct cxi_ah *cxi_ah = to_cxi_ah(ah);
	int ret;

	ret = ibv_cmd_destroy_ah(ah);
	if (!ret)
		free(cxi_ah);

	return ret;
}

struct ibv_counters *cxi_create_counters(struct ibv_context *context,
					 struct ibv_counters_init_attr *init_attr)
{
	struct verbs_counters *vcounters;
	int ret;

	vcounters = calloc(1, sizeof(*vcounters));
	if (!vcounters) {
		errno = ENOMEM;
		return NULL;
	}

	ret = ibv_cmd_create_counters(context, init_attr, vcounters, NULL);
	if (ret) {
		free(vcounters);
		errno = ret;
		return NULL;
	}

	return &vcounters->counters;
}

int cxi_destroy_counters(struct ibv_counters *counters)
{
	struct verbs_counters *vcounters = container_of(counters, struct verbs_counters, counters);
	int ret;

	ret = ibv_cmd_destroy_counters(vcounters);
	if (ret)
		return ret;

	free(vcounters);
	return 0;
}

int cxi_read_counters_ex(struct ibv_counters *counters, const uint64_t *items,
			 uint64_t *counters_value, uint64_t *timestamps, uint32_t ncounters,
			 uint32_t flags)
{
	struct verbs_counters *vcounters = container_of(counters, struct verbs_counters, counters);

	return ibv_cmd_read_counters_ex(vcounters, items, counters_value, timestamps, ncounters,
					flags, NULL);
}
