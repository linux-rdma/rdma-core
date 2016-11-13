/*
 * Copyright (c) 2016 Hisilicon Limited.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include "hns_roce_u.h"
#include "hns_roce_u_abi.h"
#include "hns_roce_u_hw_v1.h"

int hns_roce_u_query_device(struct ibv_context *context,
			    struct ibv_device_attr *attr)
{
	int ret;
	struct ibv_query_device cmd;
	uint64_t raw_fw_ver;
	unsigned int major, minor, sub_minor;

	ret = ibv_cmd_query_device(context, attr, &raw_fw_ver, &cmd,
				   sizeof(cmd));
	if (ret)
		return ret;

	major	   = (raw_fw_ver >> 32) & 0xffff;
	minor	   = (raw_fw_ver >> 16) & 0xffff;
	sub_minor = raw_fw_ver & 0xffff;

	snprintf(attr->fw_ver, sizeof(attr->fw_ver), "%d.%d.%03d", major, minor,
		 sub_minor);

	return 0;
}

int hns_roce_u_query_port(struct ibv_context *context, uint8_t port,
			  struct ibv_port_attr *attr)
{
	struct ibv_query_port cmd;

	return ibv_cmd_query_port(context, port, attr, &cmd, sizeof(cmd));
}

struct ibv_pd *hns_roce_u_alloc_pd(struct ibv_context *context)
{
	struct ibv_alloc_pd cmd;
	struct hns_roce_pd *pd;
	struct hns_roce_alloc_pd_resp resp;

	pd = (struct hns_roce_pd *)malloc(sizeof(*pd));
	if (!pd)
		return NULL;

	if (ibv_cmd_alloc_pd(context, &pd->ibv_pd, &cmd, sizeof(cmd),
			     &resp.ibv_resp, sizeof(resp))) {
		free(pd);
		return NULL;
	}

	pd->pdn = resp.pdn;

	return &pd->ibv_pd;
}

int hns_roce_u_free_pd(struct ibv_pd *pd)
{
	int ret;

	ret = ibv_cmd_dealloc_pd(pd);
	if (ret)
		return ret;

	free(to_hr_pd(pd));

	return ret;
}

struct ibv_mr *hns_roce_u_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
				 int access)
{
	int ret;
	struct ibv_mr *mr;
	struct ibv_reg_mr cmd;
	struct ibv_reg_mr_resp resp;

	if (!addr) {
		fprintf(stderr, "2nd parm addr is NULL!\n");
		return NULL;
	}

	if (!length) {
		fprintf(stderr, "3st parm length is 0!\n");
		return NULL;
	}

	mr = malloc(sizeof(*mr));
	if (!mr)
		return NULL;

	ret = ibv_cmd_reg_mr(pd, addr, length, (uintptr_t) addr, access, mr,
			     &cmd, sizeof(cmd), &resp, sizeof(resp));
	if (ret) {
		free(mr);
		return NULL;
	}

	return mr;
}

int hns_roce_u_dereg_mr(struct ibv_mr *mr)
{
	int ret;

	ret = ibv_cmd_dereg_mr(mr);
	if (ret)
		return ret;

	free(mr);

	return ret;
}

static int align_cq_size(int req)
{
	int nent;

	for (nent = HNS_ROCE_MIN_CQE_NUM; nent < req; nent <<= 1)
		;

	return nent;
}

static int hns_roce_verify_cq(int *cqe, struct hns_roce_context *context)
{
	if (*cqe < HNS_ROCE_MIN_CQE_NUM) {
		fprintf(stderr, "cqe = %d, less than minimum CQE number.\n",
			*cqe);
		*cqe = HNS_ROCE_MIN_CQE_NUM;
	}

	if (*cqe > context->max_cqe)
		return -1;

	return 0;
}

static int hns_roce_alloc_cq_buf(struct hns_roce_device *dev,
				 struct hns_roce_buf *buf, int nent)
{
	if (hns_roce_alloc_buf(buf,
			align(nent * HNS_ROCE_CQE_ENTRY_SIZE, dev->page_size),
			dev->page_size))
		return -1;
	memset(buf->buf, 0, nent * HNS_ROCE_CQE_ENTRY_SIZE);

	return 0;
}

struct ibv_cq *hns_roce_u_create_cq(struct ibv_context *context, int cqe,
				    struct ibv_comp_channel *channel,
				    int comp_vector)
{
	struct hns_roce_create_cq	cmd;
	struct hns_roce_create_cq_resp	resp;
	struct hns_roce_cq		*cq;
	int				ret;

	if (hns_roce_verify_cq(&cqe, to_hr_ctx(context)))
		return NULL;

	cq = malloc(sizeof(*cq));
	if (!cq)
		return NULL;

	cq->cons_index = 0;

	if (pthread_spin_init(&cq->lock, PTHREAD_PROCESS_PRIVATE))
		goto err;

	cqe = align_cq_size(cqe);

	if (hns_roce_alloc_cq_buf(to_hr_dev(context->device), &cq->buf, cqe))
		goto err;

	cmd.buf_addr = (uintptr_t) cq->buf.buf;

	ret = ibv_cmd_create_cq(context, cqe, channel, comp_vector,
				&cq->ibv_cq, &cmd.ibv_cmd, sizeof(cmd),
				&resp.ibv_resp, sizeof(resp));
	if (ret)
		goto err_db;

	cq->cqn = resp.cqn;
	cq->cq_depth = cqe;

	if (to_hr_dev(context->device)->hw_version == HNS_ROCE_HW_VER1)
		cq->set_ci_db = to_hr_ctx(context)->cq_tptr_base + cq->cqn * 2;
	else
		cq->set_ci_db = to_hr_ctx(context)->uar +
				ROCEE_DB_OTHERS_L_0_REG;

	cq->arm_db    = cq->set_ci_db;
	cq->arm_sn    = 1;
	*(cq->set_ci_db) = 0;
	*(cq->arm_db) = 0;

	return &cq->ibv_cq;

err_db:
	hns_roce_free_buf(&cq->buf);

err:
	free(cq);

	return NULL;
}

void hns_roce_u_cq_event(struct ibv_cq *cq)
{
	to_hr_cq(cq)->arm_sn++;
}

int hns_roce_u_destroy_cq(struct ibv_cq *cq)
{
	int ret;

	ret = ibv_cmd_destroy_cq(cq);
	if (ret)
		return ret;

	hns_roce_free_buf(&to_hr_cq(cq)->buf);
	free(to_hr_cq(cq));

	return ret;
}
