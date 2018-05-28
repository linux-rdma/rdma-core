/*
 * Copyright (c) 2006 - 2010 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * gpl-2.0.txt in the main directory of this source tree, or the
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

#include <config.h>

#include <endian.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <malloc.h>
#include <sys/mman.h>
#include <linux/if_ether.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "nes_umain.h"
#include "nes-abi.h"

#define STATIC static
#define INLINE inline

#define NES_WC_WITH_VLAN   1 << 3
#define NES_UD_RX_BATCH_SZ 64
#define NES_UD_MAX_SG_LIST_SZ 1

struct nes_ud_send_wr {
	uint32_t               wr_cnt;
	uint32_t               qpn;
	uint32_t	       flags;
	uint32_t	       resv[1];
	struct ibv_sge	       sg_list[64];
};

struct nes_ud_recv_wr {
	uint32_t               wr_cnt;
	uint32_t               qpn;
	uint32_t	       resv[2];
	struct ibv_sge	       sg_list[64];
};

/**
 * nes_uquery_device
 */
int nes_uquery_device(struct ibv_context *context, struct ibv_device_attr *attr)
{
	struct ibv_query_device cmd;
	uint64_t nes_fw_ver;
	int ret;
	unsigned int minor, major;

	ret = ibv_cmd_query_device(context, attr, &nes_fw_ver,
					&cmd, sizeof cmd);
	if (ret)
		return ret;

	major = (nes_fw_ver >> 16) & 0xffff;
	minor = nes_fw_ver & 0xffff;

	snprintf(attr->fw_ver, sizeof attr->fw_ver,
		"%d.%d", major, minor);

	return 0;
}


/**
 * nes_uquery_port
 */
int nes_uquery_port(struct ibv_context *context, uint8_t port,
		struct ibv_port_attr *attr)
{
	struct ibv_query_port cmd;

	return ibv_cmd_query_port(context, port, attr, &cmd, sizeof cmd);
}


/**
 * nes_ualloc_pd
 */
struct ibv_pd *nes_ualloc_pd(struct ibv_context *context)
{
	struct ibv_alloc_pd cmd;
	struct nes_ualloc_pd_resp resp;
	struct nes_upd *nesupd;

	nesupd = malloc(sizeof *nesupd);
	if (!nesupd)
		return NULL;

	if (ibv_cmd_alloc_pd(context, &nesupd->ibv_pd, &cmd, sizeof cmd,
			&resp.ibv_resp, sizeof resp)) {
		free(nesupd);
		return NULL;
	}
	nesupd->pd_id = resp.pd_id;
	nesupd->db_index = resp.mmap_db_index;

	nesupd->udoorbell = mmap(NULL, page_size, PROT_WRITE | PROT_READ, MAP_SHARED,
			context->cmd_fd, nesupd->db_index * page_size);

	if (nesupd->udoorbell == MAP_FAILED) {
		free(nesupd);
		return NULL;
	}

	return &nesupd->ibv_pd;
}


/**
 * nes_ufree_pd
 */
int nes_ufree_pd(struct ibv_pd *pd)
{
	int ret;
	struct nes_upd *nesupd;

	nesupd = to_nes_upd(pd);

	ret = ibv_cmd_dealloc_pd(pd);
	if (ret)
		return ret;

	munmap((void *)nesupd->udoorbell, page_size);
	free(nesupd);

	return 0;
}


/**
 * nes_ureg_mr
 */
struct ibv_mr *nes_ureg_mr(struct ibv_pd *pd, void *addr,
		size_t length, int access)
{
	struct verbs_mr *vmr;
	struct nes_ureg_mr cmd;
	struct ib_uverbs_reg_mr_resp resp;

	vmr = malloc(sizeof(*vmr));
	if (!vmr)
		return NULL;

	cmd.reg_type = IWNES_MEMREG_TYPE_MEM;
	if (ibv_cmd_reg_mr(pd, addr, length, (uintptr_t) addr,
			access, vmr, &cmd.ibv_cmd, sizeof(cmd),
			&resp, sizeof(resp))) {
		free(vmr);

		return NULL;
	}

	return &vmr->ibv_mr;
}


/**
 * nes_udereg_mr
 */
int nes_udereg_mr(struct verbs_mr *vmr)
{
	int ret;

	ret = ibv_cmd_dereg_mr(vmr);
	if (ret)
		return ret;

	free(vmr);
	return 0;
}

/**
 * nes_ucreate_cq
 */
struct ibv_cq *nes_ucreate_cq(struct ibv_context *context, int cqe,
		struct ibv_comp_channel *channel, int comp_vector)
{
	struct nes_ucq *nesucq;
	struct nes_ureg_mr reg_mr_cmd;
	struct ib_uverbs_reg_mr_resp reg_mr_resp;
	struct nes_ucreate_cq cmd;
	struct nes_ucreate_cq_resp resp;
	int ret;
	struct nes_uvcontext *nesvctx = to_nes_uctx(context);

	nesucq = malloc(sizeof *nesucq);
	if (!nesucq) {
		return NULL;
	}
	memset(nesucq, 0, sizeof(*nesucq));

	if (pthread_spin_init(&nesucq->lock, PTHREAD_PROCESS_PRIVATE)) {
		free(nesucq);
		return NULL;
	}

	if (cqe < 4) 	/* a reasonable minimum */
		cqe = 4;
	nesucq->size = cqe + 1;
	nesucq->comp_vector = comp_vector;

	nesucq->cqes = memalign(page_size, nesucq->size*sizeof(struct nes_hw_cqe));
	if (!nesucq->cqes)
		goto err;

	/* Register the memory for the CQ */
	reg_mr_cmd.reg_type = IWNES_MEMREG_TYPE_CQ;

	ret = ibv_cmd_reg_mr(&nesvctx->nesupd->ibv_pd, (void *)nesucq->cqes,
			(nesucq->size*sizeof(struct nes_hw_cqe)),
			(uintptr_t)nesucq->cqes, IBV_ACCESS_LOCAL_WRITE,
			&nesucq->vmr, &reg_mr_cmd.ibv_cmd, sizeof(reg_mr_cmd),
			&reg_mr_resp, sizeof(reg_mr_resp));
	if (ret) {
		/* fprintf(stderr, "ibv_cmd_reg_mr failed (ret = %d).\n", ret); */
		free((struct nes_hw_cqe *)nesucq->cqes);
		goto err;
	}

	/* Create the CQ */
	memset(&cmd, 0, sizeof(cmd));
	cmd.user_cq_buffer = (__u64)((uintptr_t)nesucq->cqes);
	cmd.mcrqf = nesvctx->mcrqf;

	ret = ibv_cmd_create_cq(context, nesucq->size-1, channel, comp_vector,
			&nesucq->ibv_cq, &cmd.ibv_cmd, sizeof cmd,
			&resp.ibv_resp, sizeof resp);
	if (ret)
		goto err;

	nesucq->cq_id = (uint16_t)resp.cq_id;

	/* Zero out the CQ */
	memset((struct nes_hw_cqe *)nesucq->cqes, 0, nesucq->size*sizeof(struct nes_hw_cqe));

	return &nesucq->ibv_cq;

err:
 	/* fprintf(stderr, PFX "%s: Error Creating CQ.\n", __FUNCTION__); */
	pthread_spin_destroy(&nesucq->lock);
	free(nesucq);

	return NULL;
}


/**
 * nes_uresize_cq
 */
int nes_uresize_cq(struct ibv_cq *cq, int cqe)
{
 	/* fprintf(stderr, PFX "%s\n", __FUNCTION__); */
	return -ENOSYS;
}

/**
 * nes_udestroy_cq
 */
int nes_udestroy_cq(struct ibv_cq *cq)
{
	struct nes_ucq *nesucq = to_nes_ucq(cq);
	int ret;

	ret = ibv_cmd_destroy_cq(cq);
	if (ret)
		return ret;

	ret = ibv_cmd_dereg_mr(&nesucq->vmr);
	if (ret)
		fprintf(stderr, PFX "%s: Failed to deregister CQ Memory Region.\n", __FUNCTION__);

	/* Free CQ the memory */
	free((struct nes_hw_cqe *)nesucq->cqes);
	pthread_spin_destroy(&nesucq->lock);
	free(nesucq);

	return 0;
}

#define  NES_CQ_BUF_OV_ERR 0x3

static inline
int nes_ima_upoll_cq(struct ibv_cq *cq, int num_entries, struct ibv_wc *entry)
{
	struct nes_ucq *nesucq = to_nes_ucq(cq);
	struct nes_uvcontext *nesvctx = to_nes_uctx(cq->context);
	uint32_t cqe_misc;
	int cqe_count = 0;
	uint32_t head;
	uint32_t cq_size;

	volatile struct nes_hw_nic_cqe *cqe = NULL;
	volatile struct nes_hw_nic_cqe *cqes;

	struct nes_uqp *nesuqp = nesucq->udqp;
	uint32_t vlan_tag = 0;

	cqes = (volatile struct nes_hw_nic_cqe *)nesucq->cqes;
	head = nesucq->head;
	cq_size = nesucq->size;

	if (!nesuqp || !nesvctx)
		exit(0);
	if (nesuqp->ibv_qp.state == IBV_QPS_ERR) {
		while (cqe_count < num_entries) {
			memset(entry, 0, sizeof *entry);

		if (nesuqp->recv_cq == nesucq) {
			if (nesuqp->rq_tail != nesuqp->rq_head) {
				/* Working on a RQ Completion*/
				entry->wr_id =
					nesuqp->recv_wr_id[nesuqp->rq_tail];
				if (++nesuqp->rq_tail >= nesuqp->rq_size)
					nesuqp->rq_tail = 0;
			} else
				return cqe_count;
		} else
		if (nesuqp->send_cq == nesucq) {
			if (nesuqp->sq_tail != nesuqp->sq_head) {
				entry->wr_id =
					nesuqp->send_wr_id[nesuqp->sq_tail];
				/* Working on a SQ Completion*/
				if (++nesuqp->sq_tail >= nesuqp->sq_size)
					nesuqp->sq_tail = 0;
			} else
				return cqe_count;
		}
		entry->status = IBV_WC_WR_FLUSH_ERR;
		entry++;
		cqe_count++;
		}
		return cqe_count;
	}

	while (cqe_count < num_entries) {
		const enum ibv_wc_opcode INVAL_OP = -1;

		entry->opcode = INVAL_OP;
		cqe = &cqes[head];
		cqe_misc =
			le32toh(cqe->cqe_words[NES_NIC_CQE_MISC_IDX]);
		if (cqe_misc & NES_NIC_CQE_VALID) {
			memset(entry, 0, sizeof *entry);
			entry->opcode = INVAL_OP;
			cqe->cqe_words[NES_NIC_CQE_MISC_IDX] = 0;
			entry->status = (cqe_misc & NES_NIC_CQE_ERRV_MASK) >>
						NES_NIC_CQE_ERRV_SHIFT;
			entry->qp_num = nesuqp->qp_id;
			entry->src_qp = nesuqp->qp_id;
			if (cqe_misc & NES_NIC_CQE_SQ) {
				entry->opcode = IBV_WC_SEND;

				entry->wr_id =
					nesuqp->send_wr_id[nesuqp->sq_tail];

				/* Working on a SQ Completion*/
				if (++nesuqp->sq_tail >= nesuqp->sq_size)
					nesuqp->sq_tail = 0;
			} else {
				/* no CRC counting at all - all packets
				go to higher layer as they are received -
				the fastest path */

				entry->byte_len = cqe_misc & 0xffff;
				entry->opcode = IBV_WC_RECV;

				entry->wr_id =
					nesuqp->recv_wr_id[nesuqp->rq_tail];
				if (cqe_misc & NES_NIC_CQE_TAG_VALID) {
					vlan_tag = le32toh(
				cqe->cqe_words[NES_NIC_CQE_TAG_PKT_TYPE_IDX])
									>> 16;
					entry->sl = (vlan_tag >> 12) & 0x0f;
					entry->pkey_index = vlan_tag & 0x0fff;
					entry->wc_flags |= NES_WC_WITH_VLAN;
				}


				/* Working on a RQ Completion*/
				if (++nesuqp->rq_tail >= nesuqp->rq_size)
					nesuqp->rq_tail = 0;
				if (entry->status == NES_CQ_BUF_OV_ERR)
					entry->status = IBV_WC_LOC_LEN_ERR;
			}

			if (++head >= cq_size)
				head = 0;

			if (entry->opcode != INVAL_OP) {
				/* it is possible that no entry will be
				  available */
				cqe_count++;
				entry++;
			}

			nesvctx->nesupd->udoorbell->cqe_alloc =
				htole32(nesucq->cq_id | (1 << 16));
		} else {
			break;
		}
	}
	nesucq->head = head;
	return cqe_count;
}

/**
 * nes_upoll_cq
 */
int nes_upoll_cq(struct ibv_cq *cq, int num_entries, struct ibv_wc *entry)
{
	uint64_t wrid;
	struct nes_ucq *nesucq;
	struct nes_uvcontext *nesvctx = NULL;
	struct nes_uqp *nesuqp;
	int cqe_count=0;
	uint32_t head;
	uint32_t cq_size;
	uint32_t wqe_index;
	uint32_t wq_tail = 0;
	struct nes_hw_cqe cqe;
	uint64_t u64temp;
	int move_cq_head = 1;
	uint32_t err_code;

	nesucq = to_nes_ucq(cq);
	nesvctx = to_nes_uctx(cq->context);

	if (nesucq->cq_id < 64)
		return nes_ima_upoll_cq(cq, num_entries, entry);

	pthread_spin_lock(&nesucq->lock);

	head = nesucq->head;
	cq_size = nesucq->size;

	while (cqe_count<num_entries) {
		if ((le32toh(nesucq->cqes[head].cqe_words[NES_CQE_OPCODE_IDX]) & NES_CQE_VALID) == 0)
			break;

		/* Make sure we read CQ entry contents *after* we've checked the valid bit. */
		udma_from_device_barrier();

		cqe = (volatile struct nes_hw_cqe)nesucq->cqes[head];

		/* parse CQE, get completion context from WQE (either rq or sq */
		wqe_index = le32toh(cqe.cqe_words[NES_CQE_COMP_COMP_CTX_LOW_IDX]) & 511;
		u64temp = ((uint64_t) (le32toh(cqe.cqe_words[NES_CQE_COMP_COMP_CTX_LOW_IDX]))) |
				(((uint64_t) (le32toh(cqe.cqe_words[NES_CQE_COMP_COMP_CTX_HIGH_IDX])))<<32);

		if (likely(u64temp)) {
			nesuqp = (struct nes_uqp *)(uintptr_t)(u64temp & (~1023));
			memset(entry, 0, sizeof *entry);
			if (likely(le32toh(cqe.cqe_words[NES_CQE_ERROR_CODE_IDX]) == 0)) {
				entry->status = IBV_WC_SUCCESS;
			} else {
				err_code = le32toh(cqe.cqe_words[NES_CQE_ERROR_CODE_IDX]);
				if (NES_IWARP_CQE_MAJOR_DRV == (err_code >> 16)) {
					entry->status = err_code & 0x0000ffff;
				} else {
					entry->status = IBV_WC_WR_FLUSH_ERR;
					if (le32toh(cqe.cqe_words[NES_CQE_OPCODE_IDX]) & NES_CQE_SQ) {
						if (wqe_index == 0 && nesuqp->rdma0_msg) {
							nesuqp->sq_tail = (wqe_index+1)&(nesuqp->sq_size - 1);
							move_cq_head = 0;
							wq_tail = nesuqp->sq_tail;
							nesuqp->rdma0_msg = 0;
							goto nes_upoll_cq_update;
						}
					}
				}
			}
			entry->qp_num = nesuqp->qp_id;
			entry->src_qp = nesuqp->qp_id;
			nesuqp->rdma0_msg = 0;

			if (le32toh(cqe.cqe_words[NES_CQE_OPCODE_IDX]) & NES_CQE_SQ) {
				/* Working on a SQ Completion*/
				wrid = ((uint64_t) le32toh(nesuqp->sq_vbase[wqe_index].wqe_words[NES_IWARP_SQ_WQE_COMP_SCRATCH_LOW_IDX])) |
					(((uint64_t) le32toh(nesuqp->sq_vbase[wqe_index].wqe_words[NES_IWARP_SQ_WQE_COMP_SCRATCH_HIGH_IDX]))<<32);
				entry->byte_len = le32toh(nesuqp->sq_vbase[wqe_index].wqe_words[NES_IWARP_SQ_WQE_TOTAL_PAYLOAD_IDX]);

				switch (le32toh(nesuqp->sq_vbase[wqe_index].
						wqe_words[NES_IWARP_SQ_WQE_MISC_IDX]) & 0x3f) {
					case NES_IWARP_SQ_OP_RDMAW:
						/* fprintf(stderr, PFX "%s: Operation = RDMA WRITE.\n",
								__FUNCTION__ ); */
						entry->opcode = IBV_WC_RDMA_WRITE;
						break;
					case NES_IWARP_SQ_OP_RDMAR:
						/* fprintf(stderr, PFX "%s: Operation = RDMA READ.\n",
								__FUNCTION__ ); */
						entry->opcode = IBV_WC_RDMA_READ;
						entry->byte_len = le32toh(nesuqp->sq_vbase[wqe_index].
								wqe_words[NES_IWARP_SQ_WQE_RDMA_LENGTH_IDX]);
						break;
					case NES_IWARP_SQ_OP_SENDINV:
					case NES_IWARP_SQ_OP_SENDSEINV:
					case NES_IWARP_SQ_OP_SEND:
					case NES_IWARP_SQ_OP_SENDSE:
						/* fprintf(stderr, PFX "%s: Operation = Send.\n",
								__FUNCTION__ ); */
						entry->opcode = IBV_WC_SEND;
						break;
				}

				nesuqp->sq_tail = (wqe_index+1)&(nesuqp->sq_size - 1);
				if ((entry->status != IBV_WC_SUCCESS) && (nesuqp->sq_tail != nesuqp->sq_head)) {
					move_cq_head = 0;
					wq_tail = nesuqp->sq_tail;
				}
			} else {
				/* Working on a RQ Completion*/
				entry->byte_len = le32toh(cqe.cqe_words[NES_CQE_PAYLOAD_LENGTH_IDX]);
				wrid = ((uint64_t) le32toh(nesuqp->rq_vbase[wqe_index].wqe_words[NES_IWARP_RQ_WQE_COMP_SCRATCH_LOW_IDX])) |
					(((uint64_t) le32toh(nesuqp->rq_vbase[wqe_index].wqe_words[NES_IWARP_RQ_WQE_COMP_SCRATCH_HIGH_IDX]))<<32);
				entry->opcode = IBV_WC_RECV;

				nesuqp->rq_tail = (wqe_index+1)&(nesuqp->rq_size - 1);
				if ((entry->status != IBV_WC_SUCCESS) && (nesuqp->rq_tail != nesuqp->rq_head)) {
					move_cq_head = 0;
					wq_tail = nesuqp->rq_tail;
				}
			}

			entry->wr_id = wrid;
			entry++;
			cqe_count++;
		}
nes_upoll_cq_update:
		if (move_cq_head) {
			nesucq->cqes[head].cqe_words[NES_CQE_OPCODE_IDX] = 0;
			if (++head >= cq_size)
				head = 0;
			nesucq->polled_completions++;

			if ((nesucq->polled_completions > (cq_size/2)) ||
					(nesucq->polled_completions == 255)) {
				if (nesvctx == NULL)
					nesvctx = to_nes_uctx(cq->context);
				nesvctx->nesupd->udoorbell->cqe_alloc = htole32(nesucq->cq_id |
						(nesucq->polled_completions << 16));
				nesucq->polled_completions = 0;
			}
		} else {
			/* Update the wqe index and set status to flush */
			wqe_index = le32toh(cqe.cqe_words[NES_CQE_COMP_COMP_CTX_LOW_IDX]);
			wqe_index = (wqe_index & (~511)) | wq_tail;
			nesucq->cqes[head].cqe_words[NES_CQE_COMP_COMP_CTX_LOW_IDX] = 
				htole32(wqe_index);
			nesucq->cqes[head].cqe_words[NES_CQE_ERROR_CODE_IDX] = 
				htole32((NES_IWARP_CQE_MAJOR_FLUSH << 16) | NES_IWARP_CQE_MINOR_FLUSH);
			move_cq_head = 1; /* ready for next pass */
		}
	}

	if (nesucq->polled_completions) {
		if (nesvctx == NULL)
			nesvctx = to_nes_uctx(cq->context);
		nesvctx->nesupd->udoorbell->cqe_alloc = htole32(nesucq->cq_id |
				(nesucq->polled_completions << 16));
		nesucq->polled_completions = 0;
	}
	nesucq->head = head;

	pthread_spin_unlock(&nesucq->lock);

	return cqe_count;
}


/**
 * nes_upoll_cq_no_db_read
 */
int nes_upoll_cq_no_db_read(struct ibv_cq *cq, int num_entries, struct ibv_wc *entry)
{
	uint64_t wrid;
	struct nes_ucq *nesucq;
	struct nes_uvcontext *nesvctx = NULL;
	struct nes_uqp *nesuqp;
	int cqe_count=0;
	uint32_t head;
	uint32_t cq_size;
	uint32_t wqe_index;
	uint32_t wq_tail = 0;
	struct nes_hw_cqe cqe;
	uint64_t u64temp;
	int move_cq_head = 1;
	uint32_t err_code;

	nesucq = to_nes_ucq(cq);
	nesvctx = to_nes_uctx(cq->context);

	if (nesucq->cq_id < 64)
		return nes_ima_upoll_cq(cq, num_entries, entry);

	pthread_spin_lock(&nesucq->lock);

	head = nesucq->head;
	cq_size = nesucq->size;

	while (cqe_count<num_entries) {
		if ((le32toh(nesucq->cqes[head].cqe_words[NES_CQE_OPCODE_IDX]) & NES_CQE_VALID) == 0)
			break;

		/* Make sure we read CQ entry contents *after* we've checked the valid bit. */
		udma_from_device_barrier();

		cqe = (volatile struct nes_hw_cqe)nesucq->cqes[head];

		/* parse CQE, get completion context from WQE (either rq or sq */
		wqe_index = le32toh(cqe.cqe_words[NES_CQE_COMP_COMP_CTX_LOW_IDX]) & 511;
		u64temp = ((uint64_t) (le32toh(cqe.cqe_words[NES_CQE_COMP_COMP_CTX_LOW_IDX]))) |
				(((uint64_t) (le32toh(cqe.cqe_words[NES_CQE_COMP_COMP_CTX_HIGH_IDX])))<<32);

		if (likely(u64temp)) {
			nesuqp = (struct nes_uqp *)(uintptr_t)(u64temp & (~1023));
			memset(entry, 0, sizeof *entry);
			if (likely(le32toh(cqe.cqe_words[NES_CQE_ERROR_CODE_IDX]) == 0)) {
				entry->status = IBV_WC_SUCCESS;
			} else {
				err_code = le32toh(cqe.cqe_words[NES_CQE_ERROR_CODE_IDX]);
				if (NES_IWARP_CQE_MAJOR_DRV == (err_code >> 16))
					entry->status = err_code & 0x0000ffff;
				else
					entry->status = IBV_WC_WR_FLUSH_ERR;
			}
			entry->qp_num = nesuqp->qp_id;
			entry->src_qp = nesuqp->qp_id;

			if (le32toh(cqe.cqe_words[NES_CQE_OPCODE_IDX]) & NES_CQE_SQ) {
				/* Working on a SQ Completion*/
				wrid = ((uint64_t) le32toh(nesuqp->sq_vbase[wqe_index].wqe_words[NES_IWARP_SQ_WQE_COMP_SCRATCH_LOW_IDX])) |
					(((uint64_t) le32toh(nesuqp->sq_vbase[wqe_index].wqe_words[NES_IWARP_SQ_WQE_COMP_SCRATCH_HIGH_IDX]))<<32);
				entry->byte_len = le32toh(nesuqp->sq_vbase[wqe_index].wqe_words[NES_IWARP_SQ_WQE_TOTAL_PAYLOAD_IDX]);

				switch (le32toh(nesuqp->sq_vbase[wqe_index].
						wqe_words[NES_IWARP_SQ_WQE_MISC_IDX]) & 0x3f) {
					case NES_IWARP_SQ_OP_RDMAW:
						/* fprintf(stderr, PFX "%s: Operation = RDMA WRITE.\n",
								__FUNCTION__ ); */
						entry->opcode = IBV_WC_RDMA_WRITE;
						break;
					case NES_IWARP_SQ_OP_RDMAR:
						/* fprintf(stderr, PFX "%s: Operation = RDMA READ.\n",
								__FUNCTION__ ); */
						entry->opcode = IBV_WC_RDMA_READ;
						entry->byte_len = le32toh(nesuqp->sq_vbase[wqe_index].
								wqe_words[NES_IWARP_SQ_WQE_RDMA_LENGTH_IDX]);
						break;
					case NES_IWARP_SQ_OP_SENDINV:
					case NES_IWARP_SQ_OP_SENDSEINV:
					case NES_IWARP_SQ_OP_SEND:
					case NES_IWARP_SQ_OP_SENDSE:
						/* fprintf(stderr, PFX "%s: Operation = Send.\n",
								__FUNCTION__ ); */
						entry->opcode = IBV_WC_SEND;
						break;
				}

				nesuqp->sq_tail = (wqe_index+1)&(nesuqp->sq_size - 1);
				if ((entry->status != IBV_WC_SUCCESS) && (nesuqp->sq_tail != nesuqp->sq_head)) {
					move_cq_head = 0;
					wq_tail = nesuqp->sq_tail;
				}
			} else {
				/* Working on a RQ Completion*/
				entry->byte_len = le32toh(cqe.cqe_words[NES_CQE_PAYLOAD_LENGTH_IDX]);
				wrid = ((uint64_t) le32toh(nesuqp->rq_vbase[wqe_index].wqe_words[NES_IWARP_RQ_WQE_COMP_SCRATCH_LOW_IDX])) |
					(((uint64_t) le32toh(nesuqp->rq_vbase[wqe_index].wqe_words[NES_IWARP_RQ_WQE_COMP_SCRATCH_HIGH_IDX]))<<32);
				entry->opcode = IBV_WC_RECV;

				nesuqp->rq_tail = (wqe_index+1)&(nesuqp->rq_size - 1);
				if ((entry->status != IBV_WC_SUCCESS) && (nesuqp->rq_tail != nesuqp->rq_head)) {
					move_cq_head = 0;
					wq_tail = nesuqp->rq_tail;
				}
			}

			entry->wr_id = wrid;
			entry++;
			cqe_count++;
		}

		if (move_cq_head) {
			nesucq->cqes[head].cqe_words[NES_CQE_OPCODE_IDX] = 0;
			if (++head >= cq_size)
				head = 0;
			nesucq->polled_completions++;

			if ((nesucq->polled_completions > (cq_size/2)) ||
					(nesucq->polled_completions == 255)) {
				if (nesvctx == NULL)
					nesvctx = to_nes_uctx(cq->context);
				nesvctx->nesupd->udoorbell->cqe_alloc = htole32(nesucq->cq_id |
						(nesucq->polled_completions << 16));
				nesucq->polled_completions = 0;
			}
		} else {
			/* Update the wqe index and set status to flush */
			wqe_index = le32toh(cqe.cqe_words[NES_CQE_COMP_COMP_CTX_LOW_IDX]);
			wqe_index = (wqe_index & (~511)) | wq_tail;
			nesucq->cqes[head].cqe_words[NES_CQE_COMP_COMP_CTX_LOW_IDX] =
				htole32(wqe_index);
			nesucq->cqes[head].cqe_words[NES_CQE_ERROR_CODE_IDX] =
				htole32((NES_IWARP_CQE_MAJOR_FLUSH << 16) | NES_IWARP_CQE_MINOR_FLUSH);
			move_cq_head = 1; /* ready for next pass */
		}
	}

	if (nesucq->polled_completions) {
		if (nesvctx == NULL)
			nesvctx = to_nes_uctx(cq->context);
		nesvctx->nesupd->udoorbell->cqe_alloc = htole32(nesucq->cq_id |
				(nesucq->polled_completions << 16));
		nesucq->polled_completions = 0;
	}
	nesucq->head = head;

	pthread_spin_unlock(&nesucq->lock);

	return cqe_count;
}

/**
 * nes_arm_cq
 */
static void nes_arm_cq(struct nes_ucq *nesucq, struct nes_uvcontext *nesvctx, int sol)
{
	uint32_t cq_arm;

	cq_arm = nesucq->cq_id;

	if (sol)
		cq_arm |= NES_CQE_ALLOC_NOTIFY_SE;
	else
		cq_arm |= NES_CQE_ALLOC_NOTIFY_NEXT;

	nesvctx->nesupd->udoorbell->cqe_alloc = htole32(cq_arm);
	nesucq->is_armed = 1;
	nesucq->arm_sol = sol;
	nesucq->skip_arm = 0;
	nesucq->skip_sol = 1;
}

/**
 * nes_uarm_cq
 */
int nes_uarm_cq(struct ibv_cq *cq, int solicited)
{
	struct nes_ucq *nesucq;
	struct nes_uvcontext *nesvctx;

	nesucq = to_nes_ucq(cq);
	nesvctx = to_nes_uctx(cq->context);

	pthread_spin_lock(&nesucq->lock);

	if (nesucq->is_armed) {
	/* don't arm again unless... */
		if ((nesucq->arm_sol) && (!solicited)) {
			/* solicited changed from notify SE to notify next */
			nes_arm_cq(nesucq, nesvctx, solicited);
		} else {
			nesucq->skip_arm = 1;
			nesucq->skip_sol &= solicited;
		}
	} else {
		nes_arm_cq(nesucq, nesvctx, solicited);
	}

	pthread_spin_unlock(&nesucq->lock);

	return 0;
}


/**
 * nes_cq_event
 */
void nes_cq_event(struct ibv_cq *cq)
{
	struct nes_ucq *nesucq;

	nesucq = to_nes_ucq(cq);

	pthread_spin_lock(&nesucq->lock);

	if (nesucq->skip_arm) {
		struct nes_uvcontext *nesvctx;
		nesvctx = to_nes_uctx(cq->context);
		nes_arm_cq(nesucq, nesvctx, nesucq->skip_sol);
	} else {
		nesucq->is_armed = 0;
	}

	pthread_spin_unlock(&nesucq->lock);
}


/**
 * nes_ucreate_srq
 */
struct ibv_srq *nes_ucreate_srq(struct ibv_pd *pd, struct ibv_srq_init_attr *attr)
{
	/* fprintf(stderr, PFX "%s\n", __FUNCTION__); */
	return (void *)-ENOSYS;
}


/**
 * nes_umodify_srq
 */
int nes_umodify_srq(struct ibv_srq *srq, struct ibv_srq_attr *attr, int attr_mask)
{
	/* fprintf(stderr, PFX "%s\n", __FUNCTION__); */
	return -ENOSYS;
}


/**
 * nes_udestroy_srq
 */
int nes_udestroy_srq(struct ibv_srq *srq)
{
	/* fprintf(stderr, PFX "%s\n", __FUNCTION__); */
	return -ENOSYS;
}


/**
 * nes_upost_srq_recv
 */
int nes_upost_srq_recv(struct ibv_srq *ibsrq, struct ibv_recv_wr *wr,
		struct ibv_recv_wr **bad_wr)
{
	/* fprintf(stderr, PFX "%s\n", __FUNCTION__); */
	return -ENOSYS;
}


/**
 * nes_mmapped_qp
 * will not invoke registration of memory reqion and will allow
 * the kernel module to allocate big chunk of contigous memory
 * for sq and rq... returns 1 if succeeds, 0 if fails..
 */
static int nes_mmapped_qp(struct nes_uqp *nesuqp, struct ibv_pd *pd, struct ibv_qp_init_attr *attr,
		struct nes_ucreate_qp_resp *resp)
{

	unsigned long mmap_offset;
	struct nes_ucreate_qp cmd;
	struct nes_uvcontext *nesvctx = to_nes_uctx(pd->context);
	int ret;

	memset (&cmd, 0, sizeof(cmd) );
	cmd.user_qp_buffer = (__u64) ((uintptr_t) nesuqp);

	/* fprintf(stderr, PFX "%s entering==>\n",__FUNCTION__); */
	ret = ibv_cmd_create_qp(pd, &nesuqp->ibv_qp, attr, &cmd.ibv_cmd, sizeof cmd,
		&resp->ibv_resp, sizeof (struct nes_ucreate_qp_resp) );
	if (ret)
		return 0;
	nesuqp->send_cq = to_nes_ucq(attr->send_cq);
	nesuqp->recv_cq = to_nes_ucq(attr->recv_cq);
	nesuqp->sq_db_index = resp->mmap_sq_db_index;
	nesuqp->rq_db_index = resp->mmap_rq_db_index;
	nesuqp->sq_size = resp->actual_sq_size;
	nesuqp->rq_size = resp->actual_rq_size;

	/* Map the SQ/RQ buffers */
	mmap_offset = nesvctx->max_pds*page_size;
	mmap_offset += (((sizeof(struct nes_hw_qp_wqe) * nesvctx->wq_size) + page_size-1) &
			(~(page_size-1)))*nesuqp->sq_db_index;

	nesuqp->sq_vbase = mmap(NULL, (nesuqp->sq_size+nesuqp->rq_size) *
			sizeof(struct nes_hw_qp_wqe), PROT_WRITE | PROT_READ,
			MAP_SHARED, pd->context->cmd_fd, mmap_offset);


	if (nesuqp->sq_vbase == MAP_FAILED) {
		return 0;
	}
	nesuqp->rq_vbase = (struct nes_hw_qp_wqe *)(((char *)nesuqp->sq_vbase) +
			(nesuqp->sq_size*sizeof(struct nes_hw_qp_wqe)));
	*((unsigned int *)nesuqp->sq_vbase) = 0;
	nesuqp->mapping = NES_QP_MMAP;

	return 1;
}


/**
 * nes_vmapped_qp
 * invoke registration of memory reqion. This method is used
 * when kernel can not allocate qp memory (contigous physical).
 *
 * returns 1 if succeeds, 0 if fails..
 */
static int nes_vmapped_qp(struct nes_uqp *nesuqp, struct ibv_pd *pd, struct ibv_qp_init_attr *attr,
			  struct nes_ucreate_qp_resp *resp, int sqdepth, int rqdepth)
{
	struct nes_ucreate_qp cmd;
	struct nes_ureg_mr reg_mr_cmd;
	struct ib_uverbs_reg_mr_resp reg_mr_resp;
	int totalqpsize;
	int ret;

	// fprintf(stderr, PFX "%s\n", __FUNCTION__);
	totalqpsize = (sqdepth + rqdepth) * sizeof (struct nes_hw_qp_wqe) ;
	nesuqp->sq_vbase = memalign(page_size, totalqpsize);
	if (!nesuqp->sq_vbase) {
	//	fprintf(stderr, PFX "CREATE_QP could not allocate mem of size %d\n", totalqpsize);
		return 0;
	}
	nesuqp->rq_vbase = (struct nes_hw_qp_wqe *) (((char *) nesuqp->sq_vbase) +
			   (nesuqp->sq_size * sizeof(struct nes_hw_qp_wqe)));

	reg_mr_cmd.reg_type = IWNES_MEMREG_TYPE_QP;

	//fprintf(stderr, PFX "qp_rq_vbase = %p qp_sq_vbase=%p reg_mr = %p\n",
	//		nesuqp->rq_vbase, nesuqp->sq_vbase, &nesuqp->mr);

        ret = ibv_cmd_reg_mr(pd, (void *)nesuqp->sq_vbase,totalqpsize,
			     (uintptr_t)nesuqp->sq_vbase,
			     IBV_ACCESS_LOCAL_WRITE, &nesuqp->vmr,
			     &reg_mr_cmd.ibv_cmd, sizeof(reg_mr_cmd),
			     &reg_mr_resp, sizeof(reg_mr_resp));
        if (ret) {
                // fprintf(stderr, PFX "%s ibv_cmd_reg_mr failed (ret = %d).\n", __FUNCTION__, ret);
		free((void *) nesuqp->sq_vbase);
		return 0;
        }
	// So now the memory has been registered..
	memset (&cmd, 0, sizeof(cmd) );
	cmd.user_wqe_buffers = (__u64) ((uintptr_t) nesuqp->sq_vbase);
	cmd.user_qp_buffer = (__u64) ((uintptr_t) nesuqp);
	ret = ibv_cmd_create_qp(pd, &nesuqp->ibv_qp, attr, &cmd.ibv_cmd, sizeof cmd,
				&resp->ibv_resp, sizeof (struct nes_ucreate_qp_resp) );
	if (ret) {
		ibv_cmd_dereg_mr(&nesuqp->vmr);
		free((void *)nesuqp->sq_vbase);
		return 0;
	}
	*((unsigned int *)nesuqp->rq_vbase) = 0;
	nesuqp->send_cq = to_nes_ucq(attr->send_cq);
	nesuqp->recv_cq = to_nes_ucq(attr->recv_cq);
	nesuqp->sq_db_index = resp->mmap_sq_db_index;
	nesuqp->rq_db_index = resp->mmap_rq_db_index;
	nesuqp->sq_size = resp->actual_sq_size;
	nesuqp->rq_size = resp->actual_rq_size;
	nesuqp->mapping = NES_QP_VMAP;
	return 1;
}


/**
 * nes_qp_get_qdepth
 * This routine will return the size of qdepth to be set for one
 * of the qp (sq or rq)
 */
static int nes_qp_get_qdepth(uint32_t qdepth, uint32_t maxsges)
{
	int	retdepth;

	/* Do sanity check on the parameters */
	/* Should the following be 510 or 511 */
	if ((qdepth > 510) || (maxsges > 4) )
		return 0;

	/* Do we need to do the following of */
	/* we can just return the actual value.. needed for alignment */
	if (qdepth < 32)
		retdepth = 32;
	else if (qdepth < 128)
		retdepth = 128;
	else retdepth = 512;

	return retdepth;
}


/**
 * nes_ucreate_qp
 */
struct ibv_qp *nes_ucreate_qp(struct ibv_pd *pd, struct ibv_qp_init_attr *attr)
{
	struct nes_ucreate_qp_resp resp;
	struct nes_uvcontext *nesvctx = to_nes_uctx(pd->context);
	struct nes_uqp *nesuqp;
	int	sqdepth, rqdepth;
	int	 status = 1;

	/* fprintf(stderr, PFX "%s\n", __FUNCTION__); */

	/* Sanity check QP size before proceeding */
	sqdepth = nes_qp_get_qdepth(attr->cap.max_send_wr, attr->cap.max_send_sge);
	if (!sqdepth) {
		fprintf(stderr, PFX "%s Bad sq attr parameters max_send_wr=%d max_send_sge=%d\n",
			__FUNCTION__, attr->cap.max_send_wr,attr->cap.max_send_sge);
		return NULL;
	}

	rqdepth = nes_qp_get_qdepth(attr->cap.max_recv_wr, attr->cap.max_recv_sge);
	if (!rqdepth) {
		fprintf(stderr, PFX "%s Bad rq attr parameters max_recv_wr=%d max_recv_sge=%d\n",
			__FUNCTION__, attr->cap.max_recv_wr,attr->cap.max_recv_sge);
		return NULL;
	}

	nesuqp = memalign(1024, sizeof(*nesuqp));
	if (!nesuqp)
		return NULL;
	memset(nesuqp, 0, sizeof(*nesuqp));

	if (pthread_spin_init(&nesuqp->lock, PTHREAD_PROCESS_PRIVATE)) {
		free(nesuqp);
		return NULL;
	}

	/* Initially setting it up so we will know how much memory to allocate for mapping */
	/* also setting it up in attr.. If we do not want to modify the attr struct, we */
	/* can save the original values and restore them before return. */
	nesuqp->sq_size = attr->cap.max_send_wr = sqdepth;
	nesuqp->rq_size = attr->cap.max_recv_wr = rqdepth;

	nesuqp->sq_sig_all = attr->sq_sig_all;
	if (nesvctx->virtwq) {
		status = nes_vmapped_qp(nesuqp,pd, attr,&resp,sqdepth,rqdepth);
	}else {
		status = nes_mmapped_qp(nesuqp,pd,attr, &resp);
	}

	if (!status) {
		pthread_spin_destroy(&nesuqp->lock);
		free(nesuqp);
		return NULL;
	}


	/* The following are the common parameters no matter how the */
	/* sq and rq memory was mapped.. */

	/* Account for LSMM, in theory, could get overrun if app preposts to SQ */
	nesuqp->sq_head = 1;
	nesuqp->sq_tail = 1;
	nesuqp->qp_id = resp.qp_id;
	nesuqp->nes_drv_opt = resp.nes_drv_opt;
	nesuqp->ibv_qp.qp_num = resp.qp_id;
	nesuqp->rdma0_msg = 1;

	return &nesuqp->ibv_qp;
}


/**
 * nes_uquery_qp
 */
int nes_uquery_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		  int attr_mask, struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd;

	/* fprintf(stderr, PFX "nes_uquery_qp: calling ibv_cmd_query_qp\n"); */

	return ibv_cmd_query_qp(qp, attr, attr_mask, init_attr, &cmd, sizeof(cmd));
}


/**
 * nes_umodify_qp
 */
int nes_umodify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask)
{
	struct ibv_modify_qp cmd = {};
	return ibv_cmd_modify_qp(qp, attr, attr_mask, &cmd, sizeof cmd);
}


/**
 * nes_clean_cq
 */
static void nes_clean_cq(struct nes_uqp *nesuqp, struct nes_ucq *nesucq)
{
	uint32_t cq_head;
	uint32_t lo;
	uint32_t hi;
	uint64_t u64temp;

	pthread_spin_lock(&nesucq->lock);

	cq_head = nesucq->head;
	while (le32toh(nesucq->cqes[cq_head].cqe_words[NES_CQE_OPCODE_IDX]) & NES_CQE_VALID) {
		udma_from_device_barrier();
		lo = le32toh(nesucq->cqes[cq_head].cqe_words[NES_CQE_COMP_COMP_CTX_LOW_IDX]);
		hi = le32toh(nesucq->cqes[cq_head].cqe_words[NES_CQE_COMP_COMP_CTX_HIGH_IDX]);
		u64temp = (((uint64_t)hi) << 32) | ((uint64_t)lo);
		u64temp &= (~1023);
		if (u64temp == (uint64_t)(uintptr_t)nesuqp) {
			/* Zero the context value so cqe will be ignored */
			nesucq->cqes[cq_head].cqe_words[NES_CQE_COMP_COMP_CTX_LOW_IDX] = 0;
			nesucq->cqes[cq_head].cqe_words[NES_CQE_COMP_COMP_CTX_HIGH_IDX] = 0;
		}

		if (++cq_head >= nesucq->size)
			cq_head = 0;
	}

	pthread_spin_unlock(&nesucq->lock);
}


/**
 * nes_udestroy_qp
 */
int nes_udestroy_qp(struct ibv_qp *qp)
{
	struct nes_uqp *nesuqp = to_nes_uqp(qp);
	int ret = 0;

	// fprintf(stderr, PFX "%s addr&mr= %p  \n", __FUNCTION__, &nesuqp->mr );

	if (nesuqp->mapping == NES_QP_VMAP) {
		ret = ibv_cmd_dereg_mr(&nesuqp->vmr);
		if (ret)
	 		fprintf(stderr, PFX "%s dereg_mr FAILED\n", __FUNCTION__);
		free((void *)nesuqp->sq_vbase);
	}

	if (nesuqp->mapping == NES_QP_MMAP) {
		munmap((void *)nesuqp->sq_vbase, (nesuqp->sq_size+nesuqp->rq_size) *
			sizeof(struct nes_hw_qp_wqe));
	}

	ret = ibv_cmd_destroy_qp(qp);
	if (ret) {
	 	fprintf(stderr, PFX "%s FAILED\n", __FUNCTION__);
		return ret;
	}

	pthread_spin_destroy(&nesuqp->lock);

	/* Clean any pending completions from the cq(s) */
	if (nesuqp->send_cq)
		nes_clean_cq(nesuqp, nesuqp->send_cq);

	if ((nesuqp->recv_cq) && (nesuqp->recv_cq != nesuqp->send_cq))
		nes_clean_cq(nesuqp, nesuqp->recv_cq);
	free(nesuqp);

	return 0;
}

/**
 * nes_upost_send
 */
int nes_upost_send(struct ibv_qp *ib_qp, struct ibv_send_wr *ib_wr,
		struct ibv_send_wr **bad_wr)
{
	uint64_t u64temp;
	struct nes_uqp *nesuqp = to_nes_uqp(ib_qp);
	struct nes_upd *nesupd = to_nes_upd(ib_qp->pd);
	struct nes_hw_qp_wqe volatile *wqe;
	uint32_t head;
	uint32_t qsize = nesuqp->sq_size;
	uint32_t counter;
	uint32_t err = 0;
	uint32_t wqe_count = 0;
	uint32_t outstanding_wqes;
	uint32_t total_payload_length = 0;
	int sge_index;

	pthread_spin_lock(&nesuqp->lock);
	udma_to_device_barrier();

	head = nesuqp->sq_head;
	while (ib_wr) {
		if (unlikely(nesuqp->qperr)) {
			err = -EINVAL;
			break;
		}

		/* Check for SQ overflow */
		outstanding_wqes = head + (2 * qsize) - nesuqp->sq_tail;
		outstanding_wqes &= qsize - 1;
		if (unlikely(outstanding_wqes == (qsize - 1))) {
			err = -EINVAL;
			break;
		}
		if (unlikely(ib_wr->num_sge > 4)) {
			err = -EINVAL;
			break;
		}

		wqe = (struct nes_hw_qp_wqe *)&nesuqp->sq_vbase[head];
		/* fprintf(stderr, PFX "%s: QP%u: processing sq wqe at %p, head = %u.\n",
				__FUNCTION__, nesuqp->qp_id, wqe, head);  */
		u64temp = (uint64_t) ib_wr->wr_id;
		wqe->wqe_words[NES_IWARP_SQ_WQE_COMP_SCRATCH_LOW_IDX] = htole32((uint32_t)u64temp);
		wqe->wqe_words[NES_IWARP_SQ_WQE_COMP_SCRATCH_HIGH_IDX] = htole32((uint32_t)(u64temp>>32));
		u64temp = (uint64_t)((uintptr_t)nesuqp);
		wqe->wqe_words[NES_IWARP_SQ_WQE_COMP_CTX_LOW_IDX] = htole32((uint32_t)u64temp);
		wqe->wqe_words[NES_IWARP_SQ_WQE_COMP_CTX_HIGH_IDX] = htole32((uint32_t)(u64temp>>32));
		udma_ordering_write_barrier();
		wqe->wqe_words[NES_IWARP_SQ_WQE_COMP_CTX_LOW_IDX] |= htole32(head);

		switch (ib_wr->opcode) {
		case IBV_WR_SEND:
		case IBV_WR_SEND_WITH_IMM:
			/* fprintf(stderr, PFX "%s: QP%u: processing sq wqe%u. Opcode = %s\n",
					__FUNCTION__, nesuqp->qp_id, head, "Send"); */
			if (ib_wr->send_flags & IBV_SEND_SOLICITED) {
				wqe->wqe_words[NES_IWARP_SQ_WQE_MISC_IDX] = htole32(NES_IWARP_SQ_OP_SENDSE);
			} else {
				wqe->wqe_words[NES_IWARP_SQ_WQE_MISC_IDX] = htole32(NES_IWARP_SQ_OP_SEND);
			}

			if (ib_wr->send_flags & IBV_SEND_FENCE) {
				wqe->wqe_words[NES_IWARP_SQ_WQE_MISC_IDX] |= htole32(NES_IWARP_SQ_WQE_READ_FENCE);
			}

			/* if (ib_wr->send_flags & IBV_SEND_INLINE) {
				fprintf(stderr, PFX "%s: Send SEND_INLINE, length=%d\n",
						__FUNCTION__, ib_wr->sg_list[0].length);
			} */
			if ((ib_wr->send_flags & IBV_SEND_INLINE) && (ib_wr->sg_list[0].length <= 64) &&
				((nesuqp->nes_drv_opt & NES_DRV_OPT_NO_INLINE_DATA) == 0) &&
				(ib_wr->num_sge == 1)) {
				memcpy((void *)&wqe->wqe_words[NES_IWARP_SQ_WQE_IMM_DATA_START_IDX],
						(void *)(intptr_t)ib_wr->sg_list[0].addr, ib_wr->sg_list[0].length);
				wqe->wqe_words[NES_IWARP_SQ_WQE_TOTAL_PAYLOAD_IDX] = htole32(ib_wr->sg_list[0].length);
				wqe->wqe_words[NES_IWARP_SQ_WQE_MISC_IDX] |= htole32(NES_IWARP_SQ_WQE_IMM_DATA);
			} else {
				total_payload_length = 0;
				for (sge_index=0; sge_index < ib_wr->num_sge; sge_index++) {
					wqe->wqe_words[NES_IWARP_SQ_WQE_FRAG0_LOW_IDX+(sge_index*4)] =
							htole32((uint32_t)ib_wr->sg_list[sge_index].addr);
					wqe->wqe_words[NES_IWARP_SQ_WQE_FRAG0_HIGH_IDX+(sge_index*4)] =
							htole32((uint32_t)(ib_wr->sg_list[sge_index].addr>>32));
					wqe->wqe_words[NES_IWARP_SQ_WQE_LENGTH0_IDX+(sge_index*4)] =
							htole32(ib_wr->sg_list[sge_index].length);
					wqe->wqe_words[NES_IWARP_SQ_WQE_STAG0_IDX+(sge_index*4)] =
							htole32(ib_wr->sg_list[sge_index].lkey);
					total_payload_length += ib_wr->sg_list[sge_index].length;
				}
				wqe->wqe_words[NES_IWARP_SQ_WQE_TOTAL_PAYLOAD_IDX] =
						htole32(total_payload_length);
			}

			break;
		case IBV_WR_RDMA_WRITE:
		case IBV_WR_RDMA_WRITE_WITH_IMM:
			/* fprintf(stderr, PFX "%s:QP%u: processing sq wqe%u. Opcode = %s\n",
					__FUNCTION__, nesuqp->qp_id, head, "Write"); */
			wqe->wqe_words[NES_IWARP_SQ_WQE_MISC_IDX] = htole32(NES_IWARP_SQ_OP_RDMAW);

			if (ib_wr->send_flags & IBV_SEND_FENCE) {
				wqe->wqe_words[NES_IWARP_SQ_WQE_MISC_IDX] |= htole32(NES_IWARP_SQ_WQE_READ_FENCE);
			}
			wqe->wqe_words[NES_IWARP_SQ_WQE_RDMA_STAG_IDX] = htole32(ib_wr->wr.rdma.rkey);
			wqe->wqe_words[NES_IWARP_SQ_WQE_RDMA_TO_LOW_IDX] = htole32(
					(uint32_t)ib_wr->wr.rdma.remote_addr);
			wqe->wqe_words[NES_IWARP_SQ_WQE_RDMA_TO_HIGH_IDX] = htole32(
					(uint32_t)(ib_wr->wr.rdma.remote_addr>>32));

			/* if (ib_wr->send_flags & IBV_SEND_INLINE) {
				fprintf(stderr, PFX "%s: Write SEND_INLINE, length=%d\n",
						__FUNCTION__, ib_wr->sg_list[0].length);
			} */
			if ((ib_wr->send_flags & IBV_SEND_INLINE) && (ib_wr->sg_list[0].length <= 64) &&
				((nesuqp->nes_drv_opt & NES_DRV_OPT_NO_INLINE_DATA) == 0) &&
				(ib_wr->num_sge == 1)) {
				memcpy((void *)&wqe->wqe_words[NES_IWARP_SQ_WQE_IMM_DATA_START_IDX],
						(void *)(intptr_t)ib_wr->sg_list[0].addr, ib_wr->sg_list[0].length);
				wqe->wqe_words[NES_IWARP_SQ_WQE_TOTAL_PAYLOAD_IDX] = htole32(ib_wr->sg_list[0].length);
				wqe->wqe_words[NES_IWARP_SQ_WQE_MISC_IDX] |= htole32(NES_IWARP_SQ_WQE_IMM_DATA);
			} else {
				total_payload_length = 0;
				for (sge_index=0; sge_index < ib_wr->num_sge; sge_index++) {
					wqe->wqe_words[NES_IWARP_SQ_WQE_FRAG0_LOW_IDX+(sge_index*4)] = htole32(
							(uint32_t)ib_wr->sg_list[sge_index].addr);
					wqe->wqe_words[NES_IWARP_SQ_WQE_FRAG0_HIGH_IDX+(sge_index*4)] = htole32(
							(uint32_t)(ib_wr->sg_list[sge_index].addr>>32));
					wqe->wqe_words[NES_IWARP_SQ_WQE_LENGTH0_IDX+(sge_index*4)] = htole32(
							ib_wr->sg_list[sge_index].length);
					wqe->wqe_words[NES_IWARP_SQ_WQE_STAG0_IDX+(sge_index*4)] = htole32(
							ib_wr->sg_list[sge_index].lkey);
					total_payload_length += ib_wr->sg_list[sge_index].length;
				}
				wqe->wqe_words[NES_IWARP_SQ_WQE_TOTAL_PAYLOAD_IDX] = htole32(total_payload_length);
			}
			wqe->wqe_words[NES_IWARP_SQ_WQE_RDMA_LENGTH_IDX] =
					wqe->wqe_words[NES_IWARP_SQ_WQE_TOTAL_PAYLOAD_IDX];
			break;
		case IBV_WR_RDMA_READ:
			/* fprintf(stderr, PFX "%s:QP%u:processing sq wqe%u. Opcode = %s\n",
					__FUNCTION__, nesuqp->qp_id, head, "Read"); */
			/* IWarp only supports 1 sge for RDMA reads */
			if (ib_wr->num_sge > 1) {
				err = -EINVAL;
				break;
			}
			wqe->wqe_words[NES_IWARP_SQ_WQE_MISC_IDX] = htole32(NES_IWARP_SQ_OP_RDMAR);
			wqe->wqe_words[NES_IWARP_SQ_WQE_RDMA_TO_LOW_IDX] = htole32((uint32_t)ib_wr->wr.rdma.remote_addr);
			wqe->wqe_words[NES_IWARP_SQ_WQE_RDMA_TO_HIGH_IDX] = htole32((uint32_t)(ib_wr->wr.rdma.remote_addr>>32));
			wqe->wqe_words[NES_IWARP_SQ_WQE_RDMA_STAG_IDX] = htole32(ib_wr->wr.rdma.rkey);
			wqe->wqe_words[NES_IWARP_SQ_WQE_RDMA_LENGTH_IDX] = htole32(ib_wr->sg_list->length);
			wqe->wqe_words[NES_IWARP_SQ_WQE_FRAG0_LOW_IDX] = htole32((uint32_t)ib_wr->sg_list->addr);
			wqe->wqe_words[NES_IWARP_SQ_WQE_FRAG0_HIGH_IDX] = htole32((uint32_t)(ib_wr->sg_list->addr>>32));
			wqe->wqe_words[NES_IWARP_SQ_WQE_STAG0_IDX] = htole32(ib_wr->sg_list->lkey);
			break;
		default:
			/* error */
			err = -EINVAL;
			break;
		}

			if ((ib_wr->send_flags & IBV_SEND_SIGNALED) || nesuqp->sq_sig_all) {
			/* fprintf(stderr, PFX "%s:sq wqe%u is signalled\n", __FUNCTION__, head); */
			wqe->wqe_words[NES_IWARP_SQ_WQE_MISC_IDX] |= htole32(NES_IWARP_SQ_WQE_SIGNALED_COMPL);
		}
		ib_wr = ib_wr->next;
		head++;
		wqe_count++;
		if (head >= qsize)
			head = 0;
	}

	nesuqp->sq_head = head;
	udma_to_device_barrier();
	while (wqe_count) {
		counter = (wqe_count<(uint32_t)255) ? wqe_count : 255;
		wqe_count -= counter;
		nesupd->udoorbell->wqe_alloc =  htole32((counter<<24) | 0x00800000 | nesuqp->qp_id);
	}

	if (err)
		*bad_wr = ib_wr;

	pthread_spin_unlock(&nesuqp->lock);

	return err;
}

/**
 * nes_upost_recv
 */
int nes_upost_recv(struct ibv_qp *ib_qp, struct ibv_recv_wr *ib_wr,
		struct ibv_recv_wr **bad_wr)
{
	uint64_t u64temp;
	struct nes_uqp *nesuqp = to_nes_uqp(ib_qp);
	struct nes_upd *nesupd = to_nes_upd(ib_qp->pd);
	struct nes_hw_qp_wqe *wqe;
	uint32_t head;
	uint32_t qsize = nesuqp->rq_size;
	uint32_t counter;
	uint32_t err = 0;
	uint32_t wqe_count = 0;
	uint32_t outstanding_wqes;
	uint32_t total_payload_length;
	int sge_index;

	if (unlikely(ib_wr->num_sge > 4)) {
		*bad_wr = ib_wr;
		return -EINVAL;
	}

	pthread_spin_lock(&nesuqp->lock);
	udma_to_device_barrier();

	head = nesuqp->rq_head;
	while (ib_wr) {
		if (unlikely(nesuqp->qperr)) {
			err = -EINVAL;
			break;
		}

		/* Check for RQ overflow */
		outstanding_wqes = head + (2 * qsize) - nesuqp->rq_tail;
		outstanding_wqes &= qsize - 1;
		if (unlikely(outstanding_wqes == (qsize - 1))) {
			err = -EINVAL;
			break;
		}

		wqe = (struct nes_hw_qp_wqe *)&nesuqp->rq_vbase[head];
		u64temp = ib_wr->wr_id;
		wqe->wqe_words[NES_IWARP_RQ_WQE_COMP_SCRATCH_LOW_IDX] =
				htole32((uint32_t)u64temp);
		wqe->wqe_words[NES_IWARP_RQ_WQE_COMP_SCRATCH_HIGH_IDX] =
				htole32((uint32_t)(u64temp >> 32));
		u64temp = (uint64_t)((uintptr_t)nesuqp);
		wqe->wqe_words[NES_IWARP_RQ_WQE_COMP_CTX_LOW_IDX] =
				htole32((uint32_t)u64temp);
		wqe->wqe_words[NES_IWARP_RQ_WQE_COMP_CTX_HIGH_IDX] =
				htole32((uint32_t)(u64temp >> 32));
		udma_ordering_write_barrier();
		wqe->wqe_words[NES_IWARP_RQ_WQE_COMP_CTX_LOW_IDX] |= htole32(head);

		total_payload_length = 0;
		for (sge_index=0; sge_index < ib_wr->num_sge; sge_index++) {
			wqe->wqe_words[NES_IWARP_RQ_WQE_FRAG0_LOW_IDX+(sge_index*4)] =
					htole32((uint32_t)ib_wr->sg_list[sge_index].addr);
			wqe->wqe_words[NES_IWARP_RQ_WQE_FRAG0_HIGH_IDX+(sge_index*4)] =
					htole32((uint32_t)(ib_wr->sg_list[sge_index].addr>>32));
			wqe->wqe_words[NES_IWARP_RQ_WQE_LENGTH0_IDX+(sge_index*4)] =
					htole32(ib_wr->sg_list[sge_index].length);
			wqe->wqe_words[NES_IWARP_RQ_WQE_STAG0_IDX+(sge_index*4)] =
					htole32(ib_wr->sg_list[sge_index].lkey);
			total_payload_length += ib_wr->sg_list[sge_index].length;
		}
		wqe->wqe_words[NES_IWARP_RQ_WQE_TOTAL_PAYLOAD_IDX] = htole32(total_payload_length);

		ib_wr = ib_wr->next;
		head++;
		wqe_count++;
		if (head >= qsize)
			head = 0;
	}

	nesuqp->rq_head = head;
	udma_to_device_barrier();
	while (wqe_count) {
		counter = (wqe_count<(uint32_t)255) ? wqe_count : 255;
		wqe_count -= counter;
		nesupd->udoorbell->wqe_alloc = htole32((counter << 24) | nesuqp->qp_id);
	}

	if (err)
		*bad_wr = ib_wr;

	pthread_spin_unlock(&nesuqp->lock);

	return err;
}


/**
 * nes_ucreate_ah
 */
struct ibv_ah *nes_ucreate_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr)
{
	/* fprintf(stderr, PFX "%s\n", __FUNCTION__); */
	return (void *)-ENOSYS;
}


/**
 * nes_udestroy_ah
 */
int nes_udestroy_ah(struct ibv_ah *ah)
{
	/* fprintf(stderr, PFX "%s\n", __FUNCTION__); */
	return -ENOSYS;
}


/**
 * nes_uattach_mcast
 */
int nes_uattach_mcast(struct ibv_qp *qp, const union ibv_gid *gid, uint16_t lid)
{
	int ret = 0;
	ret =  ibv_cmd_attach_mcast(qp, gid, lid);
	nes_debug(NES_DBG_UD, "%s ret=%d\n", __func__, ret);
	return ret;
}


/**
 * nes_udetach_mcast
 */
int nes_udetach_mcast(struct ibv_qp *qp, const union ibv_gid *gid, uint16_t lid)
{
	int ret = 0;
	ret = ibv_cmd_detach_mcast(qp, gid, lid);
	nes_debug(NES_DBG_UD, "%s ret=%d\n", __func__, ret);
	return ret;
}

/**
 * nes_async_event
 */
void nes_async_event(struct ibv_async_event *event)
{
	struct nes_uqp *nesuqp;

	switch (event->event_type) {
	case IBV_EVENT_QP_FATAL:
	case IBV_EVENT_QP_ACCESS_ERR:
		/* Do not let application queue anything else to the qp */
		nesuqp = to_nes_uqp(event->element.qp);
		nesuqp->qperr = 1;
		break;

	default:
		break;
	}
}
