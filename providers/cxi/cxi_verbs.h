/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
#ifndef __CXI_VERBS_H__
#define __CXI_VERBS_H__
#include <infiniband/driver.h>
#include <infiniband/verbs.h>

/* Function prototypes from verbs.c */
int cxi_query_device(struct ibv_context *context, const struct ibv_query_device_ex_input *input,
		     struct ibv_device_attr_ex *attr, size_t attr_size);
int cxi_query_port(struct ibv_context *context, uint8_t port, struct ibv_port_attr *attr);
struct ibv_pd *cxi_alloc_pd(struct ibv_context *context);
int cxi_dealloc_pd(struct ibv_pd *pd);
struct ibv_job *cxi_alloc_job(struct ibv_context *context, struct ibv_job_attr *attr,
			      void *user_context);
int cxi_dealloc_job(struct ibv_job *job);
int cxi_query_job(struct ibv_job *job, struct ibv_job_attr *attr);
int cxi_insert_addr(struct ibv_job *job, struct ibv_ah_attr_ex *ah_attr, unsigned int addr_idx);
int cxi_remove_addr(struct ibv_job *job, unsigned int addr_idx);
int cxi_query_addr(struct ibv_job *job, unsigned int addr_idx, struct ibv_ah_attr_ex *ah_attr);
int cxi_export_job(struct ibv_job *job, int *fd);
int cxi_import_job(struct ibv_context *context, int fd, struct ibv_job **job_out);
struct ibv_job_key *cxi_create_jkey(struct ibv_pd *pd, struct ibv_job *job);
int cxi_destroy_jkey(struct ibv_job_key *job_key);
struct ibv_mr *cxi_reg_mr(struct ibv_pd *pd, void *addr, size_t size, uint64_t hca_va,
			  int access);
struct ibv_mr *cxi_reg_mr_ex(struct ibv_pd *pd, struct ibv_mr_init_attr *attr);
int cxi_dereg_mr(struct verbs_mr *vmr);
struct ibv_cq *cxi_create_cq(struct ibv_context *context, int cqe, struct ibv_comp_channel *channel,
			     int comp_vector);
struct ibv_cq_ex *cxi_create_cq_ex(struct ibv_context *context, struct ibv_cq_init_attr_ex *attr);
int cxi_destroy_cq(struct ibv_cq *cq);
struct ibv_counters *cxi_create_counters(struct ibv_context *context,
					 struct ibv_counters_init_attr *init_attr);
int cxi_destroy_counters(struct ibv_counters *counters);
int cxi_read_counters_ex(struct ibv_counters *counters, const uint64_t *items,
			 uint64_t *counters_value, uint64_t *timestamps, uint32_t ncounters,
			 uint32_t flags);
int cxi_poll_cq(struct ibv_cq *cq, int ne, struct ibv_wc *wc);
int cxi_arm_cq(struct ibv_cq *cq, int solicited);
struct ibv_qp *cxi_create_qp(struct ibv_pd *pd, struct ibv_qp_init_attr *attr);
struct ibv_qp *cxi_create_qp_ex(struct ibv_context *context, struct ibv_qp_init_attr_ex *attr);
int cxi_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask);
int cxi_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask,
		 struct ibv_qp_init_attr *init_attr);
int cxi_destroy_qp(struct ibv_qp *qp);
int cxi_post_send(struct ibv_qp *qp, struct ibv_send_wr *wr, struct ibv_send_wr **bad_wr);
int cxi_post_recv(struct ibv_qp *qp, struct ibv_recv_wr *wr, struct ibv_recv_wr **bad_wr);
int cxi_post_recv64(struct ibv_qp *qp, struct ibv_recv_wr64 *wr, struct ibv_recv_wr64 **bad_wr);
int cxi_attach_mr(struct ibv_qp *qp, struct ibv_mr *ibmr);
int cxi_detach_mr(struct ibv_qp *qp, struct ibv_mr *ibmr);
struct ibv_ah *cxi_create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr);
struct ibv_ah *cxi_create_ah_ex(struct ibv_pd *pd, struct ibv_ah_attr_ex *attr);
int cxi_destroy_ah(struct ibv_ah *ah);
bool is_cxi_dev(struct ibv_device *device);
void cxi_free_context(struct ibv_context *ibvctx);
#endif
