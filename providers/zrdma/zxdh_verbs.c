// SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
/*
 * Copyright (c) 2024 ZTE Corporation.
 *
 * This software is available to you under a choice of one of two
 * licenses. You may choose to be licensed under the terms of the GNU
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
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <malloc.h>
#include <linux/if_ether.h>
#include <infiniband/driver.h>
#include <ccan/container_of.h>

#include "zxdh_zrdma.h"
#include "zxdh_abi.h"


/**
 * zxdh_uquery_device_ex - query device attributes including extended properties
 * @context: user context for the device
 * @input: extensible input struct for ibv_query_device_ex verb
 * @attr: extended device attribute struct
 * @attr_size: size of extended device attribute struct
 **/
int zxdh_uquery_device_ex(struct ibv_context *context,
			  const struct ibv_query_device_ex_input *input,
			  struct ibv_device_attr_ex *attr, size_t attr_size)
{
	return 0;
}

/**
 * zxdh_uquery_port - get port attributes (msg size, lnk, mtu...)
 * @context: user context of the device
 * @port: port for the attributes
 * @attr: to return port attributes
 **/
int zxdh_uquery_port(struct ibv_context *context, uint8_t port,
		     struct ibv_port_attr *attr)
{
	return 0;
}

/**
 * zxdh_ualloc_pd - allocates protection domain and return pd ptr
 * @context: user context of the device
 **/
struct ibv_pd *zxdh_ualloc_pd(struct ibv_context *context)
{
	struct ibv_alloc_pd cmd;
	struct zxdh_ualloc_pd_resp resp = {};
	struct zxdh_upd *iwupd;
	int err;

	iwupd = malloc(sizeof(*iwupd));
	if (!iwupd)
		return NULL;

	err = ibv_cmd_alloc_pd(context, &iwupd->ibv_pd, &cmd, sizeof(cmd),
			       &resp.ibv_resp, sizeof(resp));
	if (err)
		goto err_free;

	iwupd->pd_id = resp.pd_id;

	return &iwupd->ibv_pd;

err_free:
	free(iwupd);
	errno = err;
	return NULL;
}

/**
 * zxdh_ufree_pd - free pd resources
 * @pd: pd to free resources
 */
int zxdh_ufree_pd(struct ibv_pd *pd)
{
	struct zxdh_upd *iwupd;
	int ret;

	iwupd = container_of(pd, struct zxdh_upd, ibv_pd);
	ret = ibv_cmd_dealloc_pd(pd);
	if (ret)
		return ret;

	free(iwupd);

	return 0;
}

/**
 * zxdh_ureg_mr - register user memory region
 * @pd: pd for the mr
 * @addr: user address of the memory region
 * @length: length of the memory
 * @hca_va: hca_va
 * @access: access allowed on this mr
 */
struct ibv_mr *zxdh_ureg_mr(struct ibv_pd *pd, void *addr, size_t length,
			    uint64_t hca_va, int access)
{
	return NULL;
}

/*
 * zxdh_urereg_mr - re-register memory region
 * @vmr: mr that was allocated
 * @flags: bit mask to indicate which of the attr's of MR modified
 * @pd: pd of the mr
 * @addr: user address of the memory region
 * @length: length of the memory
 * @access: access allowed on this mr
 */
int zxdh_urereg_mr(struct verbs_mr *vmr, int flags, struct ibv_pd *pd,
		   void *addr, size_t length, int access)
{
	return 0;
}

/**
 * zxdh_udereg_mr - re-register memory region
 * @vmr: mr that was allocated
 */
int zxdh_udereg_mr(struct verbs_mr *vmr)
{
	return 0;
}

/**
 * zxdh_ualloc_mw - allocate memory window
 * @pd: protection domain
 * @type: memory window type
 */
struct ibv_mw *zxdh_ualloc_mw(struct ibv_pd *pd, enum ibv_mw_type type)
{
	return NULL;
}

/**
 * zxdh_ubind_mw - bind a memory window
 * @qp: qp to post WR
 * @mw: memory window to bind
 * @mw_bind: bind info
 */
int zxdh_ubind_mw(struct ibv_qp *qp, struct ibv_mw *mw,
		  struct ibv_mw_bind *mw_bind)
{
	return 0;
}

/**
 * zxdh_udealloc_mw - deallocate memory window
 * @mw: memory window to dealloc
 */
int zxdh_udealloc_mw(struct ibv_mw *mw)
{
	return 0;
}

struct ibv_cq *zxdh_ucreate_cq(struct ibv_context *context, int cqe,
			       struct ibv_comp_channel *channel,
			       int comp_vector)
{
	return NULL;
}

struct ibv_cq_ex *zxdh_ucreate_cq_ex(struct ibv_context *context,
				     struct ibv_cq_init_attr_ex *attr_ex)
{
	return NULL;
}

/**
 * zxdh_udestroy_cq - destroys cq
 * @cq: ptr to cq to be destroyed
 */
int zxdh_udestroy_cq(struct ibv_cq *cq)
{
	return 0;
}

int zxdh_umodify_cq(struct ibv_cq *cq, struct ibv_modify_cq_attr *attr)
{
	return 0;
}

/**
 * zxdh_upoll_cq - verb API callback to poll device CQ
 * @cq: ibv_cq to poll
 * @num_entries: max cq entries to poll
 * @entry: pointer to array of ibv_wc objects to be filled in for each completion
 *
 * Returns non-negative value equal to the number of completions
 * found and a negative error code on failure
 */
int zxdh_upoll_cq(struct ibv_cq *cq, int num_entries, struct ibv_wc *entry)
{
	return 0;
}

/**
 * zxdh_uarm_cq - callback for arm of cq
 * @cq: cq to arm
 * @solicited: to get notify params
 */
int zxdh_uarm_cq(struct ibv_cq *cq, int solicited)
{
	return 0;
}

/**
 * zxdh_cq_event - cq to do completion event
 * @cq: cq to arm
 */
void zxdh_cq_event(struct ibv_cq *cq)
{

}

void *zxdh_mmap(int fd, off_t offset)
{
	void *map;

	map = mmap(NULL, ZXDH_HW_PAGE_SIZE, PROT_WRITE | PROT_READ, MAP_SHARED,
		   fd, offset);
	if (map == MAP_FAILED)
		return map;

	if (ibv_dontfork_range(map, ZXDH_HW_PAGE_SIZE)) {
		munmap(map, ZXDH_HW_PAGE_SIZE);
		return MAP_FAILED;
	}

	return map;
}

void zxdh_munmap(void *map)
{
	ibv_dofork_range(map, ZXDH_HW_PAGE_SIZE);
	munmap(map, ZXDH_HW_PAGE_SIZE);
}

/**
 * zxdh_ucreate_qp - create qp on user app
 * @pd: pd for the qp
 * @attr: attributes of the qp to be created (sizes, sge, cq)
 */
struct ibv_qp *zxdh_ucreate_qp(struct ibv_pd *pd, struct ibv_qp_init_attr *attr)
{
	return NULL;
}

/**
 * zxdh_ucreate_qp_ex - create qp_ex on user app
 * @context: user context of the device
 * @attr: attributes of the qp_ex to be created
 */
struct ibv_qp *zxdh_ucreate_qp_ex(struct ibv_context *context,
				  struct ibv_qp_init_attr_ex *attr)
{
	return NULL;
}

/**
 * zxdh_uquery_qp - query qp for some attribute
 * @qp: qp for the attributes query
 * @attr: to return the attributes
 * @attr_mask: mask of what is query for
 * @init_attr: initial attributes during create_qp
 */
int zxdh_uquery_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask,
		   struct ibv_qp_init_attr *init_attr)
{
	return 0;
}

/**
 * zxdh_umodify_qp - send qp modify to driver
 * @qp: qp to modify
 * @attr: attribute to modify
 * @attr_mask: mask of the attribute
 */
int zxdh_umodify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask)
{
	return 0;
}

/**
 * zxdh_udestroy_qp - destroy qp
 * @qp: qp to destroy
 */
int zxdh_udestroy_qp(struct ibv_qp *qp)
{
	return 0;
}

/**
 * zxdh_post_send -  post send wr for user application
 * @ib_qp: qp to post wr
 * @ib_wr: work request ptr
 * @bad_wr: return of bad wr if err
 */
int zxdh_upost_send(struct ibv_qp *ib_qp, struct ibv_send_wr *ib_wr,
		    struct ibv_send_wr **bad_wr)
{
	return 0;
}

/**
 * zxdh_post_recv - post receive wr for user application
 * @ib_wr: work request for receive
 * @bad_wr: bad wr caused an error
 */
int zxdh_upost_recv(struct ibv_qp *ib_qp, struct ibv_recv_wr *ib_wr,
		    struct ibv_recv_wr **bad_wr)
{
	return 0;
}

/**
 * zxdh_ucreate_ah - create address handle associated with a pd
 * @ibpd: pd for the address handle
 * @attr: attributes of address handle
 */
struct ibv_ah *zxdh_ucreate_ah(struct ibv_pd *ibpd, struct ibv_ah_attr *attr)
{
	return NULL;
}

/**
 * zxdh_udestroy_ah - destroy the address handle
 * @ibah: address handle
 */
int zxdh_udestroy_ah(struct ibv_ah *ibah)
{
	return 0;
}

/**
 * zxdh_uattach_mcast - Attach qp to multicast group implemented
 * @qp: The queue pair
 * @gid:The Global ID for multicast group
 * @lid: The Local ID
 */
int zxdh_uattach_mcast(struct ibv_qp *qp, const union ibv_gid *gid,
		       uint16_t lid)
{
	return 0;
}

/**
 * zxdh_udetach_mcast - Detach qp from multicast group
 * @qp: The queue pair
 * @gid:The Global ID for multicast group
 * @lid: The Local ID
 */
int zxdh_udetach_mcast(struct ibv_qp *qp, const union ibv_gid *gid,
		       uint16_t lid)
{
	return 0;
}

/**
 * zxdh_uresize_cq - resizes a cq
 * @cq: cq to resize
 * @cqe: the number of cqes of the new cq
 */
int zxdh_uresize_cq(struct ibv_cq *cq, int cqe)
{
	return 0;
}

/**
 * zxdh_ucreate_srq - create srq on user app
 * @pd: pd for the srq
 * @srq_init_attr: attributes of the srq to be created (sizes, sge)
 */
struct ibv_srq *zxdh_ucreate_srq(struct ibv_pd *pd,
				 struct ibv_srq_init_attr *srq_init_attr)
{
	return NULL;
}

/**
 * zxdh_udestroy_srq - destroy srq on user app
 * @srq: srq to destroy
 */
int zxdh_udestroy_srq(struct ibv_srq *srq)
{
	return 0;
}

/**
 * zxdh_umodify_srq - modify srq on user app
 * @srq: srq to destroy
 */
int zxdh_umodify_srq(struct ibv_srq *srq, struct ibv_srq_attr *srq_attr,
		     int srq_attr_mask)
{
	return 0;
}

/**
 * zxdh_uquery_srq - query srq on user app
 * @srq: srq to query
 * @srq_attr: attributes of the srq to be query
 */
int zxdh_uquery_srq(struct ibv_srq *srq, struct ibv_srq_attr *srq_attr)
{
	return 0;
}

/**
 * zxdh_upost_srq_recv - post srq recv on user app
 * @srq: srq to post recv
 * @recv_wr: a list of work requests to post on the receive queue
 * @bad_recv_wr: pointer to first rejected wr
 */
int zxdh_upost_srq_recv(struct ibv_srq *srq, struct ibv_recv_wr *recv_wr,
			struct ibv_recv_wr **bad_recv_wr)
{
	return 0;
}

/**
 * zxdh_uget_srq_num - get srq num on user app
 * @srq: srq to get num
 * @srq_num: to get srq num
 */
int zxdh_uget_srq_num(struct ibv_srq *srq, uint32_t *srq_num)
{
	return 0;
}
