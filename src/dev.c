/*
 * Copyright (c) 2006-2010 Chelsio, Inc. All rights reserved.
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
#if HAVE_CONFIG_H
#  include <config.h>
#endif				/* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <string.h>
#include <signal.h>

#include "libcxgb4.h"
#include "cxgb4-abi.h"

#define PCI_VENDOR_ID_CHELSIO		0x1425
#define PCI_DEVICE_ID_CHELSIO_PE10K	0xa000
#define PCI_DEVICE_ID_CHELSIO_T440DBG	0x4400
#define PCI_DEVICE_ID_CHELSIO_T420CR	0x4401
#define PCI_DEVICE_ID_CHELSIO_T422CR	0x4402
#define PCI_DEVICE_ID_CHELSIO_T440CR	0x4403
#define PCI_DEVICE_ID_CHELSIO_T420BCH	0x4404
#define PCI_DEVICE_ID_CHELSIO_T440BCH	0x4405
#define PCI_DEVICE_ID_CHELSIO_T440CH	0x4406
#define PCI_DEVICE_ID_CHELSIO_T420SO	0x4407
#define PCI_DEVICE_ID_CHELSIO_T420CX	0x4408
#define PCI_DEVICE_ID_CHELSIO_T420BT	0x4409
#define PCI_DEVICE_ID_CHELSIO_T404BT	0x440a
#define PCI_DEVICE_ID_CHELSIO_B420	0x440b
#define PCI_DEVICE_ID_CHELSIO_B404	0x440c
#define PCI_DEVICE_ID_CHELSIO_T480CR	0x440d
#define PCI_DEVICE_ID_CHELSIO_T440LPCR	0x440e
#define PCI_DEVICE_ID_CHELSIO_T480DC	0x4480
#define PCI_DEVICE_ID_CHELSIO_T440DC	0x4481
#define PCI_DEVICE_ID_CHELSIO_T420QM	0x4485


#define HCA(v, d, t) \
	{ .vendor = PCI_VENDOR_ID_##v,			\
	  .device = PCI_DEVICE_ID_CHELSIO_##d,		\
	  .type = CHELSIO_##t }

struct {
	unsigned vendor;
	unsigned device;
	enum c4iw_hca_type type;
} hca_table[] = {
	HCA(CHELSIO, PE10K, T4),
	HCA(CHELSIO, T440DBG, T4),
	HCA(CHELSIO, T420CR, T4),
	HCA(CHELSIO, T422CR, T4),
	HCA(CHELSIO, T440CR, T4),
	HCA(CHELSIO, T420BCH, T4),
	HCA(CHELSIO, T440BCH, T4),
	HCA(CHELSIO, T440CH, T4),
	HCA(CHELSIO, T420SO, T4),
	HCA(CHELSIO, T420CX, T4),
	HCA(CHELSIO, T420BT, T4),
	HCA(CHELSIO, T404BT, T4),
	HCA(CHELSIO, B420, T4),
	HCA(CHELSIO, B404, T4),
	HCA(CHELSIO, T480CR, T4),
	HCA(CHELSIO, T440LPCR, T4),
	HCA(CHELSIO, T480DC, T4),
	HCA(CHELSIO, T440DC, T4),
	HCA(CHELSIO, T420QM, T4),
};

int c4iw_page_size;

SLIST_HEAD(devices_struct, c4iw_dev) devices;

static struct ibv_context_ops c4iw_ctx_ops = {
	.query_device = c4iw_query_device,
	.query_port = c4iw_query_port,
	.alloc_pd = c4iw_alloc_pd,
	.dealloc_pd = c4iw_free_pd,
	.reg_mr = c4iw_reg_mr,
	.dereg_mr = c4iw_dereg_mr,
	.create_cq = c4iw_create_cq,
	.resize_cq = c4iw_resize_cq,
	.destroy_cq = c4iw_destroy_cq,
	.create_srq = c4iw_create_srq,
	.modify_srq = c4iw_modify_srq,
	.destroy_srq = c4iw_destroy_srq,
	.create_qp = c4iw_create_qp,
	.modify_qp = c4iw_modify_qp,
	.destroy_qp = c4iw_destroy_qp,
	.query_qp = c4iw_query_qp,
	.create_ah = c4iw_create_ah,
	.destroy_ah = c4iw_destroy_ah,
	.attach_mcast = c4iw_attach_mcast,
	.detach_mcast = c4iw_detach_mcast,
	.post_srq_recv = c4iw_post_srq_recv,
	.req_notify_cq = c4iw_arm_cq,
};

static struct ibv_context *c4iw_alloc_context(struct ibv_device *ibdev,
					      int cmd_fd)
{
	struct c4iw_context *context;
	struct ibv_get_context cmd;
	struct c4iw_alloc_ucontext_resp resp;
	struct c4iw_dev *rhp = to_c4iw_dev(ibdev);

	context = malloc(sizeof *context);
	if (!context)
		return NULL;

	memset(context, 0, sizeof *context);
	context->ibv_ctx.cmd_fd = cmd_fd;

	if (ibv_cmd_get_context(&context->ibv_ctx, &cmd, sizeof cmd,
				&resp.ibv_resp, sizeof resp))
		goto err_free;

	context->ibv_ctx.device = ibdev;
	context->ibv_ctx.ops = c4iw_ctx_ops;

	switch (rhp->hca_type) {
	case CHELSIO_T4:
		PDBG("%s T4 device\n", __FUNCTION__);
		context->ibv_ctx.ops.async_event = c4iw_async_event;
		context->ibv_ctx.ops.post_send = c4iw_post_send;
		context->ibv_ctx.ops.post_recv = c4iw_post_receive;
		context->ibv_ctx.ops.poll_cq = c4iw_poll_cq;
		context->ibv_ctx.ops.req_notify_cq = c4iw_arm_cq;
		break;
	default:
		PDBG("%s unknown hca type %d\n", __FUNCTION__, rhp->hca_type);
		goto err_free;
		break;
	}

	return &context->ibv_ctx;

err_free:
	free(context);
	return NULL;
}

static void c4iw_free_context(struct ibv_context *ibctx)
{
	struct c4iw_context *context = to_c4iw_ctx(ibctx);

	free(context);
}

static struct ibv_device_ops c4iw_dev_ops = {
	.alloc_context = c4iw_alloc_context,
	.free_context = c4iw_free_context
};

#ifdef STALL_DETECTION

int stall_to;

static void dump_cq(struct c4iw_cq *chp)
{
	int i;

	fprintf(stderr,
		"CQ: id %u queue_va %p cidx 0x%08x depth %u error %u \
		bits_type_ts %016lx\n"
		chp->cq.cqid, chp->cq.queue, chp->cq.cidx,
		chp->cq.size, chp->cq.error, be64_to_cpu(chp->cq.bits_type_ts));
	for (i=0; i < chp->cq.size; i++) {
		u64 *p = (u64 *)(chp->cq.queue + i);

		fprintf(stderr, "%02x: %016lx", i, be64_to_cpu(*p++));
		if (i == chp->cq.cidx)
			fprintf(stderr, " <-- cidx\n");
		else
			fprintf(stderr, "\n");
		fprintf(stderr, "%02x: %016lx\n", i, be64_to_cpu(*p++));
		fprintf(stderr, "%02x: %016lx\n", i, be64_to_cpu(*p++));
		fprintf(stderr, "%02x: %016lx\n", i, be64_to_cpu(*p++));
	}
}

static void dump_qp(struct c4iw_qp *qhp, int qid)
{
	int i;
	int j;
	struct t4_swsqe *swsqe;
	struct t4_swrqe *swrqe;
	u16 cidx, pidx;

	fprintf(stderr,
		"QP: id %u error %d qid_mask 0x%x\n"
		"    SQ: id %u va %p cidx %u pidx %u wq_pidx %u depth %u\n"
		"    RQ: id %u va %p cidx %u pidx %u depth %u\n",
		qhp->wq.sq.qid,
		qhp->wq.error,
		qhp->wq.qid_mask,
		qhp->wq.sq.qid,
		qhp->wq.sq.queue,
		qhp->wq.sq.cidx,
		qhp->wq.sq.pidx,
		qhp->wq.sq.wq_pidx,
		qhp->wq.sq.size,
		qhp->wq.rq.qid,
		qhp->wq.rq.queue,
		qhp->wq.rq.cidx,
		qhp->wq.rq.pidx,
		qhp->wq.rq.size);
	if (qid == qhp->wq.sq.qid) {
		fprintf(stderr, "SQ: \n");
		cidx = qhp->wq.sq.cidx;
		pidx = qhp->wq.sq.pidx;
		while (cidx != pidx) {
			swsqe = &qhp->wq.sq.sw_sq[cidx];
			fprintf(stderr, "%04u: wr_id %016" PRIx64
				" sq_wptr %08x read_len %u opcode 0x%x "
				"complete %u signaled %u\n",
				cidx,
				swsqe->wr_id,
				swsqe->idx,
				swsqe->read_len,
				swsqe->opcode,
				swsqe->complete,
				swsqe->signaled);
			if (++cidx == qhp->wq.sq.size)
				cidx = 0;
		}

		fprintf(stderr, "SQ WQ: \n");
		for (i=0; i < qhp->wq.sq.size; i++) {
			for (j=0; j < 16; j++) {
				fprintf(stderr, "%04u %016" PRIx64 " ",
					i, ntohll(qhp->wq.sq.queue[i].flits[j]));
				if (j == 0 && i == qhp->wq.sq.wq_pidx)
					fprintf(stderr, " <-- pidx");
				fprintf(stderr, "\n");
			}
		}
	} else if (qid == qhp->wq.rq.qid) {
		fprintf(stderr, "RQ: \n");
		cidx = qhp->wq.rq.cidx;
		pidx = qhp->wq.rq.pidx;
		while (cidx != pidx) {
			swrqe = &qhp->wq.rq.sw_rq[cidx];
			fprintf(stderr, "%04u: wr_id %016" PRIx64 "\n",
				cidx,
				swrqe->wr_id );
			if (++cidx == qhp->wq.rq.size)
				cidx = 0;
		}

		fprintf(stderr, "RQ WQ: \n");
		for (i=0; i < qhp->wq.rq.size; i++) {
			for (j=0; j < 16; j++) {
				fprintf(stderr, "%04u %016" PRIx64 " ",
					i, ntohll(qhp->wq.rq.queue[i].flits[j]));
				if (j == 0 && i == qhp->wq.rq.pidx)
					fprintf(stderr, " <-- pidx");
				if (j == 0 && i == qhp->wq.rq.cidx)
					fprintf(stderr, " <-- cidx");
				fprintf(stderr, "\n");
			}
		}
	}
}

void dump_state()
{
	struct c4iw_dev *dev;
	int i;

	fprintf(stderr, "STALL DETECTED:\n");
	SLIST_FOREACH(dev, &devices, list) {
		fprintf(stderr, "Device %s\n", dev->ibv_dev.name);
		for (i = 0; i < T4_MAX_NUM_CQ; i++) {
			if (dev->cqid2ptr[i]) {
				struct c4iw_cq *chp = dev->cqid2ptr[i];
				dump_cq(chp);
			}
		}
		for (i = 0; i < T4_MAX_NUM_QP; i++) {
			if (dev->qpid2ptr[i]) {
				struct c4iw_qp *qhp = dev->qpid2ptr[i];
				dump_qp(qhp, i);
			}
		}
	}
	fprintf(stderr, "DUMP COMPLETE:\n");
	fflush(stderr);
}

#endif /* end of STALL_DETECTION */

/*
 * c4iw_abi_version is used to store ABI for iw_cxgb4 so the user mode library
 * can know if the driver supports the kernel mode db ringing. 
 */
int c4iw_abi_version = 1;

static struct ibv_device *cxgb4_driver_init(const char *uverbs_sys_path,
					    int abi_version)
{
	char devstr[IBV_SYSFS_PATH_MAX], ibdev[16], value[32], *cp;
	struct c4iw_dev *dev;
	unsigned vendor, device, fw_maj, fw_min;
	int i;

	if (ibv_read_sysfs_file(uverbs_sys_path, "device/vendor",
				value, sizeof value) < 0)
		return NULL;
	sscanf(value, "%i", &vendor);

	if (ibv_read_sysfs_file(uverbs_sys_path, "device/device",
				value, sizeof value) < 0)
		return NULL;
	sscanf(value, "%i", &device);

	for (i = 0; i < sizeof hca_table / sizeof hca_table[0]; ++i)
		if (vendor == hca_table[i].vendor &&
		    device == hca_table[i].device)
			goto found;

	return NULL;

found:
	c4iw_abi_version = abi_version;	

	/*
	 * Verify that the firmware major number matches.  Major number
	 * mismatches are fatal.  Minor number mismatches are tolerated.
	 */
	if (ibv_read_sysfs_file(uverbs_sys_path, "ibdev",
				ibdev, sizeof ibdev) < 0)
		return NULL;

	memset(devstr, 0, sizeof devstr);
	snprintf(devstr, sizeof devstr, "%s/class/infiniband/%s",
		 ibv_get_sysfs_path(), ibdev);
	if (ibv_read_sysfs_file(devstr, "fw_ver", value, sizeof value) < 0)
		return NULL;

	cp = strtok(value+1, ".");
	sscanf(cp, "%i", &fw_maj);
	cp = strtok(NULL, ".");
	sscanf(cp, "%i", &fw_min);

	if (fw_maj < FW_MAJ) {
		fprintf(stderr, "libcxgb4: Fatal firmware version mismatch.  "
			"Firmware major number is %u and libcxgb4 needs %u.\n",
			fw_maj, FW_MAJ);
		fflush(stderr);
		return NULL;
	}

	DBGLOG("libcxgb4");

	if (fw_min < FW_MIN) {
		PDBG("libcxgb4: non-fatal firmware version mismatch.  "
			"Firmware minor number is %u and libcxgb4 needs %u.\n",
			fw_maj, FW_MAJ);
		fflush(stderr);
	}

	PDBG("%s found vendor %d device %d type %d\n",
	     __FUNCTION__, vendor, device, hca_table[i].type);

	dev = malloc(sizeof *dev);
	if (!dev) {
		return NULL;
	}

	pthread_spin_init(&dev->lock, PTHREAD_PROCESS_PRIVATE);
	dev->ibv_dev.ops = c4iw_dev_ops;
	dev->hca_type = hca_table[i].type;
	dev->abi_version = abi_version;

	dev->mmid2ptr = calloc(T4_MAX_NUM_STAG, sizeof(void *));
	if (!dev->mmid2ptr) {
		goto err1;
	}
	dev->qpid2ptr = calloc(T4_QID_BASE + T4_MAX_NUM_QP, sizeof(void *));
	if (!dev->qpid2ptr) {
		goto err2;
	}
	dev->cqid2ptr = calloc(T4_MAX_NUM_CQ, sizeof(void *));
	if (!dev->cqid2ptr)
		goto err3;
	PDBG("%s device claimed\n", __FUNCTION__);
	SLIST_INSERT_HEAD(&devices, dev, list);
#ifdef STALL_DETECTION
	{
		char *c = getenv("CXGB4_STALL_TIMEOUT");
		if (c) {
			stall_to = strtol(c, NULL, 0);
			if (errno || stall_to < 0)
				stall_to = 0;
		}
	}
#endif
	return &dev->ibv_dev;
err3:
	free(dev->qpid2ptr);
err2:
	free(dev->mmid2ptr);
err1:
	free(dev);
	return NULL;
}

static __attribute__((constructor)) void cxgb4_register_driver(void)
{
	c4iw_page_size = sysconf(_SC_PAGESIZE);
	ibv_register_driver("cxgb4", cxgb4_driver_init);
#ifdef SIM
{
	extern void *sim_thread(void *);

	pthread_t *p = malloc(sizeof *p);

	if (p)
		pthread_create(p, NULL, sim_thread, NULL);
	sleep(1);
}
#endif
}

#ifdef STATS
void __attribute__ ((destructor)) cs_fini(void);
void  __attribute__ ((destructor)) cs_fini(void)
{
	syslog(LOG_NOTICE, "cxgb4 stats - sends %lu recv %lu read %lu "
	       "write %lu arm %lu cqe %lu mr %lu qp %lu cq %lu\n",
	       c4iw_stats.send, c4iw_stats.recv, c4iw_stats.read,
	       c4iw_stats.write, c4iw_stats.arm, c4iw_stats.cqe,
	       c4iw_stats.mr, c4iw_stats.qp, c4iw_stats.cq);
}
#endif
