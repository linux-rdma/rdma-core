/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
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
 *
 * $Id$
 */

#ifndef INFINIBAND_VERBS_H
#define INFINIBAND_VERBS_H

#include <stdint.h>

#include <sysfs/libsysfs.h>

#ifdef __cplusplus
#  define BEGIN_C_DECLS extern "C" {
#  define END_C_DECLS   }
#else /* !__cplusplus */
#  define BEGIN_C_DECLS
#  define END_C_DECLS
#endif /* __cplusplus */

BEGIN_C_DECLS

enum ib_event_type {
	IBV_EVENT_CQ_ERR,
	IBV_EVENT_QP_FATAL,
	IBV_EVENT_QP_REQ_ERR,
	IBV_EVENT_QP_ACCESS_ERR,
	IBV_EVENT_COMM_EST,
	IBV_EVENT_SQ_DRAINED,
	IBV_EVENT_PATH_MIG,
	IBV_EVENT_PATH_MIG_ERR,
	IBV_EVENT_DEVICE_FATAL,
	IBV_EVENT_PORT_ACTIVE,
	IBV_EVENT_PORT_ERR,
	IBV_EVENT_LID_CHANGE,
	IBV_EVENT_PKEY_CHANGE,
	IBV_EVENT_SM_CHANGE
};

struct ibv_async_event {
	union {
		struct ibv_cq *cq;
		struct ibv_qp *qp;
		int            port_num;
	}                  element;
	enum ib_event_type event_type;
};

enum ibv_access_flags {
	IBV_ACCESS_LOCAL_WRITE		= 1,
	IBV_ACCESS_REMOTE_WRITE		= (1<<1),
	IBV_ACCESS_REMOTE_READ		= (1<<2),
	IBV_ACCESS_REMOTE_ATOMIC	= (1<<3),
	IBV_ACCESS_MW_BIND		= (1<<4)
};

struct ibv_pd {

};

struct ibv_mr {

};

struct ibv_qp {

};

struct ibv_cq {

};

struct ibv_device_ops {

};

struct ibv_device {
	struct sysfs_class_device *dev;
	struct sysfs_class_device *ibdev;
	struct ibv_driver         *driver;
	struct ibv_device_ops      ops;
};

struct ibv_context {
	struct ibv_device         *device;
	int                        cmd_fd;
	int                        async_fd;
	int                        num_comp;
	int                        cq_fd[1];
};

/**
 * ibv_get_devices - Return list of IB devices
 */
extern struct dlist *ibv_get_devices(void);

/**
 * ibv_get_device_name - Return kernel device name
 */
extern const char *ibv_get_device_name(struct ibv_device *device);

/**
 * ibv_get_device_guid - Return device's node GUID
 */
extern uint64_t ibv_get_device_guid(struct ibv_device *device);

/**
 * ibv_open_device - Initialize device for use
 */
extern struct ibv_context *ibv_open_device(struct ibv_device *device);

/**
 * ibv_close_device - Release device
 */
extern int ibv_close_device(struct ibv_context *context);

/**
 * ibv_get_async_event - Get next async event
 */
extern int ibv_get_async_event(struct ibv_context *context,
			       struct ibv_async_event *event);

/**
 * ibv_alloc_pd - Allocate a protection domain
 */
extern struct ibv_pd *ibv_alloc_pd(struct ibv_context *context);

/**
 * ibv_dealloc_pd - Free a protection domain
 */
extern int ibv_dealloc_pd(struct ibv_pd *pd);

/**
 * ibv_reg_mr - Register a memory region
 */
extern struct ibv_mr *ibv_reg_mr(struct ibv_pd *pd, void *addr,
				 size_t length, enum ibv_access_flags access);

/**
 * ibv_dereg_mr - Deregister a memory region
 */
extern int ibv_dereg_mr(struct ibv_mr *mr);

END_C_DECLS

#endif /* INFINIBAND_VERBS_H */
