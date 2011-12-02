/*
 * Copyright (c) 2006-2007 The Regents of the University of California.
 * Copyright (c) 2004-2009 Voltaire Inc.  All rights reserved.
 * Copyright (c) 2002-2010 Mellanox Technologies LTD. All rights reserved.
 * Copyright (c) 1996-2003 Intel Corporation. All rights reserved.
 * Copyright (c) 2009 HNR Consulting. All rights reserved.
 * Copyright (c) 2011 Lawrence Livermore National Security. All rights reserved.
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
 */

#ifndef _IBDIAG_COMMON_H_
#define _IBDIAG_COMMON_H_

#include <infiniband/iba/ib_types.h>
#include <infiniband/mad.h>
#include <infiniband/ibnetdisc.h>

extern int ibverbose;
extern char *ibd_ca;
extern int ibd_ca_port;
extern enum MAD_DEST ibd_dest_type;
extern ib_portid_t *ibd_sm_id;
extern int ibd_timeout;
extern uint32_t ibd_ibnetdisc_flags;

/*========================================================*/
/*                External interface                      */
/*========================================================*/

#undef DEBUG
#define DEBUG(fmt, ...) do { \
	if (ibdebug) IBDEBUG(fmt, ## __VA_ARGS__); \
} while (0)
#define VERBOSE(fmt, ...) do { \
	if (ibverbose) IBVERBOSE(fmt, ## __VA_ARGS__); \
} while (0)
#define IBERROR(fmt, ...) iberror(__FUNCTION__, fmt, ## __VA_ARGS__)

/* not all versions of ib_types.h will have this define */
#ifndef IB_PM_PC_XMIT_WAIT_SUP
#define IB_PM_PC_XMIT_WAIT_SUP (CL_HTON16(((uint16_t)1)<<12))
#endif

struct ibdiag_opt {
	const char *name;
	char letter;
	unsigned has_arg;
	const char *arg_tmpl;
	const char *description;
};

extern int ibdiag_process_opts(int argc, char *const argv[], void *context,
			       const char *exclude_common_str,
			       const struct ibdiag_opt custom_opts[],
			       int (*custom_handler) (void *cxt, int val,
						      char *optarg),
			       const char *usage_args,
			       const char *usage_examples[]);
extern void ibdiag_show_usage();
extern void iberror(const char *fn, char *msg, ...);

/* convert counter values to a float with a unit specifier returned (using
 * binary prefix)
 * "data" is a flag indicating this counter is a byte counter multiplied by 4
 * as per PortCounters[Extended]
 */
extern char *conv_cnt_human_readable(uint64_t val64, float *val, int data);

int is_mlnx_ext_port_info_supported(uint32_t devid);

/* define an SA query structure to be common
 * This is by no means optimal but it moves the saquery functionality out of
 * the saquery tool and provides it to other utilities.
 */
struct bind_handle {
	int fd, agent;
	ib_portid_t dport;
	struct ibmad_port *srcport;
};
typedef struct bind_handle * bind_handle_t;
bind_handle_t sa_get_bind_handle(void);
void sa_free_bind_handle(bind_handle_t h);

struct sa_query_result {
	uint32_t status;
	unsigned result_cnt;
	void *p_result_madw;
};
int sa_query(struct bind_handle *h, uint8_t method,
	     uint16_t attr, uint32_t mod, uint64_t comp_mask, uint64_t sm_key,
	     void *data, struct sa_query_result *result);
void sa_free_result_mad(struct sa_query_result *result);
void *sa_get_query_rec(void *mad, unsigned i);
void sa_report_err(int status);

#define cl_hton8(x) (x)
#define CHECK_AND_SET_VAL(val, size, comp_with, target, name, mask) \
	if ((int##size##_t) val != (int##size##_t) comp_with) { \
		target = cl_hton##size((uint##size##_t) val); \
		comp_mask |= IB_##name##_COMPMASK_##mask; \
	}

#define CHECK_AND_SET_GID(val, target, name, mask) \
	if (valid_gid(&(val))) { \
		memcpy(&(target), &(val), sizeof(val)); \
		comp_mask |= IB_##name##_COMPMASK_##mask; \
	}

#define CHECK_AND_SET_VAL_AND_SEL(val, target, name, mask, sel) \
	if (val) { \
		target = val; \
		comp_mask |= IB_##name##_COMPMASK_##mask##sel; \
		comp_mask |= IB_##name##_COMPMASK_##mask; \
	}

void get_max_msg(char *width_msg, char *speed_msg, int msg_size,
		 ibnd_port_t * port);

#endif				/* _IBDIAG_COMMON_H_ */
