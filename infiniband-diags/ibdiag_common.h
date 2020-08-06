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

#include <endian.h>

#include <stdarg.h>
#include <infiniband/mad.h>
#include <util/iba_types.h>
#include <infiniband/ibnetdisc.h>
#include <linux/types.h>

extern int ibverbose;
extern char *ibd_ca;
extern int ibd_ca_port;
extern enum MAD_DEST ibd_dest_type;
extern ib_portid_t *ibd_sm_id;
extern int ibd_timeout;
extern uint32_t ibd_ibnetdisc_flags;
extern uint64_t ibd_mkey;
extern uint64_t ibd_sakey;
extern int show_keys;
extern char *ibd_nd_format;

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
#define IBEXIT(fmt, ...) ibexit(__FUNCTION__, fmt, ## __VA_ARGS__)

#define NOT_DISPLAYED_STR "<not displayed>"

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
			       int (*custom_handler) (void *cxt, int val),
			       const char *usage_args,
			       const char *usage_examples[]);
extern void ibdiag_show_usage(void);
extern void ibexit(const char *fn, const char *msg, ...)
	__attribute__((format(printf, 2, 3)));

/* convert counter values to a float with a unit specifier returned (using
 * binary prefix)
 * "data" is a flag indicating this counter is a byte counter multiplied by 4
 * as per PortCounters[Extended]
 */
const char *conv_cnt_human_readable(uint64_t val64, float *val, int data);

int is_mlnx_ext_port_info_supported(uint32_t vendorid, uint16_t devid);

int is_port_info_extended_supported(ib_portid_t * dest, int port,
				    struct ibmad_port *srcport);
void get_max_msg(char *width_msg, char *speed_msg, int msg_size,
		 ibnd_port_t * port);

int resolve_sm_portid(char *ca_name, uint8_t portnum, ib_portid_t *sm_id);
int resolve_self(char *ca_name, uint8_t ca_port, ib_portid_t *portid,
                 int *port, ibmad_gid_t *gid);
int resolve_portid_str(char *ca_name, uint8_t ca_port, ib_portid_t * portid,
		       char *addr_str, enum MAD_DEST dest_type,
		       ib_portid_t *sm_id, const struct ibmad_port *srcport);
int vsnprint_field(char *buf, size_t n, enum MAD_FIELDS f, int spacing,
		   const char *format, va_list va_args)
	__attribute__((format(printf, 5, 0)));
int snprint_field(char *buf, size_t n, enum MAD_FIELDS f, int spacing,
		  const char *format, ...)
	__attribute__((format(printf, 5, 6)));
void dump_portinfo(void *pi, int tabs);

/**
 * Some common command line parsing
 */
typedef const char *(op_fn_t)(ib_portid_t *dest, char **argv, int argc);

typedef struct match_rec {
	const char *name, *alias;
	op_fn_t *fn;
	unsigned opt_portnum;
	const char *ops_extra;
} match_rec_t;

op_fn_t *match_op(const match_rec_t match_tbl[], char *name);

#endif				/* _IBDIAG_COMMON_H_ */
