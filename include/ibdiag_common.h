/*
 * Copyright (c) 2006-2007 The Regents of the University of California.
 * Copyright (c) 2004-2009 Voltaire Inc.  All rights reserved.
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

extern int ibverbose;
extern char *ibd_ca;
extern int ibd_ca_port;
extern enum MAD_DEST ibd_dest_type;
extern ib_portid_t *ibd_sm_id;
extern int ibd_timeout;

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

#endif				/* _IBDIAG_COMMON_H_ */
