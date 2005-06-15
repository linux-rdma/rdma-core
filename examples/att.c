/*
 * Copyright (c) 2005 Voltaire, Inc.  All rights reserved.
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
 * $Id:$
 */

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <string.h>
#include <glob.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <endian.h>
#include <byteswap.h>
#include <netinet/in.h>
#include <unistd.h>

#include <infiniband/at.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t cpu_to_be64(uint64_t x) { return bswap_64(x); }
static inline uint32_t cpu_to_be32(uint32_t x) { return bswap_32(x); }
static inline uint16_t cpu_to_be16(uint16_t x) { return bswap_16(x); }
static inline uint64_t be64_to_cpu(uint64_t x) { return bswap_64(x); }
#define be32_to_cpu ntohl
#define be16_to_cpu ntohs
#elif __BYTE_ORDER == __BIG_ENDIAN
static inline uint64_t cpu_to_be64(uint64_t x) { return x; }
static inline uint32_t cpu_to_be32(uint32_t x) { return x; }
static inline uint16_t cpu_to_be16(uint16_t x) { return x; }
static inline uint64_t be64_to_cpu(uint64_t x) { return x; }
static inline uint32_t be32_to_cpu(uint32_t x) { return x; }
static inline uint16_t be16_to_cpu(uint16_t x) { return x; }
#endif

//#define WARN(fmt, ...)        while (0) {}
//#define DEBUG(fmt, ...)       while (0) {}
#define WARN(fmt, arg ...)      printf("uatt: " fmt "\n", ## arg);
#define DEBUG(fmt, arg ...)     printf("uatt: %s: " fmt "\n", __FUNCTION__,  ## arg);

#define MAX_REQ 32
#define SLEEP 30

static struct ib_sa_path_rec att_path[MAX_REQ];
static struct ib_at_completion att_path_comp[MAX_REQ];
static struct ib_at_ib_route att_rt[MAX_REQ];
static struct ib_at_completion att_rt_comp[MAX_REQ];


static void att_path_comp_fn(uint64_t req_id, void *context, int rec_num)
{
	struct ib_sa_path_rec *path = context;
	int i;

	DEBUG("id %lld context %p completed with rec_num %d",
	      req_id, context, rec_num);

	i = path - att_path;

	if (i < 0 || i >= MAX_REQ) {
		DEBUG("bad req context %d\n", i);
		return;
	}

	if (rec_num <= 0) {
		printf("path resolve failed (%d)!!!\n", rec_num);
		return;
	}

	printf("===> slid 0x%x dlid 0x%x\n",
		(int)be16_to_cpu(path->slid),
		(int)be16_to_cpu(path->dlid));
}

static void dump_rt(struct ib_at_ib_route *rt)
{
	printf("===> rt %p sgid 0x%016llx%016llx dgid 0x%016llx%016llx\n",
		rt,
		be64_to_cpu(rt->sgid.global.subnet_prefix),
		be64_to_cpu(rt->sgid.global.interface_id),
		be64_to_cpu(rt->dgid.global.subnet_prefix),
		be64_to_cpu(rt->dgid.global.interface_id));
}

static void att_rt_comp_fn(uint64_t req_id, void *context, int rec_num)
{
	struct ib_at_ib_route *rt = context;
	int r, i;
	uint64_t req_id2;

	DEBUG("id %lld context %p completed with rec_num %d",
	      req_id, context, rec_num);

	i = rt - att_rt;

	if (i < 0 || i >= MAX_REQ) {
		DEBUG("bad req context %d\n", i);
		return;
	}

	if (rec_num <= 0)
		return;

	dump_rt(rt);

	DEBUG("ib_at_paths_by_route: route %p context %p compl %p", rt, att_path_comp[i].context, att_path_comp + i);
	r = ib_at_paths_by_route(rt, 0, att_path_comp[i].context,
				 1, att_path_comp + i, &req_id2);

	DEBUG("ib_at_paths_by_route: returned %d id %lld %lld",
	      r, att_path_comp[i].req_id, req_id2);

	/* Check for callback events */
	/* Should this be timed ? */
	r = ib_at_callback_get();
	if (r) {
		printf("Error <%d:%d> getting callback event\n",
		       r, errno);
	}
}

int main(int argc, char **argv)
{
	int r, i;

	DEBUG("uat test start");

	for (i = 0; i < MAX_REQ; i++) {
		att_rt_comp[i].fn = att_rt_comp_fn;
		att_rt_comp[i].context = att_rt + i;
		att_path_comp[i].fn = att_path_comp_fn;
		att_path_comp[i].context = att_path + i;
	}

	for (i = 0; i < MAX_REQ; i++) {
		r = ib_at_route_by_ip(0x0100a8c0, 0, 0, 0,
				      att_rt + i, att_rt_comp + i);

		DEBUG("ib_at_route_by_ip: ret %d errno %d for request %d id %lld",
		      r, errno, i + 1, att_rt_comp[i].req_id);
		if (r == 1)
			att_rt_comp_fn(att_rt_comp[i].req_id, att_rt + i, 1);
	}

	/* make sleep period command line driven !!! */
	DEBUG("sleeping for %d secs", SLEEP);
	sleep(SLEEP);	/* hang out here for a while */

	DEBUG("uat test cleanup");

	for (i = 0; i < MAX_REQ; i++) {
		if ((r = ib_at_cancel(att_rt_comp[i].req_id)) < 0) {
			DEBUG("cancel but no rt id %lld ret %d errno %d", att_rt_comp[i].req_id, r, errno);
		} else
			DEBUG("canceling rt id %lld ret %d",
			      att_rt_comp[i].req_id, r);

		if ((r = ib_at_cancel(att_path_comp[i].req_id)) < 0) {
			DEBUG("cancel but no path id %lld ret %d errno %d", att_path_comp[i].req_id, r, errno);
		} else
			DEBUG("canceling path id %lld ret %d",
			       att_path_comp[i].req_id, r);
	}

	return 0;
}
