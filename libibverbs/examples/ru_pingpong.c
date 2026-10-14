/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2025,2026 Broadcom. All rights reserved. The term Broadcom
 * refers to Broadcom Inc. and/or its subsidiaries.
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
#define _GNU_SOURCE
#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <malloc.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <time.h>
#include <inttypes.h>
#include <endian.h>

#include "pingpong.h"

#include <ccan/minmax.h>

#define DEFAULT_JOB_ID		42

/* the PIDonFEP assigned to the RU QP; encoded in the QPN */
#define DEFAULT_PID_ON_FEP	10

/* the Resource Index assigned to the RU QP; encoded in the QPN */
#define DEFAULT_RESOURCE_INDEX	15

/* long-only option ids (no short flag) */
#define PP_OPT_PIDONFEP		1000
#define PP_OPT_RI		1001

enum {
	PINGPONG_RECV_WRID = 1,
	PINGPONG_SEND_WRID = 2,
};

static int page_size;
static int validate_buf;
static int use_new_send;
static int use_auto_qpn; /* let the provider assign the QPN (PIDonFEP/RI) */
static int use_imm; /* 0 = off, 32 or 64 = send-with-immediate bits */

#define PP_MAX_SGE 8
static int use_sge = 1; /* SGEs (scatter/gather) per send/recv WR */
static int use_lkey32; /* 0 = 64-bit LKeys (ibv_sge64), 1 = 32-bit (ibv_sge) */

#define PP_IMM_DATA_32	((uint32_t)0x0000cafe)
#define PP_IMM_DATA_64	((uint64_t)0xcacadeadbeefULL)

struct pingpong_context {
	struct ibv_context	*context;
	union ibv_gid		 gid;
	struct ibv_comp_channel *channel;
	struct ibv_pd		*pd;
	struct ibv_mr		*mr;
	struct ibv_job		*job;
	struct ibv_job_key	*job_key;
	struct ibv_ah_ex	*ah;
	uint16_t		 resource_index;
	union {
		struct ibv_cq		*cq;
		struct ibv_cq_ex	*cq_ex;
	} cq_s;
	struct ibv_qp		*qp;
	struct ibv_qp_ex	*qpx;
	char			*buf;
	int			 size;
	int			 send_flags;
	int			 rx_depth;
	int			 pending;
	struct ibv_port_attr	portinfo;
	uint64_t		 completion_timestamp_mask;
};

static struct ibv_cq *pp_cq(struct pingpong_context *ctx)
{
	return ibv_cq_ex_to_cq(ctx->cq_s.cq_ex);
}

struct pingpong_dest {
	int lid;
	int qpn;
	int psn;
	union ibv_gid gid;
};

static int pp_connect_ctx(struct pingpong_context *ctx, int port, int my_psn,
			  enum ibv_mtu mtu, int sl,
			  struct pingpong_dest *dest, int sgid_idx)
{
	struct ibv_ah_attr_ex ah_attr_ex;

	/* The RU QP is already in the RTS state after creation (no INIT/RTR
	 * modify is required); only the address handle needs to be set up.
	 */
	(void)port;
	(void)my_psn;
	(void)mtu;
	(void)sl;

	memset(&ah_attr_ex, 0, sizeof(ah_attr_ex));
	ah_attr_ex.ah_attr.is_global = 1;
	ah_attr_ex.ah_attr.grh.hop_limit = 1;
	ah_attr_ex.ah_attr.grh.dgid = dest->gid;
	ah_attr_ex.ah_attr.grh.sgid_index = sgid_idx;
	ah_attr_ex.ah_attr.port_num = 1;
	ah_attr_ex.remote_qpn = dest->qpn;

	ctx->ah = ibv_ah_to_ah_ex(ibv_create_ah_ex(ctx->pd, &ah_attr_ex));
	if (ctx->ah == NULL) {
		fprintf(stderr, "Failed to create address handle\n");
		return 1;
	}

	return 0;
}

/*
 * A link-local IPv6 address (fe80::/10) is not connectable without a scope
 * (interface) id. If the peer address is given without one (e.g. "fe80::1"
 * rather than "fe80::1%eth0"), determine it from the interface that owns the
 * local source GID (-g), so the correct NIC is used on a multi-homed host.
 * Falls back to the first non-loopback link-local interface if the GID does
 * not match one (e.g. single-NIC setups where the GID differs slightly).
 */
static unsigned int pp_link_local_scope_id(const union ibv_gid *sgid)
{
	struct ifaddrs *ifaddr, *ifa;
	unsigned int scope = 0, fallback = 0;

	if (getifaddrs(&ifaddr) != 0)
		return 0;

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		struct sockaddr_in6 *sa6;

		if (!ifa->ifa_addr ||
		    ifa->ifa_addr->sa_family != AF_INET6 ||
		    (ifa->ifa_flags & IFF_LOOPBACK))
			continue;

		sa6 = (struct sockaddr_in6 *)ifa->ifa_addr;
		if (!IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr))
			continue;

		/* prefer the interface whose address is the source GID */
		if (memcmp(&sa6->sin6_addr, sgid->raw, 16) == 0) {
			scope = if_nametoindex(ifa->ifa_name);
			break;
		}

		if (!fallback)
			fallback = if_nametoindex(ifa->ifa_name);
	}

	freeifaddrs(ifaddr);
	return scope ? scope : fallback;
}

/* set the scope id on a scopeless link-local IPv6 destination so connect() works */
static void pp_fixup_link_local(struct addrinfo *t, const union ibv_gid *sgid)
{
	struct sockaddr_in6 *sa6;

	if (t->ai_family != AF_INET6)
		return;

	sa6 = (struct sockaddr_in6 *)t->ai_addr;
	if (IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr) && sa6->sin6_scope_id == 0)
		sa6->sin6_scope_id = pp_link_local_scope_id(sgid);
}

static struct pingpong_dest *pp_client_exch_dest(struct pingpong_context *ctx,
					const char *servername, int port,
					const struct pingpong_dest *my_dest)
{
	struct addrinfo *res, *t;
	struct addrinfo hints = {
		.ai_family   = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM
	};
	char *service;
	char msg[sizeof("0000:000000:0000:000000:00000000000000000000000000000000")];
	int n;
	int sockfd = -1;
	struct pingpong_dest *rem_dest = NULL;
	char gid[33];

	if (asprintf(&service, "%d", port) < 0)
		return NULL;

	n = getaddrinfo(servername, service, &hints, &res);

	if (n < 0) {
		fprintf(stderr, "%s for %s:%d\n", gai_strerror(n), servername, port);
		free(service);
		return NULL;
	}

	for (t = res; t; t = t->ai_next) {
		pp_fixup_link_local(t, &my_dest->gid);
		sockfd = socket(t->ai_family, t->ai_socktype, t->ai_protocol);
		if (sockfd >= 0) {
			if (!connect(sockfd, t->ai_addr, t->ai_addrlen))
				break;
			close(sockfd);
			sockfd = -1;
		}
	}

	freeaddrinfo(res);
	free(service);

	if (sockfd < 0) {
		fprintf(stderr, "Couldn't connect to %s:%d\n", servername, port);
		return NULL;
	}

	gid_to_wire_gid(&my_dest->gid, gid);
	sprintf(msg, "%04x:%06x:%06x:%s", my_dest->lid, my_dest->qpn,
		my_dest->psn, gid);

	if (write(sockfd, msg, sizeof(msg)) != sizeof(msg)) {
		fprintf(stderr, "Couldn't send local address\n");
		goto out;
	}

	if (read(sockfd, msg, sizeof(msg)) != sizeof(msg) ||
	    write(sockfd, "done", sizeof("done")) != sizeof("done")) {
		perror("client read/write");
		fprintf(stderr, "Couldn't read/write remote address\n");
		goto out;
	}

	rem_dest = malloc(sizeof(*rem_dest));
	if (!rem_dest)
		goto out;

	if (sscanf(msg, "%x:%x:%x:%s", &rem_dest->lid, &rem_dest->qpn,
		   &rem_dest->psn, gid) != 4) {
		fprintf(stderr, "Couldn't parse remote address\n");
		free(rem_dest);
		rem_dest = NULL;
		goto out;
	}
	wire_gid_to_gid(gid, &rem_dest->gid);

out:
	close(sockfd);
	return rem_dest;
}

static struct pingpong_dest *pp_server_exch_dest(struct pingpong_context *ctx,
						 int ib_port, enum ibv_mtu mtu,
						 int port, int sl,
						 const struct pingpong_dest *my_dest,
						 int sgid_idx)
{
	struct addrinfo *res, *t;
	/*
	 * Bind the IPv6 wildcard (::) as a dual-stack socket (IPV6_V6ONLY=0
	 * below) so the server accepts both IPv6 and IPv4(-mapped) clients on
	 * one listener. AF_UNSPEC + AI_PASSIVE can bind 0.0.0.0 first, which
	 * would refuse IPv6 clients.
	 */
	struct addrinfo hints = {
		.ai_flags    = AI_PASSIVE,
		.ai_family   = AF_INET6,
		.ai_socktype = SOCK_STREAM
	};
	char *service;
	char msg[sizeof("0000:000000:0000:000000:00000000000000000000000000000000")];
	int n;
	int sockfd = -1, connfd;
	struct pingpong_dest *rem_dest = NULL;
	char gid[33];

	if (asprintf(&service, "%d", port) < 0)
		return NULL;

	n = getaddrinfo(NULL, service, &hints, &res);

	if (n < 0) {
		fprintf(stderr, "%s for port %d\n", gai_strerror(n), port);
		free(service);
		return NULL;
	}

	for (t = res; t; t = t->ai_next) {
		sockfd = socket(t->ai_family, t->ai_socktype, t->ai_protocol);
		if (sockfd >= 0) {
			n = 1;

			setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &n,
				   sizeof(n));

			/* accept both IPv6 and IPv4(-mapped) on the :: socket */
			if (t->ai_family == AF_INET6) {
				n = 0;
				setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY,
					   &n, sizeof(n));
			}

			if (!bind(sockfd, t->ai_addr, t->ai_addrlen))
				break;

			close(sockfd);
			sockfd = -1;
		}
	}

	freeaddrinfo(res);
	free(service);

	if (sockfd < 0) {
		fprintf(stderr, "Couldn't listen to port %d\n", port);
		return NULL;
	}

	listen(sockfd, 1);
	connfd = accept(sockfd, NULL, NULL);
	close(sockfd);

	if (connfd < 0) {
		fprintf(stderr, "accept() failed\n");
		return NULL;
	}

	n = read(connfd, msg, sizeof(msg));
	if (n != sizeof(msg)) {
		perror("server read");
		fprintf(stderr, "%d/%d: Couldn't read remote address\n",
			n, (int)sizeof(msg));
		goto out;
	}

	rem_dest = malloc(sizeof(*rem_dest));
	if (!rem_dest)
		goto out;

	if (sscanf(msg, "%x:%x:%x:%s", &rem_dest->lid, &rem_dest->qpn,
		   &rem_dest->psn, gid) != 4) {
		fprintf(stderr, "Couldn't parse remote address\n");
		free(rem_dest);
		rem_dest = NULL;
		goto out;
	}

	wire_gid_to_gid(gid, &rem_dest->gid);

	if (pp_connect_ctx(ctx, ib_port, my_dest->psn, mtu, sl, rem_dest,
			   sgid_idx)) {
		fprintf(stderr, "Couldn't connect to remote QP\n");
		free(rem_dest);
		rem_dest = NULL;
		goto out;
	}

	gid_to_wire_gid(&my_dest->gid, gid);
	sprintf(msg, "%04x:%06x:%06x:%s", my_dest->lid, my_dest->qpn,
		my_dest->psn, gid);

	if (write(connfd, msg, sizeof(msg)) != sizeof(msg) ||
	    read(connfd, msg, sizeof(msg)) != sizeof("done")) {
		fprintf(stderr, "Couldn't send/recv local address\n");
		free(rem_dest);
		rem_dest = NULL;
		goto out;
	}


out:
	close(connfd);
	return rem_dest;
}

/* verify the device exposes every capability this run relies on */
static int pp_check_dev_caps(struct ibv_context *context)
{
	struct ibv_device_attr_ex attr;
	int rc;

	memset(&attr, 0, sizeof(attr));
	rc = ibv_query_device_ex(context, NULL, &attr);
	if (rc) {
		fprintf(stderr, "ibv_query_device_ex failed (%d)\n", rc);
		return -1;
	}

	if (!(attr.device_cap_flags_ex & IBV_DEVICE_RU)) {
		fprintf(stderr, "device does not support RU (UET) queue pairs\n");
		return -1;
	}

	/* the s/g list carries 64-bit LKeys unless -L/--lkey32 was given */
	if (!use_lkey32 && !(attr.device_cap_flags_ex & IBV_DEVICE_KEY64)) {
		fprintf(stderr,
			"device does not support 64-bit keys (KEY64); use -L\n");
		return -1;
	}

	/* The scatter/gather buffer array is sized at PP_MAX_SGE; make sure
	 * the device can actually accept that many SGEs per WR.
	 */
	if (attr.orig_attr.max_sge < PP_MAX_SGE) {
		fprintf(stderr,
			"PP_MAX_SGE (%d) exceeds device max_sge (%d)\n",
			PP_MAX_SGE, attr.orig_attr.max_sge);
		return -1;
	}

	return 0;
}

static struct pingpong_context *pp_init_ctx(struct ibv_device *ib_dev, int size,
					    int rx_depth, int port, int gidx,
					    int use_event, uint32_t pid_on_fep,
					    uint16_t resource_index)
{
	struct pingpong_context *ctx;
	int access_flags = IBV_ACCESS_LOCAL_WRITE;
	uint32_t src_id;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->size           = size;
	ctx->rx_depth       = rx_depth;
	ctx->send_flags     = IBV_SEND_SIGNALED;
	ctx->resource_index = resource_index;

	ctx->buf = memalign(page_size, size);
	if (!ctx->buf) {
		fprintf(stderr, "Couldn't allocate work buf.\n");
		goto clean_ctx;
	}

	memset(ctx->buf, 0x7b, size);

	ctx->context = ibv_open_device(ib_dev);
	if (!ctx->context) {
		fprintf(stderr, "Couldn't get context for %s\n",
			ibv_get_device_name(ib_dev));
		goto clean_buffer;
	}

	if (pp_check_dev_caps(ctx->context))
		goto clean_device;

	if (gidx >= 0) {
		if (ibv_query_gid(ctx->context, port, gidx, &ctx->gid)) {
			fprintf(stderr, "can't read sgid of index %d\n", gidx);
			goto clean_device;
		}
	} else {
		fprintf(stderr, "invalid gid index %d\n", gidx);
		goto clean_device;
	}

	memcpy(&src_id, &ctx->gid.raw[12], sizeof(src_id));

	if (use_event) {
		ctx->channel = ibv_create_comp_channel(ctx->context);
		if (!ctx->channel) {
			fprintf(stderr, "Couldn't create completion channel\n");
			goto clean_device;
		}
	} else {
		ctx->channel = NULL;
	}

	ctx->pd = ibv_alloc_pd(ctx->context);
	if (!ctx->pd) {
		fprintf(stderr, "Couldn't allocate PD\n");
		goto clean_comp_channel;
	}

	{
		struct ibv_job_attr job_attr = {
			.comp_mask = (IBV_JOB_ATTR_ID |
				      IBV_JOB_ATTR_PORT_NUM |
				      IBV_JOB_ATTR_SGID_INDEX),
			.id = DEFAULT_JOB_ID,
			.port_num = port,
			.sgid_index = gidx,
		};

		ctx->job = ibv_alloc_job(ctx->context, &job_attr, NULL);
		if (!ctx->job) {
			fprintf(stderr, "Couldn't allocate job\n");
			goto clean_pd;
		}
	}

	/* create a job key for the job */
	ctx->job_key = ibv_create_jkey(ctx->pd, ctx->job, 0);
	if (!ctx->job_key) {
		fprintf(stderr, "Couldn't create job key\n");
		goto clean_job;
	}

	ctx->mr = ibv_reg_mr(ctx->pd, ctx->buf, size, access_flags);

	if (!ctx->mr) {
		fprintf(stderr, "Couldn't register MR\n");
		goto clean_job_key;
	}

	struct ibv_cq_init_attr_ex attr_ex;

	memset(&attr_ex, 0, sizeof(struct ibv_cq_init_attr_ex));
	attr_ex.cqe = rx_depth + 1;
	attr_ex.cq_context = NULL;
	attr_ex.channel = ctx->channel;

	/* the received immediate is read through the extended CQ read ops */
	if (use_imm) {
		attr_ex.wc_flags = IBV_WC_EX_WITH_IMM;
		if (use_imm == 64)
			attr_ex.wc_flags |= IBV_WC_EX_WITH_IMM64;
	}

	ctx->cq_s.cq_ex = ibv_create_cq_ex(ctx->context, &attr_ex);

	if (!pp_cq(ctx)) {
		fprintf(stderr, "Couldn't create CQ\n");
		goto clean_mr;
	}

	{
		struct ibv_qp_attr attr;
		struct ibv_qp_init_attr init_attr = {
			.send_cq = pp_cq(ctx),
			.recv_cq = pp_cq(ctx),
			.cap     = {
				.max_send_wr  = 1,
				.max_recv_wr  = rx_depth,
				.max_send_sge = 1,
				.max_recv_sge = 1
			},
			.qp_type = IBV_QPT_RU
		};

		struct ibv_qp_init_attr_ex init_attr_ex;

		memset(&init_attr_ex, 0, sizeof(struct ibv_qp_init_attr_ex));
		init_attr_ex.send_cq = pp_cq(ctx);
		init_attr_ex.recv_cq = pp_cq(ctx);
		init_attr_ex.cap.max_send_wr = 1;
		init_attr_ex.cap.max_recv_wr = rx_depth;
		init_attr_ex.cap.max_send_sge = use_sge;
		init_attr_ex.cap.max_recv_sge = use_sge;
		init_attr_ex.qp_type = IBV_QPT_RU;
		init_attr_ex.sq_sig_all = 1;
		init_attr_ex.comp_mask |= IBV_QP_INIT_ATTR_PD;
		init_attr_ex.pd = ctx->pd;

		init_attr_ex.comp_mask |=
			IBV_QP_INIT_ATTR_QP_SEMANTICS;

		struct ibv_qp_semantics semantics;

		memset(&semantics, 0, sizeof(struct ibv_qp_semantics));
		init_attr_ex.qp_semantics = &semantics;

		/* Relative Addressing (ABS/REL bit clear); the Resource Index
		 * is encoded in the QPN. Without a source QPN the provider
		 * assigns the PIDonFEP and Resource Index.
		 */
		if (!use_auto_qpn) {
			/* create_flags is only honored when its comp_mask bit
			 * is also set
			 */
			init_attr_ex.comp_mask |= IBV_QP_INIT_ATTR_CREATE_FLAGS;
			init_attr_ex.create_flags |= IBV_QP_CREATE_SOURCE_QPN;
			init_attr_ex.source_qpn =
				((((uint32_t)pid_on_fep <<
				   IBV_QPN_UET_PID_ON_FEP_SHIFT) &
				  IBV_QPN_UET_PID_ON_FEP_MASK) |
				 (((uint32_t)ctx->resource_index <<
				   IBV_QPN_UET_RI_SHIFT) &
				  IBV_QPN_UET_RI_MASK));
		}

		init_attr_ex.comp_mask |= IBV_QP_INIT_ATTR_SRC_ID;
		init_attr_ex.src_id = src_id;
		init_attr_ex.comp_mask |= IBV_QP_INIT_ATTR_JKEY;
		init_attr_ex.job_key = ctx->job_key;

		/* specify attributes at create time via the QP_ATTR channel */
		struct ibv_qp_attr qp_attr;

		memset(&qp_attr, 0, sizeof(qp_attr));
		qp_attr.port_num = port;
		init_attr_ex.comp_mask |= IBV_QP_INIT_ATTR_QP_ATTR;
		init_attr_ex.qp_attr = &qp_attr;
		init_attr_ex.qp_attr_mask = IBV_QP_PORT;

		if (use_new_send) {
			init_attr_ex.comp_mask |=
				IBV_QP_INIT_ATTR_SEND_OPS_FLAGS;
			init_attr_ex.send_ops_flags = IBV_QP_EX_WITH_SEND;

			if (use_imm == 32) {
				init_attr_ex.send_ops_flags |=
					IBV_QP_EX_WITH_SEND_WITH_IMM;
			} else if (use_imm == 64) {
				init_attr_ex.send_ops_flags |=
					IBV_QP_EX_WITH_SEND_WITH_IMM64;
				semantics.comp_mask |=
					IBV_QP_SEMANTICS_MASK_IMM;
				semantics.imm_data_size |=
					IBV_IMM_DATA_SIZE_64;
			}
		}

		ctx->qp = ibv_create_qp_ex(ctx->context, &init_attr_ex);
		if (!ctx->qp)  {
			fprintf(stderr, "Couldn't create QP\n");
			goto clean_cq;
		}

		if (use_new_send)
			ctx->qpx = ibv_qp_to_qp_ex(ctx->qp);

		ibv_query_qp(ctx->qp, &attr, IBV_QP_CAP, &init_attr);
		if (init_attr.cap.max_inline_data >= size)
			ctx->send_flags |= IBV_SEND_INLINE;
	}

	/* the RU QP is created directly in RTS (no INIT/RTR modify) */
	return ctx;

clean_cq:
	ibv_destroy_cq(pp_cq(ctx));

clean_mr:
	ibv_dereg_mr(ctx->mr);

clean_job_key:
	if (ctx->job_key)
		ibv_destroy_jkey(ctx->job_key);

clean_job:
	if (ctx->job)
		ibv_dealloc_job(ctx->job);

clean_pd:
	ibv_dealloc_pd(ctx->pd);

clean_comp_channel:
	if (ctx->channel)
		ibv_destroy_comp_channel(ctx->channel);

clean_device:
	ibv_close_device(ctx->context);

clean_buffer:
	free(ctx->buf);

clean_ctx:
	free(ctx);

	return NULL;
}

static int pp_close_ctx(struct pingpong_context *ctx)
{
	if (ibv_destroy_qp(ctx->qp)) {
		fprintf(stderr, "Couldn't destroy QP\n");
		return 1;
	}

	if (ibv_destroy_cq(pp_cq(ctx))) {
		fprintf(stderr, "Couldn't destroy CQ\n");
		return 1;
	}

	if (ibv_dereg_mr(ctx->mr)) {
		fprintf(stderr, "Couldn't deregister MR\n");
		return 1;
	}

	if (ctx->ah) {
		if (ibv_destroy_ah(&ctx->ah->ah_base)) {
			fprintf(stderr, "Couldn't free AH\n");
			return 1;
		}
	}

	if (ctx->job_key) {
		if (ibv_destroy_jkey(ctx->job_key)) {
			fprintf(stderr, "Couldn't destroy job key\n");
			return 1;
		}
	}

	if (ctx->job) {
		if (ibv_dealloc_job(ctx->job)) {
			fprintf(stderr, "Couldn't deallocate job\n");
			return 1;
		}
	}

	if (ibv_dealloc_pd(ctx->pd)) {
		fprintf(stderr, "Couldn't deallocate PD\n");
		return 1;
	}

	if (ctx->channel) {
		if (ibv_destroy_comp_channel(ctx->channel)) {
			fprintf(stderr, "Couldn't destroy completion channel\n");
			return 1;
		}
	}

	if (ibv_close_device(ctx->context)) {
		fprintf(stderr, "Couldn't release context\n");
		return 1;
	}

	free(ctx->buf);
	free(ctx);

	return 0;
}

/* split the message buffer into use_sge contiguous segments
 *
 * RU QPs normally use 64-bit memory keys, so the scatter/gather elements are
 * struct ibv_sge64: sends flag them with IBV_SEND_SGE64 and receives are
 * posted with ibv_post_recv64(). -L/--lkey32 selects the 32-bit struct
 * ibv_sge and the corresponding legacy paths instead.
 */
static int pp_build_sge(struct pingpong_context *ctx, struct ibv_sge *list)
{
	size_t seg = (ctx->size / use_sge);
	int i;

	for (i = 0; i < use_sge; i++) {
		list[i].addr   = ((uintptr_t)ctx->buf + (size_t)i * seg);
		list[i].length = (i == use_sge - 1) ?
				 (ctx->size - (size_t)i * seg) : seg;
		list[i].lkey   = ctx->mr->lkey;
	}

	return use_sge;
}

static int pp_build_sge64(struct pingpong_context *ctx, struct ibv_sge64 *list)
{
	size_t seg = (ctx->size / use_sge);
	int i;

	for (i = 0; i < use_sge; i++) {
		list[i].addr   = ((uintptr_t)ctx->buf + (size_t)i * seg);
		list[i].length = (i == use_sge - 1) ?
				 (ctx->size - (size_t)i * seg) : seg;
		list[i].lkey64 = ctx->mr->lkey64;
	}

	return use_sge;
}

static int pp_post_recv(struct pingpong_context *ctx, int n)
{
	struct ibv_sge list[PP_MAX_SGE];
	struct ibv_sge64 list64[PP_MAX_SGE];
	int i;

	if (use_lkey32) {
		struct ibv_recv_wr wr = {
			.wr_id	    = PINGPONG_RECV_WRID,
			.sg_list    = list,
			.num_sge    = pp_build_sge(ctx, list),
		};
		struct ibv_recv_wr *bad_wr;

		for (i = 0; i < n; ++i) {
			if (ibv_post_recv(ctx->qp, &wr, &bad_wr))
				break;
		}
	} else {
		struct ibv_recv_wr64 wr = {
			.wr_id	    = PINGPONG_RECV_WRID,
			.sg_list    = list64,
			.num_sge    = pp_build_sge64(ctx, list64),
		};
		struct ibv_recv_wr64 *bad_wr;

		for (i = 0; i < n; ++i) {
			if (ibv_post_recv64(ctx->qp, &wr, &bad_wr))
				break;
		}
	}

	return i;
}

static int pp_post_send(struct pingpong_context *ctx)
{
	struct ibv_sge list[PP_MAX_SGE];
	struct ibv_sge64 list64[PP_MAX_SGE];
	int nsge;

	nsge = use_lkey32 ? pp_build_sge(ctx, list) :
			    pp_build_sge64(ctx, list64);

	if (use_new_send) {
		ibv_wr_start(ctx->qpx);

		ctx->qpx->wr_id = PINGPONG_SEND_WRID;
		ctx->qpx->wr_flags = ctx->send_flags;

		if (use_imm == 32)
			ibv_wr_send_imm(ctx->qpx, htonl(PP_IMM_DATA_32));
		else if (use_imm == 64)
			ibv_wr_send_imm64(ctx->qpx, htobe64(PP_IMM_DATA_64));
		else
			ibv_wr_send(ctx->qpx);
		ibv_wr_set_ru_addr(ctx->qpx, ctx->ah, 0);
		ibv_wr_set_job_key(ctx->qpx, ctx->job_key->jkey);
		if (use_lkey32)
			ibv_wr_set_sge_list(ctx->qpx, nsge, list);
		else
			ibv_wr_set_sge64_list(ctx->qpx, nsge, list64);

		return ibv_wr_complete(ctx->qpx);
	}

	struct ibv_send_wr wr = {
		.wr_id	      = PINGPONG_SEND_WRID,
		.num_sge      = nsge,
		.opcode       = IBV_WR_SEND,
		.send_flags   = ctx->send_flags,
		.wr.ru.ah     = ctx->ah,
		.wr.ru.jkey   = ctx->job_key->jkey
	};
	struct ibv_send_wr *bad_wr;

	if (use_lkey32) {
		wr.sg_list = list;
	} else {
		wr.sg64_list = list64;
		wr.send_flags |= IBV_SEND_SGE64;
	}

	return ibv_post_send(ctx->qp, &wr, &bad_wr);
}

struct ts_params {
	uint64_t		 comp_recv_max_time_delta;
	uint64_t		 comp_recv_min_time_delta;
	uint64_t		 comp_recv_total_time_delta;
	uint64_t		 comp_recv_prev_time;
	int			 last_comp_with_ts;
	unsigned int		 comp_with_time_iters;
};

static inline int parse_single_wc(struct pingpong_context *ctx, int *scnt,
				  int *rcnt, int *routs, int iters,
				  uint64_t wr_id, enum ibv_wc_status status,
				  uint64_t completion_timestamp,
				  struct ts_params *ts)
{
	if (status != IBV_WC_SUCCESS) {
		fprintf(stderr, "Failed status %s (%d) for wr_id %d\n",
			ibv_wc_status_str(status),
			status, (int)wr_id);
		return 1;
	}

	switch ((int)wr_id) {
	case PINGPONG_SEND_WRID:
		++(*scnt);
		break;

	case PINGPONG_RECV_WRID:
		if (--(*routs) <= 1) {
			*routs += pp_post_recv(ctx, ctx->rx_depth - *routs);
			if (*routs < ctx->rx_depth) {
				fprintf(stderr,
					"Couldn't post receive (%d)\n",
					*routs);
				return 1;
			}
		}

		++(*rcnt);
		ts->last_comp_with_ts = 0;

		break;

	default:
		fprintf(stderr, "Completion for unknown wr_id %d\n",
			(int)wr_id);
		return 1;
	}

	ctx->pending &= ~(int)wr_id;

	if (*scnt < iters && !ctx->pending) {
		if (pp_post_send(ctx)) {
			fprintf(stderr, "Couldn't post send\n");
			return 1;
		}

		ctx->pending = PINGPONG_RECV_WRID | PINGPONG_SEND_WRID;
	}

	return 0;
}

/* Poll and drain the extended CQ, verifying the immediate on each receive
 * completion. Used when send-with-immediate is enabled: the plain
 * ibv_poll_cq() path cannot read a 64-bit immediate.
 */
static int pp_drain_imm(struct pingpong_context *ctx, int *scnt, int *rcnt,
			int *routs, int iters, struct ts_params *ts)
{
	struct ibv_cq_ex *cq_ex = ctx->cq_s.cq_ex;
	struct ibv_poll_cq_attr attr;
	int ret, first;

	memset(&attr, 0, sizeof(attr));

	ret = ibv_start_poll(cq_ex, &attr);
	if (ret == ENOENT)
		return 0;
	if (ret) {
		fprintf(stderr, "start_poll failed %d\n", ret);
		return 1;
	}

	for (first = 1; ; first = 0) {
		enum ibv_wc_status status;
		enum ibv_wc_opcode opcode;
		uint64_t wr_id;

		if (!first) {
			ret = ibv_next_poll(cq_ex);
			if (ret == ENOENT)
				break;
			if (ret) {
				fprintf(stderr, "next_poll failed %d\n", ret);
				ibv_end_poll(cq_ex);
				return 1;
			}
		}

		wr_id  = cq_ex->wr_id;
		status = cq_ex->status;
		opcode = ibv_wc_read_opcode(cq_ex);

		/* the peer's send delivers its immediate to our receive */
		if (status == IBV_WC_SUCCESS && opcode == IBV_WC_RECV) {
			if (use_imm == 64) {
				uint64_t got =
					be64toh(ibv_wc_read_imm64_data(cq_ex));

				if (got != PP_IMM_DATA_64) {
					fprintf(stderr,
						"bad imm64 0x%" PRIx64
						" (expected 0x%" PRIx64 ")\n",
						got, (uint64_t)PP_IMM_DATA_64);
					ibv_end_poll(cq_ex);
					return 1;
				}
			} else {
				uint32_t got =
					ntohl(ibv_wc_read_imm_data(cq_ex));

				if (got != PP_IMM_DATA_32) {
					fprintf(stderr,
						"bad imm 0x%x (expected 0x%x)\n",
						got, PP_IMM_DATA_32);
					ibv_end_poll(cq_ex);
					return 1;
				}
			}
		}

		if (parse_single_wc(ctx, scnt, rcnt, routs, iters, wr_id,
				    status, 0, ts)) {
			ibv_end_poll(cq_ex);
			return 1;
		}
	}

	ibv_end_poll(cq_ex);
	return 0;
}

static void usage(const char *argv0)
{
	printf("Usage:\n");
	printf("  %s            start a server and wait for connection\n", argv0);
	printf("  %s <host>     connect to server at <host>\n", argv0);
	printf("\n");
	printf("Options:\n");
	printf("  -p, --port <port>         listen on/connect to port <port> (default 18515)\n");
	printf("  -d, --ib-dev <dev>        use IB device <dev> (default first device found)\n");
	printf("  -i, --ib-port <port>      use port <port> of IB device (default 1)\n");
	printf("  -s, --size <size>         size of message to exchange (default 4096)\n");
	printf("  -m, --mtu <size>          path MTU (default 1024, same on both sides)\n");
	printf("  -r, --rx-depth <dep>      number of receives to post at a time (default 500)\n");
	printf("  -n, --iters <iters>       number of exchanges (default 1000)\n");
	printf("  -e, --events              sleep on CQ events (default poll)\n");
	printf("  -g, --gid-idx <gid index> local port gid index\n");
	printf("  -c, --chk	            validate received buffer\n");
	printf("  -N, --new_send            use new post send WR API\n");
	printf("  -Q, --auto-qpn            let the provider assign the QPN (PIDonFEP/RI)\n");
	printf("  -I, --imm <bits>          send with a <bits>-bit immediate (32 or 64)\n");
	printf("  -S, --sge <n>             spread send/send_imm/recv over <n> SGEs (1..%d)\n",
	       PP_MAX_SGE);
	printf("  -L, --lkey32              post 32-bit LKeys (struct ibv_sge; default 64-bit)\n");
	printf("      --pidonfep <n>        source QPN PIDonFEP (default %d)\n",
	       DEFAULT_PID_ON_FEP);
	printf("      --ri <n>              source QPN Resource Index (default %d)\n",
	       DEFAULT_RESOURCE_INDEX);
	printf("\n");
	printf("Note: -Q (provider-assigned QPN) cannot be combined with --pidonfep or --ri;\n");
	printf("      the provider chooses the QPN, so an explicit source QPN is ignored.\n");
}

int main(int argc, char *argv[])
{
	struct ibv_device      **dev_list;
	struct ibv_device	*ib_dev;
	struct pingpong_context *ctx;
	struct pingpong_dest     my_dest;
	struct pingpong_dest    *rem_dest;
	struct timeval           start, end;
	char                    *ib_devname = NULL;
	char                    *servername = NULL;
	unsigned int             port = 18515;
	int                      ib_port = 1;
	unsigned int             size = 4096;
	enum ibv_mtu		 mtu = IBV_MTU_1024;
	unsigned int             rx_depth = 500;
	unsigned int             iters = 1000;
	int                      use_event = 0;
	int                      routs;
	int                      rcnt, scnt;
	int			 gidx = -1;
	char			 gid[33];
	struct ts_params	 ts;
	uint16_t		 pid_on_fep = DEFAULT_PID_ON_FEP;
	uint16_t		 resource_index = DEFAULT_RESOURCE_INDEX;

	srand48(getpid() * time(NULL));

	while (1) {
		int c;

		static struct option long_options[] = {
			{ .name = "port",     .has_arg = 1, .val = 'p' },
			{ .name = "ib-dev",   .has_arg = 1, .val = 'd' },
			{ .name = "ib-port",  .has_arg = 1, .val = 'i' },
			{ .name = "size",     .has_arg = 1, .val = 's' },
			{ .name = "mtu",      .has_arg = 1, .val = 'm' },
			{ .name = "rx-depth", .has_arg = 1, .val = 'r' },
			{ .name = "iters",    .has_arg = 1, .val = 'n' },
			{ .name = "events",   .has_arg = 0, .val = 'e' },
			{ .name = "gid-idx",  .has_arg = 1, .val = 'g' },
			{ .name = "chk",      .has_arg = 0, .val = 'c' },
			{ .name = "new_send", .has_arg = 0, .val = 'N' },
			{ .name = "auto-qpn", .has_arg = 0, .val = 'Q' },
			{ .name = "imm",      .has_arg = 1, .val = 'I' },
			{ .name = "sge",      .has_arg = 1, .val = 'S' },
			{ .name = "lkey32",   .has_arg = 0, .val = 'L' },
			{ .name = "pidonfep", .has_arg = 1, .val = PP_OPT_PIDONFEP },
			{ .name = "ri",       .has_arg = 1, .val = PP_OPT_RI },
			{}
		};

		c = getopt_long(argc, argv, "p:d:i:s:m:r:n:eg:cNQI:S:L",
				long_options, NULL);

		if (c == -1)
			break;

		switch (c) {
		case 'p':
			port = strtoul(optarg, NULL, 0);
			if (port > 65535) {
				usage(argv[0]);
				return 1;
			}
			break;
		case 'd':
			ib_devname = strdupa(optarg);
			break;
		case 'i':
			ib_port = strtol(optarg, NULL, 0);
			if (ib_port < 1) {
				usage(argv[0]);
				return 1;
			}
			break;
		case 's':
			size = strtoul(optarg, NULL, 0);
			break;
		case 'm':
			mtu = pp_mtu_to_enum(strtol(optarg, NULL, 0));
			if (mtu == 0) {
				usage(argv[0]);
				return 1;
			}
			break;
		case 'r':
			rx_depth = strtoul(optarg, NULL, 0);
			break;
		case 'n':
			iters = strtoul(optarg, NULL, 0);
			break;
		case 'e':
			++use_event;
			break;
		case 'g':
			gidx = strtol(optarg, NULL, 0);
			break;
		case 'c':
			validate_buf = 1;
			break;
		case 'N':
			use_new_send = 1;
			break;
		case 'L':
			use_lkey32 = 1;
			break;
		case 'Q':
			use_auto_qpn = 1;
			break;
		case 'I':
			use_imm = strtol(optarg, NULL, 0);
			if (use_imm != 32 && use_imm != 64) {
				fprintf(stderr, "--imm must be 32 or 64\n");
				usage(argv[0]);
				return 1;
			}

			/* the immediate is sent using the new post-send API */
			use_new_send = 1;
			break;
		case 'S':
			use_sge = strtol(optarg, NULL, 0);
			if ((use_sge < 1) || (use_sge > PP_MAX_SGE)) {
				fprintf(stderr, "--sge must be 1..%d\n",
					PP_MAX_SGE);
				usage(argv[0]);
				return 1;
			}
			break;
		case PP_OPT_PIDONFEP:
			pid_on_fep = strtoul(optarg, NULL, 0);
			break;
		case PP_OPT_RI:
			resource_index = strtoul(optarg, NULL, 0);
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (optind == argc - 1) {
		servername = strdupa(argv[optind]);
	} else if (optind < argc) {
		usage(argv[0]);
		return 1;
	}

	page_size = sysconf(_SC_PAGESIZE);

	dev_list = ibv_get_device_list(NULL);
	if (!dev_list) {
		perror("Failed to get IB devices list");
		return 1;
	}

	if (!ib_devname) {
		ib_dev = *dev_list;
		if (!ib_dev) {
			fprintf(stderr, "No IB devices found\n");
			return 1;
		}
	} else {
		int i;

		for (i = 0; dev_list[i]; ++i) {
			if (!strcmp(ibv_get_device_name(dev_list[i]),
				    ib_devname))
				break;
		}

		ib_dev = dev_list[i];

		if (!ib_dev) {
			fprintf(stderr, "IB device %s not found\n", ib_devname);
			return 1;
		}
	}

	ctx = pp_init_ctx(ib_dev, size, rx_depth, ib_port, gidx, use_event,
			  pid_on_fep, resource_index);
	if (!ctx)
		return 1;

	routs = pp_post_recv(ctx, ctx->rx_depth);
	if (routs < ctx->rx_depth) {
		fprintf(stderr, "Couldn't post receive (%d)\n", routs);
		return 1;
	}

	if (pp_get_port_info(ctx->context, ib_port, &ctx->portinfo)) {
		fprintf(stderr, "Couldn't get port info\n");
		return 1;
	}

	my_dest.lid = ctx->portinfo.lid;
	if ((ctx->portinfo.link_layer != IBV_LINK_LAYER_ETHERNET) &&
	    !my_dest.lid) {
		fprintf(stderr, "Couldn't get local LID\n");
		return 1;
	}

	if (gidx >= 0) {
		if (ibv_query_gid(ctx->context, ib_port, gidx, &my_dest.gid)) {
			fprintf(stderr, "can't read sgid of index %d\n", gidx);
			return 1;
		}
	} else {
		memset(&my_dest.gid, 0, sizeof(my_dest.gid));
	}

	my_dest.qpn = ctx->qp->qp_num;
	my_dest.psn = lrand48() & 0xffffff;
	inet_ntop(AF_INET6, &my_dest.gid, gid, sizeof(gid));
	printf("  local address:  LID 0x%04x, QPN 0x%06x, PSN 0x%06x, GID %s\n",
	       my_dest.lid, my_dest.qpn, my_dest.psn, gid);

	if (servername)
		rem_dest = pp_client_exch_dest(ctx, servername, port, &my_dest);
	else
		rem_dest = pp_server_exch_dest(ctx, ib_port, mtu, port, 0,
					       &my_dest, gidx);

	if (!rem_dest)
		return 1;

	inet_ntop(AF_INET6, &rem_dest->gid, gid, sizeof(gid));
	printf("  remote address: LID 0x%04x, QPN 0x%06x, PSN 0x%06x, GID %s\n",
	       rem_dest->lid, rem_dest->qpn, rem_dest->psn, gid);

	if (servername) {
		if (pp_connect_ctx(ctx, ib_port, my_dest.psn, mtu, 0,
				   rem_dest, gidx))
			return 1;
	}

	ctx->pending = PINGPONG_RECV_WRID;

	if (servername) {
		if (validate_buf) {
			for (int i = 0; i < size; i += page_size)
				ctx->buf[i] = i / page_size % sizeof(char);
		}

		if (pp_post_send(ctx)) {
			fprintf(stderr, "Couldn't post send\n");
			return 1;
		}

		ctx->pending |= PINGPONG_SEND_WRID;
	}

	if (gettimeofday(&start, NULL)) {
		perror("gettimeofday");
		return 1;
	}

	rcnt = scnt = 0;

	/* event mode, arm once before the loop */
	if (use_event) {
		if (ibv_req_notify_cq(pp_cq(ctx), 0)) {
			fprintf(stderr, "Couldn't request CQ notification\n");
			return 1;
		}
	}

	while (rcnt < iters || scnt < iters) {
		int ret, ne;
		struct ibv_wc wc[1];

		/* event mode, wait for event if not already triggered */
		if (use_event) {
			struct ibv_cq *ev_cq;
			void          *ev_ctx;

			/* wait for an event on the channel */
			if (ibv_get_cq_event(ctx->channel, &ev_cq, &ev_ctx)) {
				fprintf(stderr, "Failed to get cq_event\n");
				return 1;
			}

			if (ev_cq != pp_cq(ctx)) {
				fprintf(stderr, "CQ event for unknown CQ %p\n",
					ev_cq);
				return 1;
			}

			/* ack the event */
			ibv_ack_cq_events(ev_cq, 1);

			/* re-arm the channel */
			if (ibv_req_notify_cq(pp_cq(ctx), 0)) {
				fprintf(stderr,
					"Couldn't request CQ notification\n");
				return 1;
			}
		}

		if (use_imm) {
			/* extended-CQ path reads and verifies the immediate */
			if (pp_drain_imm(ctx, &scnt, &rcnt, &routs, iters, &ts))
				return 1;
		} else {
			do {
				ne = ibv_poll_cq(pp_cq(ctx), 1, wc);
				if (ne < 0) {
					fprintf(stderr, "poll CQ failed %d\n", ne);
					return 1;
				}

				if (ne == 1) {
					ret = parse_single_wc(ctx, &scnt, &rcnt,
							      &routs, iters,
							      wc[0].wr_id,
							      wc[0].status,
							      0, &ts);
					if (ret) {
						fprintf(stderr, "parse WC failed\n");
						return 1;
					}
				}
			} while (ne > 0); /* drain until empty */
		}
	}

	if (gettimeofday(&end, NULL)) {
		perror("gettimeofday");
		return 1;
	}

	{
		float usec = (end.tv_sec - start.tv_sec) * 1000000 +
			(end.tv_usec - start.tv_usec);
		long long bytes = (long long) size * iters * 2;

		printf("%lld bytes in %.2f seconds = %.2f Mbit/sec\n",
		       bytes, usec / 1000000., bytes * 8. / usec);
		printf("%d iters in %.2f seconds = %.2f usec/iter\n",
		       iters, usec / 1000000., usec / iters);

		if ((!servername) && (validate_buf)) {
			for (int i = 0; i < size; i += page_size) {
				if (ctx->buf[i] != i / page_size % sizeof(char))
					printf("invalid data in page %d\n",
					       i / page_size);
			}
		}
	}

	if (pp_close_ctx(ctx))
		return 1;

	ibv_free_device_list(dev_list);
	free(rem_dest);

	return 0;
}
