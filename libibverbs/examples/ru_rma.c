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
#include <stdbool.h>
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

#define RU_DEFAULT_JOB_ID	46

/* the PIDonFEP assigned to the RU QP; encoded in the QPN */
#define RU_DEFAULT_PID_ON_FEP	10

/* the Resource Index assigned to the RU QP; encoded in the QPN */
#define RU_DEFAULT_RESOURCE_INDEX	15

/* long-only option ids (no short flag) */
#define RU_OPT_PIDONFEP			1000
#define RU_OPT_RI			1001

/* max scatter/gather entries the local buffer can be split across */
#define RU_MAX_SGE		8

/* index used when exercising the job address table */
#define RU_ADDR_INDEX		3

#define RU_DEFAULT_IB_PORT	1
#define RU_DEFAULT_GID_INDEX	1

#define RU_TCP_PORT		18515

#define RU_NUM_ITERATIONS	100
#define RU_MSG_SZ		4096
#define RU_RX_DEPTH		500
#define RU_TX_DEPTH		500

#define RU_SERVER_BUF_DATA	((char) 0xca)
#define RU_CLIENT_BUF_DATA	((char) 0xbe)

#define RU_IMM_DATA		0xcaca
#define RU_IMM_DATA_64		0xcacacdeadbeef

enum ru_rc {
	RU_ERR_RC     = -1,
	RU_SUCCESS_RC =  0
};

enum {
	RU_RECV_WRID = 1,
	RU_SEND_WRID = 2
};

#define RU_ERR(fmt, ...)                                    \
	fprintf(stdout, "[%s] %s:%-4d: " fmt "\n", "error", \
		__FILE__, __LINE__, ##__VA_ARGS__)

#define RU_PRINT_ERRNO(CALL)                              \
	fprintf(stdout, "%s(): %s:%-4d, ret = %d (%s)\n", \
		(CALL), __FILE__, __LINE__, errno, strerror(errno))

/* Relative Addressing (ABS/REL bit clear); PIDonFEP in bits 11:0 and the
 * Resource Index in bits 23:12
 */
#define RU_GET_QPN(PID_ON_FEP, RI)                                   \
	((((uint32_t)(PID_ON_FEP) << IBV_QPN_UET_PID_ON_FEP_SHIFT) & \
	  IBV_QPN_UET_PID_ON_FEP_MASK) |                             \
	 (((uint32_t)(RI) << IBV_QPN_UET_RI_SHIFT) &                 \
	  IBV_QPN_UET_RI_MASK))

struct ru_cfg {
	char *prog_name;
	char *ib_devname;
	bool client;
	bool do_rma_ex;
	bool do_rma_ex64;
	bool write32;
	bool read32;
	bool auto_qpn;
	bool derive_mr;
	bool addr_table;
	bool job_mr;
	bool user_rkey;
	uint64_t user_rkey_val;
	bool absolute;
	uint32_t job_id;
	char *peer_ip_addr_string;
	uint32_t peer_ipv4_addr;
	uint32_t tcp_port;
	uint16_t pid_on_fep;
	uint16_t resource_index;
	int num_iterations;
	int sge;
	size_t msg_size;
	int ib_port;
	int gidx;
	uint32_t rx_depth;
	uint32_t tx_depth;
	uint32_t imm_data;
	uint64_t imm_data64;
	int use_event;
	int validate_buf;
	enum ibv_mtu mtu;
};

struct ru_exchange_info {
	int qpn;
	uint64_t rkey;
	uint32_t job_id;
	union ibv_gid gid;
};

struct ru_context {
	struct ru_cfg cfg;
	struct ibv_job *job;
	struct ibv_job_key *job_key;
	struct ibv_job *peer_job;
	struct ibv_job_key *peer_job_key;
	struct ibv_job_key *send_job_key;
	char *buf;
	struct ibv_context *context;
	struct ibv_comp_channel *channel;
	union ibv_gid gid;
	uint32_t src_id;
	struct ibv_pd *pd;
	struct ibv_mr *mr;
	struct ibv_mr *parent_mr;	/* backing region when mr is derived */
	bool mr_attached;
	struct ibv_cq *cq;
	struct ibv_cq_ex *cq_ex;
	struct ibv_qp *qp;
	struct ibv_qp_ex *qp_ex;
	struct ibv_ah_ex *ah;
	struct ru_exchange_info peer_info;
};

static void RU_USAGE(const char *argv0)
{
	printf("Usage:\n");
	printf("  %s            start a server and wait for connection\n", argv0);
	printf("  %s <host>     connect to server at <host>\n", argv0);
	printf("\n");
	printf("Options:\n");
	printf("  -p, --port <port>      listen on/connect to port <port> (default %d)\n",
	       RU_TCP_PORT);
	printf("  -d, --ib-dev <dev>     use IB device <dev> (default first device found)\n");
	printf("  -i, --ib-port <port>   use port <port> of IB device (default %d)\n",
	       RU_DEFAULT_IB_PORT);
	printf("  -s, --size <size>      size of message to exchange (default %d)\n", RU_MSG_SZ);
	printf("  -m, --mtu <size>       path MTU (default 1024, same on both sides)\n");
	printf("  -r, --rx-depth <dep>   number of receives to post at a time (default %d)\n",
	       RU_RX_DEPTH);
	printf("  -n, --iters <iters>    number of exchanges (default %d)\n", RU_NUM_ITERATIONS);
	printf("  -e, --events           sleep on CQ events (default poll)\n");
	printf("  -g, --gid-idx <idx>    local port gid index (default %d)\n",
	       RU_DEFAULT_GID_INDEX);
	printf("  -c, --chk              validate received buffer\n");
	printf("  -t, --test <test>      test to run: rma, rma_ex, rma_ex64 (default rma_ex64)\n");
	printf("  -Q, --auto-qpn         let the provider assign the QPN (PIDonFEP/RI)\n");
	printf("  -D, --derive-mr        use a derived memory region for transfers\n");
	printf("  -A, --addr-table       target the peer via the job address table\n");
	printf("  -J, --job-mr           register a job-restricted memory region\n");
	printf("  -u, --user-rkey <key>  register the MR with a user-assigned RKey <key>\n");
	printf("  -b, --absolute         use absolute addressing (server accepts any JobID)\n");
	printf("  -j, --job-id <id>      this side's JobID (default %d)\n", RU_DEFAULT_JOB_ID);
	printf("  -W, --write32          RDMA write with a 32-bit RKey (default 64-bit)\n");
	printf("  -R, --read32           RDMA read with a 32-bit RKey (default 64-bit)\n");
	printf("                         (-W and -R need a device with 32-bit keys)\n");
	printf("  -S, --sge <n>          spread RMA read/write over <n> local SGEs (1..%d)\n",
	       RU_MAX_SGE);
	printf("      --pidonfep <n>     source QPN PIDonFEP (default %d)\n",
	       RU_DEFAULT_PID_ON_FEP);
	printf("      --ri <n>           source QPN Resource Index (default %d)\n",
	       RU_DEFAULT_RESOURCE_INDEX);
	printf("\n");
	printf("Note: -Q (provider-assigned QPN) cannot be combined with -b, --pidonfep, or\n");
	printf("      --ri. The provider chooses the QPN (always relative), so an explicit\n");
	printf("      source QPN (--pidonfep/--ri) is ignored and absolute addressing (-b) is\n");
	printf("      not possible.\n");
}

static struct ru_context ru_ctx;

static void ru_free_res(struct ru_context *ctx)
{
	if (ctx->mr_attached) {
		ctx->mr_attached = false;
		ibv_detach_mr(ctx->qp, ctx->mr);
	}

	if (ctx->qp) {
		ibv_destroy_qp(ctx->qp);
		ctx->qp = NULL;
	}

	if (ctx->cq) {
		ibv_destroy_cq(ctx->cq);
		ctx->cq = NULL;
	}

	if (ctx->mr) {
		ibv_dereg_mr(ctx->mr);
		ctx->mr = NULL;
	}

	if (ctx->parent_mr) {
		ibv_dereg_mr(ctx->parent_mr);
		ctx->parent_mr = NULL;
	}

	if (ctx->job_key) {
		ibv_destroy_jkey(ctx->job_key);
		ctx->job_key = NULL;
	}

	if (ctx->peer_job_key) {
		ibv_destroy_jkey(ctx->peer_job_key);
		ctx->peer_job_key = NULL;
	}

	if (ctx->peer_job) {
		ibv_dealloc_job(ctx->peer_job);
		ctx->peer_job = NULL;
	}

	if (ctx->job && ctx->cfg.addr_table)
		ibv_remove_addr(ctx->job, RU_ADDR_INDEX, 0);

	if (ctx->job) {
		ibv_dealloc_job(ctx->job);
		ctx->job = NULL;
	}

	if (ctx->pd) {
		ibv_dealloc_pd(ctx->pd);
		ctx->pd = NULL;
	}

	if (ctx->channel) {
		ibv_destroy_comp_channel(ctx->channel);
		ctx->channel = NULL;
	}

	if (ctx->context) {
		ibv_close_device(ctx->context);
		ctx->context = NULL;
	}

	if (ctx->buf) {
		free(ctx->buf);
		ctx->buf = NULL;
	}

	if (ctx->cfg.ib_devname) {
		free(ctx->cfg.ib_devname);
		ctx->cfg.ib_devname = NULL;
	}

	if (ctx->cfg.peer_ip_addr_string) {
		free(ctx->cfg.peer_ip_addr_string);
		ctx->cfg.peer_ip_addr_string = NULL;
	}
}

static int ru_init_cfg(int argc, char *argv[], struct ru_context *ctx)
{
	struct in_addr peer_in_addr;

	/* Set defaults */
	ctx->cfg.prog_name = argv[0];
	ctx->cfg.ib_devname = NULL;
	ctx->cfg.resource_index = RU_DEFAULT_RESOURCE_INDEX;
	ctx->cfg.pid_on_fep = RU_DEFAULT_PID_ON_FEP;
	ctx->cfg.ib_port = RU_DEFAULT_IB_PORT;
	ctx->cfg.gidx = RU_DEFAULT_GID_INDEX;
	ctx->cfg.tcp_port = RU_TCP_PORT;
	ctx->cfg.num_iterations = RU_NUM_ITERATIONS;
	ctx->cfg.sge = 1;
	ctx->cfg.msg_size = RU_MSG_SZ;
	ctx->cfg.rx_depth = RU_RX_DEPTH;
	ctx->cfg.tx_depth = RU_TX_DEPTH;
	ctx->cfg.imm_data = RU_IMM_DATA;
	ctx->cfg.imm_data64 = RU_IMM_DATA_64;
	ctx->cfg.use_event = 0;
	ctx->cfg.validate_buf = 0;
	ctx->cfg.mtu = IBV_MTU_1024;
	ctx->cfg.do_rma_ex = false;
	ctx->cfg.do_rma_ex64 = true;  /* default to rma_ex64 */
	ctx->cfg.job_id = RU_DEFAULT_JOB_ID;

	while (1) {
		int c;

		static struct option long_options[] = {
			{ .name = "port",       .has_arg = 1, .val = 'p' },
			{ .name = "ib-dev",     .has_arg = 1, .val = 'd' },
			{ .name = "ib-port",    .has_arg = 1, .val = 'i' },
			{ .name = "size",       .has_arg = 1, .val = 's' },
			{ .name = "mtu",        .has_arg = 1, .val = 'm' },
			{ .name = "rx-depth",   .has_arg = 1, .val = 'r' },
			{ .name = "iters",      .has_arg = 1, .val = 'n' },
			{ .name = "events",     .has_arg = 0, .val = 'e' },
			{ .name = "gid-idx",    .has_arg = 1, .val = 'g' },
			{ .name = "chk",        .has_arg = 0, .val = 'c' },
			{ .name = "test",       .has_arg = 1, .val = 't' },
			{ .name = "auto-qpn",   .has_arg = 0, .val = 'Q' },
			{ .name = "derive-mr",  .has_arg = 0, .val = 'D' },
			{ .name = "addr-table", .has_arg = 0, .val = 'A' },
			{ .name = "job-mr",     .has_arg = 0, .val = 'J' },
			{ .name = "user-rkey",  .has_arg = 1, .val = 'u' },
			{ .name = "absolute",   .has_arg = 0, .val = 'b' },
			{ .name = "job-id",     .has_arg = 1, .val = 'j' },
			{ .name = "write32",    .has_arg = 0, .val = 'W' },
			{ .name = "read32",     .has_arg = 0, .val = 'R' },
			{ .name = "sge",        .has_arg = 1, .val = 'S' },
			{ .name = "pidonfep",   .has_arg = 1, .val = RU_OPT_PIDONFEP },
			{ .name = "ri",         .has_arg = 1, .val = RU_OPT_RI },
			{}
		};

		c = getopt_long(argc, argv, "p:d:i:s:m:r:n:eg:ct:QDAJu:bj:WRS:",
				long_options, NULL);

		if (c == -1)
			break;

		switch (c) {
		case 'p':
			ctx->cfg.tcp_port = strtoul(optarg, NULL, 0);
			if (ctx->cfg.tcp_port > 65535) {
				RU_USAGE(argv[0]);
				return RU_ERR_RC;
			}
			break;
		case 'd':
			ctx->cfg.ib_devname = strdup(optarg);
			break;
		case 'i':
			ctx->cfg.ib_port = strtol(optarg, NULL, 0);
			if (ctx->cfg.ib_port < 1) {
				RU_USAGE(argv[0]);
				return RU_ERR_RC;
			}
			break;
		case 's':
			ctx->cfg.msg_size = strtoul(optarg, NULL, 0);
			break;
		case 'm':
			ctx->cfg.mtu = pp_mtu_to_enum(strtol(optarg, NULL, 0));
			if (ctx->cfg.mtu == 0) {
				RU_USAGE(argv[0]);
				return RU_ERR_RC;
			}
			break;
		case 'r':
			ctx->cfg.rx_depth = strtoul(optarg, NULL, 0);
			break;
		case 'n':
			ctx->cfg.num_iterations = strtoul(optarg, NULL, 0);
			break;
		case 'e':
			ctx->cfg.use_event = 1;
			break;
		case 'g':
			ctx->cfg.gidx = strtol(optarg, NULL, 0);
			break;
		case 'c':
			ctx->cfg.validate_buf = 1;
			break;
		case 'Q':
			ctx->cfg.auto_qpn = true;
			break;
		case 'D':
			ctx->cfg.derive_mr = true;
			break;
		case 'A':
			ctx->cfg.addr_table = true;
			break;
		case 'J':
			ctx->cfg.job_mr = true;
			break;
		case 'u':
			ctx->cfg.user_rkey = true;
			ctx->cfg.user_rkey_val = strtoull(optarg, NULL, 0);
			break;
		case 'b':
			ctx->cfg.absolute = true;
			break;
		case 'W':
			ctx->cfg.write32 = true;
			break;
		case 'R':
			ctx->cfg.read32 = true;
			break;
		case 'S':
			ctx->cfg.sge = strtol(optarg, NULL, 0);
			if ((ctx->cfg.sge < 1) || (ctx->cfg.sge > RU_MAX_SGE)) {
				RU_ERR("--sge must be 1..%d", RU_MAX_SGE);
				return RU_ERR_RC;
			}
			break;
		case RU_OPT_PIDONFEP:
			ctx->cfg.pid_on_fep = strtoul(optarg, NULL, 0);
			break;
		case RU_OPT_RI:
			ctx->cfg.resource_index = strtoul(optarg, NULL, 0);
			break;
		case 'j':
			ctx->cfg.job_id = strtoul(optarg, NULL, 0);
			break;
		case 't':
			if (strcmp(optarg, "rma") == 0) {
				ctx->cfg.do_rma_ex = false;
				ctx->cfg.do_rma_ex64 = false;
			} else if (strcmp(optarg, "rma_ex") == 0) {
				ctx->cfg.do_rma_ex = true;
				ctx->cfg.do_rma_ex64 = false;
			} else if (strcmp(optarg, "rma_ex64") == 0) {
				ctx->cfg.do_rma_ex = false;
				ctx->cfg.do_rma_ex64 = true;
			} else {
				RU_ERR("Invalid test: %s", optarg);
				RU_USAGE(argv[0]);
				return RU_ERR_RC;
			}
			break;
		default:
			RU_USAGE(argv[0]);
			return RU_ERR_RC;
		}
	}

	/* after options, check for optional servername (makes us client) */
	if (optind < argc - 1) {
		RU_USAGE(argv[0]);
		return RU_ERR_RC;
	}

	if (optind == argc - 1) {
		ctx->cfg.client = true;
		ctx->cfg.peer_ip_addr_string = strdup(argv[optind]);
		if (inet_pton(AF_INET, ctx->cfg.peer_ip_addr_string,
			      &peer_in_addr) == 1)
			ctx->cfg.peer_ipv4_addr = ntohl(peer_in_addr.s_addr);
	} else {
		ctx->cfg.client = false;
	}

	return RU_SUCCESS_RC;
}

/* verify the device exposes every capability this run relies on */
static int ru_check_dev_caps(struct ru_context *ctx)
{
	struct ibv_device_attr_ex attr;
	uint64_t caps;
	int rc;

	memset(&attr, 0, sizeof(attr));
	rc = ibv_query_device_ex(ctx->context, NULL, &attr);
	if (rc) {
		RU_ERR("ibv_query_device_ex failed (%d)", rc);
		return RU_ERR_RC;
	}

	caps = attr.device_cap_flags_ex;

	/* the example always creates RU (UET) queue pairs */
	if (!(caps & IBV_DEVICE_RU)) {
		RU_ERR("device does not support RU (UET) queue pairs");
		return RU_ERR_RC;
	}

	/* the example always exchanges and uses 64-bit memory keys */
	if (!(caps & IBV_DEVICE_KEY64)) {
		RU_ERR("device does not support 64-bit keys (KEY64)");
		return RU_ERR_RC;
	}

	/* the rma_ex64 test transfers 64-bit immediate data */
	if (ctx->cfg.do_rma_ex64 && !(caps & IBV_DEVICE_IMM64)) {
		RU_ERR("device does not support 64-bit immediate data (IMM64)");
		return RU_ERR_RC;
	}

	/* could register a memory region with a user-assigned RKey */
	if (ctx->cfg.user_rkey && !(caps & IBV_DEVICE_USER_RKEY)) {
		RU_ERR("device does not support user-assigned RKeys (USER_RKEY)");
		return RU_ERR_RC;
	}

	/* the local SGE array is sized at RU_MAX_SGE; the device must accept
	 * that many SGEs per WR.
	 */
	if (attr.orig_attr.max_sge < RU_MAX_SGE) {
		RU_ERR("RU_MAX_SGE (%d) exceeds device max_sge (%d)",
		       RU_MAX_SGE, attr.orig_attr.max_sge);
		return RU_ERR_RC;
	}

	return RU_SUCCESS_RC;
}

static int ru_init_ctx(struct ru_context *ctx)
{
	struct ibv_device **dev_list;
	struct ibv_device  *ib_dev;
	int page_size, access_flags;
	uint8_t buf_data;
	struct ibv_cq_init_attr_ex cq_attr_ex;
	struct ibv_qp_init_attr_ex qp_init_attr_ex;
	struct ibv_qp_attr qp_attr;
	struct ibv_qp_semantics semantics;
	struct ibv_mr_init_attr mra;

	dev_list = ibv_get_device_list(NULL);
	if (!dev_list) {
		RU_PRINT_ERRNO("Failed to get IB devices list");
		return RU_ERR_RC;
	}

	if (!ctx->cfg.ib_devname) {
		ib_dev = *dev_list;
		if (!ib_dev) {
			RU_ERR("No IB devices found");
			return RU_ERR_RC;
		}
	} else {
		int i;

		for (i = 0; dev_list[i]; ++i) {
			if (!strcmp(ibv_get_device_name(dev_list[i]),
				    ctx->cfg.ib_devname))
				break;
		}

		ib_dev = dev_list[i];
		if (!ib_dev) {
			RU_ERR("IB device %s not found", ctx->cfg.ib_devname);
			return RU_ERR_RC;
		}
	}

	page_size = sysconf(_SC_PAGESIZE);

	ctx->buf = memalign(page_size, ctx->cfg.msg_size);
	if (!ctx->buf) {
		RU_ERR("Couldn't allocate buffer");
		return RU_ERR_RC;
	}

	if (ctx->cfg.client)
		buf_data = RU_CLIENT_BUF_DATA;
	else
		buf_data = RU_SERVER_BUF_DATA;

	memset(ctx->buf, buf_data, ctx->cfg.msg_size);

	ctx->context = ibv_open_device(ib_dev);
	if (!ctx->context) {
		RU_PRINT_ERRNO("ibv_open_device failed");
		RU_ERR("Couldn't get context for %s",
		       ibv_get_device_name(ib_dev));
		goto err_exit;
	}

	if (ru_check_dev_caps(ctx) != RU_SUCCESS_RC)
		goto err_exit;

	if (ctx->cfg.use_event) {
		ctx->channel = ibv_create_comp_channel(ctx->context);
		if (!ctx->channel) {
			RU_PRINT_ERRNO("Couldn't create completion channel");
			goto err_exit;
		}
	} else {
		ctx->channel = NULL;
	}

	if (ibv_query_gid(ctx->context, ctx->cfg.ib_port,
			  ctx->cfg.gidx, &ctx->gid)) {
		RU_PRINT_ERRNO("ibv_query_gid failed");
		RU_ERR("Couldn't read sgid of index %d\n", ctx->cfg.gidx);
		goto err_exit;
	}

	memcpy(&ctx->src_id, &ctx->gid.raw[12], sizeof(ctx->src_id));

	ctx->pd = ibv_alloc_pd(ctx->context);
	if (!ctx->pd) {
		RU_PRINT_ERRNO("Couldn't allocate protection domain");
		goto err_exit;
	}

	struct ibv_job_attr job_attr = {
		.comp_mask = (IBV_JOB_ATTR_ID |
			      IBV_JOB_ATTR_PORT_NUM |
			      IBV_JOB_ATTR_SGID_INDEX),
		.id = ctx->cfg.job_id,
		.port_num = ctx->cfg.ib_port,
		.sgid_index = ctx->cfg.gidx,
	};

	ctx->job = ibv_alloc_job(ctx->context, &job_attr, NULL);
	if (!ctx->job) {
		RU_ERR("Couldn't allocate job");
		goto err_exit;
	}

	ctx->job_key = ibv_create_jkey(ctx->pd, ctx->job, 0);
	if (!ctx->job_key) {
		RU_ERR("Couldn't create job key");
		goto err_exit;
	}

	/* Outgoing sends use the local job key by default; an absolute server
	 * later switches to a job key for the client's JobID (set up after the
	 * address exchange) so its write-back reaches the relative client.
	 */
	ctx->send_job_key = ctx->job_key;

	access_flags = (IBV_ACCESS_LOCAL_WRITE |
			IBV_ACCESS_REMOTE_WRITE |
			IBV_ACCESS_REMOTE_READ |
			IBV_ACCESS_ZERO_BASED);

	if ((ctx->cfg.job_mr || ctx->cfg.user_rkey) && !ctx->cfg.derive_mr) {
		memset(&mra, 0, sizeof(mra));
		mra.comp_mask = IBV_REG_MR_MASK_ADDR;
		mra.addr = ctx->buf;
		mra.length = ctx->cfg.msg_size;
		mra.access = access_flags;

		if (ctx->cfg.job_mr) {
			/* restrict the region to the job's JobID */
			mra.comp_mask |= IBV_REG_MR_MASK_JKEY;
			mra.job_key = ctx->job_key;
		}

		if (ctx->cfg.user_rkey) {
			/* register with a user-assigned RKey */
			mra.comp_mask |= IBV_REG_MR_MASK_RKEY;
			mra.rkey = ctx->cfg.user_rkey_val;
		}

		ctx->mr = ibv_reg_mr_ex(ctx->pd, &mra);
	} else {
		ctx->mr = ibv_reg_mr(ctx->pd, ctx->buf,
				     ctx->cfg.msg_size, access_flags);
	}

	if (!ctx->mr) {
		RU_PRINT_ERRNO("Couldn't allocate memory region");
		goto err_exit;
	}

	/* Optionally derive a memory region contained within the first one
	 * and use it for the transfers.
	 */
	if (ctx->cfg.derive_mr) {
		memset(&mra, 0, sizeof(mra));
		mra.comp_mask = (IBV_REG_MR_MASK_ADDR |
				 IBV_REG_MR_MASK_CUR_MR);
		mra.addr = ctx->buf;
		mra.length = ctx->cfg.msg_size;
		mra.access = access_flags;
		mra.cur_mr = ctx->mr;

		/* The derived MR (used for transfers) carries any job and
		 * user-key restriction. The parent stays a plain provider-key
		 * region
		 */
		if (ctx->cfg.job_mr) {
			mra.comp_mask |= IBV_REG_MR_MASK_JKEY;
			mra.job_key = ctx->job_key;
		}

		if (ctx->cfg.user_rkey) {
			mra.comp_mask |= IBV_REG_MR_MASK_RKEY;
			mra.rkey = ctx->cfg.user_rkey_val;
		}

		ctx->parent_mr = ctx->mr;
		ctx->mr = ibv_reg_mr_ex(ctx->pd, &mra);
		if (!ctx->mr) {
			RU_PRINT_ERRNO("Couldn't derive memory region");
			ctx->mr = ctx->parent_mr;
			ctx->parent_mr = NULL;
			goto err_exit;
		}
	}

	if (ctx->cfg.do_rma_ex || ctx->cfg.do_rma_ex64) {
		memset(&cq_attr_ex, 0, sizeof(struct ibv_cq_init_attr_ex));
		cq_attr_ex.cqe = ctx->cfg.rx_depth + 1;
		cq_attr_ex.channel = ctx->channel;
		cq_attr_ex.wc_flags =
			(IBV_WC_EX_WITH_BYTE_LEN	|
			 IBV_WC_EX_WITH_QP_NUM		|
			 IBV_WC_EX_WITH_IMM		|
			 IBV_WC_EX_WITH_IMM64		|
			 IBV_WC_EX_WITH_JOB_ID		|
			 IBV_WC_EX_WITH_SRC_ID);

		ctx->cq_ex = ibv_create_cq_ex(ctx->context, &cq_attr_ex);
		if (ctx->cq_ex)
			ctx->cq = ibv_cq_ex_to_cq(ctx->cq_ex);
	} else {
		ctx->cq = ibv_create_cq(ctx->context, ctx->cfg.rx_depth + 1,
					NULL, ctx->channel, 0);
	}

	if (!ctx->cq) {
		RU_PRINT_ERRNO("Couldn't create completion queue");
		goto err_exit;
	}

	memset(&qp_init_attr_ex, 0, sizeof(struct ibv_qp_init_attr_ex));
	qp_init_attr_ex.send_cq = ctx->cq;
	qp_init_attr_ex.recv_cq = ctx->cq;
	qp_init_attr_ex.cap.max_send_wr = ctx->cfg.tx_depth;
	qp_init_attr_ex.cap.max_recv_wr = ctx->cfg.rx_depth;
	qp_init_attr_ex.cap.max_send_sge = ctx->cfg.sge;
	qp_init_attr_ex.cap.max_recv_sge = ctx->cfg.sge;
	qp_init_attr_ex.qp_type = IBV_QPT_RU;
	qp_init_attr_ex.sq_sig_all = 1;

	/* without a source QPN the provider assigns the PIDonFEP/RI */
	if (!ctx->cfg.auto_qpn) {
		qp_init_attr_ex.create_flags = IBV_QP_CREATE_SOURCE_QPN;
		qp_init_attr_ex.source_qpn =
			RU_GET_QPN(ctx->cfg.pid_on_fep,
				   ctx->cfg.resource_index);

		/* An absolute server publishes an absolute QPN (bit 31 set)
		 * so peers address it by PIDonFEP/RI and it receives any
		 * JobID, the client stays relative (demux/authorize by its
		 * JobID).
		 */
		if (ctx->cfg.absolute && !ctx->cfg.client) {
			qp_init_attr_ex.source_qpn |=
				IBV_QPN_UET_ABSOLUTE_ADDR_BIT;
		}
	}

	qp_init_attr_ex.comp_mask = (IBV_QP_INIT_ATTR_PD |
				     IBV_QP_INIT_ATTR_SRC_ID |
				     IBV_QP_INIT_ATTR_QP_SEMANTICS |
				     IBV_QP_INIT_ATTR_QP_ATTR |
				     IBV_QP_INIT_ATTR_JKEY);

	/* create_flags (IBV_QP_CREATE_SOURCE_QPN, set above) is only honored
	 * when its comp_mask bit is also set
	 */
	if (!ctx->cfg.auto_qpn)
		qp_init_attr_ex.comp_mask |= IBV_QP_INIT_ATTR_CREATE_FLAGS;

	qp_init_attr_ex.pd = ctx->pd;
	qp_init_attr_ex.src_id = ctx->src_id;
	qp_init_attr_ex.job_key = ctx->job_key;

	/* specify attributes at create time via the QP_ATTR channel */
	memset(&qp_attr, 0, sizeof(struct ibv_qp_attr));
	qp_attr.path_mtu = ctx->cfg.mtu;
	qp_init_attr_ex.qp_attr = &qp_attr;
	qp_init_attr_ex.qp_attr_mask = IBV_QP_PATH_MTU;

	memset(&semantics, 0, sizeof(struct ibv_qp_semantics));

	/* use the 64-bit RKey work-request ops */
	if (ctx->cfg.do_rma_ex) {
		qp_init_attr_ex.comp_mask |= IBV_QP_INIT_ATTR_SEND_OPS_FLAGS;
		qp_init_attr_ex.send_ops_flags =
				IBV_QP_EX_WITH_RDMA_WRITE		|
				IBV_QP_EX_WITH_RDMA_WRITE64_WITH_IMM	|
				IBV_QP_EX_WITH_RDMA_READ;
	} else if (ctx->cfg.do_rma_ex64) {
		qp_init_attr_ex.comp_mask |= IBV_QP_INIT_ATTR_SEND_OPS_FLAGS;
		qp_init_attr_ex.send_ops_flags =
				IBV_QP_EX_WITH_RDMA_WRITE		|
				IBV_QP_EX_WITH_RDMA_WRITE64_WITH_IMM64	|
				IBV_QP_EX_WITH_RDMA_READ;
		semantics.comp_mask |= IBV_QP_SEMANTICS_MASK_IMM;
		semantics.imm_data_size |= IBV_IMM_DATA_SIZE_64;
	}

	qp_init_attr_ex.qp_semantics = &semantics;

	ctx->qp = ibv_create_qp_ex(ctx->context, &qp_init_attr_ex);
	if (!ctx->qp)  {
		RU_PRINT_ERRNO("Couldn't create queue pair");
		goto err_exit;
	}

	ctx->qp_ex = ibv_qp_to_qp_ex(ctx->qp);

	/* Smoke-test QP error recovery. The QP is created in RTS, cycle it
	 * through RTS -> ERR -> RST -> RTS. A broken endpoint reset/re-enable
	 * fails here or breaks the subsequent transfers.
	 */
	{
		enum ibv_qp_state cycle[] = { IBV_QPS_ERR,
					      IBV_QPS_RESET,
					      IBV_QPS_RTS };
		struct ibv_qp_attr sattr;
		int i;

		for (i = 0; i < 3; i++) {
			memset(&sattr, 0, sizeof(sattr));
			sattr.qp_state = cycle[i];
			errno = ibv_modify_qp(ctx->qp, &sattr, IBV_QP_STATE);
			if (errno) {
				RU_PRINT_ERRNO("QP state-recovery cycle failed");
				goto err_exit;
			}
		}
	}

	errno = ibv_attach_mr(ctx->qp, ctx->mr);
	if (errno) {
		RU_PRINT_ERRNO("Couldn't attach memory region to queue pair");
		goto err_exit;
	}

	/* Smoke-test MR access revoke + re-enable: detach revokes remote
	 * access (the MR returns to the registered state), then re-attach
	 * re-binds and re-enables it. A broken disable/re-enable cycle fails
	 * here, before any data transfer.
	 */
	errno = ibv_detach_mr(ctx->qp, ctx->mr);
	if (errno) {
		RU_PRINT_ERRNO("Couldn't detach memory region");
		goto err_exit;
	}

	errno = ibv_attach_mr(ctx->qp, ctx->mr);
	if (errno) {
		RU_PRINT_ERRNO("Couldn't re-attach memory region");
		goto err_exit;
	}

	ctx->mr_attached = true;

	/* the RU QP is created directly in RTS (no INIT/RTR modify) */
	return RU_SUCCESS_RC;

err_exit:
	ru_free_res(ctx);
	return RU_ERR_RC;
}

static int ru_connect_ctx(struct ru_context *ctx)
{
	struct ibv_ah_attr_ex ah_attr_ex;

	/* The RU QP is already in the RTS state after creation (no INIT/RTR
	 * modify is required); only the address handle needs to be set up.
	 */
	memset(&ah_attr_ex, 0, sizeof(ah_attr_ex));
	ah_attr_ex.ah_attr.is_global = 1;
	ah_attr_ex.ah_attr.grh.hop_limit = 1;
	ah_attr_ex.ah_attr.grh.dgid = ctx->peer_info.gid;
	ah_attr_ex.ah_attr.grh.sgid_index = ctx->cfg.gidx;
	ah_attr_ex.ah_attr.port_num = ctx->cfg.ib_port;
	ah_attr_ex.remote_qpn = ctx->peer_info.qpn;

	if (ctx->cfg.addr_table) {
		struct ibv_ah_attr_ex qattr;

		/* Insert the peer address into the job's address table and
		 * target it by index instead of using an explicit AH.
		 */
		if (ibv_insert_addr(ctx->job, &ah_attr_ex, RU_ADDR_INDEX, 0)) {
			RU_PRINT_ERRNO("Failed to insert address into table");
			return RU_ERR_RC;
		}

		memset(&qattr, 0, sizeof(qattr));
		if (ibv_query_addr(ctx->job, RU_ADDR_INDEX, &qattr, 0)) {
			RU_PRINT_ERRNO("Failed to query address table");
			return RU_ERR_RC;
		}

		/* The kernel takes the hop limit from the route, as it does
		 * for an address handle.
		 */
		qattr.ah_attr.grh.hop_limit = ah_attr_ex.ah_attr.grh.hop_limit;

		if (memcmp(&ah_attr_ex, &qattr,
			   sizeof(struct ibv_ah_attr_ex)) != 0) {
			RU_ERR("address table mismatch");
			return RU_ERR_RC;
		}
	} else {
		ctx->ah = ibv_ah_to_ah_ex(ibv_create_ah_ex(ctx->pd,
							   &ah_attr_ex));
		if (ctx->ah == NULL) {
			RU_PRINT_ERRNO("Failed to create address handle");
			return RU_ERR_RC;
		}
	}

	return RU_SUCCESS_RC;
}

/*
 * A link-local IPv6 address (fe80::/10) is not connectable without a scope
 * (interface) id. If the peer address is given without one (e.g. "fe80::1"
 * rather than "fe80::1%eth0"), determine it from the interface that owns the
 * local source GID (-g), so the correct NIC is used on a multi-homed host.
 * Falls back to the first non-loopback link-local interface if the GID does
 * not match one (e.g. single-NIC setups where the GID differs slightly).
 */
static unsigned int ru_link_local_scope_id(const union ibv_gid *sgid)
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
static void ru_fixup_link_local(struct addrinfo *t, const union ibv_gid *sgid)
{
	struct sockaddr_in6 *sa6;

	if (t->ai_family != AF_INET6)
		return;

	sa6 = (struct sockaddr_in6 *)t->ai_addr;
	if (IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr) && sa6->sin6_scope_id == 0)
		sa6->sin6_scope_id = ru_link_local_scope_id(sgid);
}

static int ru_client_exchange(struct ru_context *ctx)
{
	enum ru_rc rc = RU_ERR_RC;
	int n, sockfd = -1;
	char *service = NULL, gid[33];
	struct ru_exchange_info info;
	struct addrinfo hints = {
		.ai_family   = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM
	};
	struct addrinfo *res = NULL, *t;
	char msg[sizeof(
		"00000000:0000000000000000:00000000:00000000000000000000000000000000")];

	if (asprintf(&service, "%d", ctx->cfg.tcp_port) < 0) {
		RU_PRINT_ERRNO("asprintf failed");
		goto exit;
	}

	n = getaddrinfo(ctx->cfg.peer_ip_addr_string, service, &hints, &res);
	if (n) {
		RU_ERR("%s for %s:%d\n", gai_strerror(n),
		       ctx->cfg.peer_ip_addr_string,
		       ctx->cfg.tcp_port);
		goto exit;
	}

	for (t = res; t; t = t->ai_next) {
		ru_fixup_link_local(t, &ctx->gid);
		sockfd = socket(t->ai_family, t->ai_socktype, t->ai_protocol);
		if (sockfd >= 0) {
			if (!connect(sockfd, t->ai_addr, t->ai_addrlen))
				break;
			close(sockfd);
			sockfd = -1;
		}
	}

	if (sockfd < 0) {
		RU_PRINT_ERRNO("socket/connect failed");
		RU_ERR("Couldn't connect to %s:%d\n",
		       ctx->cfg.peer_ip_addr_string,
		       ctx->cfg.tcp_port);
		goto exit;
	}

	info.gid = ctx->gid;
	info.qpn = ctx->qp->qp_num;
	info.rkey = ctx->mr->rkey64;
	info.job_id = ctx->cfg.job_id;
	inet_ntop(AF_INET6, &info.gid, gid, sizeof(gid));
	printf("local address: QPN 0x%06x, GID %s\n", info.qpn, gid);

	memset(gid, 0, sizeof(gid));
	gid_to_wire_gid(&info.gid, gid);

	sprintf(msg, "%08x:%016" PRIx64 ":%08x:%s", info.qpn, info.rkey,
		info.job_id, gid);

	if (write(sockfd, msg, sizeof(msg)) != sizeof(msg)) {
		RU_PRINT_ERRNO("Couldn't write local address to peer");
		goto exit;
	}

	if (read(sockfd, msg, sizeof(msg)) != sizeof(msg)) {
		RU_PRINT_ERRNO("Couldn't read remote address from peer");
		goto exit;
	}

	sscanf(msg, "%x:%" SCNx64 ":%x:%s",
	       &ctx->peer_info.qpn, &ctx->peer_info.rkey,
	       &ctx->peer_info.job_id, gid);
	wire_gid_to_gid(gid, &ctx->peer_info.gid);

	if (ru_connect_ctx(ctx)) {
		RU_ERR("Couldn't connect to peer queue pair");
		goto exit;
	}

	if (write(sockfd, "done", sizeof("done")) != sizeof("done")) {
		RU_PRINT_ERRNO("Couldn't complete address exchange with peer");
		goto exit;
	}

	inet_ntop(AF_INET6, &ctx->peer_info.gid, gid, sizeof(gid));
	printf("remote address: QPN 0x%06x, GID %s\n",
	       ctx->peer_info.qpn, gid);

	rc = RU_SUCCESS_RC;

exit:
	if (sockfd >= 0)
		close(sockfd);

	if (res)
		freeaddrinfo(res);

	if (service)
		free(service);

	return rc;
}

static int ru_server_exchange(struct ru_context *ctx)
{
	enum ru_rc rc = RU_ERR_RC;
	int n, sockfd = -1, connfd = -1;
	char *service = NULL, gid[33];
	struct ru_exchange_info info;
	/*
	 * Bind the IPv6 wildcard (::) as a dual-stack socket (IPV6_V6ONLY=0
	 * below) so the server accepts both IPv6 and IPv4(-mapped) clients on
	 * one listener. AF_UNSPEC + AI_PASSIVE can bind 0.0.0.0 first, which
	 * would refuse IPv6 clients.
	 */
	struct addrinfo hints = {
		.ai_flags	= AI_PASSIVE,
		.ai_family	= AF_INET6,
		.ai_socktype	= SOCK_STREAM
	};
	struct addrinfo *res = NULL, *t;
	char msg[sizeof(
		"00000000:0000000000000000:00000000:00000000000000000000000000000000")];

	if (asprintf(&service, "%d", ctx->cfg.tcp_port) < 0) {
		RU_PRINT_ERRNO("asprintf failed");
		goto exit;
	}

	n = getaddrinfo(NULL, service, &hints, &res);
	if (n) {
		RU_ERR("%s for tcp port %d\n", gai_strerror(n),
		       ctx->cfg.tcp_port);
		goto exit;
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

	if (sockfd < 0) {
		RU_PRINT_ERRNO("socket/bind failed");
		RU_ERR("Couldn't bind to port %d\n", ctx->cfg.tcp_port);
		goto exit;
	}

	inet_ntop(AF_INET6, &ctx->gid, gid, sizeof(gid));
	printf("local address: QPN 0x%06x, GID %s\n", ctx->qp->qp_num, gid);

	if (listen(sockfd, 1)) {
		RU_PRINT_ERRNO("listen failed");
		RU_ERR("Couldn't listen to port %d", ctx->cfg.tcp_port);
		goto exit;
	}

	connfd = accept(sockfd, NULL, NULL);
	if (connfd < 0) {
		RU_PRINT_ERRNO("Couldn't accept connection");
		goto exit;
	}

	if (read(connfd, msg, sizeof(msg)) != sizeof(msg)) {
		RU_PRINT_ERRNO("Couldn't read remote address from peer");
		goto exit;
	}

	sscanf(msg, "%x:%" SCNx64 ":%x:%s",
	       &ctx->peer_info.qpn, &ctx->peer_info.rkey,
	       &ctx->peer_info.job_id, gid);
	wire_gid_to_gid(gid, &ctx->peer_info.gid);

	if (ru_connect_ctx(ctx)) {
		RU_ERR("Couldn't connect to peer queue pair");
		goto exit;
	}

	info.gid = ctx->gid;
	info.qpn = ctx->qp->qp_num;
	info.rkey = ctx->mr->rkey64;
	info.job_id = ctx->cfg.job_id;

	memset(gid, 0, sizeof(gid));
	gid_to_wire_gid(&info.gid, gid);

	sprintf(msg, "%08x:%016" PRIx64 ":%08x:%s", info.qpn, info.rkey,
		info.job_id, gid);

	if (write(connfd, msg, sizeof(msg)) != sizeof(msg)) {
		RU_PRINT_ERRNO("Couldn't write local address to peer");
		goto exit;
	}

	if (read(connfd, msg, sizeof(msg)) != sizeof("done")) {
		RU_PRINT_ERRNO("Couldn't complete address exchange with peer");
		goto exit;
	}

	inet_ntop(AF_INET6, &ctx->peer_info.gid, gid, sizeof(gid));
	printf("remote address: QPN 0x%06x, GID %s\n",
	       ctx->peer_info.qpn, gid);

	rc = RU_SUCCESS_RC;

exit:
	if (sockfd >= 0)
		close(sockfd);

	if (connfd >= 0)
		close(connfd);

	if (res)
		freeaddrinfo(res);

	if (service)
		free(service);

	return rc;
}

/* Split the local buffer into cfg.sge contiguous segments for scatter/gather.
 * The remote side of the RMA is a single {addr, key}.
 *
 * The rma_ex64 mode uses 64-bit LKeys and therefore struct ibv_sge64; the
 * rma and rma_ex modes use the 32-bit struct ibv_sge.
 */
static int ru_build_sge(struct ru_context *ctx, struct ibv_sge *list)
{
	size_t seg = (ctx->cfg.msg_size / ctx->cfg.sge);
	int i;

	for (i = 0; i < ctx->cfg.sge; i++) {
		list[i].addr   = ((uintptr_t)ctx->buf + (size_t)i * seg);
		list[i].length = (i == ctx->cfg.sge - 1) ?
				 (ctx->cfg.msg_size - (size_t)i * seg) : seg;
		list[i].lkey   = ctx->mr->lkey;
	}

	return ctx->cfg.sge;
}

static int ru_build_sge64(struct ru_context *ctx, struct ibv_sge64 *list)
{
	size_t seg = (ctx->cfg.msg_size / ctx->cfg.sge);
	int i;

	for (i = 0; i < ctx->cfg.sge; i++) {
		list[i].addr   = ((uintptr_t)ctx->buf + (size_t)i * seg);
		list[i].length = (i == ctx->cfg.sge - 1) ?
				 (ctx->cfg.msg_size - (size_t)i * seg) : seg;
		list[i].lkey64 = ctx->mr->lkey64;
	}

	return ctx->cfg.sge;
}

static int ru_post_send_ex(struct ru_context *ctx, enum ibv_wr_opcode opcode,
			   enum ibv_imm_data_size imm_data_size)
{
	struct ibv_sge list[RU_MAX_SGE];
	struct ibv_sge64 list64[RU_MAX_SGE];
	int nsge;

	ctx->qp_ex->wr_id = RU_SEND_WRID;
	ctx->qp_ex->wr_flags = IBV_SEND_SIGNALED;

	ibv_wr_start(ctx->qp_ex);

	switch (opcode) {

	case IBV_WR_RDMA_WRITE:
		if (ctx->cfg.write32)
			ibv_wr_rdma_write(ctx->qp_ex,
					  (uint32_t)ctx->peer_info.rkey,
					  (uint64_t)0);
		else
			ibv_wr_rdma_write64(ctx->qp_ex,
					    ctx->peer_info.rkey,
					    (uint64_t)0);
		break;

	case IBV_WR_RDMA_WRITE_WITH_IMM:
		if (imm_data_size == IBV_IMM_DATA_SIZE_32)
			ibv_wr_rdma_write64_imm(ctx->qp_ex,
						ctx->peer_info.rkey,
						(uint64_t)0,
						htonl(ctx->cfg.imm_data));
		else
			ibv_wr_rdma_write64_imm64(ctx->qp_ex,
						  ctx->peer_info.rkey,
						  (uint64_t)0,
						  htobe64(ctx->cfg.imm_data64));
		break;

	case IBV_WR_RDMA_READ:
		if (ctx->cfg.read32)
			ibv_wr_rdma_read(ctx->qp_ex,
					 (uint32_t)ctx->peer_info.rkey,
					 (uint64_t)0);
		else
			ibv_wr_rdma_read64(ctx->qp_ex,
					   ctx->peer_info.rkey,
					   (uint64_t)0);
		break;

	default:
		break;
	}

	if (ctx->cfg.do_rma_ex64) {
		nsge = ru_build_sge64(ctx, list64);
		if (nsge == 1)
			ibv_wr_set_sge64(ctx->qp_ex, list64[0].lkey64,
					 list64[0].addr, list64[0].length);
		else
			ibv_wr_set_sge64_list(ctx->qp_ex, nsge, list64);
	} else {
		nsge = ru_build_sge(ctx, list);
		if (nsge == 1)
			ibv_wr_set_sge(ctx->qp_ex, list[0].lkey,
				       list[0].addr, list[0].length);
		else
			ibv_wr_set_sge_list(ctx->qp_ex, nsge, list);
	}

	if (ctx->cfg.addr_table)
		ibv_wr_set_ru_addr(ctx->qp_ex, NULL, RU_ADDR_INDEX);
	else
		ibv_wr_set_ru_addr(ctx->qp_ex, ctx->ah, 0);

	ibv_wr_set_job_key(ctx->qp_ex, ctx->send_job_key->jkey);

	return ibv_wr_complete(ctx->qp_ex);
}

static int ru_post_send(struct ru_context *ctx, enum ibv_wr_opcode opcode)
{
	struct ibv_sge list[RU_MAX_SGE];
	struct ibv_send_wr wr, *bad_wr;
	int nsge;

	if (ctx->cfg.do_rma_ex)
		return ru_post_send_ex(ctx, opcode, IBV_IMM_DATA_SIZE_32);

	if (ctx->cfg.do_rma_ex64)
		return ru_post_send_ex(ctx, opcode, IBV_IMM_DATA_SIZE_64);

	nsge = ru_build_sge(ctx, list);

	memset(&wr, 0, sizeof(struct ibv_send_wr));
	wr.wr_id = RU_SEND_WRID;
	wr.sg_list = list;
	wr.num_sge = nsge;
	wr.opcode = opcode;
	wr.send_flags = IBV_SEND_SIGNALED;
	if (opcode == IBV_WR_RDMA_WRITE_WITH_IMM)
		wr.imm_data = htonl(ctx->cfg.imm_data);
	wr.wr.ru_rdma.ah = ctx->ah;
	wr.wr.ru_rdma.jkey = ctx->send_job_key->jkey;
	wr.wr.ru_rdma.remote_addr = 0;
	wr.wr.ru_rdma.rkey64 = ctx->peer_info.rkey;

	return ibv_post_send(ctx->qp, &wr, &bad_wr);
}

static int ru_post_write(struct ru_context *ctx)
{
	int ret;

	ret = ru_post_send(ctx, IBV_WR_RDMA_WRITE);
	if (ret) {
		RU_PRINT_ERRNO("Post send of plain write failed");
		return RU_ERR_RC;
	}

	return RU_SUCCESS_RC;
}

static int ru_post_write_imm(struct ru_context *ctx)
{
	int ret;

	ret = ru_post_send(ctx, IBV_WR_RDMA_WRITE_WITH_IMM);
	if (ret) {
		RU_PRINT_ERRNO("Post send of write imm failed");
		return RU_ERR_RC;
	}

	return RU_SUCCESS_RC;
}

static int ru_post_read(struct ru_context *ctx)
{
	int ret;

	ret = ru_post_send(ctx, IBV_WR_RDMA_READ);
	if (ret) {
		RU_PRINT_ERRNO("Post send of read failed");
		return RU_ERR_RC;
	}

	return RU_SUCCESS_RC;
}

static int ru_wait_cq_event(struct ru_context *ctx)
{
	struct ibv_cq *ev_cq;
	void *ev_ctx;

	if (!ctx->cfg.use_event)
		return 0;

	/* wait for an event on the channel */
	if (ibv_get_cq_event(ctx->channel, &ev_cq, &ev_ctx)) {
		RU_PRINT_ERRNO("Failed to get cq_event");
		return -1;
	}

	if (ev_cq != ctx->cq) {
		RU_ERR("CQ event for unknown CQ %p", ev_cq);
		return -1;
	}

	/* ack the event */
	ibv_ack_cq_events(ev_cq, 1);

	/* re-arm the channel */
	if (ibv_req_notify_cq(ctx->cq, 0)) {
		RU_PRINT_ERRNO("Couldn't request CQ notification");
		return -1;
	}

	return 0;
}

static int ru_poll_cmpl_ex(struct ru_context *ctx, struct ibv_wc *wc,
			   __be64 *imm_data64, uint32_t *src_id)
{
	int ret = 0;
	uint64_t job_id;
	uint64_t expected_job_id = (uint64_t)ctx->cfg.job_id;
	struct ibv_poll_cq_attr attr;

	memset(&attr, 0, sizeof(attr));

	ret = ibv_start_poll(ctx->cq_ex, &attr);
	if (ret == ENOENT)
		return 0;
	if (ret) {
		RU_ERR("ibv_start_poll failed");
		return -1;
	}

	wc->status = ctx->cq_ex->status;
	wc->wr_id = ctx->cq_ex->wr_id;
	wc->opcode = ibv_wc_read_opcode(ctx->cq_ex);
	wc->vendor_err = ibv_wc_read_vendor_err(ctx->cq_ex);
	wc->byte_len = ibv_wc_read_byte_len(ctx->cq_ex);
	wc->imm_data = ibv_wc_read_imm_data(ctx->cq_ex);
	wc->qp_num = ibv_wc_read_qp_num(ctx->cq_ex);
	if (src_id)
		*src_id = ibv_wc_read_src_id(ctx->cq_ex);
	job_id = ibv_wc_read_job_id(ctx->cq_ex);

	if (imm_data64)
		*imm_data64 = ibv_wc_read_imm64_data(ctx->cq_ex);

	if (wc->status != IBV_WC_SUCCESS) {
		RU_ERR("Failed completion status %s (%d) for wr_id 0x%" PRIx64,
		       ibv_wc_status_str(wc->status), wc->status, wc->wr_id);
		ret = -1;
		goto exit;
	}

	if (job_id != expected_job_id) {
		RU_ERR("Bad completion job id 0x%" PRIx64 " (expected 0x%" PRIx64 ")",
		       job_id, expected_job_id);
		ret = -1;
		goto exit;
	}

	ret = 1;

exit:
	ibv_end_poll(ctx->cq_ex);
	return ret;

}

static int ru_poll_cmpl(struct ru_context *ctx, struct ibv_wc *wc)
{
	int ret;

	ret = ibv_poll_cq(ctx->cq, 1, wc);
	if (ret < 0) {
		RU_ERR("ibv_poll_cq failed");
		return -1;
	}
	if (ret == 0)
		return 0;

	if (wc->status != IBV_WC_SUCCESS) {
		RU_ERR("Failed completion status %s (%d) for wr_id 0x%" PRIx64,
		       ibv_wc_status_str(wc->status), wc->status, wc->wr_id);
		return -1;
	}

	return 1;
}

static int ru_wait_cmpl(struct ru_context *ctx, struct ibv_wc *wc,
			__be64 *imm_data64, uint32_t *src_id)
{
	int ret;

	if (imm_data64)
		*imm_data64 = 0;

	while (1) {
		if (ctx->cfg.do_rma_ex || ctx->cfg.do_rma_ex64)
			ret = ru_poll_cmpl_ex(ctx, wc, imm_data64, src_id);
		else
			ret = ru_poll_cmpl(ctx, wc);

		if (ret < 0)
			return -1;
		if (ret > 0)
			return 0;

		if (ctx->cfg.use_event) {
			if (ru_wait_cq_event(ctx))
				return -1;
		}
	}
}

static int ru_wait_send_cmpl(struct ru_context *ctx)
{
	struct ibv_wc wc;
	uint64_t expected_wr_id = (uint64_t)RU_SEND_WRID;

	if (ru_wait_cmpl(ctx, &wc, NULL, NULL)) {
		RU_ERR("Wait for send completion failed");
		return RU_ERR_RC;
	}

	if (wc.wr_id != expected_wr_id) {
		RU_ERR("Unexpected cmpl wr_id (got 0x%" PRIx64 ", expected 0x%" PRIx64 ")",
		       wc.wr_id, expected_wr_id);
		return -1;
	}

	return RU_SUCCESS_RC;
}

static int ru_wait_recv_imm_cmpl(struct ru_context *ctx)
{
	struct ibv_wc wc;
	__be64 imm_data64;
	uint32_t src_id = 0;

	if (ru_wait_cmpl(ctx, &wc, &imm_data64, &src_id)) {
		RU_ERR("Wait for recv immediate completion failed");
		return RU_ERR_RC;
	}

	/* The completion reports the SourceID (SES initiator) of the peer
	 * that issued the write (i.e., the last 4 bytes of its GID). SourceID
	 * is a UET-specific field, so it is only available on the cq_ex path.
	 */
	if (ctx->cfg.do_rma_ex || ctx->cfg.do_rma_ex64) {
		uint32_t expected_src_id;

		memcpy(&expected_src_id, &ctx->peer_info.gid.raw[12],
		       sizeof(expected_src_id));
		if (src_id != expected_src_id) {
			RU_ERR("Unexpected SourceID (got 0x%x, expected 0x%x)",
			       src_id, expected_src_id);
			return -1;
		}
	}

	if (ctx->cfg.do_rma_ex64) {
		uint64_t expected_imm_data64 = ctx->cfg.imm_data64;
		uint64_t recv_imm_data64;

		recv_imm_data64 = (uint64_t)be64toh(imm_data64);

		if (recv_imm_data64 != expected_imm_data64) {
			RU_ERR("Unexpected cmpl imm data64 (got 0x%" PRIx64
			       ", expected 0x%" PRIx64 ")",
			       recv_imm_data64, expected_imm_data64);
			return -1;
		}
	} else {
		uint32_t expected_imm_data = ctx->cfg.imm_data, recv_imm_data;

		recv_imm_data = ntohl(wc.imm_data);

		if (recv_imm_data != expected_imm_data) {
			RU_ERR("Unexpected cmpl imm data (got 0x%x, expected 0x%x)",
			       recv_imm_data, expected_imm_data);
			return -1;
		}
	}
	return RU_SUCCESS_RC;
}

static enum ru_rc ru_validate_buf(struct ru_context *ctx)
{
	if (!ctx->cfg.validate_buf)
		return RU_SUCCESS_RC;

	for (size_t i = 0; i < ctx->cfg.msg_size; i++) {
		if (ctx->buf[i] != RU_SERVER_BUF_DATA) {
			RU_ERR("Invalid buffer data 0x%02x", ctx->buf[i]);
			return RU_ERR_RC;
		}
	}

	return RU_SUCCESS_RC;
}

/*
 * perform client RMA data transfer exchange as follows:
 *   - read data from server RMA buffer
 *   - wait for read completion
 *   - write to server RMA buffer
 *     - include immediate data to generate completion at server
 *   - wait for write completion
 *   - wait for remote write completion to indicate data has been written
 *     back to client's RMA buffer by server
 *   - validate data is correct
 */
static int ru_rma_client(struct ru_context *ctx)
{
	enum ru_rc rc;

	rc = ru_post_read(ctx);
	if (rc != RU_SUCCESS_RC)
		goto exit;

	rc = ru_wait_send_cmpl(ctx);
	if (rc != RU_SUCCESS_RC)
		goto exit;

	/* Exercise the plain (no-immediate) RDMA write builder op (qp_ex
	 * paths only). Defaults to the 64-bit-RKey wr_rdma_write64.
	 * -w/--write32 selects the 32-bit wr_rdma_write, which truncates
	 * a 64-bit key.
	 */
	if (ctx->cfg.do_rma_ex || ctx->cfg.do_rma_ex64) {
		rc = ru_post_write(ctx);
		if (rc != RU_SUCCESS_RC)
			goto exit;

		rc = ru_wait_send_cmpl(ctx);
		if (rc != RU_SUCCESS_RC)
			goto exit;
	}

	rc = ru_post_write_imm(ctx);
	if (rc != RU_SUCCESS_RC)
		goto exit;

	rc = ru_wait_send_cmpl(ctx);
	if (rc != RU_SUCCESS_RC)
		goto exit;

	rc = ru_wait_recv_imm_cmpl(ctx);
	if (rc != RU_SUCCESS_RC)
		goto exit;

	rc = ru_validate_buf(ctx);

exit:
	return rc;
}

/*
 * perform server RMA data transfer exchange as follows:
 *   - wait for remote write completion to indicate data has been written to
 *     the server RMA buffer by the client
 *   - validate data is correct
 *   - write data back to client RMA buffer
 *     - include immediate data to generate completion at client
 *   - wait for write completion
 */
static int ru_rma_server(struct ru_context *ctx)
{
	enum ru_rc rc;

	rc = ru_wait_recv_imm_cmpl(ctx);
	if (rc != RU_SUCCESS_RC)
		goto exit;

	rc = ru_validate_buf(ctx);
	if (rc != RU_SUCCESS_RC)
		goto exit;

	rc = ru_post_write_imm(ctx);
	if (rc != RU_SUCCESS_RC)
		goto exit;

	rc = ru_wait_send_cmpl(ctx);
	if (rc != RU_SUCCESS_RC)
		goto exit;

exit:
	return rc;
}

/* do one run - cfg must already be initialized */
static int ru_run(struct ru_context *ctx)
{
	enum ru_rc rc;
	int iteration = 0;

	rc = ru_init_ctx(ctx);
	if (rc != RU_SUCCESS_RC)
		goto exit;

	if (ctx->cfg.use_event) {
		if (ibv_req_notify_cq(ctx->cq, 0)) {
			RU_PRINT_ERRNO("Couldn't request CQ notification");
			rc = RU_ERR_RC;
			goto exit;
		}
	}

	if (ctx->cfg.client)
		rc = ru_client_exchange(ctx);
	else
		rc = ru_server_exchange(ctx);

	if (rc != RU_SUCCESS_RC)
		goto exit;

	/* An absolute server writes back to a relative client, which demuxes
	 * by its own JobID. Import the client's JobID (learned during the
	 * exchange) as a job key and use it for the server's outgoing sends.
	 */
	if (ctx->cfg.absolute && !ctx->cfg.client) {
		/* The peer's JobID has to differ from ours. A JobID is the
		 * receive-side demux key and what a memory region binds to.
		 * So one JobID names one job and that is how a server keeps
		 * its clients isolated from each other.
		 */
		if (ctx->peer_info.job_id == (uint32_t)ctx->cfg.job_id) {
			RU_ERR("peer JobID 0x%x is ours; absolute mode needs one per side (-j)",
			       ctx->peer_info.job_id);
			rc = RU_ERR_RC;
			goto exit;
		}

		struct ibv_job_attr peer_job_attr = {
			.comp_mask = (IBV_JOB_ATTR_ID |
				      IBV_JOB_ATTR_PORT_NUM |
				      IBV_JOB_ATTR_SGID_INDEX),
			.id = ctx->peer_info.job_id,
			.port_num = ctx->cfg.ib_port,
			.sgid_index = ctx->cfg.gidx,
		};

		ctx->peer_job = ibv_alloc_job(ctx->context, &peer_job_attr, NULL);
		if (!ctx->peer_job) {
			RU_ERR("Couldn't allocate peer job");
			rc = RU_ERR_RC;
			goto exit;
		}

		ctx->peer_job_key = ibv_create_jkey(ctx->pd, ctx->peer_job, 0);
		if (!ctx->peer_job_key) {
			RU_ERR("Couldn't create peer job key");
			rc = RU_ERR_RC;
			goto exit;
		}

		ctx->send_job_key = ctx->peer_job_key;
	}

	for (iteration = 0; iteration < ctx->cfg.num_iterations; iteration++) {
		if (ctx->cfg.client)
			rc = ru_rma_client(ctx);
		else
			rc = ru_rma_server(ctx);
		if (rc != RU_SUCCESS_RC)
			goto exit;
	}

exit:
	printf("Completed %d iterations\n", iteration);

	ru_free_res(ctx);

	return rc;
}

int main(int argc, char *argv[])
{
	int rc;
	struct ru_context *ctx = &ru_ctx;
	const char *test_name;

	memset(ctx, 0, sizeof(struct ru_context));

	rc = ru_init_cfg(argc, argv, ctx);
	if (rc != RU_SUCCESS_RC)
		return rc;

	/* Determine test name for banner */
	if (ctx->cfg.do_rma_ex64)
		test_name = "RMA Extended Read/Write Test (64b imm)";
	else if (ctx->cfg.do_rma_ex)
		test_name = "RMA Extended Read/Write Test (32b imm)";
	else
		test_name = "RMA Read/Write Test (32b imm)";

	printf("\n%s\n", test_name);
	for (size_t i = 0; i < strlen(test_name); i++)
		printf("=");
	printf("\n");

	rc = ru_run(ctx);

	return rc;
}
