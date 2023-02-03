// SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
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
#include <time.h>
#include <inttypes.h>
#include <fcntl.h>

#include "pingpong.h"

#define EXCH_MSG "00000000:0000000000000000:0000:000000:000000:00000000000000000000000000000000"

static int page_size;
static int validate_buf;

enum {
	PINGPONG_RECV_WRID = 1,
	PINGPONG_SEND_WRID = 2,
};

struct pingpong_context {
	struct ibv_context	*context;
	struct ibv_comp_channel *channel;
	struct ibv_pd		*pd;
	struct ibv_mr		*mr;
	struct ibv_cq		*cq;
	struct ibv_qp		*qp;
	struct ibv_port_attr     portinfo;
	char			*buf;
	int			 size;
	int			 rx_depth;
	int			 conn_fd;
	int			 pending;
};

struct pingpong_dest {
	union ibv_gid		 gid;
	uintptr_t		 addr;
	uint32_t		 rkey;
	int			 lid;
	int			 qpn;
	int			 psn;
};

static void usage(const char *argv0)
{
	printf("Usage:\n");
	printf("  %s            run a basic hlib test\n", argv0);
	printf("\n");
	printf("Options:\n");
	printf("  -d, --ib-dev=<dev>        use IB device <dev> (default first device found)\n");
	printf("  -i, --ib-port=<port>      use port <port> of IB device (default 1)\n");
	printf("  -s, --size=<size>         size of message to exchange (default 4096)\n");
	printf("  -g, --gid-idx=<gid index> local port gid index\n");
	printf("  -c, --chk                 validate received buffer\n");
	printf("  -n, --iters=<iters>       number of exchanges (default 1000)\n");
	printf("  -h, --help                display options\n");
}

static struct pingpong_context *pp_init_ctx(struct ibv_device *ib_dev, int size,
					    int rx_depth, int port)
{
	struct pingpong_context *ctx;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->size       = size;
	ctx->rx_depth   = rx_depth;

	ctx->buf = memalign(page_size, size);
	if (!ctx->buf) {
		fprintf(stderr, "Couldn't allocate work buf.\n");
		goto clean_ctx;
	}

	/* FIXME memset(ctx->buf, 0, size); */
	memset(ctx->buf, 0x7b, size);

	ctx->context = ibv_open_device(ib_dev);
	if (!ctx->context) {
		fprintf(stderr, "Couldn't get context for %s\n",
			ibv_get_device_name(ib_dev));
		goto clean_buffer;
	}

	ctx->pd = ibv_alloc_pd(ctx->context);
	if (!ctx->pd) {
		fprintf(stderr, "Couldn't allocate PD\n");
		goto clean_device;
	}

	ctx->mr = ibv_reg_mr(ctx->pd, ctx->buf, size,
				IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);
	if (!ctx->mr) {
		fprintf(stderr, "Couldn't register MR\n");
		goto clean_pd;
	}

	ctx->cq = ibv_create_cq(ctx->context, rx_depth + 1, NULL, NULL, 0);
	if (!ctx->cq) {
		fprintf(stderr, "Couldn't create CQ\n");
		goto clean_mr;
	}

	{
		struct ibv_qp_init_attr init_attr = {
			.send_cq = ctx->cq,
			.recv_cq = ctx->cq,
			.cap     = {
				.max_send_wr  = 1,
				.max_send_sge = 1,
				.max_recv_wr = 0,
				.max_recv_sge = 1
			},
			.qp_type = IBV_QPT_RC
		};

		ctx->qp = ibv_create_qp(ctx->pd, &init_attr);
		if (!ctx->qp)  {
			fprintf(stderr, "Couldn't create QP\n");
			goto clean_cq;
		}
	}

	{
		struct ibv_qp_attr attr = {
			.qp_state        = IBV_QPS_INIT,
			.pkey_index      = 0,
			.port_num        = port,
			.qp_access_flags = IBV_ACCESS_REMOTE_WRITE,
		};

		if (ibv_modify_qp(ctx->qp, &attr,
				  IBV_QP_STATE              |
				  IBV_QP_PKEY_INDEX         |
				  IBV_QP_PORT               |
				  IBV_QP_ACCESS_FLAGS)) {
			fprintf(stderr, "Failed to modify QP to INIT\n");
			goto clean_qp;
		}
	}

	return ctx;

clean_qp:
	ibv_destroy_qp(ctx->qp);

clean_cq:
	ibv_destroy_cq(ctx->cq);

clean_mr:
	ibv_dereg_mr(ctx->mr);

clean_pd:
	ibv_dealloc_pd(ctx->pd);

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
	if (ctx->qp && ibv_destroy_qp(ctx->qp)) {
		fprintf(stderr, "Couldn't destroy QP\n");
		return 1;
	}

	if (ctx->cq && ibv_destroy_cq(ctx->cq)) {
		fprintf(stderr, "Couldn't destroy CQ\n");
		return 1;
	}

	if (ctx->mr && ibv_dereg_mr(ctx->mr)) {
		fprintf(stderr, "Couldn't deregister MR\n");
		return 1;
	}

	if (ctx->pd && ibv_dealloc_pd(ctx->pd)) {
		fprintf(stderr, "Couldn't deallocate PD\n");
		return 1;
	}

	if (ctx->context && ibv_close_device(ctx->context)) {
		fprintf(stderr, "Couldn't release context\n");
		return 1;
	}

	free(ctx->buf);
	free(ctx);

	return 0;
}

static int pp_connect_ctx(struct pingpong_context *ctx, int port, int my_psn,
			  struct pingpong_dest *dest, int sgid_idx)
{
	struct ibv_qp_attr attr = {
		.qp_state		= IBV_QPS_RTR,
		.path_mtu		= IBV_MTU_1024,
		.dest_qp_num		= dest->qpn,
		.rq_psn			= dest->psn,
		.max_dest_rd_atomic	= 1,
		.min_rnr_timer		= 12,
		.ah_attr		= {
			.is_global	= 0,
			.dlid		= dest->lid,
			.sl		= 0,
			.src_path_bits	= 0,
			.port_num	= port
		}
	};

	if (dest->gid.global.interface_id) {
		attr.ah_attr.is_global = 1;
		attr.ah_attr.grh.hop_limit = 1;
		attr.ah_attr.grh.dgid = dest->gid;
		attr.ah_attr.grh.sgid_index = sgid_idx;
	}

	if (ibv_modify_qp(ctx->qp, &attr,
			  IBV_QP_STATE              |
			  IBV_QP_AV                 |
			  IBV_QP_PATH_MTU           |
			  IBV_QP_DEST_QPN           |
			  IBV_QP_RQ_PSN             |
			  IBV_QP_MAX_DEST_RD_ATOMIC |
			  IBV_QP_MIN_RNR_TIMER)) {
		fprintf(stderr, "Failed to modify QP to RTR\n");
		return 1;
	}

	attr.qp_state	    = IBV_QPS_RTS;
	attr.timeout	    = 14;
	attr.retry_cnt	    = 7;
	attr.rnr_retry	    = 7;
	attr.sq_psn	    = my_psn;
	attr.max_rd_atomic  = 1;
	if (ibv_modify_qp(ctx->qp, &attr,
			  IBV_QP_STATE              |
			  IBV_QP_TIMEOUT            |
			  IBV_QP_RETRY_CNT          |
			  IBV_QP_RNR_RETRY          |
			  IBV_QP_SQ_PSN             |
			  IBV_QP_MAX_QP_RD_ATOMIC)) {
		fprintf(stderr, "Failed to modify QP to RTS\n");
		return 1;
	}

	return 0;
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
	struct pingpong_dest *rem_dest = NULL;
	char *service;
	int n;
	int sockfd = -1;
	char gid[33];
	char msg[sizeof(EXCH_MSG)];

	if (asprintf(&service, "%d", port) < 0)
		return NULL;

	n = getaddrinfo(servername, service, &hints, &res);
	if (n < 0) {
		fprintf(stderr, "%s for %s:%d\n", gai_strerror(n), servername, port);
		free(service);
		return NULL;
	}

	for (t = res; t; t = t->ai_next) {
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
	sprintf(msg, "%08x:%016" PRIxPTR ":%04x:%06x:%06x:%s", my_dest->rkey, my_dest->addr,
							       my_dest->lid, my_dest->qpn,
							       my_dest->psn, gid);
	if (write(sockfd, msg, sizeof(msg)) != sizeof(msg)) {
		fprintf(stderr, "Couldn't send local address\n");
		goto out;
	}

	if (read(sockfd, msg, sizeof(msg)) != sizeof(msg) ||
	    write(sockfd, "done", sizeof "done") != sizeof "done") {
		perror("client read/write");
		fprintf(stderr, "Couldn't read/write remote address\n");
		goto out;
	}

	rem_dest = malloc(sizeof(*rem_dest));
	if (!rem_dest)
		goto out;

	n = sscanf(msg, "%x:%" SCNxPTR ":%x:%x:%x:%s", &rem_dest->rkey, &rem_dest->addr,
						       &rem_dest->lid, &rem_dest->qpn,
						       &rem_dest->psn, gid);
	if (n != 6) {
		fprintf(stderr, "Couldn't parse server data\n");
		free(rem_dest);
		rem_dest = NULL;
		goto out;
	}
	wire_gid_to_gid(gid, &rem_dest->gid);

	ctx->conn_fd = sockfd;
out:
	return rem_dest;
}

static struct pingpong_dest *pp_server_exch_dest(struct pingpong_context *ctx,
						 int ib_port, int port,
						 const struct pingpong_dest *my_dest,
						 int sgid_idx)
{
	struct addrinfo *res, *t;
	struct addrinfo hints = {
		.ai_flags    = AI_PASSIVE,
		.ai_family   = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM
	};
	struct pingpong_dest *rem_dest = NULL;
	int n;
	int sockfd = -1, connfd;
	char *service;
	char gid[33];
	char msg[sizeof(EXCH_MSG)];

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

			setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &n, sizeof(n));

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
		fprintf(stderr, "%d/%d: Couldn't read remote address\n", n, (int) sizeof(msg));
		goto out;
	}

	rem_dest = malloc(sizeof(*rem_dest));
	if (!rem_dest)
		goto out;

	n = sscanf(msg, "%x:%" SCNxPTR ":%x:%x:%x:%s", &rem_dest->rkey, &rem_dest->addr,
						       &rem_dest->lid, &rem_dest->qpn,
						       &rem_dest->psn, gid);
	if (n != 6) {
		fprintf(stderr, "Couldn't parse client data\n");
		free(rem_dest);
		rem_dest = NULL;
		goto out;
	}

	wire_gid_to_gid(gid, &rem_dest->gid);

	if (pp_connect_ctx(ctx, ib_port, my_dest->psn, rem_dest, sgid_idx)) {
		fprintf(stderr, "Couldn't connect to remote QP\n");
		free(rem_dest);
		rem_dest = NULL;
		goto out;
	}

	gid_to_wire_gid(&my_dest->gid, gid);
	sprintf(msg, "%08x:%016" PRIxPTR ":%04x:%06x:%06x:%s", my_dest->rkey, my_dest->addr,
							       my_dest->lid, my_dest->qpn,
							       my_dest->psn, gid);
	if (write(connfd, msg, sizeof(msg)) != sizeof(msg) ||
	    read(connfd, msg, sizeof(msg)) != sizeof "done") {
		fprintf(stderr, "Couldn't send/recv local address\n");
		free(rem_dest);
		rem_dest = NULL;
		goto out;
	}

	ctx->conn_fd = connfd;
out:
	return rem_dest;
}

static int pp_post_send(struct pingpong_context *ctx, struct pingpong_dest *rem_dest)
{
	struct ibv_sge list = {
		.addr	= (uintptr_t) ctx->buf,
		.length = ctx->size,
		.lkey	= ctx->mr->lkey
	};
	struct ibv_send_wr wr = {
		.wr_id			= PINGPONG_SEND_WRID,
		.sg_list		= &list,
		.num_sge		= 1,
		.opcode			= IBV_WR_RDMA_WRITE,
		.send_flags		= IBV_SEND_SIGNALED,
		.wr.rdma		= {
			.remote_addr    = (uint64_t) rem_dest->addr,
			.rkey		= rem_dest->rkey,
		}
	};
	struct ibv_send_wr *bad_wr;

	return ibv_post_send(ctx->qp, &wr, &bad_wr);
}

static inline int parse_single_wc(struct pingpong_context *ctx, int *scnt, int *rcnt,
				  int iters, struct pingpong_dest *rem_dest,
				  uint64_t wr_id, enum ibv_wc_status status)
{
	char msg[sizeof "recv_ack"];

	if (status != IBV_WC_SUCCESS) {
		fprintf(stderr, "Failed status %s (%d) for wr_id %d\n",
			ibv_wc_status_str(status),
			status, (int)wr_id);
		return 1;
	}

	switch ((int)wr_id) {
	case PINGPONG_SEND_WRID:
		++(*scnt);

		strcpy(msg, "recv_ack");
		if (write(ctx->conn_fd, msg, sizeof(msg)) != sizeof(msg)) {
			fprintf(stderr, "Couldn't send recv ack\n");
			return 1;
		}

		break;

	case PINGPONG_RECV_WRID:
		++(*rcnt);
		break;

	default:
		fprintf(stderr, "Completion for unknown wr_id %d\n", (int)wr_id);
		return 1;
	}

	ctx->pending &= ~(int)wr_id;
	if (*scnt < iters && !ctx->pending) {
		if (pp_post_send(ctx, rem_dest)) {
			fprintf(stderr, "Couldn't post send\n");
			return 1;
		}
		ctx->pending = PINGPONG_RECV_WRID | PINGPONG_SEND_WRID;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct ibv_device	**dev_list;
	struct ibv_device	 *ib_dev;
	struct pingpong_context	 *ctx;
	struct pingpong_dest	  my_dest;
	struct pingpong_dest	 *rem_dest;
	struct timeval		  start, end;
	char			 *ib_devname = NULL;
	char			 *servername = NULL;
	unsigned int		  size = 4096;
	unsigned int		  rx_depth = 500;
	unsigned int		  port = 18515;
	unsigned int		  iters = 1000;
	int			  ib_port = 1;
	int			  gidx = -1;
	int			  scnt, rcnt;
	char			  gid[33];

	srand48(getpid() * time(NULL));

	while (1) {
		int c;

		static struct option long_options[] = {
			{ .name = "ib-dev",    .has_arg = 1, .val = 'd' },
			{ .name = "ib-port",   .has_arg = 1, .val = 'i' },
			{ .name = "size",      .has_arg = 1, .val = 's' },
			{ .name = "gid-idx",   .has_arg = 1, .val = 'g' },
			{ .name = "iters",     .has_arg = 1, .val = 'n' },
			{ .name = "chk",       .has_arg = 0, .val = 'c' },
			{ .name = "help",      .has_arg = 0, .val = 'h' },
			{}
		};

		c = getopt_long(argc, argv, "d:i:s:g:n:ch", long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
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

		case 'g':
			gidx = strtol(optarg, NULL, 0);
			break;

		case 'n':
			iters = strtoul(optarg, NULL, 0);
			break;

		case 'c':
			validate_buf = 1;
			break;

		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (optind == argc - 1)
		servername = strdupa(argv[optind]);
	else if (optind < argc) {
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

		for (i = 0; dev_list[i]; ++i)
			if (!strcmp(ibv_get_device_name(dev_list[i]), ib_devname))
				break;
		ib_dev = dev_list[i];
		if (!ib_dev) {
			fprintf(stderr, "IB device %s not found\n", ib_devname);
			return 1;
		}
	}

	printf("Running on IB device %s\n", ibv_get_device_name(ib_dev));

	ctx = pp_init_ctx(ib_dev, size, rx_depth, ib_port);
	if (!ctx)
		return 1;

	if (pp_get_port_info(ctx->context, ib_port, &ctx->portinfo)) {
		fprintf(stderr, "Couldn't get port info\n");
		return 1;
	}

	my_dest.lid = ctx->portinfo.lid;
	if (ctx->portinfo.link_layer != IBV_LINK_LAYER_ETHERNET &&
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
	my_dest.rkey = ctx->mr->rkey;
	my_dest.addr = (uintptr_t) ctx->buf;
	inet_ntop(AF_INET6, &my_dest.gid, gid, sizeof(gid));
	printf("  local: RKEY 0x%08x, ADDR 0x%016" PRIxPTR ", LID 0x%04x, QPN 0x%06x, PSN 0x%06x, GID %s\n",
	       my_dest.rkey, my_dest.addr, my_dest.lid, my_dest.qpn, my_dest.psn, gid);

	if (servername)
		rem_dest = pp_client_exch_dest(ctx, servername, port, &my_dest);
	else
		rem_dest = pp_server_exch_dest(ctx, ib_port, port, &my_dest, gidx);

	if (!rem_dest)
		return 1;

	inet_ntop(AF_INET6, &rem_dest->gid, gid, sizeof(gid));
	printf("  remote: RKEY 0x%08x, ADDR 0x%016" PRIxPTR ", LID 0x%04x, QPN 0x%06x, PSN 0x%06x, GID %s\n",
	       rem_dest->rkey, rem_dest->addr, rem_dest->lid, rem_dest->qpn, rem_dest->psn, gid);

	if (servername)
		if (pp_connect_ctx(ctx, ib_port, my_dest.psn, rem_dest, gidx))
			return 1;

	ctx->pending = PINGPONG_RECV_WRID;

	if (servername) {
		if (validate_buf)
			for (int i = 0; i < size; i += page_size)
				ctx->buf[i] = i / page_size % sizeof(char);

		if (pp_post_send(ctx, rem_dest)) {
			fprintf(stderr, "Couldn't post send\n");
			return 1;
		}
		ctx->pending |= PINGPONG_SEND_WRID;
	}

	if (gettimeofday(&start, NULL)) {
		perror("gettimeofday");
		return 1;
	}

	scnt = rcnt = 0;
	while (rcnt < iters || scnt < iters) {
		int ne, i, ret;
		struct ibv_wc wc[2];

		do {
			char msg[sizeof "recv_ack"];
			int flags;

			ne = ibv_poll_cq(ctx->cq, 2, wc);
			if (ne < 0) {
				fprintf(stderr, "poll CQ failed %d\n", ne);
				return 1;
			}

			flags = fcntl(ctx->conn_fd, F_GETFL, 0);
			fcntl(ctx->conn_fd, F_SETFL, flags | O_NONBLOCK);
			if (read(ctx->conn_fd, msg, sizeof(msg)) > 0) {
				if (!strcmp("recv_ack", msg)) {
					wc[ne].status = IBV_WC_SUCCESS;
					wc[ne].wr_id = PINGPONG_RECV_WRID;
					ne++;
				} else
					fprintf(stderr, "Invalid msg %s\n", msg);
			}
		} while (ne < 1);

		for (i = 0; i < ne; ++i) {
			ret = parse_single_wc(ctx, &scnt, &rcnt, iters, rem_dest,
					      wc[i].wr_id, wc[i].status);
			if (ret) {
				fprintf(stderr, "parse WC failed %d\n", ne);
				return 1;
			}
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
	}

	if ((!servername) && (validate_buf)) {
		for (int i = 0; i < size; i += page_size)
			if (ctx->buf[i] != i / page_size % sizeof(char)) {
				fprintf(stderr, "invalid data in page %d\n",
					i / page_size);
				return 1;
			}
	}

	free(rem_dest);
	close(ctx->conn_fd);

	if (pp_close_ctx(ctx))
		return 1;

	ibv_free_device_list(dev_list);

	return 0;
}
