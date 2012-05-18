/*
 * Copyright (c) 2008-2012 Intel Corporation.  All rights reserved.
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

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>
#include <rdma/rsocket.h>
#include "cma.h"
#include "indexer.h"

#define RS_INLINE 64
#define RS_OLAP_START_SIZE 2048
#define RS_MAX_TRANSFER 65536
#define RS_QP_SIZE 512
#define RS_QP_MAX_SIZE 0xFFFE
#define RS_QP_MIN_SIZE 8
#define RS_QP_CTRL_SIZE 4
#define RS_CONN_RETRIES 6
#define RS_SGL_SIZE 2
#define RS_BUF_SIZE (1 << 17)
static struct index_map idm;
static pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;

/*
 * Immediate data format is determined by the upper bits
 * bit 31: message type, 0 - data, 1 - control
 * bit 30: buffers updated, 0 - target, 1 - direct-receive
 * bit 29: more data, 0 - end of transfer, 1 - more data available
 *
 * for data transfers:
 * bits [28:0]: bytes transfered, 0 = 1 GB
 * for control messages:
 * bits [28-0]: receive credits granted
 */

enum {
	RS_OP_DATA,
	RS_OP_DATA_MORE,
	RS_OP_DRA,
	RS_OP_DRA_MORE,
	RS_OP_SGL,
	RS_OP_RSVD1,
	RS_OP_DRA_SGL,
	RS_OP_CTRL
};
#define rs_msg_set(op, data)  ((op << 29) | (uint32_t) (data))
#define rs_msg_op(imm_data)   (imm_data >> 29)
#define rs_msg_data(imm_data) (imm_data & 0x1FFFFFFF)

enum {
	RS_CTRL_DISCONNECT
};

struct rs_msg {
	uint32_t op;
	uint32_t data;
};

struct rs_sge {
	uint64_t addr;
	uint32_t key;
	uint32_t length;
};

#define rs_host_is_net() (1 == htonl(1))
#define RS_CONN_FLAG_NET 1

struct rs_conn_data {
	uint8_t		  version;
	uint8_t		  flags;
	uint16_t	  credits;
	uint32_t	  reserved2;
	struct rs_sge	  target_sgl;
	struct rs_sge	  data_buf;
};

union rs_wr_id {
	uint64_t	  wr_id;
	struct {
		uint32_t  reserved; /* sqe_count; */
		uint32_t  length;
	};
};

enum rs_state {
	rs_init,
	rs_bound,
	rs_listening,
	rs_resolving_addr,
	rs_resolving_route,
	rs_connecting,
	rs_accepting,
	rs_connected,
	rs_disconnected,
	rs_connect_error,
	rs_error
};

#define RS_OPT_SWAP_SGL 1

struct rsocket {
	struct rdma_cm_id *cm_id;
	fastlock_t	  slock;
	fastlock_t	  rlock;
	fastlock_t	  cq_lock;
	fastlock_t	  cq_wait_lock;

	int		  opts;
	long		  fd_flags;
	uint64_t	  so_opts;
	uint64_t	  tcp_opts;
	enum rs_state	  state;
	int		  cq_armed;
	int		  retries;
	int		  err;
	int		  index;
	int		  ctrl_avail;
	int		  sqe_avail;
	int		  sbuf_bytes_avail;
	uint16_t	  sseq_no;
	uint16_t	  sseq_comp;
	uint16_t	  sq_size;

	uint16_t	  rq_size;
	uint16_t	  rseq_no;
	uint16_t	  rseq_comp;
	int		  rbuf_bytes_avail;
	int		  rbuf_free_offset;
	int		  rbuf_offset;
	int		  rmsg_head;
	int		  rmsg_tail;
	struct rs_msg	  *rmsg;

	int		  remote_sge;
	struct rs_sge	  remote_sgl;

	struct ibv_mr	 *target_mr;
	int		  target_sge;
	volatile struct rs_sge	  target_sgl[RS_SGL_SIZE];

	uint32_t	  rbuf_size;
	struct ibv_mr	 *rmr;
	uint8_t		  *rbuf;

	uint32_t	  sbuf_size;
	struct ibv_mr	 *smr;
	struct ibv_sge	  ssgl[2];
	uint8_t		  *sbuf;
};

/*
 * We currently generate a completion per send.  sqe_count = 1
 */
static union rs_wr_id rs_wrid(uint32_t sqe_count, uint32_t length)
{
	union rs_wr_id wrid;
	/* wrid.reserved = sqe_count; */
	wrid.length = length;
	return wrid;
}

static int rs_insert(struct rsocket *rs)
{
	pthread_mutex_lock(&mut);
	rs->index = idm_set(&idm, rs->cm_id->channel->fd, rs);
	pthread_mutex_unlock(&mut);
	return rs->index;
}

static void rs_remove(struct rsocket *rs)
{
	pthread_mutex_lock(&mut);
	idm_clear(&idm, rs->index);
	pthread_mutex_unlock(&mut);
}

static struct rsocket *rs_alloc(struct rsocket *inherited_rs)
{
	struct rsocket *rs;

	rs = calloc(1, sizeof *rs);
	if (!rs)
		return NULL;

	rs->index = -1;
	if (inherited_rs) {
		rs->sbuf_size = inherited_rs->sbuf_size;
		rs->rbuf_size = inherited_rs->rbuf_size;
		rs->sq_size = inherited_rs->sq_size;
		rs->rq_size = inherited_rs->rq_size;
		rs->ctrl_avail = inherited_rs->ctrl_avail;
	} else {
		rs->sbuf_size = rs->rbuf_size = RS_BUF_SIZE;
		rs->sq_size = rs->rq_size = RS_QP_SIZE;
		rs->ctrl_avail = RS_QP_CTRL_SIZE;
	}
	fastlock_init(&rs->slock);
	fastlock_init(&rs->rlock);
	fastlock_init(&rs->cq_lock);
	fastlock_init(&rs->cq_wait_lock);
	return rs;
}

static int rs_set_nonblocking(struct rsocket *rs, long arg)
{
	int ret = 0;

	if (rs->cm_id->recv_cq_channel)
		ret = fcntl(rs->cm_id->recv_cq_channel->fd, F_SETFL, arg);

	if (!ret && rs->state != rs_connected)
		ret = fcntl(rs->cm_id->channel->fd, F_SETFL, arg);

	return ret;
}

static void rs_set_qp_size(struct rsocket *rs)
{
	uint16_t max_size;

	max_size = min(ucma_max_qpsize(rs->cm_id), RS_QP_MAX_SIZE);

	if (rs->sq_size > max_size)
		rs->sq_size = max_size;
	if (rs->rq_size > max_size)
		rs->rq_size = max_size;
}

static int rs_init_bufs(struct rsocket *rs)
{
	rs->rmsg = calloc(rs->rq_size + 1, sizeof(*rs->rmsg));
	if (!rs->rmsg)
		return -1;

	rs->sbuf = calloc(rs->sbuf_size, sizeof(*rs->sbuf));
	if (!rs->sbuf)
		return -1;

	rs->smr = rdma_reg_msgs(rs->cm_id, rs->sbuf, rs->sbuf_size);
	if (!rs->smr)
		return -1;

	rs->target_mr = rdma_reg_write(rs->cm_id, (void *) rs->target_sgl,
				       sizeof(rs->target_sgl));
	if (!rs->target_mr)
		return -1;

	rs->rbuf = calloc(rs->rbuf_size, sizeof(*rs->rbuf));
	if (!rs->rbuf)
		return -1;

	rs->rmr = rdma_reg_write(rs->cm_id, rs->rbuf, rs->rbuf_size);
	if (!rs->rmr)
		return -1;

	rs->ssgl[0].addr = rs->ssgl[1].addr = (uintptr_t) rs->sbuf;
	rs->sbuf_bytes_avail = rs->sbuf_size;
	rs->ssgl[0].lkey = rs->ssgl[1].lkey = rs->smr->lkey;

	rs->rbuf_free_offset = rs->rbuf_size >> 1;
	rs->rbuf_bytes_avail = rs->rbuf_size >> 1;
	rs->sqe_avail = rs->sq_size - rs->ctrl_avail;
	rs->rseq_comp = rs->rq_size >> 1;
	return 0;
}

static int rs_create_cq(struct rsocket *rs)
{
	rs->cm_id->recv_cq_channel = ibv_create_comp_channel(rs->cm_id->verbs);
	if (!rs->cm_id->recv_cq_channel)
		return -1;

	rs->cm_id->recv_cq = ibv_create_cq(rs->cm_id->verbs, rs->sq_size + rs->rq_size,
					   rs->cm_id, rs->cm_id->recv_cq_channel, 0);
	if (!rs->cm_id->recv_cq)
		goto err1;

	if (rs->fd_flags & O_NONBLOCK) {
		if (rs_set_nonblocking(rs, O_NONBLOCK))
			goto err2;
	}

	rs->cm_id->send_cq_channel = rs->cm_id->recv_cq_channel;
	rs->cm_id->send_cq = rs->cm_id->recv_cq;
	return 0;

err2:
	ibv_destroy_cq(rs->cm_id->recv_cq);
	rs->cm_id->recv_cq = NULL;
err1:
	ibv_destroy_comp_channel(rs->cm_id->recv_cq_channel);
	rs->cm_id->recv_cq_channel = NULL;
	return -1;
}

static int rs_create_ep(struct rsocket *rs)
{
	struct ibv_qp_init_attr qp_attr;
	int i, ret;

	rs_set_qp_size(rs);
	ret = rs_init_bufs(rs);
	if (ret)
		return ret;

	ret = rs_create_cq(rs);
	if (ret)
		return ret;

	memset(&qp_attr, 0, sizeof qp_attr);
	qp_attr.qp_context = rs;
	qp_attr.send_cq = rs->cm_id->send_cq;
	qp_attr.recv_cq = rs->cm_id->recv_cq;
	qp_attr.qp_type = IBV_QPT_RC;
	qp_attr.sq_sig_all = 1;
	qp_attr.cap.max_send_wr = rs->sq_size;
	qp_attr.cap.max_recv_wr = rs->rq_size;
	qp_attr.cap.max_send_sge = 2;
	qp_attr.cap.max_recv_sge = 1;
	qp_attr.cap.max_inline_data = RS_INLINE;

	ret = rdma_create_qp(rs->cm_id, NULL, &qp_attr);
	if (ret)
		return ret;

	for (i = 0; i < rs->rq_size; i++) {
		ret = rdma_post_recvv(rs->cm_id, NULL, NULL, 0);
		if (ret)
			return ret;
	}
	return 0;
}

static void rs_free(struct rsocket *rs)
{
	if (rs->index >= 0)
		rs_remove(rs);

	if (rs->rmsg)
		free(rs->rmsg);

	if (rs->sbuf) {
		if (rs->smr)
			rdma_dereg_mr(rs->smr);
		free(rs->sbuf);
	}

	if (rs->rbuf) {
		if (rs->rmr)
			rdma_dereg_mr(rs->rmr);
		free(rs->rbuf);
	}

	if (rs->target_mr)
		rdma_dereg_mr(rs->target_mr);

	if (rs->cm_id) {
		if (rs->cm_id->qp)
			rdma_destroy_qp(rs->cm_id);
		rdma_destroy_id(rs->cm_id);
	}

	fastlock_destroy(&rs->cq_wait_lock);
	fastlock_destroy(&rs->cq_lock);
	fastlock_destroy(&rs->rlock);
	fastlock_destroy(&rs->slock);
	free(rs);
}

static void rs_set_conn_data(struct rsocket *rs, struct rdma_conn_param *param,
			     struct rs_conn_data *conn)
{
	conn->version = 1;
	conn->flags = rs_host_is_net() ? RS_CONN_FLAG_NET : 0;
	conn->credits = htons(rs->rq_size);
	conn->reserved2 = 0;

	conn->target_sgl.addr = htonll((uintptr_t) rs->target_sgl);
	conn->target_sgl.length = htonl(RS_SGL_SIZE);
	conn->target_sgl.key = htonl(rs->target_mr->rkey);

	conn->data_buf.addr = htonll((uintptr_t) rs->rbuf);
	conn->data_buf.length = htonl(rs->rbuf_size >> 1);
	conn->data_buf.key = htonl(rs->rmr->rkey);

	param->private_data = conn;
	param->private_data_len = sizeof *conn;
}

static void rs_save_conn_data(struct rsocket *rs, struct rs_conn_data *conn)
{
	rs->remote_sgl.addr = ntohll(conn->target_sgl.addr);
	rs->remote_sgl.length = ntohl(conn->target_sgl.length);
	rs->remote_sgl.key = ntohl(conn->target_sgl.key);
	rs->remote_sge = 1;
	if ((rs_host_is_net() && !(conn->flags & RS_CONN_FLAG_NET)) ||
	    (!rs_host_is_net() && (conn->flags & RS_CONN_FLAG_NET)))
		rs->opts = RS_OPT_SWAP_SGL;

	rs->target_sgl[0].addr = ntohll(conn->data_buf.addr);
	rs->target_sgl[0].length = ntohl(conn->data_buf.length);
	rs->target_sgl[0].key = ntohl(conn->data_buf.key);

	rs->sseq_comp = ntohs(conn->credits);
}

int rsocket(int domain, int type, int protocol)
{
	struct rsocket *rs;
	int ret;

	if ((domain != PF_INET && domain != PF_INET6) ||
	    (type != SOCK_STREAM) || (protocol && protocol != IPPROTO_TCP))
		return ERR(ENOTSUP);

	rs = rs_alloc(NULL);
	if (!rs)
		return ERR(ENOMEM);

	ret = rdma_create_id(NULL, &rs->cm_id, rs, RDMA_PS_TCP);
	if (ret)
		goto err;

	ret = rs_insert(rs);
	if (ret < 0)
		goto err;

	rs->cm_id->route.addr.src_addr.sa_family = domain;
	return rs->index;

err:
	rs_free(rs);
	return ret;
}

int rbind(int socket, const struct sockaddr *addr, socklen_t addrlen)
{
	struct rsocket *rs;
	int ret;

	rs = idm_at(&idm, socket);
	ret = rdma_bind_addr(rs->cm_id, (struct sockaddr *) addr);
	if (!ret)
		rs->state = rs_bound;
	return ret;
}

int rlisten(int socket, int backlog)
{
	struct rsocket *rs;
	int ret;

	rs = idm_at(&idm, socket);
	ret = rdma_listen(rs->cm_id, backlog);
	if (!ret)
		rs->state = rs_listening;
	return ret;
}

/*
 * Nonblocking is usually not inherited between sockets, but we need to
 * inherit it here to establish the connection only.  This is needed to
 * prevent rdma_accept from blocking until the remote side finishes
 * establishing the connection.  If we were to allow rdma_accept to block,
 * then a single thread cannot establish a connection with itself, or
 * two threads which try to connect to each other can deadlock trying to
 * form a connection.
 *
 * Data transfers on the new socket remain blocking unless the user
 * specifies otherwise through rfcntl.
 */
int raccept(int socket, struct sockaddr *addr, socklen_t *addrlen)
{
	struct rsocket *rs, *new_rs;
	struct rdma_conn_param param;
	struct rs_conn_data *creq, cresp;
	int ret;

	rs = idm_at(&idm, socket);
	new_rs = rs_alloc(rs);
	if (!new_rs)
		return ERR(ENOMEM);

	ret = rdma_get_request(rs->cm_id, &new_rs->cm_id);
	if (ret)
		goto err;

	ret = rs_insert(new_rs);
	if (ret < 0)
		goto err;

	creq = (struct rs_conn_data *) new_rs->cm_id->event->param.conn.private_data;
	if (creq->version != 1) {
		ret = ERR(ENOTSUP);
		goto err;
	}

	if (rs->fd_flags & O_NONBLOCK)
		rs_set_nonblocking(new_rs, O_NONBLOCK);

	ret = rs_create_ep(new_rs);
	if (ret)
		goto err;

	rs_save_conn_data(new_rs, creq);
	param = new_rs->cm_id->event->param.conn;
	rs_set_conn_data(new_rs, &param, &cresp);
	ret = rdma_accept(new_rs->cm_id, &param);
	if (!ret)
		new_rs->state = rs_connected;
	else if (errno == EAGAIN || errno == EWOULDBLOCK)
		new_rs->state = rs_accepting;
	else
		goto err;

	if (addr && addrlen)
		rgetpeername(new_rs->index, addr, addrlen);
	return new_rs->index;

err:
	rs_free(new_rs);
	return ret;
}

static int rs_do_connect(struct rsocket *rs)
{
	struct rdma_conn_param param;
	struct rs_conn_data creq, *cresp;
	int to, ret;

	switch (rs->state) {
	case rs_init:
	case rs_bound:
resolve_addr:
		to = 1000 << rs->retries++;
		ret = rdma_resolve_addr(rs->cm_id, NULL,
					&rs->cm_id->route.addr.dst_addr, to);
		if (!ret)
			goto resolve_route;
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			rs->state = rs_resolving_addr;
		break;
	case rs_resolving_addr:
		ret = ucma_complete(rs->cm_id);
		if (ret) {
			if (errno == ETIMEDOUT && rs->retries <= RS_CONN_RETRIES)
				goto resolve_addr;
			break;
		}

		rs->retries = 0;
resolve_route:
		to = 1000 << rs->retries++;
		ret = rdma_resolve_route(rs->cm_id, to);
		if (!ret)
			goto do_connect;
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			rs->state = rs_resolving_route;
		break;
	case rs_resolving_route:
		ret = ucma_complete(rs->cm_id);
		if (ret) {
			if (errno == ETIMEDOUT && rs->retries <= RS_CONN_RETRIES)
				goto resolve_route;
			break;
		}
do_connect:
		ret = rs_create_ep(rs);
		if (ret)
			break;

		memset(&param, 0, sizeof param);
		rs_set_conn_data(rs, &param, &creq);
		param.flow_control = 1;
		param.retry_count = 7;
		param.rnr_retry_count = 7;
		rs->retries = 0;

		ret = rdma_connect(rs->cm_id, &param);
		if (!ret)
			goto connected;
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			rs->state = rs_connecting;
		break;
	case rs_connecting:
		ret = ucma_complete(rs->cm_id);
		if (ret)
			break;
connected:
		cresp = (struct rs_conn_data *) rs->cm_id->event->param.conn.private_data;
		if (cresp->version != 1) {
			ret = ERR(ENOTSUP);
			break;
		}

		rs_save_conn_data(rs, cresp);
		rs->state = rs_connected;
		break;
	case rs_accepting:
		if (!(rs->fd_flags & O_NONBLOCK))
			rs_set_nonblocking(rs, 0);

		ret = ucma_complete(rs->cm_id);
		if (ret)
			break;

		rs->state = rs_connected;
		break;
	default:
		ret = ERR(EINVAL);
		break;
	}

	if (ret) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			errno = EINPROGRESS;
		} else {
			rs->state = rs_connect_error;
			rs->err = errno;
		}
	}
	return ret;
}

int rconnect(int socket, const struct sockaddr *addr, socklen_t addrlen)
{
	struct rsocket *rs;

	rs = idm_at(&idm, socket);
	memcpy(&rs->cm_id->route.addr.dst_addr, addr, addrlen);
	return rs_do_connect(rs);
}

static int rs_post_write(struct rsocket *rs, uint64_t wr_id,
			 struct ibv_sge *sgl, int nsge,
			 uint32_t imm_data, int flags,
			 uint64_t addr, uint32_t rkey)
{
	struct ibv_send_wr wr, *bad;

	wr.wr_id = wr_id;
	wr.next = NULL;
	wr.sg_list = sgl;
	wr.num_sge = nsge;
	wr.opcode = IBV_WR_RDMA_WRITE_WITH_IMM;
	wr.send_flags = flags;
	wr.imm_data = htonl(imm_data);
	wr.wr.rdma.remote_addr = addr;
	wr.wr.rdma.rkey = rkey;

	return rdma_seterrno(ibv_post_send(rs->cm_id->qp, &wr, &bad));
}

/*
 * Update target SGE before sending data.  Otherwise the remote side may
 * update the entry before we do.
 */
static int rs_write_data(struct rsocket *rs, union rs_wr_id wr_id,
			 struct ibv_sge *sgl, int nsge,
			 uint32_t imm_data, int flags)
{
	uint64_t addr;
	uint32_t rkey;

	rs->sseq_no++;
	rs->sqe_avail--;
	rs->sbuf_bytes_avail -= wr_id.length;

	addr = rs->target_sgl[rs->target_sge].addr;
	rkey = rs->target_sgl[rs->target_sge].key;

	rs->target_sgl[rs->target_sge].addr += wr_id.length;
	rs->target_sgl[rs->target_sge].length -= wr_id.length;

	if (!rs->target_sgl[rs->target_sge].length) {
		if (++rs->target_sge == RS_SGL_SIZE)
			rs->target_sge = 0;
	}

	return rs_post_write(rs, wr_id.wr_id, sgl, nsge, imm_data, flags, addr, rkey);
}

static uint32_t rs_sbuf_left(struct rsocket *rs)
{
	return (uint32_t) (((uint64_t) (uintptr_t) &rs->sbuf[rs->sbuf_size]) -
			   rs->ssgl[0].addr);
}

static void rs_send_credits(struct rsocket *rs)
{
	struct ibv_sge ibsge;
	struct rs_sge sge;

	rs->ctrl_avail--;
	rs->rseq_comp = rs->rseq_no + (rs->rq_size >> 1);
	if (rs->rbuf_bytes_avail >= (rs->rbuf_size >> 1)) {
		if (!(rs->opts & RS_OPT_SWAP_SGL)) {
			sge.addr = (uintptr_t) &rs->rbuf[rs->rbuf_free_offset];
			sge.key = rs->rmr->rkey;
			sge.length = rs->rbuf_size >> 1;
		} else {
			sge.addr = bswap_64((uintptr_t) &rs->rbuf[rs->rbuf_free_offset]);
			sge.key = bswap_32(rs->rmr->rkey);
			sge.length = bswap_32(rs->rbuf_size >> 1);
		}

		ibsge.addr = (uintptr_t) &sge;
		ibsge.lkey = 0;
		ibsge.length = sizeof(sge);

		rs_post_write(rs, 0, &ibsge, 1,
			      rs_msg_set(RS_OP_SGL, rs->rseq_no + rs->rq_size),
			      IBV_SEND_INLINE,
			      rs->remote_sgl.addr +
			      rs->remote_sge * sizeof(struct rs_sge),
			      rs->remote_sgl.key);

		rs->rbuf_bytes_avail -= rs->rbuf_size >> 1;
		rs->rbuf_free_offset += rs->rbuf_size >> 1;
		if (rs->rbuf_free_offset >= rs->rbuf_size)
			rs->rbuf_free_offset = 0;
		if (++rs->remote_sge == rs->remote_sgl.length)
			rs->remote_sge = 0;
	} else {
		rs_post_write(rs, 0, NULL, 0,
			      rs_msg_set(RS_OP_SGL, rs->rseq_no + rs->rq_size), 0, 0, 0);
	}
}

static int rs_give_credits(struct rsocket *rs)
{
	return ((rs->rbuf_bytes_avail >= (rs->rbuf_size >> 1)) ||
	        ((short) ((short) rs->rseq_no - (short) rs->rseq_comp) >= 0)) &&
	       rs->ctrl_avail && (rs->state == rs_connected);
}

static void rs_update_credits(struct rsocket *rs)
{
	if (rs_give_credits(rs))
		rs_send_credits(rs);
}

static int rs_poll_cq(struct rsocket *rs)
{
	struct ibv_wc wc;
	union rs_wr_id *wr_id;
	uint32_t imm_data;
	int ret, rcnt = 0;

	while ((ret = ibv_poll_cq(rs->cm_id->recv_cq, 1, &wc)) > 0) {
		if (wc.opcode == IBV_WC_RECV_RDMA_WITH_IMM) {
			if (wc.status != IBV_WC_SUCCESS)
				continue;
			rcnt++;

			imm_data = ntohl(wc.imm_data);
			switch (rs_msg_op(imm_data)) {
			case RS_OP_SGL:
				rs->sseq_comp = (uint16_t) rs_msg_data(imm_data);
				break;
			case RS_OP_CTRL:
				if (rs_msg_data(imm_data) == RS_CTRL_DISCONNECT) {
					rs->state = rs_disconnected;
					return ERR(ECONNRESET);
				}
				break;
			default:
				rs->rmsg[rs->rmsg_tail].op = rs_msg_op(imm_data);
				rs->rmsg[rs->rmsg_tail].data = rs_msg_data(imm_data);
				if (++rs->rmsg_tail == rs->rq_size + 1)
					rs->rmsg_tail = 0;
				break;
			}
		} else {
			if (wc.wr_id) {
				wr_id = (union rs_wr_id *) &wc.wr_id;
				rs->sqe_avail++; /* += wr_id->sqe_count; */
				rs->sbuf_bytes_avail += wr_id->length;
			} else {
				rs->ctrl_avail++;
			}
			if (wc.status != IBV_WC_SUCCESS && rs->state == rs_connected) {
				rs->state = rs_error;
				rs->err = EIO;
			}
		}
	}

	if (rs->state == rs_connected) {
		while (!ret && rcnt--)
			ret = rdma_post_recvv(rs->cm_id, NULL, NULL, 0);

		if (ret) {
			rs->state = rs_error;
			rs->err = errno;
		}
	}
	return ret;
}

static int rs_get_cq_event(struct rsocket *rs)
{
	struct ibv_cq *cq;
	void *context;
	int ret;

	if (!rs->cq_armed)
		return 0;

	ret = ibv_get_cq_event(rs->cm_id->recv_cq_channel, &cq, &context);
	if (!ret) {
		ibv_ack_cq_events(rs->cm_id->recv_cq, 1);
		rs->cq_armed = 0;
	} else if (errno != EAGAIN && rs->state == rs_connected) {
		rs->state = rs_error;
	}

	return ret;
}

/*
 * Although we serialize rsend and rrecv calls with respect to themselves,
 * both calls may run simultaneously and need to poll the CQ for completions.
 * We need to serialize access to the CQ, but rsend and rrecv need to
 * allow each other to make forward progress.
 *
 * For example, rsend may need to wait for credits from the remote side,
 * which could be stalled until the remote process calls rrecv.  This should
 * not block rrecv from receiving data from the remote side however.
 *
 * We handle this by using two locks.  The cq_lock protects against polling
 * the CQ and processing completions.  The cq_wait_lock serializes access to
 * waiting on the CQ.
 */
static int rs_process_cq(struct rsocket *rs, int nonblock, int (*test)(struct rsocket *rs))
{
	int ret;

	fastlock_acquire(&rs->cq_lock);
	do {
		rs_update_credits(rs);
		ret = rs_poll_cq(rs);
		if (test(rs)) {
			ret = 0;
			break;
		} else if (ret) {
			break;
		} else if (nonblock) {
			ret = ERR(EWOULDBLOCK);
		} else if (!rs->cq_armed) {
			ibv_req_notify_cq(rs->cm_id->recv_cq, 0);
			rs->cq_armed = 1;
		} else {
			rs_update_credits(rs);
			fastlock_acquire(&rs->cq_wait_lock);
			fastlock_release(&rs->cq_lock);

			ret = rs_get_cq_event(rs);
			fastlock_release(&rs->cq_wait_lock);
			fastlock_acquire(&rs->cq_lock);
		}
	} while (!ret);

	rs_update_credits(rs);
	fastlock_release(&rs->cq_lock);
	return ret;
}

static int rs_nonblocking(struct rsocket *rs, int flags)
{
	return (rs->fd_flags & O_NONBLOCK) || (flags & MSG_DONTWAIT);
}

static int rs_is_cq_armed(struct rsocket *rs)
{
	return rs->cq_armed;
}

static int rs_poll_all(struct rsocket *rs)
{
	return 1;
}

/*
 * We use hardware flow control to prevent over running the remote
 * receive queue.  However, data transfers still require space in
 * the remote rmsg queue, or we risk losing notification that data
 * has been transfered.
 *
 * Be careful with race conditions in the check below.  The target SGL
 * may be updated by a remote RDMA write.
 */
static int rs_can_send(struct rsocket *rs)
{
	return rs->sqe_avail && rs->sbuf_bytes_avail &&
	       (rs->sseq_no != rs->sseq_comp) &&
	       (rs->target_sgl[rs->target_sge].length != 0);
}

static int rs_conn_can_send(struct rsocket *rs)
{
	return rs_can_send(rs) || (rs->state != rs_connected);
}

static int rs_can_send_ctrl(struct rsocket *rs)
{
	return rs->ctrl_avail;
}

static int rs_have_rdata(struct rsocket *rs)
{
	return (rs->rmsg_head != rs->rmsg_tail);
}

static int rs_conn_have_rdata(struct rsocket *rs)
{
	return rs_have_rdata(rs) || (rs->state != rs_connected);
}

static int rs_all_sends_done(struct rsocket *rs)
{
	return (rs->sqe_avail + rs->ctrl_avail) == rs->sq_size;
}

static ssize_t rs_peek(struct rsocket *rs, void *buf, size_t len)
{
	size_t left = len;
	uint32_t end_size, rsize;
	int rmsg_head, rbuf_offset;

	rmsg_head = rs->rmsg_head;
	rbuf_offset = rs->rbuf_offset;

	for (; left && (rmsg_head != rs->rmsg_tail); left -= rsize) {
		if (left < rs->rmsg[rmsg_head].data) {
			rsize = left;
		} else {
			rsize = rs->rmsg[rmsg_head].data;
			if (++rmsg_head == rs->rq_size + 1)
				rmsg_head = 0;
		}

		end_size = rs->rbuf_size - rbuf_offset;
		if (rsize > end_size) {
			memcpy(buf, &rs->rbuf[rbuf_offset], end_size);
			rbuf_offset = 0;
			buf += end_size;
			rsize -= end_size;
			left -= end_size;
		}
		memcpy(buf, &rs->rbuf[rbuf_offset], rsize);
		rbuf_offset += rsize;
		buf += rsize;
	}

	return len - left;
}

/*
 * Continue to receive any queued data even if the remote side has disconnected.
 */
ssize_t rrecv(int socket, void *buf, size_t len, int flags)
{
	struct rsocket *rs;
	size_t left = len;
	uint32_t end_size, rsize;
	int ret;

	rs = idm_at(&idm, socket);
	if (rs->state != rs_connected &&
	    (rs->state == rs_resolving_addr || rs->state == rs_resolving_route ||
	     rs->state == rs_connecting || rs->state ==	rs_accepting)) {
		ret = rs_do_connect(rs);
		if (ret) {
			if (errno == EINPROGRESS)
				errno = EAGAIN;
			return ret;
		}
	}
	fastlock_acquire(&rs->rlock);
	if (!rs_have_rdata(rs)) {
		ret = rs_process_cq(rs, rs_nonblocking(rs, flags), rs_conn_have_rdata);
		if (ret && errno != ECONNRESET)
			goto out;
	}

	ret = 0;
	if (flags & MSG_PEEK) {
		left = len - rs_peek(rs, buf, len);
		goto out;
	}

	for (; left && rs_have_rdata(rs); left -= rsize) {
		if (left < rs->rmsg[rs->rmsg_head].data) {
			rsize = left;
			rs->rmsg[rs->rmsg_head].data -= left;
		} else {
			rs->rseq_no++;
			rsize = rs->rmsg[rs->rmsg_head].data;
			if (++rs->rmsg_head == rs->rq_size + 1)
				rs->rmsg_head = 0;
		}

		end_size = rs->rbuf_size - rs->rbuf_offset;
		if (rsize > end_size) {
			memcpy(buf, &rs->rbuf[rs->rbuf_offset], end_size);
			rs->rbuf_offset = 0;
			buf += end_size;
			rsize -= end_size;
			left -= end_size;
		}
		memcpy(buf, &rs->rbuf[rs->rbuf_offset], rsize);
		rs->rbuf_offset += rsize;
		buf += rsize;
	}
	rs->rbuf_bytes_avail += len - left;
out:
	fastlock_release(&rs->rlock);
	return ret ? ret : len - left;
}

ssize_t rrecvfrom(int socket, void *buf, size_t len, int flags,
		  struct sockaddr *src_addr, socklen_t *addrlen)
{
	int ret;

	ret = rrecv(socket, buf, len, flags);
	if (ret > 0 && src_addr)
		rgetpeername(socket, src_addr, addrlen);

	return ret;
}

/*
 * Simple, straightforward implementation for now that only tries to fill
 * in the first vector.
 */
static ssize_t rrecvv(int socket, const struct iovec *iov, int iovcnt, int flags)
{
	return rrecv(socket, iov[0].iov_base, iov[0].iov_len, flags);
}

ssize_t rrecvmsg(int socket, struct msghdr *msg, int flags)
{
	if (msg->msg_control && msg->msg_controllen)
		return ERR(ENOTSUP);

	return rrecvv(socket, msg->msg_iov, (int) msg->msg_iovlen, msg->msg_flags);
}

ssize_t rread(int socket, void *buf, size_t count)
{
	return rrecv(socket, buf, count, 0);
}

ssize_t rreadv(int socket, const struct iovec *iov, int iovcnt)
{
	return rrecvv(socket, iov, iovcnt, 0);
}

/*
 * We overlap sending the data, by posting a small work request immediately,
 * then increasing the size of the send on each iteration.
 */
ssize_t rsend(int socket, const void *buf, size_t len, int flags)
{
	struct rsocket *rs;
	struct ibv_sge sge;
	size_t left;
	uint32_t xfer_size, olen = RS_OLAP_START_SIZE;
	int ret = 0;

	rs = idm_at(&idm, socket);
	if (rs->state != rs_connected) {
		ret = rs_do_connect(rs);
		if (ret) {
			if (errno == EINPROGRESS)
				errno = EAGAIN;
			return ret;
		}
	}

	fastlock_acquire(&rs->slock);
	for (left = len; left; left -= xfer_size, buf += xfer_size) {
		if (!rs_can_send(rs)) {
			ret = rs_process_cq(rs, rs_nonblocking(rs, flags),
					    rs_conn_can_send);
			if (ret)
				break;
			if (rs->state != rs_connected) {
				ret = ERR(ECONNRESET);
				break;
			}
		}

		if (olen < left) {
			xfer_size = olen;
			if (olen < RS_MAX_TRANSFER)
				olen <<= 1;
		} else {
			xfer_size = left;
		}

		if (xfer_size > rs->sbuf_bytes_avail)
			xfer_size = rs->sbuf_bytes_avail;
		if (xfer_size > rs->target_sgl[rs->target_sge].length)
			xfer_size = rs->target_sgl[rs->target_sge].length;

		if (xfer_size <= RS_INLINE) {
			sge.addr = (uintptr_t) buf;
			sge.length = xfer_size;
			sge.lkey = 0;
			ret = rs_write_data(rs, rs_wrid(1, xfer_size),
					    &sge, 1, rs_msg_set(RS_OP_DATA, xfer_size),
					    IBV_SEND_INLINE);
		} else if (xfer_size <= rs_sbuf_left(rs)) {
			memcpy((void *) (uintptr_t) rs->ssgl[0].addr, buf, xfer_size);
			rs->ssgl[0].length = xfer_size;
			ret = rs_write_data(rs, rs_wrid(1, xfer_size),
					    rs->ssgl, 1,
					    rs_msg_set(RS_OP_DATA, xfer_size), 0);
			if (xfer_size < rs_sbuf_left(rs))
				rs->ssgl[0].addr += xfer_size;
			else
				rs->ssgl[0].addr = (uintptr_t) rs->sbuf;
		} else {
			rs->ssgl[0].length = rs_sbuf_left(rs);
			memcpy((void *) (uintptr_t) rs->ssgl[0].addr, buf,
				rs->ssgl[0].length);
			rs->ssgl[1].length = xfer_size - rs->ssgl[0].length;
			memcpy(rs->sbuf, buf + rs->ssgl[0].length, rs->ssgl[1].length);
			ret = rs_write_data(rs, rs_wrid(1, xfer_size),
					    rs->ssgl, 2,
					    rs_msg_set(RS_OP_DATA, xfer_size), 0);
			rs->ssgl[0].addr = (uintptr_t) rs->sbuf + rs->ssgl[1].length;
		}
		if (ret)
			break;
	}
	fastlock_release(&rs->slock);

	return (ret && left == len) ? ret : len - left;
}

ssize_t rsendto(int socket, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen)
{
	if (dest_addr || addrlen)
		return ERR(EISCONN);

	return rsend(socket, buf, len, flags);
}

static void rs_copy_iov(void *dst, const struct iovec **iov, size_t *offset, size_t len)
{
	size_t size;

	while (len) {
		size = (*iov)->iov_len - *offset;
		if (size > len) {
			memcpy (dst, (*iov)->iov_base + *offset, len);
			*offset += len;
			break;
		}

		memcpy(dst, (*iov)->iov_base + *offset, size);
		len -= size;
		dst += size;
		(*iov)++;
		*offset = 0;
	}
}

static ssize_t rsendv(int socket, const struct iovec *iov, int iovcnt, int flags)
{
	struct rsocket *rs;
	const struct iovec *cur_iov;
	size_t left, len, offset = 0;
	uint32_t xfer_size, olen = RS_OLAP_START_SIZE;
	int i, ret = 0;

	rs = idm_at(&idm, socket);
	if (rs->state != rs_connected) {
		ret = rs_do_connect(rs);
		if (ret) {
			if (errno == EINPROGRESS)
				errno = EAGAIN;
			return ret;
		}
	}

	cur_iov = iov;
	len = iov[0].iov_len;
	for (i = 1; i < iovcnt; i++)
		len += iov[i].iov_len;

	fastlock_acquire(&rs->slock);
	for (left = len; left; left -= xfer_size) {
		if (!rs_can_send(rs)) {
			ret = rs_process_cq(rs, rs_nonblocking(rs, flags),
					    rs_conn_can_send);
			if (ret)
				break;
			if (rs->state != rs_connected) {
				ret = ERR(ECONNRESET);
				break;
			}
		}

		if (olen < left) {
			xfer_size = olen;
			if (olen < RS_MAX_TRANSFER)
				olen <<= 1;
		} else {
			xfer_size = left;
		}

		if (xfer_size > rs->sbuf_bytes_avail)
			xfer_size = rs->sbuf_bytes_avail;
		if (xfer_size > rs->target_sgl[rs->target_sge].length)
			xfer_size = rs->target_sgl[rs->target_sge].length;

		if (xfer_size <= rs_sbuf_left(rs)) {
			rs_copy_iov((void *) (uintptr_t) rs->ssgl[0].addr,
				    &cur_iov, &offset, xfer_size);
			rs->ssgl[0].length = xfer_size;
			ret = rs_write_data(rs, rs_wrid(1, xfer_size),
					    rs->ssgl, 1,
					    rs_msg_set(RS_OP_DATA, xfer_size),
					    xfer_size <= RS_INLINE ? IBV_SEND_INLINE : 0);
			if (xfer_size < rs_sbuf_left(rs))
				rs->ssgl[0].addr += xfer_size;
			else
				rs->ssgl[0].addr = (uintptr_t) rs->sbuf;
		} else {
			rs->ssgl[0].length = rs_sbuf_left(rs);
			rs_copy_iov((void *) (uintptr_t) rs->ssgl[0].addr, &cur_iov,
				    &offset, rs->ssgl[0].length);
			rs->ssgl[1].length = xfer_size - rs->ssgl[0].length;
			rs_copy_iov(rs->sbuf, &cur_iov, &offset, rs->ssgl[1].length);
			ret = rs_write_data(rs, rs_wrid(1, xfer_size),
					    rs->ssgl, 2,
					    rs_msg_set(RS_OP_DATA, xfer_size),
					    xfer_size <= RS_INLINE ? IBV_SEND_INLINE : 0);
			rs->ssgl[0].addr = (uintptr_t) rs->sbuf + rs->ssgl[1].length;
		}
		if (ret)
			break;
	}
	fastlock_release(&rs->slock);

	return (ret && left == len) ? ret : len - left;
}

ssize_t rsendmsg(int socket, const struct msghdr *msg, int flags)
{
	if (msg->msg_control && msg->msg_controllen)
		return ERR(ENOTSUP);

	return rsendv(socket, msg->msg_iov, (int) msg->msg_iovlen, msg->msg_flags);
}

ssize_t rwrite(int socket, const void *buf, size_t count)
{
	return rsend(socket, buf, count, 0);
}

ssize_t rwritev(int socket, const struct iovec *iov, int iovcnt)
{
	return rsendv(socket, iov, iovcnt, 0);
}

static struct pollfd *rs_fds_alloc(nfds_t nfds)
{
	static __thread struct pollfd *rfds;
	static __thread nfds_t rnfds;

	if (nfds > rnfds) {
		if (rfds)
			free(rfds);

		rfds = malloc(sizeof *rfds * nfds);
		rnfds = rfds ? nfds : 0;
	}

	return rfds;
}

static int rs_poll_rs(struct rsocket *rs, int events,
		      int nonblock, int (*test)(struct rsocket *rs))
{
	struct pollfd fds;
	short revents;
	int ret;

	switch (rs->state) {
	case rs_listening:
		fds.fd = rs->cm_id->channel->fd;
		fds.events = events;
		fds.revents = 0;
		poll(&fds, 1, 0);
		return fds.revents;
	case rs_resolving_addr:
	case rs_resolving_route:
	case rs_connecting:
	case rs_accepting:
		ret = rs_do_connect(rs);
		if (ret) {
			if (errno == EINPROGRESS) {
				errno = 0;
				return 0;
			} else {
				return POLLOUT;
			}
		}
		/* fall through */
	case rs_connected:
	case rs_disconnected:
	case rs_error:
		rs_process_cq(rs, nonblock, test);

		revents = 0;
		if ((events & POLLIN) && rs_have_rdata(rs))
			revents |= POLLIN;
		if ((events & POLLOUT) && rs_can_send(rs))
			revents |= POLLOUT;
		if (rs->state == rs_disconnected)
			revents |= POLLHUP;
		if (rs->state == rs_error)
			revents |= POLLERR;

		return revents;
	case rs_connect_error:
		return (rs->err && events & POLLOUT) ? POLLOUT : 0;
	default:
		return 0;
	}
}

static int rs_poll_check(struct pollfd *fds, nfds_t nfds)
{
	struct rsocket *rs;
	int i, cnt = 0;

	for (i = 0; i < nfds; i++) {
		rs = idm_lookup(&idm, fds[i].fd);
		if (rs)
			fds[i].revents = rs_poll_rs(rs, fds[i].events, 1, rs_poll_all);
		else
			poll(&fds[i], 1, 0);

		if (fds[i].revents)
			cnt++;
	}
	return cnt;
}

static int rs_poll_arm(struct pollfd *rfds, struct pollfd *fds, nfds_t nfds)
{
	struct rsocket *rs;
	int i;

	for (i = 0; i < nfds; i++) {
		rs = idm_lookup(&idm, fds[i].fd);
		if (rs) {
			fds[i].revents = rs_poll_rs(rs, fds[i].events, 0, rs_is_cq_armed);
			if (fds[i].revents)
				return 1;

			switch (rs->state) {
			case rs_connected:
			case rs_disconnected:
			case rs_error:
				rfds[i].fd = rs->cm_id->recv_cq_channel->fd;
				break;
			default:
				rfds[i].fd = rs->cm_id->channel->fd;
				break;
			}
			rfds[i].events = POLLIN;
		} else {
			rfds[i].fd = fds[i].fd;
			rfds[i].events = fds[i].events;
		}
		rfds[i].revents = 0;

	}
	return 0;
}

static int rs_poll_events(struct pollfd *rfds, struct pollfd *fds, nfds_t nfds)
{
	struct rsocket *rs;
	int i, cnt = 0;

	for (i = 0; i < nfds; i++) {
		if (!rfds[i].revents)
			continue;

		rs = idm_lookup(&idm, fds[i].fd);
		if (rs) {
			rs_get_cq_event(rs);
			fds[i].revents = rs_poll_rs(rs, fds[i].events, 1, rs_poll_all);
		} else {
			fds[i].revents = rfds[i].revents;
		}
		if (fds[i].revents)
			cnt++;
	}
	return cnt;
}

/*
 * We need to poll *all* fd's that the user specifies at least once.
 * Note that we may receive events on an rsocket that may not be reported
 * to the user (e.g. connection events or credit updates).  Process those
 * events, then return to polling until we find ones of interest.
 */
int rpoll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	struct pollfd *rfds;
	int ret;

	ret = rs_poll_check(fds, nfds);
	if (ret || !timeout)
		return ret;

	rfds = rs_fds_alloc(nfds);
	if (!rfds)
		return ERR(ENOMEM);

	do {
		ret = rs_poll_arm(rfds, fds, nfds);
		if (ret)
			break;

		ret = poll(rfds, nfds, timeout);
		if (ret <= 0)
			break;

		ret = rs_poll_events(rfds, fds, nfds);
	} while (!ret);

	return ret;
}

static struct pollfd *
rs_select_to_poll(int *nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds)
{
	struct pollfd *fds;
	int fd, i = 0;

	fds = calloc(*nfds, sizeof *fds);
	if (!fds)
		return NULL;

	for (fd = 0; fd < *nfds; fd++) {
		if (readfds && FD_ISSET(fd, readfds)) {
			fds[i].fd = fd;
			fds[i].events = POLLIN;
		}

		if (writefds && FD_ISSET(fd, writefds)) {
			fds[i].fd = fd;
			fds[i].events |= POLLOUT;
		}

		if (exceptfds && FD_ISSET(fd, exceptfds))
			fds[i].fd = fd;

		if (fds[i].fd)
			i++;
	}

	*nfds = i;
	return fds;
}

static int
rs_poll_to_select(int nfds, struct pollfd *fds, fd_set *readfds,
		  fd_set *writefds, fd_set *exceptfds)
{
	int i, cnt = 0;

	for (i = 0; i < nfds; i++) {
		if (readfds && (fds[i].revents & POLLIN)) {
			FD_SET(fds[i].fd, readfds);
			cnt++;
		}

		if (writefds && (fds[i].revents & POLLOUT)) {
			FD_SET(fds[i].fd, writefds);
			cnt++;
		}

		if (exceptfds && (fds[i].revents & ~(POLLIN | POLLOUT))) {
			FD_SET(fds[i].fd, exceptfds);
			cnt++;
		}
	}
	return cnt;
}

static int rs_convert_timeout(struct timeval *timeout)
{
	return !timeout ? -1 :
		timeout->tv_sec * 1000 + timeout->tv_usec / 1000;
}

int rselect(int nfds, fd_set *readfds, fd_set *writefds,
	    fd_set *exceptfds, struct timeval *timeout)
{
	struct pollfd *fds;
	int ret;

	fds = rs_select_to_poll(&nfds, readfds, writefds, exceptfds);
	if (!fds)
		return ERR(ENOMEM);

	ret = rpoll(fds, nfds, rs_convert_timeout(timeout));

	if (readfds)
		FD_ZERO(readfds);
	if (writefds)
		FD_ZERO(writefds);
	if (exceptfds)
		FD_ZERO(exceptfds);

	if (ret > 0)
		ret = rs_poll_to_select(nfds, fds, readfds, writefds, exceptfds);

	free(fds);
	return ret;
}

/*
 * For graceful disconnect, notify the remote side that we're
 * disconnecting and wait until all outstanding sends complete.
 */
int rshutdown(int socket, int how)
{
	struct rsocket *rs;
	int ret = 0;

	rs = idm_at(&idm, socket);
	if (rs->fd_flags & O_NONBLOCK)
		rs_set_nonblocking(rs, 0);

	if (rs->state == rs_connected) {
		rs->state = rs_disconnected;
		if (!rs_can_send_ctrl(rs)) {
			ret = rs_process_cq(rs, 0, rs_can_send_ctrl);
			if (ret)
				return ret;
		}

		rs->ctrl_avail--;
		ret = rs_post_write(rs, 0, NULL, 0,
				    rs_msg_set(RS_OP_CTRL, RS_CTRL_DISCONNECT),
				    0, 0, 0);
	}

	if (!rs_all_sends_done(rs) && rs->state != rs_error)
		rs_process_cq(rs, 0, rs_all_sends_done);

	return 0;
}

int rclose(int socket)
{
	struct rsocket *rs;

	rs = idm_at(&idm, socket);
	if (rs->state == rs_connected)
		rshutdown(socket, SHUT_RDWR);

	rs_free(rs);
	return 0;
}

static void rs_copy_addr(struct sockaddr *dst, struct sockaddr *src, socklen_t *len)
{
	socklen_t size;

	if (src->sa_family == AF_INET) {
		size = min(*len, sizeof(struct sockaddr_in));
		*len = sizeof(struct sockaddr_in);
	} else {
		size = min(*len, sizeof(struct sockaddr_in6));
		*len = sizeof(struct sockaddr_in6);
	}
	memcpy(dst, src, size);
}

int rgetpeername(int socket, struct sockaddr *addr, socklen_t *addrlen)
{
	struct rsocket *rs;

	rs = idm_at(&idm, socket);
	rs_copy_addr(addr, rdma_get_peer_addr(rs->cm_id), addrlen);
	return 0;
}

int rgetsockname(int socket, struct sockaddr *addr, socklen_t *addrlen)
{
	struct rsocket *rs;

	rs = idm_at(&idm, socket);
	rs_copy_addr(addr, rdma_get_local_addr(rs->cm_id), addrlen);
	return 0;
}

int rsetsockopt(int socket, int level, int optname,
		const void *optval, socklen_t optlen)
{
	struct rsocket *rs;
	int ret, opt_on = 0;
	uint64_t *opts = NULL;

	ret = ERR(ENOTSUP);
	rs = idm_at(&idm, socket);
	switch (level) {
	case SOL_SOCKET:
		opts = &rs->so_opts;
		switch (optname) {
		case SO_REUSEADDR:
			ret = rdma_set_option(rs->cm_id, RDMA_OPTION_ID,
					      RDMA_OPTION_ID_REUSEADDR,
					      (void *) optval, optlen);
			if (ret && ((errno == ENOSYS) || ((rs->state != rs_init) &&
			    rs->cm_id->context &&
			    (rs->cm_id->verbs->device->transport_type == IBV_TRANSPORT_IB))))
				ret = 0;
			opt_on = *(int *) optval;
			break;
		case SO_RCVBUF:
			if (!rs->rbuf)
				rs->rbuf_size = (*(uint32_t *) optval) << 1;
			ret = 0;
			break;
		case SO_SNDBUF:
			if (!rs->sbuf)
				rs->sbuf_size = (*(uint32_t *) optval) << 1;
			ret = 0;
			break;
		case SO_LINGER:
			/* Invert value so default so_opt = 0 is on */
			opt_on =  !((struct linger *) optval)->l_onoff;
			ret = 0;
			break;
		case SO_KEEPALIVE:
			opt_on = *(int *) optval;
			ret = 0;
			break;
		default:
			break;
		}
		break;
	case IPPROTO_TCP:
		opts = &rs->tcp_opts;
		switch (optname) {
		case TCP_NODELAY:
			opt_on = *(int *) optval;
			ret = 0;
			break;
		default:
			break;
		}
		break;
	case SOL_RDMA:
		break;
	default:
		break;
	}

	if (!ret) {
		if (opt_on)
			*opts |= (1 << optname);
		else
			*opts &= ~(1 << optname);
	}

	return ret;
}

int rgetsockopt(int socket, int level, int optname,
		void *optval, socklen_t *optlen)
{
	struct rsocket *rs;
	int ret = 0;

	rs = idm_at(&idm, socket);
	switch (level) {
	case SOL_SOCKET:
		switch (optname) {
		case SO_REUSEADDR:
		case SO_KEEPALIVE:
			*((int *) optval) = !!(rs->so_opts & (1 << optname));
			*optlen = sizeof(int);
			break;
		case SO_RCVBUF:
			*((int *) optval) = rs->rbuf_size;
			*optlen = sizeof(int);
			break;
		case SO_SNDBUF:
			*((int *) optval) = rs->sbuf_size;
			*optlen = sizeof(int);
			break;
		case SO_LINGER:
			/* Value is inverted so default so_opt = 0 is on */
			((struct linger *) optval)->l_onoff =
					!(rs->so_opts & (1 << optname));
			((struct linger *) optval)->l_linger = 0;
			*optlen = sizeof(struct linger);
			break;
		case SO_ERROR:
			*((int *) optval) = rs->err;
			*optlen = sizeof(int);
			rs->err = 0;
			break;
		default:
			ret = ENOTSUP;
			break;
		}
		break;
	case IPPROTO_TCP:
		switch (optname) {
		case TCP_NODELAY:
			*((int *) optval) = !!(rs->tcp_opts & (1 << optname));
			*optlen = sizeof(int);
			break;
		default:
			ret = ENOTSUP;
			break;
		}
		break;
	case SOL_RDMA:
		ret = ENOTSUP;
		break;
	default:
		ret = ENOTSUP;
		break;
	}

	return rdma_seterrno(ret);
}

int rfcntl(int socket, int cmd, ... /* arg */ )
{
	struct rsocket *rs;
	va_list args;
	long param;
	int ret = 0;

	rs = idm_at(&idm, socket);
	va_start(args, cmd);
	switch (cmd) {
	case F_GETFL:
		return (int) rs->fd_flags;
	case F_SETFL:
		param = va_arg(args, long);
		if (param & O_NONBLOCK)
			ret = rs_set_nonblocking(rs, O_NONBLOCK);

		if (!ret)
			rs->fd_flags |= param;
		break;
	default:
		ret = ERR(ENOTSUP);
	}
	va_end(args);
	return ret;
}
