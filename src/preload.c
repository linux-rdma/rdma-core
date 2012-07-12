/*
 * Copyright (c) 2011-2012 Intel Corporation.  All rights reserved.
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
#include <sys/stat.h>
#include <stdarg.h>
#include <dlfcn.h>
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

static int (*real_socket)(int domain, int type, int protocol);
static int (*real_bind)(int socket, const struct sockaddr *addr,
			socklen_t addrlen);
static int (*real_listen)(int socket, int backlog);
static int (*real_accept)(int socket, struct sockaddr *addr,
			  socklen_t *addrlen);
static int (*real_connect)(int socket, const struct sockaddr *addr,
			   socklen_t addrlen);
static ssize_t (*real_recv)(int socket, void *buf, size_t len, int flags);
static ssize_t (*real_recvfrom)(int socket, void *buf, size_t len, int flags,
				struct sockaddr *src_addr, socklen_t *addrlen);
static ssize_t (*real_recvmsg)(int socket, struct msghdr *msg, int flags);
static ssize_t (*real_read)(int socket, void *buf, size_t count);
static ssize_t (*real_readv)(int socket, const struct iovec *iov, int iovcnt);
static ssize_t (*real_send)(int socket, const void *buf, size_t len, int flags);
static ssize_t (*real_sendto)(int socket, const void *buf, size_t len, int flags,
			      const struct sockaddr *dest_addr, socklen_t addrlen);
static ssize_t (*real_sendmsg)(int socket, const struct msghdr *msg, int flags);
static ssize_t (*real_write)(int socket, const void *buf, size_t count);
static ssize_t (*real_writev)(int socket, const struct iovec *iov, int iovcnt);
static int (*real_poll)(struct pollfd *fds, nfds_t nfds, int timeout);
static int (*real_shutdown)(int socket, int how);
static int (*real_close)(int socket);
static int (*real_getpeername)(int socket, struct sockaddr *addr,
			       socklen_t *addrlen);
static int (*real_getsockname)(int socket, struct sockaddr *addr,
			       socklen_t *addrlen);
static int (*real_setsockopt)(int socket, int level, int optname,
			      const void *optval, socklen_t optlen);
static int (*real_getsockopt)(int socket, int level, int optname,
			      void *optval, socklen_t *optlen);
static int (*real_fcntl)(int socket, int cmd, ... /* arg */);

static struct index_map idm;
static pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;

static int sq_size;
static int rq_size;
static int sq_inline;

enum fd_type {
	fd_normal,
	fd_rsocket
};

struct fd_info {
	enum fd_type type;
	int fd;
};

static int fd_open(void)
{
	struct fd_info *fdi;
	int ret, index;

	fdi = calloc(1, sizeof *fdi);
	if (!fdi)
		return ERR(ENOMEM);

	index = open("/dev/null", O_RDONLY);
	if (index < 0) {
		ret = index;
		goto err1;
	}

	pthread_mutex_lock(&mut);
	ret = idm_set(&idm, index, fdi);
	pthread_mutex_unlock(&mut);
	if (ret < 0)
		goto err2;

	return index;

err2:
	close(index);
err1:
	free(fdi);
	return ret;
}

static void fd_store(int index, int fd, enum fd_type type)
{
	struct fd_info *fdi;

	fdi = idm_at(&idm, index);
	fdi->fd = fd;
	fdi->type = type;
}

static inline enum fd_type fd_get(int index, int *fd)
{
	struct fd_info *fdi;

	fdi = idm_lookup(&idm, index);
	if (fdi) {
		*fd = fdi->fd;
		return fdi->type;

	} else {
		*fd = index;
		return fd_normal;
	}
}

static inline int fd_getd(int index)
{
	struct fd_info *fdi;

	fdi = idm_lookup(&idm, index);
	return fdi ? fdi->fd : index;
}

static inline enum fd_type fd_gett(int index)
{
	struct fd_info *fdi;

	fdi = idm_lookup(&idm, index);
	return fdi ? fdi->type : fd_normal;
}

static enum fd_type fd_close(int index, int *fd)
{
	struct fd_info *fdi;
	enum fd_type type;

	fdi = idm_lookup(&idm, index);
	if (fdi) {
		idm_clear(&idm, index);
		*fd = fdi->fd;
		type = fdi->type;
		close(index);
		free(fdi);
	} else {
		*fd = index;
		type = fd_normal;
	}
	return type;
}

void getenv_options(void)
{
	char *var;

	var = getenv("RS_SQ_SIZE");
	if (var)
		sq_size = atoi(var);

	var = getenv("RS_RQ_SIZE");
	if (var)
		rq_size = atoi(var);

	var = getenv("RS_INLINE");
	if (var)
		sq_inline = atoi(var);
}

static void init_preload(void)
{
	static int init;

	/* Quick check without lock */
	if (init)
		return;

	pthread_mutex_lock(&mut);
	if (init)
		goto out;

	real_socket = dlsym(RTLD_NEXT, "socket");
	real_bind = dlsym(RTLD_NEXT, "bind");
	real_listen = dlsym(RTLD_NEXT, "listen");
	real_accept = dlsym(RTLD_NEXT, "accept");
	real_connect = dlsym(RTLD_NEXT, "connect");
	real_recv = dlsym(RTLD_NEXT, "recv");
	real_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
	real_recvmsg = dlsym(RTLD_NEXT, "recvmsg");
	real_read = dlsym(RTLD_NEXT, "read");
	real_readv = dlsym(RTLD_NEXT, "readv");
	real_send = dlsym(RTLD_NEXT, "send");
	real_sendto = dlsym(RTLD_NEXT, "sendto");
	real_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
	real_write = dlsym(RTLD_NEXT, "write");
	real_writev = dlsym(RTLD_NEXT, "writev");
	real_poll = dlsym(RTLD_NEXT, "poll");
	real_shutdown = dlsym(RTLD_NEXT, "shutdown");
	real_close = dlsym(RTLD_NEXT, "close");
	real_getpeername = dlsym(RTLD_NEXT, "getpeername");
	real_getsockname = dlsym(RTLD_NEXT, "getsockname");
	real_setsockopt = dlsym(RTLD_NEXT, "setsockopt");
	real_getsockopt = dlsym(RTLD_NEXT, "getsockopt");
	real_fcntl = dlsym(RTLD_NEXT, "fcntl");

	getenv_options();
	init = 1;
out:
	pthread_mutex_unlock(&mut);
}

/*
 * Convert from an rsocket to a normal socket.  The new socket should have the
 * same settings and bindings as the rsocket.  We currently only handle setting
 * a few of the more common values.
 */
static int socket_fallback(int socket, int *fd)
{
	socklen_t len = 0;
	int new_fd, param, ret;

	ret = rgetsockname(*fd, NULL, &len);
	if (ret)
		return ret;

	param = (len == sizeof(struct sockaddr_in6)) ? PF_INET6 : PF_INET;
	new_fd = real_socket(param, SOCK_STREAM, IPPROTO_TCP);
	if (new_fd < 0)
		return new_fd;

	ret = rfcntl(*fd, F_GETFL);
	if (ret > 0)
		ret = real_fcntl(new_fd, F_SETFL, ret);
	if (ret)
		goto err;

	len = sizeof param;
	ret = rgetsockopt(*fd, SOL_SOCKET, SO_REUSEADDR, &param, &len);
	if (param && !ret)
		ret = real_setsockopt(new_fd, SOL_SOCKET, SO_REUSEADDR, &param, len);
	if (ret)
		goto err;

	len = sizeof param;
	ret = rgetsockopt(*fd, IPPROTO_TCP, TCP_NODELAY, &param, &len);
	if (param && !ret)
		ret = real_setsockopt(new_fd, IPPROTO_TCP, TCP_NODELAY, &param, len);
	if (ret)
		goto err;

	rclose(*fd);
	fd_store(socket, new_fd, fd_normal);
	*fd = new_fd;
	return 0;

err:
	real_close(new_fd);
	return ret;
}

/*
 * Use defaults on failure.
 */
void set_rsocket_options(int rsocket)
{
	if (sq_size)
		rsetsockopt(rsocket, SOL_RDMA, RDMA_SQSIZE, &sq_size, sizeof sq_size);

	if (rq_size)
		rsetsockopt(rsocket, SOL_RDMA, RDMA_RQSIZE, &rq_size, sizeof rq_size);

	if (sq_inline)
		rsetsockopt(rsocket, SOL_RDMA, RDMA_INLINE, &sq_inline, sizeof sq_inline);
}

int socket(int domain, int type, int protocol)
{
	static __thread int recursive;
	int index, ret;

	if (recursive)
		goto real;

	init_preload();
	index = fd_open();
	if (index < 0)
		return index;

	recursive = 1;
	ret = rsocket(domain, type, protocol);
	recursive = 0;
	if (ret >= 0) {
		fd_store(index, ret, fd_rsocket);
		set_rsocket_options(ret);
		return index;
	}
	fd_close(index, &ret);
real:
	return real_socket(domain, type, protocol);
}

int bind(int socket, const struct sockaddr *addr, socklen_t addrlen)
{
	struct sockaddr_in *sin;
	int fd, ret;

	if (fd_get(socket, &fd) == fd_rsocket) {
		sin = (struct sockaddr_in *) addr;
		if (!sin->sin_port || ntohs(sin->sin_port) > 1024)
			return rbind(fd, addr, addrlen);

		ret = socket_fallback(socket, &fd);
		if (ret)
			return ret;
	}

	return real_bind(fd, addr, addrlen);
}

int listen(int socket, int backlog)
{
	int fd;
	return (fd_get(socket, &fd) == fd_rsocket) ?
		rlisten(fd, backlog) : real_listen(fd, backlog);
}

int accept(int socket, struct sockaddr *addr, socklen_t *addrlen)
{
	int fd, index, ret;

	if (fd_get(socket, &fd) == fd_rsocket) {
		index = fd_open();
		if (index < 0)
			return index;

		ret = raccept(fd, addr, addrlen);
		if (ret < 0) {
			fd_close(index, &fd);
			return ret;
		}

		fd_store(index, ret, fd_rsocket);
		return index;
	} else {
		return real_accept(fd, addr, addrlen);
	}
}

int connect(int socket, const struct sockaddr *addr, socklen_t addrlen)
{
	struct sockaddr_in *sin;
	int fd, ret;

	if (fd_get(socket, &fd) == fd_rsocket) {
		sin = (struct sockaddr_in *) addr;
		if (ntohs(sin->sin_port) > 1024) {
			ret = rconnect(fd, addr, addrlen);
			if (!ret || errno == EINPROGRESS)
				return ret;
		}

		ret = socket_fallback(socket, &fd);
		if (ret)
			return ret;
	}

	return real_connect(fd, addr, addrlen);
}

ssize_t recv(int socket, void *buf, size_t len, int flags)
{
	int fd;
	return (fd_get(socket, &fd) == fd_rsocket) ?
		rrecv(fd, buf, len, flags) : real_recv(fd, buf, len, flags);
}

ssize_t recvfrom(int socket, void *buf, size_t len, int flags,
		 struct sockaddr *src_addr, socklen_t *addrlen)
{
	int fd;
	return (fd_get(socket, &fd) == fd_rsocket) ?
		rrecvfrom(fd, buf, len, flags, src_addr, addrlen) :
		real_recvfrom(fd, buf, len, flags, src_addr, addrlen);
}

ssize_t recvmsg(int socket, struct msghdr *msg, int flags)
{
	int fd;
	return (fd_get(socket, &fd) == fd_rsocket) ?
		rrecvmsg(fd, msg, flags) : real_recvmsg(fd, msg, flags);
}

ssize_t read(int socket, void *buf, size_t count)
{
	int fd;
	init_preload();
	return (fd_get(socket, &fd) == fd_rsocket) ?
		rread(fd, buf, count) : real_read(fd, buf, count);
}

ssize_t readv(int socket, const struct iovec *iov, int iovcnt)
{
	int fd;
	init_preload();
	return (fd_get(socket, &fd) == fd_rsocket) ?
		rreadv(fd, iov, iovcnt) : real_readv(fd, iov, iovcnt);
}

ssize_t send(int socket, const void *buf, size_t len, int flags)
{
	int fd;
	return (fd_get(socket, &fd) == fd_rsocket) ?
		rsend(fd, buf, len, flags) : real_send(fd, buf, len, flags);
}

ssize_t sendto(int socket, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen)
{
	int fd;
	return (fd_get(socket, &fd) == fd_rsocket) ?
		rsendto(fd, buf, len, flags, dest_addr, addrlen) :
		real_sendto(fd, buf, len, flags, dest_addr, addrlen);
}

ssize_t sendmsg(int socket, const struct msghdr *msg, int flags)
{
	int fd;
	return (fd_get(socket, &fd) == fd_rsocket) ?
		rsendmsg(fd, msg, flags) : real_sendmsg(fd, msg, flags);
}

ssize_t write(int socket, const void *buf, size_t count)
{
	int fd;
	init_preload();
	return (fd_get(socket, &fd) == fd_rsocket) ?
		rwrite(fd, buf, count) : real_write(fd, buf, count);
}

ssize_t writev(int socket, const struct iovec *iov, int iovcnt)
{
	int fd;
	init_preload();
	return (fd_get(socket, &fd) == fd_rsocket) ?
		rwritev(fd, iov, iovcnt) : real_writev(fd, iov, iovcnt);
}

static struct pollfd *fds_alloc(nfds_t nfds)
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

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	struct pollfd *rfds;
	int i, ret;

	init_preload();
	for (i = 0; i < nfds; i++) {
		if (fd_gett(fds[i].fd) == fd_rsocket)
			goto use_rpoll;
	}

	return real_poll(fds, nfds, timeout);

use_rpoll:
	rfds = fds_alloc(nfds);
	if (!rfds)
		return ERR(ENOMEM);

	for (i = 0; i < nfds; i++) {
		rfds[i].fd = fd_getd(fds[i].fd);
		rfds[i].events = fds[i].events;
		rfds[i].revents = 0;
	}

	ret = rpoll(rfds, nfds, timeout);

	for (i = 0; i < nfds; i++)
		fds[i].revents = rfds[i].revents;

	return ret;
}

static void select_to_rpoll(struct pollfd *fds, int *nfds,
			    fd_set *readfds, fd_set *writefds, fd_set *exceptfds)
{
	int fd, events, i = 0;

	for (fd = 0; fd < *nfds; fd++) {
		events = (readfds && FD_ISSET(fd, readfds)) ? POLLIN : 0;
		if (writefds && FD_ISSET(fd, writefds))
			events |= POLLOUT;

		if (events || (exceptfds && FD_ISSET(fd, exceptfds))) {
			fds[i].fd = fd_getd(fd);
			fds[i++].events = events;
		}
	}

	*nfds = i;
}

static int rpoll_to_select(struct pollfd *fds, int nfds,
			   fd_set *readfds, fd_set *writefds, fd_set *exceptfds)
{
	int fd, rfd, i, cnt = 0;

	for (i = 0, fd = 0; i < nfds; fd++) {
		rfd = fd_getd(fd);
		if (rfd != fds[i].fd)
			continue;

		if (readfds && (fds[i].revents & POLLIN)) {
			FD_SET(fd, readfds);
			cnt++;
		}

		if (writefds && (fds[i].revents & POLLOUT)) {
			FD_SET(fd, writefds);
			cnt++;
		}

		if (exceptfds && (fds[i].revents & ~(POLLIN | POLLOUT))) {
			FD_SET(fd, exceptfds);
			cnt++;
		}
		i++;
	}

	return cnt;
}

static int rs_convert_timeout(struct timeval *timeout)
{
	return !timeout ? -1 : timeout->tv_sec * 1000 + timeout->tv_usec / 1000;
}

int select(int nfds, fd_set *readfds, fd_set *writefds,
	   fd_set *exceptfds, struct timeval *timeout)
{
	struct pollfd *fds;
	int ret;

	fds = fds_alloc(nfds);
	if (!fds)
		return ERR(ENOMEM);

	select_to_rpoll(fds, &nfds, readfds, writefds, exceptfds);
	ret = rpoll(fds, nfds, rs_convert_timeout(timeout));

	if (readfds)
		FD_ZERO(readfds);
	if (writefds)
		FD_ZERO(writefds);
	if (exceptfds)
		FD_ZERO(exceptfds);

	if (ret > 0)
		ret = rpoll_to_select(fds, nfds, readfds, writefds, exceptfds);

	return ret;
}

int shutdown(int socket, int how)
{
	int fd;
	return (fd_get(socket, &fd) == fd_rsocket) ?
		rshutdown(fd, how) : real_shutdown(fd, how);
}

int close(int socket)
{
	int fd;
	init_preload();
	return (fd_close(socket, &fd) == fd_rsocket) ? rclose(fd) : real_close(fd);
}

int getpeername(int socket, struct sockaddr *addr, socklen_t *addrlen)
{
	int fd;
	return (fd_get(socket, &fd) == fd_rsocket) ?
		rgetpeername(fd, addr, addrlen) :
		real_getpeername(fd, addr, addrlen);
}

int getsockname(int socket, struct sockaddr *addr, socklen_t *addrlen)
{
	int fd;
	return (fd_get(socket, &fd) == fd_rsocket) ?
		rgetsockname(fd, addr, addrlen) :
		real_getsockname(fd, addr, addrlen);
}

int setsockopt(int socket, int level, int optname,
		const void *optval, socklen_t optlen)
{
	int fd;
	return (fd_get(socket, &fd) == fd_rsocket) ?
		rsetsockopt(fd, level, optname, optval, optlen) :
		real_setsockopt(fd, level, optname, optval, optlen);
}

int getsockopt(int socket, int level, int optname,
		void *optval, socklen_t *optlen)
{
	int fd;
	return (fd_get(socket, &fd) == fd_rsocket) ?
		rgetsockopt(fd, level, optname, optval, optlen) :
		real_getsockopt(fd, level, optname, optval, optlen);
}

int fcntl(int socket, int cmd, ... /* arg */)
{
	va_list args;
	long lparam;
	void *pparam;
	int fd, ret;

	init_preload();
	va_start(args, cmd);
	switch (cmd) {
	case F_GETFD:
	case F_GETFL:
	case F_GETOWN:
	case F_GETSIG:
	case F_GETLEASE:
		ret = (fd_get(socket, &fd) == fd_rsocket) ?
			rfcntl(fd, cmd) : real_fcntl(fd, cmd);
		break;
	case F_DUPFD:
	/*case F_DUPFD_CLOEXEC:*/
	case F_SETFD:
	case F_SETFL:
	case F_SETOWN:
	case F_SETSIG:
	case F_SETLEASE:
	case F_NOTIFY:
		lparam = va_arg(args, long);
		ret = (fd_get(socket, &fd) == fd_rsocket) ?
			rfcntl(fd, cmd, lparam) : real_fcntl(fd, cmd, lparam);
		break;
	default:
		pparam = va_arg(args, void *);
		ret = (fd_get(socket, &fd) == fd_rsocket) ?
			rfcntl(fd, cmd, pparam) : real_fcntl(fd, cmd, pparam);
		break;
	}
	va_end(args);
	return ret;
}
