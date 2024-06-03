/*
 * Copyright (c) 2005-2006,2012 Intel Corporation.  All rights reserved.
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <unistd.h>

#include <rdma/rdma_cma.h>
#include "common.h"

int use_rs = 1;

int get_rdma_addr(const char *src, const char *dst, const char *port,
		  struct rdma_addrinfo *hints, struct rdma_addrinfo **rai)
{
	struct rdma_addrinfo rai_hints, *res;
	int ret;

	if (hints->ai_flags & RAI_PASSIVE) {
		ret = rdma_getaddrinfo(src, port, hints, rai);
		goto out;
	}

	rai_hints = *hints;
	if (src) {
		rai_hints.ai_flags |= RAI_PASSIVE;
		ret = rdma_getaddrinfo(src, NULL, &rai_hints, &res);
		if (ret)
			goto out;

		rai_hints.ai_src_addr = res->ai_src_addr;
		rai_hints.ai_src_len = res->ai_src_len;
		rai_hints.ai_flags &= ~RAI_PASSIVE;
	}

	ret = rdma_getaddrinfo(dst, port, &rai_hints, rai);
	if (src)
		rdma_freeaddrinfo(res);

out:
	if (ret)
		printf("rdma_getaddrinfo error: %s\n", gai_strerror(ret));
	return ret;
}

void size_str(char *str, size_t ssize, long long size)
{
	long long base, fraction = 0;
	char mag;

	if (size >= (1 << 30)) {
		base = 1 << 30;
		mag = 'g';
	} else if (size >= (1 << 20)) {
		base = 1 << 20;
		mag = 'm';
	} else if (size >= (1 << 10)) {
		base = 1 << 10;
		mag = 'k';
	} else {
		base = 1;
		mag = '\0';
	}

	if (size / base < 10)
		fraction = (size % base) * 10 / base;
	if (fraction) {
		snprintf(str, ssize, "%lld.%lld%c", size / base, fraction, mag);
	} else {
		snprintf(str, ssize, "%lld%c", size / base, mag);
	}
}

void cnt_str(char *str, size_t ssize, long long cnt)
{
	if (cnt >= 1000000000)
		snprintf(str, ssize, "%lldb", cnt / 1000000000);
	else if (cnt >= 1000000)
		snprintf(str, ssize, "%lldm", cnt / 1000000);
	else if (cnt >= 1000)
		snprintf(str, ssize, "%lldk", cnt / 1000);
	else
		snprintf(str, ssize, "%lld", cnt);
}

int size_to_count(int size)
{
	if (size >= (1 << 20))
		return 100;
	else if (size >= (1 << 16))
		return 1000;
	else if (size >= (1 << 10))
		return 10000;
	else
		return 100000;
}

void format_buf(void *buf, int size)
{
	uint8_t *array = buf;
	static uint8_t data;
	int i;

	for (i = 0; i < size; i++)
		array[i] = data++;
}

int verify_buf(void *buf, int size)
{
	static long long total_bytes;
	uint8_t *array = buf;
	static uint8_t data;
	int i;

	for (i = 0; i < size; i++, total_bytes++) {
		if (array[i] != data++) {
			printf("data verification failed byte %lld\n", total_bytes);
			return -1;
		}
	}
	return 0;
}

int do_poll(struct pollfd *fds, int timeout)
{
	int ret;

	do {
		ret = rs_poll(fds, 1, timeout);
	} while (!ret);

	return ret == 1 ? (fds->revents & (POLLERR | POLLHUP)) : ret;
}

struct rdma_event_channel *create_event_channel(void)
{
	struct rdma_event_channel *channel;

	channel = rdma_create_event_channel();
	if (!channel) {
		if (errno == ENODEV)
			fprintf(stderr, "No RDMA devices were detected\n");
		else
			perror("failed to create RDMA CM event channel");
	}
	return channel;
}

int oob_server_setup(const char *src_addr, const char *port, int *sock)
{
	struct addrinfo hint = {}, *ai;
	int listen_sock;
	int optval = 1;
	int ret;

	hint.ai_flags = AI_PASSIVE;
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_STREAM;
	ret = getaddrinfo(src_addr, port, &hint, &ai);
	if (ret) {
		printf("getaddrinfo error: %s\n", gai_strerror(ret));
		return ret;
	}

	listen_sock = socket(ai->ai_family, ai->ai_socktype, 0);
	if (listen_sock == -1) {
		ret = -errno;
		goto free;
	}

	setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	ret = bind(listen_sock, ai->ai_addr, ai->ai_addrlen);
	if (ret) {
		ret = -errno;
		goto close;
	}

	ret = listen(listen_sock, 1);
	if (ret) {
		ret = -errno;
		goto close;
	}

	*sock = accept(listen_sock, NULL, NULL);
	if (*sock == -1)
		ret = -errno;
	setsockopt(*sock, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));

close:
	close(listen_sock);
free:
	freeaddrinfo(ai);
	return ret;
}

int oob_client_setup(const char *dst_addr, const char *port, int *sock)
{
	struct addrinfo hint = {}, *ai;
	int nodelay = 1;
	int ret;

	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_STREAM;
	ret = getaddrinfo(dst_addr, port, &hint, &ai);
	if (ret) {
		printf("getaddrinfo error: %s\n", gai_strerror(ret));
		return ret;
	}

	*sock = socket(ai->ai_family, ai->ai_socktype, 0);
	if (*sock == -1) {
		ret = -errno;
		goto out;
	}
	setsockopt(*sock, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

	ret = connect(*sock, ai->ai_addr, ai->ai_addrlen);
out:
	freeaddrinfo(ai);
	return ret;
}

int oob_sendrecv(int sock, char val)
{
	char c = val;
	ssize_t ret;

	ret = send(sock, (void *) &c, sizeof(c), 0);
	if (ret != sizeof(c))
		return -errno;

	ret = recv(sock, (void *) &c, sizeof(c), 0);
	if (ret != sizeof(c))
		return -errno;

	if (c != val)
		return -EINVAL;
	return 0;
}

int oob_recvsend(int sock, char val)
{
	char c = 0;
	ssize_t ret;

	ret = recv(sock, (void *) &c, sizeof(c), 0);
	if (ret != sizeof(c))
		return -errno;

	if (c != val)
		return -EINVAL;

	ret = send(sock, (void *) &c, sizeof(c), 0);
	if (ret != sizeof(c))
		return -errno;

	return 0;
}

static void *wq_handler(void *arg);

int wq_init(struct work_queue *wq, int thread_cnt)
{
	int ret, i;

	wq->head = NULL;
	wq->tail = NULL;

	ret = pthread_mutex_init(&wq->lock, NULL);
	if (ret) {
		perror("pthread_mutex_init");
		return ret;
	}

	ret = pthread_cond_init(&wq->cond, NULL);
	if (ret) {
		perror("pthread_cond_init");
		return ret;
	}

	wq->thread_cnt = thread_cnt;
	wq->thread = calloc(thread_cnt, sizeof(*wq->thread));
	if (!wq->thread)
		return -ENOMEM;

	wq->running = true;
	for (i = 0; i < thread_cnt; i++) {
		ret = pthread_create(&wq->thread[i], NULL, wq_handler, wq);
		if (ret) {
			perror("pthread_create");
			return ret;
		}
	}

	return 0;
}

void wq_cleanup(struct work_queue *wq)
{
	int i;

	pthread_mutex_lock(&wq->lock);
	wq->running = false;
	pthread_cond_broadcast(&wq->cond);
	pthread_mutex_unlock(&wq->lock);

	for (i = 0; i < wq->thread_cnt; i++)
		pthread_join(wq->thread[i], NULL);
	pthread_cond_destroy(&wq->cond);
	pthread_mutex_destroy(&wq->lock);
}

void wq_insert(struct work_queue *wq, struct work_item *item,
	       void (*work_handler)(struct work_item *item))
{
	bool empty;

	item->next = NULL;
	item->work_handler = work_handler;
	pthread_mutex_lock(&wq->lock);
	if (wq->head) {
		wq->tail->next = item;
		empty = false;
	} else {
		wq->head = item;
		empty = true;
	}
	wq->tail = item;
	pthread_mutex_unlock(&wq->lock);

	if (empty)
		pthread_cond_signal(&wq->cond);
}

struct work_item *wq_remove(struct work_queue *wq)
{
	struct work_item *item;

	item = wq->head;
	wq->head = wq->head->next;
	item->next = NULL;
	return item;
}

static void *wq_handler(void *arg)
{
	struct work_queue *wq = arg;
	struct work_item *item;

	pthread_mutex_lock(&wq->lock);
	while (wq->running) {
		while (!wq->head) {
			pthread_cond_wait(&wq->cond, &wq->lock);
			if (!wq->running)
				goto out;
		}

		item = wq_remove(wq);
		if (wq->head)
			pthread_cond_signal(&wq->cond);
		pthread_mutex_unlock(&wq->lock);

		item->work_handler(item);
		pthread_mutex_lock(&wq->lock);
	}

out:
	if (wq->head)
		pthread_cond_signal(&wq->cond);
	pthread_mutex_unlock(&wq->lock);
	return NULL;
}
