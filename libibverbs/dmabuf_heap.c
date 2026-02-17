// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/*
 * Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 * DMA-buf heap allocator implementation
 */

#include "config.h"

#include <errno.h>
#include <infiniband/dmabuf_heap.h>

#if HAVE_LINUX_DMA_HEAP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/dma-heap.h>
#include <util/util.h>

struct ibv_dmabuf_heap {
	int heap_fd;
};

static struct ibv_dmabuf_heap *ibv_dmabuf_heap_init(const char *heap_name)
{
	struct ibv_dmabuf_heap *heap;
	char path[256];
	int fd;

	if (!heap_name) {
		errno = EINVAL;
		return NULL;
	}

	if (!check_snprintf(path, sizeof(path), "/dev/dma_heap/%s", heap_name)) {
		errno = ENOMEM;
		return NULL;
	}

	fd = open(path, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return NULL;

	heap = calloc(1, sizeof(*heap));
	if (!heap) {
		close(fd);
		errno = ENOMEM;
		return NULL;
	}

	heap->heap_fd = fd;
	return heap;
}

struct ibv_dmabuf_heap *ibv_dmabuf_heap_cc_shared_init(void)
{
	return ibv_dmabuf_heap_init("system_cc_shared");
}

void ibv_dmabuf_heap_destroy(struct ibv_dmabuf_heap *heap)
{
	close(heap->heap_fd);
	free(heap);
}

void *ibv_dmabuf_heap_alloc(struct ibv_dmabuf_heap *heap, size_t size,
			    int *dmabuf_fd)
{
	struct dma_heap_allocation_data heap_data = {};
	void *buf;
	int fd;

	heap_data.len = size;
	heap_data.fd_flags = O_RDWR | O_CLOEXEC;
	if (ioctl(heap->heap_fd, DMA_HEAP_IOCTL_ALLOC, &heap_data) < 0)
		return NULL;

	fd = heap_data.fd;

	buf = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		close(fd);
		return NULL;
	}

	*dmabuf_fd = fd;
	return buf;
}

void ibv_dmabuf_heap_free(void *buf, size_t size, int dmabuf_fd)
{
	munmap(buf, size);
	close(dmabuf_fd);
}

#else /* !HAVE_LINUX_DMA_HEAP_H */

struct ibv_dmabuf_heap *ibv_dmabuf_heap_cc_shared_init(void)
{
	errno = EOPNOTSUPP;
	return NULL;
}

void ibv_dmabuf_heap_destroy(struct ibv_dmabuf_heap *heap)
{
}

void *ibv_dmabuf_heap_alloc(struct ibv_dmabuf_heap *heap, size_t size,
			    int *dmabuf_fd)
{
	errno = EOPNOTSUPP;
	return NULL;
}

void ibv_dmabuf_heap_free(void *buf, size_t size, int dmabuf_fd)
{
}

#endif /* HAVE_LINUX_DMA_HEAP_H */
