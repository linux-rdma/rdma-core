/* SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB) */
/*
 * Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 * DMA-buf heap allocator API
 *
 * Provides a simple interface for allocating memory from Linux DMA-buf heaps.
 * currently only CoCo shared heap is supported. The allocated buffers are
 * mmap'd into user-space and can be used with RDMA verbs.
 */

#ifndef INFINIBAND_DMABUF_HEAP_H
#define INFINIBAND_DMABUF_HEAP_H

#include <stddef.h>

struct ibv_dmabuf_heap;

/**
 * ibv_dmabuf_heap_cc_shared_init - Open the CoCo shared DMA-buf heap
 */
struct ibv_dmabuf_heap *ibv_dmabuf_heap_cc_shared_init(void);

/**
 * ibv_dmabuf_heap_destroy - Close the heap device and free the handle
 * @heap: Heap handle from ibv_dmabuf_heap_cc_shared_init()
 */
void ibv_dmabuf_heap_destroy(struct ibv_dmabuf_heap *heap);

/**
 * ibv_dmabuf_heap_alloc - Allocate a buffer from the DMA-buf heap
 * @heap: Heap handle from ibv_dmabuf_heap_cc_shared_init()
 * @size: Requested buffer size in bytes
 * @dmabuf_fd: On success, set to the DMA-buf file descriptor
 *
 * Returns an mmap'd pointer on success, or NULL on failure with errno set.
 * The caller must store both the returned pointer and *dmabuf_fd and pass
 * them to ibv_dmabuf_heap_free() when done.
 */
void *ibv_dmabuf_heap_alloc(struct ibv_dmabuf_heap *heap, size_t size,
			    int *dmabuf_fd);

/**
 * ibv_dmabuf_heap_free - Free a buffer allocated with ibv_dmabuf_heap_alloc
 * @buf: Pointer returned by ibv_dmabuf_heap_alloc()
 * @size: Same size passed to ibv_dmabuf_heap_alloc()
 * @dmabuf_fd: DMA-buf fd returned by ibv_dmabuf_heap_alloc()
 *
 * Unmaps the buffer and closes the DMA-buf fd.
 */
void ibv_dmabuf_heap_free(void *buf, size_t size, int dmabuf_fd);

#endif /* INFINIBAND_DMABUF_HEAP_H */
