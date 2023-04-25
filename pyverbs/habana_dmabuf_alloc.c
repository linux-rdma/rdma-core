// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright 2023 Amazon.com, Inc. or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include "synapse_api.h"
#include "hlthunk.h"
#include "habana_dmabuf_alloc.h"

#define ACCEL_PAGE_SIZE 4096

struct habana_dmabuf {
	synDeviceId device_id;
	int dmabuf_fd;
	int device_fd;
	void *addr;
};

static int hl_memory_init(struct habana_dmabuf *dmabuf)
{
	synStatus status;
	synDeviceInfo device_info;

	status = synInitialize();
	if (status != synSuccess) {
		fprintf(stderr, "Failed to initialize HL synapse, status %d\n", status);
		return -1;
	}

	status = synDeviceAcquire(&dmabuf->device_id, NULL);
	if (status != synSuccess) {
		fprintf(stderr, "Failed to acquire HL device, status %d\n", status);
		return -1;
	}

	status = synDeviceGetInfo(dmabuf->device_id, &device_info);
	if (status != synSuccess) {
		fprintf(stderr, "Failed to get HL device info, status %d\n", status);
		return -1;
	}

	dmabuf->device_fd = device_info.fd;
	return 0;
}

struct habana_dmabuf *habana_dmabuf_alloc(unsigned long size)
{
	struct habana_dmabuf *dmabuf;
	int fd, status;
	uint64_t buffer_addr, buf_size;

	dmabuf = malloc(sizeof(*dmabuf));
	if (!dmabuf)
		return NULL;

	status = hl_memory_init(dmabuf);
	if (status != 0)
		return NULL;

	buf_size = size;
	if (size % ACCEL_PAGE_SIZE != 0)
		buf_size = (size + ACCEL_PAGE_SIZE - 1) & ~(ACCEL_PAGE_SIZE - 1);

	synStatus syn_status = synDeviceMalloc(dmabuf->device_id, buf_size, 0, 0, &buffer_addr);

	if (syn_status != synSuccess) {
		fprintf(stderr, "Failed to allocate HL memory on device %d of size %lu\n",
			dmabuf->device_id, (unsigned long)buf_size);
		return NULL;
	}

	fd = hlthunk_device_memory_export_dmabuf_fd(dmabuf->device_fd, buffer_addr, buf_size, 0);
	if (fd < 0) {
		fprintf(stderr, "Failed to export HL dmabuf. sz[%lu] ptr[%p] err[%d]\n",
			(unsigned long)buf_size, (void *)buffer_addr, fd);
		return NULL;
	}

	dmabuf->dmabuf_fd = fd;
	dmabuf->addr = (void *)buffer_addr;
	return dmabuf;
}

void habana_dmabuf_free(struct habana_dmabuf *dmabuf)
{
	synDeviceFree(dmabuf->device_id, (uint64_t)dmabuf->addr, 0);
	close(dmabuf->dmabuf_fd);
	synDeviceRelease(dmabuf->device_id);
	close(dmabuf->device_fd);
	synDestroy();

	free(dmabuf);
}

int habana_dmabuf_get_buf_fd(struct habana_dmabuf *dmabuf)
{
	if (!dmabuf)
		return -1;

	return dmabuf->dmabuf_fd;
}

int habana_dmabuf_get_device_fd(struct habana_dmabuf *dmabuf)
{
	if (!dmabuf)
		return -1;

	return dmabuf->device_fd;
}

void *habana_dmabuf_get_addr(struct habana_dmabuf *dmabuf)
{
	if (!dmabuf)
		return NULL;

	return dmabuf->addr;
}
