// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2018-2025 Advanced Micro Devices, Inc.  All rights reserved.
 */

#include <infiniband/driver.h>
#include <sys/mman.h>

#include "ionic_memory.h"

#define IONIC_ANON_MFLAGS	(MAP_PRIVATE | MAP_ANONYMOUS)
#define IONIC_ANON_MPROT	(PROT_READ | PROT_WRITE)

#define IONIC_DEV_MFLAGS	MAP_SHARED
#define IONIC_DEV_MPROT		PROT_WRITE

void *ionic_map_anon(size_t size)
{
	void *ptr;
	int rc;

	ptr = mmap(NULL, size, IONIC_ANON_MPROT, IONIC_ANON_MFLAGS, -1, 0);
	if (ptr == MAP_FAILED)
		return NULL;

	rc = ibv_dontfork_range(ptr, size);
	if (rc) {
		munmap(ptr, size);
		errno = rc;
		return NULL;
	}

	return ptr;
}

void *ionic_map_device(size_t size, int fd, size_t offset)
{
	void *ptr;
	int rc;

	ptr = mmap(NULL, size, IONIC_DEV_MPROT, IONIC_DEV_MFLAGS, fd, offset);
	if (ptr == MAP_FAILED)
		return NULL;

	rc = ibv_dontfork_range(ptr, size);
	if (rc) {
		munmap(ptr, size);
		errno = rc;
		return NULL;
	}

	return ptr;
}

void ionic_unmap(void *ptr, size_t size)
{
	if (ptr) {
		ibv_dofork_range(ptr, size);
		munmap(ptr, size);
	}
}
