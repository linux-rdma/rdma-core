// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright 2021 Intel Corporation. All rights reserved. See COPYING file
 */

#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include "dmabuf_alloc.h"

struct dmabuf *dmabuf_alloc(uint64_t size, int gpu, int gtt)
{
	errno = EOPNOTSUPP;
	return NULL;
}

void dmabuf_free(struct dmabuf *dmabuf)
{
	errno = EOPNOTSUPP;
}

int dmabuf_get_drm_fd(struct dmabuf *dmabuf)
{
	errno = EOPNOTSUPP;
	return -1;
}

int dmabuf_get_fd(struct dmabuf *dmabuf)
{
	errno = EOPNOTSUPP;
	return -1;
}

uint64_t dmabuf_get_offset(struct dmabuf *dmabuf)
{
	errno = EOPNOTSUPP;
	return -1;
}

