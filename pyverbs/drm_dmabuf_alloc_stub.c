// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright 2021 Intel Corporation. All rights reserved. See COPYING file
 */

#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include "drm_dmabuf_alloc.h"

struct drm_dmabuf *drm_dmabuf_alloc(uint64_t size, int gpu, int gtt)
{
	errno = EOPNOTSUPP;
	return NULL;
}

void drm_dmabuf_free(struct drm_dmabuf *dmabuf)
{
	errno = EOPNOTSUPP;
}

int drm_dmabuf_get_buf_fd(struct drm_dmabuf *dmabuf)
{
	errno = EOPNOTSUPP;
	return -1;
}

int drm_dmabuf_get_device_fd(struct drm_dmabuf *dmabuf)
{
	errno = EOPNOTSUPP;
	return -1;
}

uint64_t drm_dmabuf_get_offset(struct drm_dmabuf *dmabuf)
{
	errno = EOPNOTSUPP;
	return -1;
}

