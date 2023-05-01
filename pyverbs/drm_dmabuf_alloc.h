/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright 2020 Intel Corporation. All rights reserved. See COPYING file
 */

#ifndef _DRM_DMABUF_ALLOC_H_
#define _DRM_DMABUF_ALLOC_H_

#include <stdint.h>

struct drm_dmabuf;

struct drm_dmabuf *drm_dmabuf_alloc(uint64_t size, int gpu, int gtt);
void drm_dmabuf_free(struct drm_dmabuf *dmabuf);
int drm_dmabuf_get_buf_fd(struct drm_dmabuf *dmabuf);
int drm_dmabuf_get_device_fd(struct drm_dmabuf *dmabuf);
uint64_t drm_dmabuf_get_offset(struct drm_dmabuf *dmabuf);

#endif /* _DRM_DMABUF_ALLOC_H_ */
