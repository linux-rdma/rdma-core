/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright 2020 Intel Corporation. All rights reserved. See COPYING file
 */

#ifndef _DMABUF_ALLOC_H_
#define _DMABUF_ALLOC_H_

#include <stdint.h>

struct dmabuf;

struct dmabuf *dmabuf_alloc(uint64_t size, int gpu, int gtt);
void dmabuf_free(struct dmabuf *dmabuf);
int dmabuf_get_drm_fd(struct dmabuf *dmabuf);
int dmabuf_get_fd(struct dmabuf *dmabuf);
uint64_t dmabuf_get_offset(struct dmabuf *dmabuf);

#endif /* _DMABUF_ALLOC_H_ */
