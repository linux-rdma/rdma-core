/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright 2023 Amazon.com, Inc. or its affiliates. All rights reserved.
 */

#ifndef _HABANA_DMABUF_ALLOC_H_
#define _HABANA_DMABUF_ALLOC_H_

#include <stdint.h>

struct habana_dmabuf;

struct habana_dmabuf *habana_dmabuf_alloc(unsigned long size);
void habana_dmabuf_free(struct habana_dmabuf *dmabuf);
int habana_dmabuf_get_buf_fd(struct habana_dmabuf *dmabuf);
int habana_dmabuf_get_device_fd(struct habana_dmabuf *dmabuf);
void *habana_dmabuf_get_addr(struct habana_dmabuf *dmabuf);

#endif /* _HABANA_DMABUF_ALLOC_H_ */
