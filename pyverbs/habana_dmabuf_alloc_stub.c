// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright 2023 Amazon.com, Inc. or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include "habana_dmabuf_alloc.h"

struct habana_dmabuf *habana_dmabuf_alloc(unsigned long size)
{
	errno = EOPNOTSUPP;
	return NULL;
}

void habana_dmabuf_free(struct habana_dmabuf *dmabuf)
{
	errno = EOPNOTSUPP;
}

int habana_dmabuf_get_buf_fd(struct habana_dmabuf *dmabuf)
{
	errno = EOPNOTSUPP;
	return -1;
}

int habana_dmabuf_get_device_fd(struct habana_dmabuf *dmabuf)
{
	errno = EOPNOTSUPP;
	return -1;
}

void *habana_dmabuf_get_addr(struct habana_dmabuf *dmabuf)
{
	errno = EOPNOTSUPP;
	return NULL;
}
