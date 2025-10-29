// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 - 2022, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <config.h>

#include <signal.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "util/util.h"
#include "xscale.h"

int xsc_alloc_buf(struct xsc_buf *buf, size_t size, int page_size)
{
	int ret;
	int al_size;

	al_size = align(size, page_size);
	ret = posix_memalign(&buf->buf, page_size, al_size);
	if (ret)
		return ret;

	ret = ibv_dontfork_range(buf->buf, al_size);
	if (ret)
		free(buf->buf);

	buf->length = al_size;

	return ret;
}

void xsc_free_buf(struct xsc_buf *buf)
{
	ibv_dofork_range(buf->buf, buf->length);
	free(buf->buf);
}
