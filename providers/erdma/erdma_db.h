/* SPDX-License-Identifier: GPL-2.0 or OpenIB.org BSD (MIT) See COPYING file */
/*
 * Authors: Cheng Xu <chengyou@linux.alibaba.com>
 * Copyright (c) 2020-2021, Alibaba Group.
 */

#ifndef __ERDMA_DB_H__
#define __ERDMA_DB_H__

#include <inttypes.h>

#include "erdma.h"

uint64_t *erdma_alloc_dbrecords(struct erdma_context *ctx);
void erdma_dealloc_dbrecords(struct erdma_context *ctx, uint64_t *dbrecords);

#endif
