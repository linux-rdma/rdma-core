/*
 * Copyright (c) 2016 Hisilicon Limited.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/types.h>

#include "hns_roce_u.h"

#ifndef _HNS_ROCE_U_DB_H
#define _HNS_ROCE_U_DB_H

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define HNS_ROCE_PAIR_TO_64(val) ((uint64_t) val[1] << 32 | val[0])
#elif __BYTE_ORDER == __BIG_ENDIAN
#define HNS_ROCE_PAIR_TO_64(val) ((uint64_t) val[0] << 32 | val[1])
#else
#error __BYTE_ORDER not defined
#endif

static inline void hns_roce_write64(uint32_t val[2],
				    struct hns_roce_context *ctx, int offset)
{
	*(volatile uint64_t *) (ctx->uar + offset) = HNS_ROCE_PAIR_TO_64(val);
}

void *hns_roce_alloc_db(struct hns_roce_context *ctx,
			enum hns_roce_db_type type);
void hns_roce_free_db(struct hns_roce_context *ctx, unsigned int *db,
		      enum hns_roce_db_type type);

#endif /* _HNS_ROCE_U_DB_H */
