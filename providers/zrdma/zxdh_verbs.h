/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR Linux-OpenIB) */
/*
 * Copyright (c) 2024 ZTE Corporation.
 *
 * This software is available to you under a choice of one of two
 * licenses. You may choose to be licensed under the terms of the GNU
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
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef __ZXDH_VERBS_H__
#define __ZXDH_VERBS_H__

struct zxdh_dev_attrs {
	__u64 feature_flags;
	__aligned_u64 sq_db_pa;
	__aligned_u64 cq_db_pa;
	__u32 max_hw_wq_frags;
	__u32 max_hw_read_sges;
	__u32 max_hw_inline;
	__u32 max_hw_rq_quanta;
	__u32 max_hw_srq_quanta;
	__u32 max_hw_wq_quanta;
	__u32 min_hw_cq_size;
	__u32 max_hw_cq_size;
	__u16 max_hw_sq_chunk;
	__u32 max_hw_srq_wr;
	__u8 db_addr_type;
	__u8 chip_rev;
	__u16 rdma_tool_flags;
};

#endif /* __ZXDH_VERBS_H__ */
