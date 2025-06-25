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
#ifndef ZXDH_USER_IOCTL_VERBS_H
#define ZXDH_USER_IOCTL_VERBS_H

#include <linux/types.h>
#include <stdbool.h>

//todo ailgn
struct zxdh_query_qpc_resp {
	__u8 retry_flag;
	__u8 rnr_retry_flag;
	__u8 read_retry_flag;
	__u8 cur_retry_count;
	__u8 retry_cqe_sq_opcode;
	__u8 err_flag;
	__u8 ack_err_flag;
	__u8 package_err_flag;
	__u8 recv_err_flag;
	__u8 retry_count;
	__u32 tx_last_ack_psn;
};

struct zxdh_modify_qpc_req {
	__u8 retry_flag;
	__u8 rnr_retry_flag;
	__u8 read_retry_flag;
	__u8 cur_retry_count;
	__u8 retry_cqe_sq_opcode;
	__u8 err_flag;
	__u8 ack_err_flag;
	__u8 package_err_flag;
};

#endif
