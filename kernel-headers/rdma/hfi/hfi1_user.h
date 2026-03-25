/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/*
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2015 - 2020 Intel Corporation.
 * Copyright 2025 Cornelis Networks.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * BSD LICENSE
 *
 * Copyright(c) 2015 Intel Corporation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  - Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  - Neither the name of Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _LINUX__HFI1_USER_H
#define _LINUX__HFI1_USER_H

#include <linux/types.h>
#include <rdma/rdma_user_ioctl.h>
#include <rdma/hfi2-abi.h>

#define HFI1_USER_SWMAJOR HFI2_USER_SWMAJOR
#define HFI1_USER_SWMINOR HFI2_USER_SWMINOR
#define HFI1_SWMAJOR_SHIFT HFI2_SWMAJOR_SHIFT

#define HFI1_CAP_DMA_RTAIL        HFI2_CAP_DMA_RTAIL
#define HFI1_CAP_SDMA             HFI2_CAP_SDMA
#define HFI1_CAP_SDMA_AHG         HFI2_CAP_SDMA_AHG
#define HFI1_CAP_EXTENDED_PSN     HFI2_CAP_EXTENDED_PSN
#define HFI1_CAP_HDRSUPP          HFI2_CAP_HDRSUPP
#define HFI1_CAP_TID_RDMA         HFI2_CAP_TID_RDMA
#define HFI1_CAP_USE_SDMA_HEAD    HFI2_CAP_USE_SDMA_HEAD
#define HFI1_CAP_MULTI_PKT_EGR    HFI2_CAP_MULTI_PKT_EGR
#define HFI1_CAP_NODROP_RHQ_FULL  HFI2_CAP_NODROP_RHQ_FULL
#define HFI1_CAP_NODROP_EGR_FULL  HFI2_CAP_NODROP_EGR_FULL
#define HFI1_CAP_TID_UNMAP        HFI2_CAP_TID_UNMAP
#define HFI1_CAP_PRINT_UNIMPL     HFI2_CAP_PRINT_UNIMPL
#define HFI1_CAP_ALLOW_PERM_JKEY  HFI2_CAP_ALLOW_PERM_JKEY
#define HFI1_CAP_NO_INTEGRITY     HFI2_CAP_NO_INTEGRITY
#define HFI1_CAP_PKEY_CHECK       HFI2_CAP_PKEY_CHECK
#define HFI1_CAP_STATIC_RATE_CTRL HFI2_CAP_STATIC_RATE_CTRL
#define HFI1_CAP_OPFN             HFI2_CAP_OPFN
#define HFI1_CAP_SDMA_HEAD_CHECK  HFI2_CAP_SDMA_HEAD_CHECK
#define HFI1_CAP_EARLY_CREDIT_RETURN HFI2_CAP_EARLY_CREDIT_RETURN
#define HFI1_CAP_AIP              HFI2_CAP_AIP

#define HFI1_RCVHDR_ENTSIZE_2    HFI2_RCVHDR_ENTSIZE_2
#define HFI1_RCVHDR_ENTSIZE_16   HFI2_RCVHDR_ENTSIZE_16
#define HFI1_RCVDHR_ENTSIZE_32   HFI2_RCVHDR_ENTSIZE_32

#define _HFI1_EVENT_FROZEN_BIT		_HFI2_EVENT_FROZEN_BIT
#define _HFI1_EVENT_LINKDOWN_BIT	_HFI2_EVENT_LINKDOWN_BIT
#define _HFI1_EVENT_LID_CHANGE_BIT	_HFI2_EVENT_LID_CHANGE_BIT
#define _HFI1_EVENT_LMC_CHANGE_BIT      _HFI2_EVENT_LMC_CHANGE_BIT
#define _HFI1_EVENT_SL2VL_CHANGE_BIT    _HFI2_EVENT_SL2VL_CHANGE_BIT
#define _HFI1_EVENT_TID_MMU_NOTIFY_BIT  _HFI2_EVENT_TID_MMU_NOTIFY_BIT
#define _HFI1_MAX_EVENT_BIT _HFI2_EVENT_TID_MMU_NOTIFY_BIT

#define HFI1_EVENT_FROZEN            HFI2_EVENT_FROZEN
#define HFI1_EVENT_LINKDOWN          HFI2_EVENT_LINKDOWN
#define HFI1_EVENT_LID_CHANGE        HFI2_EVENT_LID_CHANGE
#define HFI1_EVENT_LMC_CHANGE        HFI2_EVENT_LMC_CHANGE
#define HFI1_EVENT_SL2VL_CHANGE      HFI2_EVENT_SL2VL_CHANGE
#define HFI1_EVENT_TID_MMU_NOTIFY    HFI2_EVENT_TID_MMU_NOTIFY

#define HFI1_STATUS_INITTED       HFI2_STATUS_INITTED
#define HFI1_STATUS_CHIP_PRESENT HFI2_STATUS_CHIP_PRESENT
#define HFI1_STATUS_IB_READY     HFI2_STATUS_IB_READY
#define HFI1_STATUS_IB_CONF      HFI2_STATUS_IB_CONF
#define HFI1_STATUS_HWERROR     HFI2_STATUS_HWERROR

#define HFI1_MAX_SHARED_CTXTS HFI2_MAX_SHARED_CTXTS

#define HFI1_POLL_TYPE_ANYRCV     HFI2_POLL_TYPE_ANYRCV
#define HFI1_POLL_TYPE_URGENT     HFI2_POLL_TYPE_URGENT

#define hfi1_sdma_comp_state hfi2_sdma_comp_state
#define hfi1_sdma_comp_entry hfi2_sdma_comp_entry


#define HFI1_SDMA_REQ_VERSION_MASK HFI2_SDMA_REQ_VERSION_MASK
#define HFI1_SDMA_REQ_VERSION_SHIFT HFI2_SDMA_REQ_VERSION_SHIFT
#define HFI1_SDMA_REQ_OPCODE_MASK HFI2_SDMA_REQ_OPCODE_MASK
#define HFI1_SDMA_REQ_OPCODE_SHIFT HFI2_SDMA_REQ_OPCODE_SHIFT
#define HFI1_SDMA_REQ_IOVCNT_MASK HFI2_SDMA_REQ_IOVCNT_MASK
#define HFI1_SDMA_REQ_IOVCNT_SHIFT HFI2_SDMA_REQ_IOVCNT_SHIFT

#define hfi1_kdeth_header hfi2_kdeth_header
#define hfi1_pkt_header hfi2_pkt_header
#define hfi1_ureg hfi2_ureg

#endif /* _LINIUX__HFI1_USER_H */
