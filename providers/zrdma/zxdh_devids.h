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
#ifndef __ZXDH_DEVIDS_H__
#define __ZXDH_DEVIDS_H__

/* ZXDH VENDOR ID */
#define PCI_VENDOR_ID_ZXDH_EVB 0x16c3
#define PCI_VENDOR_ID_ZXDH_E312 0x1cf2
#define PCI_VENDOR_ID_ZXDH_E310 0x1cf2
#define PCI_VENDOR_ID_ZXDH_E310_RDMA 0x1cf2
#define PCI_VENDOR_ID_ZXDH_E316 0x1cf2
#define PCI_VENDOR_ID_ZXDH_X512 0x1cf2
/* ZXDH Devices ID */
#define ZXDH_DEV_ID_ADAPTIVE_EVB_PF 0x8040 /* ZXDH EVB PF DEVICE ID*/
#define ZXDH_DEV_ID_ADAPTIVE_EVB_VF 0x8041 /* ZXDH EVB VF DEVICE ID*/
#define ZXDH_DEV_ID_ADAPTIVE_E312_PF 0x8049 /* ZXDH E312 PF DEVICE ID*/
#define ZXDH_DEV_ID_ADAPTIVE_E312_VF 0x8060 /* ZXDH E312 VF DEVICE ID*/
#define ZXDH_DEV_ID_ADAPTIVE_E310_PF 0x8061 /* ZXDH E310 PF DEVICE ID*/
#define ZXDH_DEV_ID_ADAPTIVE_E310_VF 0x8062 /* ZXDH E310 VF DEVICE ID*/
#define ZXDH_DEV_ID_ADAPTIVE_E310_RDMA_PF 0x8084 /* ZXDH E310_RDMA PF DEVICE ID*/
#define ZXDH_DEV_ID_ADAPTIVE_E310_RDMA_VF 0x8085 /* ZXDH E310_RDMA VF DEVICE ID*/
#define ZXDH_DEV_ID_ADAPTIVE_E316_PF 0x807e /* ZXDH E316 PF DEVICE ID*/
#define ZXDH_DEV_ID_ADAPTIVE_E316_VF 0x807f /* ZXDH E316 VF DEVICE ID*/
#define ZXDH_DEV_ID_ADAPTIVE_X512_PF 0x806B /* ZXDH X512 PF DEVICE ID*/
#define ZXDH_DEV_ID_ADAPTIVE_X512_VF 0x806C /* ZXDH X512 VF DEVICE ID*/
#endif /* __ZXDH_DEVIDS_H__ */
