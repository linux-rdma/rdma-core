/*******************************************************************************
*
* Copyright (c) 2015-2016 Intel Corporation.  All rights reserved.
*
* This software is available to you under a choice of one of two
* licenses.  You may choose to be licensed under the terms of the GNU
* General Public License (GPL) Version 2, available from the file
* COPYING in the main directory of this source tree, or the
* OpenFabrics.org BSD license below:
*
*   Redistribution and use in source and binary forms, with or
*   without modification, are permitted provided that the following
*   conditions are met:
*
*    - Redistributions of source code must retain the above
*	copyright notice, this list of conditions and the following
*	disclaimer.
*
*    - Redistributions in binary form must reproduce the above
*	copyright notice, this list of conditions and the following
*	disclaimer in the documentation and/or other materials
*	provided with the distribution.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
* NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
* BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
* ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
* CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*
*******************************************************************************/

#ifndef I40IW_OSDEP_H
#define I40IW_OSDEP_H

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <util/udma_barrier.h>
#include <linux/types.h>
typedef unsigned char u8;
typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned long i40iw_uintptr;
typedef unsigned long *i40iw_bits_t;
typedef __be16 BE16;
typedef __be32 BE32;
typedef __be64 BE64;
typedef __le16 LE16;
typedef __le32 LE32;
typedef __le64 LE64;

#define STATS_TIMER_DELAY 1000
#define INLINE inline

static inline void set_64bit_val(u64 *wqe_words, u32 byte_index, u64 value)
{
	wqe_words[byte_index >> 3] = value;
}

/**
 * set_32bit_val - set 32 value to hw wqe
 * @wqe_words: wqe addr to write
 * @byte_index: index in wqe
 * @value: value to write
 **/
static inline void set_32bit_val(u32 *wqe_words, u32 byte_index, u32 value)
{
	wqe_words[byte_index >> 2] = value;
}

/**
 * get_64bit_val - read 64 bit value from wqe
 * @wqe_words: wqe addr
 * @byte_index: index to read from
 * @value: read value
 **/
static inline void get_64bit_val(u64 *wqe_words, u32 byte_index, u64 *value)
{
	*value = wqe_words[byte_index >> 3];
}

/**
 * get_32bit_val - read 32 bit value from wqe
 * @wqe_words: wqe addr
 * @byte_index: index to reaad from
 * @value: return 32 bit value
 **/
static inline void get_32bit_val(u32 *wqe_words, u32 byte_index, u32 *value)
{
	*value = wqe_words[byte_index >> 2];
}

#define i40iw_get_virt_to_phy
#define IOMEM

static inline void db_wr32(u32 value, u32 *wqe_word)
{
	*wqe_word = value;
}

#define ACQUIRE_LOCK()
#define RELEASE_LOCK()

#endif				/* _I40IW_OSDEP_H_ */
