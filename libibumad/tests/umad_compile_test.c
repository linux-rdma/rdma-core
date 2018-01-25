/*
 * Copyright (c) 2017 Mellanox Technologies LTD. All rights reserved.
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
 *
 */

#include <config.h>

#include <stddef.h>
#include <endian.h>
#include <ccan/build_assert.h>
#include <infiniband/umad.h>
#include <infiniband/umad_types.h>
#include <infiniband/umad_sm.h>
#include <infiniband/umad_sa.h>
#include <infiniband/umad_cm.h>

int main(int argc, char *argv[])
{
#ifndef __CHECKER__
	/*
	 * Hide these checks for sparse because these checks fail with
	 * older versions of sparse.
	 */
	BUILD_ASSERT(__alignof__(union umad_gid) == 4);
#endif

	/* umad_types.h structure checks */
	BUILD_ASSERT(sizeof(struct umad_hdr) == 24);
	BUILD_ASSERT(sizeof(struct umad_rmpp_hdr) == 12);
	BUILD_ASSERT(sizeof(struct umad_packet) == 256);
	BUILD_ASSERT(sizeof(struct umad_rmpp_packet) == 256);
	BUILD_ASSERT(sizeof(struct umad_dm_packet) == 256);
	BUILD_ASSERT(sizeof(struct umad_vendor_packet) == 256);
	BUILD_ASSERT(sizeof(struct umad_class_port_info) == 72);
	BUILD_ASSERT(offsetof(struct umad_class_port_info, redirgid) == 8);
	BUILD_ASSERT(offsetof(struct umad_class_port_info, trapgid) == 40);

	/* umad_sm.h structure check */
	BUILD_ASSERT(sizeof(struct umad_smp) == 256);

	/* umad_sa.h structure check */
	BUILD_ASSERT(sizeof(struct umad_sa_packet) == 256);

	return 0;
}
