/*
 * Copyright (c) 2018 Mellanox Technologies, Ltd.  All rights reserved.
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
#ifdef _STATIC_LIBRARY_BUILD_
#define RDMA_STATIC_PROVIDERS none
#include <infiniband/verbs.h>
#include <infiniband/driver.h>
#include <infiniband/all_providers.h>

/* When static linking this object will be included in the final link only if
 * something refers to the 'verbs_provider_all' symbol. It in turn brings all
 * the providers into the link as well. Otherwise the static linker will not
 * include this. It is important this is the only thing in this file.
 */
#define FOR_PROVIDER(x) &verbs_provider_ ## x,
static const struct verbs_device_ops *all_providers[] = {
	FOR_EACH_PROVIDER()
	NULL
};

const struct verbs_device_ops verbs_provider_all = {
	.static_providers = all_providers,
};

#endif
