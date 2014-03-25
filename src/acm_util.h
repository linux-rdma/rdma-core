/*
 * Copyright (c) 2014 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under the OpenFabrics.org BSD license
 * below:
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
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AWV
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#if !defined(ACM_IF_H)
#define ACM_IF_H

#include <infiniband/verbs.h>

#ifdef ACME_PRINTS

#define acm_log(level, format, ...) \
	printf(format, ## __VA_ARGS__)

#else /* !ACME_PRINTS */
#define acm_log(level, format, ...) \
	acm_write(level, "%s: "format, __func__, ## __VA_ARGS__)

void acm_write(int level, const char *format, ...);
#endif /* ACME_PRINTS */

int acm_if_is_ib(char *ifname);
int acm_if_get_pkey(char *ifname, uint16_t *pkey);
int acm_if_get_sgid(char *ifname, union ibv_gid *sgid);

typedef void (*acm_if_iter_cb)(char *ifname, union ibv_gid *gid, uint16_t pkey,
				uint8_t addr_type, uint8_t *addr, size_t addr_len,
				char *addr_name, void *ctx);
int acm_if_iter_sys(acm_if_iter_cb cb, void *ctx);

#endif /* ACM_IF_H */
