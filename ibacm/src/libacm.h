/*
 * Copyright (c) 2009 Intel Corporation.  All rights reserved.
 * Copyright (c) 2013 Mellanox Technologies LTD. All rights reserved.
 *
 * This software is available to you under the OpenIB.org BSD license
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

#ifndef LIBACM_H
#define LIBACM_H

#include <infiniband/acm.h>

struct sockaddr;

int ib_acm_connect(char *dest_svc);
void ib_acm_disconnect(void);

int ib_acm_resolve_name(char *src, char *dest,
	struct ibv_path_data **paths, int *count, uint32_t flags,
	int print);
int ib_acm_resolve_ip(struct sockaddr *src, struct sockaddr *dest,
	struct ibv_path_data **paths, int *count, uint32_t flags,
	int print);
int ib_acm_resolve_path(struct ibv_path_record *path, uint32_t flags);
#define ib_acm_free_paths(paths) free(paths)

int ib_acm_query_perf(int index, uint64_t **counters, int *count);
int ib_acm_query_perf_ep_addr(uint8_t *src, uint8_t type,
			      uint64_t **counters, int *count);
#define ib_acm_free_perf(counters) free(counters)

const char *ib_acm_cntr_name(int index);

int ib_acm_enum_ep(int index, struct acm_ep_config_data **data, uint8_t port);
#define ib_acm_free_ep_data(data) free(data)

#endif /* LIBACM_H */
