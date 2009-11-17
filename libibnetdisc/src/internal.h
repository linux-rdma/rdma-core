/*
 * Copyright (c) 2008 Lawrence Livermore National Laboratory
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

/** =========================================================================
 * Define the internal data structures.
 */

#ifndef _INTERNAL_H_
#define _INTERNAL_H_

#include <infiniband/ibnetdisc.h>

#define	IBND_DEBUG(fmt, ...) \
	if (ibdebug) { \
		printf("%s:%u; " fmt, __FILE__, __LINE__, ## __VA_ARGS__); \
	}
#define	IBND_ERROR(fmt, ...) \
		fprintf(stderr, "%s:%u; " fmt, __FILE__, __LINE__, ## __VA_ARGS__)

/* HASH table defines */
#define HASHGUID(guid) ((uint32_t)(((uint32_t)(guid) * 101) ^ ((uint32_t)((guid) >> 32) * 103)))

#define MAXHOPS         63

typedef struct ibnd_node_scan {
	ibnd_node_t *node;
	struct ibnd_node_scan *dnext;	/* nodesdist next */
} ibnd_node_scan_t;

typedef struct ibnd_scan {
	ibnd_node_scan_t *nodesdist[MAXHOPS + 1];
	ib_portid_t selfportid;
} ibnd_scan_t;

#endif				/* _INTERNAL_H_ */
