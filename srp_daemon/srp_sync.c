/*
 * srp_sync - discover SRP targets over IB
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2006 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2006 Mellanox Technologies Ltd.  All rights reserved.
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
 * $Author: ishai Rabinovitz [ishai@mellanox.co.il]$
 */

#include <pthread.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "srp_daemon.h"

int sync_resources_init(struct sync_resources *res)
{
	int ret;

	res->stop_threads = 0;
	res->recalc = 1;
	res->next_task = 0;
	ret = pthread_mutex_init(&res->mutex, NULL);
	if (ret < 0) {
		pr_err("coult not initilize mutex\n");
		return ret;
	}
	ret = pthread_cond_init(&res->cond, NULL);
	if (ret < 0)
		pr_err("coult not initilize cond\n");

	res->retry_tasks_head = NULL;
	ret = pthread_mutex_init(&res->retry_mutex, NULL);
	if (ret < 0) {
		pr_err("coult not initilize mutex\n");
		return ret;
	}
	ret = pthread_cond_init(&res->retry_cond, NULL);
	if (ret < 0)
		pr_err("coult not initilize cond\n");

	return ret;
}

void push_gid_to_list(struct sync_resources *res, ib_gid_t *gid)
{
	int i;

	/* If there is going to be a recalc soon - do nothing */
	if (res->recalc)
		return;

	pthread_mutex_lock(&res->mutex);

	/* check if the gid is already in the list */

	for (i=0; i < res->next_task; ++i)
		if (!memcmp(&res->tasks[i].gid, gid, 16)) {
			pr_debug("gid is already in task list\n");
			pthread_mutex_unlock(&res->mutex);
			return;
		}

	if (res->next_task == SIZE_OF_TASKS_LIST) {
		/* if the list is full, lets do a full rescan */

		res->recalc = 1;
		res->next_task = 0;
	} else {
		/* otherwise enter to the next entry */

		res->tasks[res->next_task].gid = *gid;
		res->tasks[res->next_task].lid = 0;
		++res->next_task;
	}

	pthread_cond_signal(&res->cond);
	pthread_mutex_unlock(&res->mutex);
}

void push_lid_to_list(struct sync_resources *res, uint16_t lid)
{
	int i;

	/* If there is going to be a recalc soon - do nothing */
	if (res->recalc)
		return;

	pthread_mutex_lock(&res->mutex);


	/* check if the lid is already in the list */

	for (i=0; i < res->next_task; ++i)
		if (res->tasks[i].lid == lid) {
			pr_debug("lid %d is already in task list\n", lid);
			pthread_mutex_unlock(&res->mutex);
			return;
		}

	if (res->next_task == SIZE_OF_TASKS_LIST) {
		/* if the list is full, lets do a full rescan */

		res->recalc = 1;
		res->next_task = 0;
	} else {
		/* otherwise enter to the next entry */

		res->tasks[res->next_task].lid = lid;
		memset(&res->tasks[res->next_task].gid, 0, 16);
		++res->next_task;
	}

	pthread_cond_signal(&res->cond);
	pthread_mutex_unlock(&res->mutex);
}

void clear_traps_list(struct sync_resources *res)
{
	pthread_mutex_lock(&res->mutex);
	res->next_task = 0;
	pthread_mutex_unlock(&res->mutex);
}


/* assumes that res->mutex is locked !!! */
int pop_from_list(struct sync_resources *res, uint16_t *lid, ib_gid_t *gid)
{
	int ret=0;
	int i;

	if (res->next_task) {
		*lid = res->tasks[0].lid;
		*gid = res->tasks[0].gid;
		/* push the rest down */
		for (i=1; i < res->next_task; ++i)
			res->tasks[i-1] = res->tasks[i];
		ret = 1;
		--res->next_task;
	}

	return ret;
}


/* assumes that res->retry_mutex is locked !!! */
struct target_details *pop_from_retry_list(struct sync_resources *res)
{
	struct target_details *ret = res->retry_tasks_head;

	if (ret)
		res->retry_tasks_head = ret->next;
	else
		res->retry_tasks_tail = NULL;

	return ret;
}

void push_to_retry_list(struct sync_resources *res,
			struct target_details *orig_target)
{
	struct target_details *target;

	/* If there is going to be a recalc soon - do nothing */
	if (res->recalc)
		return;

	target = malloc(sizeof(struct target_details));
	memcpy(target, orig_target, sizeof(struct target_details));

	pthread_mutex_lock(&res->retry_mutex);

	if (!res->retry_tasks_head)
		res->retry_tasks_head = target;

	if (res->retry_tasks_tail)
		res->retry_tasks_tail->next = target;

	res->retry_tasks_tail = target;

	target->next = NULL;

	pthread_cond_signal(&res->retry_cond);
	pthread_mutex_unlock(&res->retry_mutex);
}

/* assumes that res->retry_mutex is locked !!! */
int retry_list_is_empty(struct sync_resources *res)
{
	return res->retry_tasks_head == NULL;
}
