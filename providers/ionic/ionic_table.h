/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2018-2025 Advanced Micro Devices, Inc.  All rights reserved.
 */

#ifndef IONIC_TABLE_H
#define IONIC_TABLE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

/* Number of valid bits in a key */
#define TBL_KEY_SHIFT           24

/* Number bits used for index in a node */
#define TBL_NODE_SHIFT          12

#define TBL_NODE_MASK           (BIT(TBL_NODE_SHIFT) - 1u)
#define TBL_NODE_CAPACITY       BIT(TBL_NODE_SHIFT)
#define TBL_ROOT_CAPACITY       BIT(TBL_KEY_SHIFT - TBL_NODE_SHIFT)

struct ionic_tbl_node {
	void			*val[TBL_NODE_CAPACITY];
};

struct ionic_tbl_root {
	/* for lookup in table */
	struct ionic_tbl_node	*node[TBL_ROOT_CAPACITY];

	/* for insertion and deletion in table */
	int			refcount[TBL_ROOT_CAPACITY];
	struct ionic_tbl_node	*free_node;
};

/**
 * ionic_tbl_init() - Initialize a table
 * @tbl:	Table root
 */
static inline void ionic_tbl_init(struct ionic_tbl_root *tbl)
{
	uint32_t node_i;

	tbl->free_node = NULL;

	for (node_i = 0; node_i < TBL_ROOT_CAPACITY; ++node_i) {
		tbl->node[node_i] = NULL;
		tbl->refcount[node_i] = 0;
	}
}

/**
 * ionic_tbl_init() - Destroy the table, which should be empty
 * @tbl:	Table root
 */
static inline void ionic_tbl_destroy(struct ionic_tbl_root *tbl)
{
	uint32_t node_i;

	/* The table should be empty.  If not empty, it means the context is
	 * being destroyed, but there are qps still in the table that have not
	 * been destroyed.
	 *
	 * The interface is such that freeing the context must succeed, so here
	 * will make a best effort to free table resources.  Any qps that were
	 * not destroyed, however will still refer to the context after it is
	 * freed.  Those qps must not be used, not even for ibv_destroy_qp, or
	 * the application will likely crash.
	 *
	 * This best-effort freeing of resources replaces an assert.  The
	 * assert was seen in perftest, which will destroy the context even if
	 * there is an error destroying a qp or other resource.
	 */
	for (node_i = 0; node_i < TBL_ROOT_CAPACITY; ++node_i) {
		if (!tbl->node[node_i])
			continue;

		free(tbl->node[node_i]);
	}

	free(tbl->free_node);
}

/**
 * ionic_tbl_lookup() - Lookup value for key in the table
 * @tbl:	Table root
 * @key:	Key for lookup
 *
 * Synopsis:
 *
 * pthread_spin_lock(&my_table_lock);
 * val = ionic_tbl_lookup(&my_table, key);
 * if (val)
 *     my_val_routine(val);
 * pthread_spin_unlock(&my_table_lock);
 *
 * Return: Value for key
 */
static inline void *ionic_tbl_lookup(struct ionic_tbl_root *tbl, uint32_t key)
{
	uint32_t node_i = key >> TBL_NODE_SHIFT;

	if (unlikely(key >> TBL_KEY_SHIFT))
		return NULL;

	if (unlikely(!tbl->node[node_i]))
		return NULL;

	return tbl->node[node_i]->val[key & TBL_NODE_MASK];
}

/**
 * ionic_tbl_alloc_node() - Allocate the free node prior to insertion
 * @tbl:	Table root
 *
 * This should be called before inserting.
 *
 * Synopsis: see ionic_tbl_insert()
 */
static inline void ionic_tbl_alloc_node(struct ionic_tbl_root *tbl)
{
	if (!tbl->free_node)
		tbl->free_node = calloc(1, sizeof(*tbl->free_node));
}

/**
 * ionic_tbl_free_node() - Free the free node prior to deletion
 * @tbl:	Table root
 *
 * This should be called before deleting.
 *
 * Synopsis: see ionic_tbl_delete()
 */
static inline void ionic_tbl_free_node(struct ionic_tbl_root *tbl)
{
	free(tbl->free_node);
	tbl->free_node = NULL;
}

/**
 * ionic_tbl_insert() - Insert a value for key in the table
 * @tbl:	Table root
 * @val:	Value to insert
 * @key:	Key to insert
 *
 * The tbl->free_node must not be null when inserting.
 *
 * Synopsis:
 *
 * pthread_mutex_lock(&my_table_mut);
 * ionic_tbl_alloc_node(&my_table);
 * ionic_tbl_insert(&my_table, val, key);
 * pthread_mutex_unlock(&my_table_mut);
 *
 * pthread_spin_lock(&my_table_lock);
 * pthread_spin_unlock(&my_table_lock);
 */
static inline void ionic_tbl_insert(struct ionic_tbl_root *tbl,
				    void *val, uint32_t key)
{
	struct ionic_tbl_node	*node;
	uint32_t node_i = key >> TBL_NODE_SHIFT;

	if (unlikely(key >> TBL_KEY_SHIFT)) {
		assert(key >> TBL_KEY_SHIFT == 0);
		return;
	}

	node = tbl->node[node_i];
	if (!node)
		node = tbl->free_node;

	if (unlikely(!node)) {
		assert(node != NULL);
		return;
	}

	/* warning: with NDEBUG the old value will leak */
	assert(node->val[key & TBL_NODE_MASK] == NULL);

	node->val[key & TBL_NODE_MASK] = val;

	if (!tbl->refcount[node_i]) {
		tbl->node[node_i] = node;
		tbl->free_node = NULL;
	}

	++tbl->refcount[node_i];
}

/**
 * ionic_tbl_delete() - Delete the value for key in the table
 * @tbl:	Table root
 * @val:	Value to insert
 * @key:	Key to insert
 *
 * The tbl->free_node must be null when deleting.
 *
 * Synopsis:
 *
 * pthread_mutex_lock(&my_table_mut);
 * ionic_tbl_free_node(&my_table);
 * ionic_tbl_delete(&my_table, key);
 * pthread_mutex_unlock(&my_table_mut);
 *
 * pthread_spin_lock(&my_table_lock);
 * pthread_spin_unlock(&my_table_lock);
 * free(old_val_at_key);
 */
static inline void ionic_tbl_delete(struct ionic_tbl_root *tbl, uint32_t key)
{
	struct ionic_tbl_node	*node;
	uint32_t node_i = key >> TBL_NODE_SHIFT;

	if (unlikely(key >> TBL_KEY_SHIFT)) {
		assert(key >> TBL_KEY_SHIFT == 0);
		return;
	}

	node = tbl->node[node_i];
	if (unlikely(!node)) {
		assert(node != NULL);
		return;
	}

	if (unlikely(!node->val[key & TBL_NODE_MASK])) {
		assert(node->val[key & TBL_NODE_MASK] != NULL);
		return;
	}

	node->val[key & TBL_NODE_MASK] = NULL;

	--tbl->refcount[node_i];

	if (!tbl->refcount[node_i]) {
		/* warning: with NDEBUG the old free node will leak */
		assert(node != NULL);
		tbl->free_node = node;
		tbl->node[node_i] = NULL;
	}
}

#endif /* IONIC_TABLE_H */
