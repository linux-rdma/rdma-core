/*
 * Copyright (c) 2004-2009 Voltaire, Inc. All rights reserved.
 * Copyright (c) 2002-2005 Mellanox Technologies LTD. All rights reserved.
 * Copyright (c) 1996-2003 Intel Corporation. All rights reserved.
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

/*
 * Abstract:
 *	Implementation of quick map, a binary tree where the caller always
 *	provides all necessary storage.
 *
 */

/*****************************************************************************
*
* Map
*
* Map is an associative array.  By providing a key, the caller can retrieve
* an object from the map.  All objects in the map have an associated key,
* as specified by the caller when the object was inserted into the map.
* In addition to random access, the caller can traverse the map much like
* a linked list, either forwards from the first object or backwards from
* the last object.  The objects in the map are always traversed in
* order since the nodes are stored sorted.
*
* This implementation of Map uses a red black tree verified against
* Cormen-Leiserson-Rivest text, McGraw-Hill Edition, fourteenth
* printing, 1994.
*
*****************************************************************************/

#include <util/cl_qmap.h>
#include <string.h>

static inline void __cl_primitive_insert(cl_list_item_t *const p_list_item,
					 cl_list_item_t *const p_new_item)
{
        /* CL_ASSERT that a non-null pointer is provided. */
        assert(p_list_item);
        /* CL_ASSERT that a non-null pointer is provided. */
	assert(p_new_item);

	p_new_item->p_next = p_list_item;
        p_new_item->p_prev = p_list_item->p_prev;
        p_list_item->p_prev = p_new_item;
        p_new_item->p_prev->p_next = p_new_item;
}

static inline void __cl_primitive_remove(cl_list_item_t *const p_list_item)
{
        /* CL_ASSERT that a non-null pointer is provided. */
        assert(p_list_item);

        /* set the back pointer */
        p_list_item->p_next->p_prev = p_list_item->p_prev;
        /* set the next pointer */
        p_list_item->p_prev->p_next = p_list_item->p_next;

        /* if we're debugging, spruce up the pointers to help find bugs */
#if defined( _DEBUG_ )
        if (p_list_item != p_list_item->p_next) {
                p_list_item->p_next = NULL;
                p_list_item->p_prev = NULL;
        }
#endif                          /* defined( _DEBUG_ ) */
}

/******************************************************************************
 IMPLEMENTATION OF QUICK MAP
******************************************************************************/

/*
 * Get the root.
 */
static inline cl_map_item_t *__cl_map_root(const cl_qmap_t * const p_map)
{
	assert(p_map);
	return (p_map->root.p_left);
}

/*
 * Returns whether a given item is on the left of its parent.
 */
static bool __cl_map_is_left_child(const cl_map_item_t * const p_item)
{
	assert(p_item);
	assert(p_item->p_up);
	assert(p_item->p_up != p_item);

	return (p_item->p_up->p_left == p_item);
}

/*
 * Retrieve the pointer to the parent's pointer to an item.
 */
static cl_map_item_t **__cl_map_get_parent_ptr_to_item(cl_map_item_t *
						       const p_item)
{
	assert(p_item);
	assert(p_item->p_up);
	assert(p_item->p_up != p_item);

	if (__cl_map_is_left_child(p_item))
		return (&p_item->p_up->p_left);

	assert(p_item->p_up->p_right == p_item);
	return (&p_item->p_up->p_right);
}

/*
 * Rotate a node to the left.  This rotation affects the least number of links
 * between nodes and brings the level of C up by one while increasing the depth
 * of A one.  Note that the links to/from W, X, Y, and Z are not affected.
 *
 *	    R				      R
 *	    |				      |
 *	    A				      C
 *	  /   \			        /   \
 *	W       C			  A       Z
 *	       / \			 / \
 *	      B   Z			W   B
 *	     / \			   / \
 *	    X   Y			  X   Y
 */
static void __cl_map_rot_left(cl_qmap_t * const p_map,
			      cl_map_item_t * const p_item)
{
	cl_map_item_t **pp_root;

	assert(p_map);
	assert(p_item);
	assert(p_item->p_right != &p_map->nil);

	pp_root = __cl_map_get_parent_ptr_to_item(p_item);

	/* Point R to C instead of A. */
	*pp_root = p_item->p_right;
	/* Set C's parent to R. */
	(*pp_root)->p_up = p_item->p_up;

	/* Set A's right to B */
	p_item->p_right = (*pp_root)->p_left;
	/*
	 * Set B's parent to A.  We trap for B being NIL since the
	 * caller may depend on NIL not changing.
	 */
	if ((*pp_root)->p_left != &p_map->nil)
		(*pp_root)->p_left->p_up = p_item;

	/* Set C's left to A. */
	(*pp_root)->p_left = p_item;
	/* Set A's parent to C. */
	p_item->p_up = *pp_root;
}

/*
 * Rotate a node to the right.  This rotation affects the least number of links
 * between nodes and brings the level of A up by one while increasing the depth
 * of C one.  Note that the links to/from W, X, Y, and Z are not affected.
 *
 *	        R				     R
 *	        |				     |
 *	        C				     A
 *	      /   \				   /   \
 *	    A       Z			 W       C
 *	   / \    				        / \
 *	  W   B   				       B   Z
 *	     / \				      / \
 *	    X   Y				     X   Y
 */
static void __cl_map_rot_right(cl_qmap_t * const p_map,
			       cl_map_item_t * const p_item)
{
	cl_map_item_t **pp_root;

	assert(p_map);
	assert(p_item);
	assert(p_item->p_left != &p_map->nil);

	/* Point R to A instead of C. */
	pp_root = __cl_map_get_parent_ptr_to_item(p_item);
	(*pp_root) = p_item->p_left;
	/* Set A's parent to R. */
	(*pp_root)->p_up = p_item->p_up;

	/* Set C's left to B */
	p_item->p_left = (*pp_root)->p_right;
	/*
	 * Set B's parent to C.  We trap for B being NIL since the
	 * caller may depend on NIL not changing.
	 */
	if ((*pp_root)->p_right != &p_map->nil)
		(*pp_root)->p_right->p_up = p_item;

	/* Set A's right to C. */
	(*pp_root)->p_right = p_item;
	/* Set C's parent to A. */
	p_item->p_up = *pp_root;
}

void cl_qmap_init(cl_qmap_t * const p_map)
{
	assert(p_map);

	memset(p_map, 0, sizeof(cl_qmap_t));

	/* special setup for the root node */
	p_map->root.p_up = &p_map->root;
	p_map->root.p_left = &p_map->nil;
	p_map->root.p_right = &p_map->nil;
	p_map->root.color = CL_MAP_BLACK;

	/* Setup the node used as terminator for all leaves. */
	p_map->nil.p_up = &p_map->nil;
	p_map->nil.p_left = &p_map->nil;
	p_map->nil.p_right = &p_map->nil;
	p_map->nil.color = CL_MAP_BLACK;

	cl_qmap_remove_all(p_map);
}

cl_map_item_t *cl_qmap_get(const cl_qmap_t * const p_map,
			   const uint64_t key)
{
	cl_map_item_t *p_item;

	assert(p_map);

	p_item = __cl_map_root(p_map);

	while (p_item != &p_map->nil) {
		if (key == p_item->key)
			break;	/* just right */

		if (key < p_item->key)
			p_item = p_item->p_left;	/* too small */
		else
			p_item = p_item->p_right;	/* too big */
	}

	return (p_item);
}

cl_map_item_t *cl_qmap_get_next(const cl_qmap_t * const p_map,
				const uint64_t key)
{
	cl_map_item_t *p_item;
	cl_map_item_t *p_item_found;

	assert(p_map);

	p_item = __cl_map_root(p_map);
	p_item_found = (cl_map_item_t *) & p_map->nil;

	while (p_item != &p_map->nil) {
		if (key < p_item->key) {
			p_item_found = p_item;
			p_item = p_item->p_left;
		} else {
			p_item = p_item->p_right;
		}
	}

	return (p_item_found);
}

void cl_qmap_apply_func(const cl_qmap_t * const p_map,
			cl_pfn_qmap_apply_t pfn_func,
			const void *const context)
{
	cl_map_item_t *p_map_item;

	/* Note that context can have any arbitrary value. */
	assert(p_map);
	assert(pfn_func);

	p_map_item = cl_qmap_head(p_map);
	while (p_map_item != cl_qmap_end(p_map)) {
		pfn_func(p_map_item, (void *)context);
		p_map_item = cl_qmap_next(p_map_item);
	}
}

/*
 * Balance a tree starting at a given item back to the root.
 */
static void __cl_map_ins_bal(cl_qmap_t * const p_map,
			     cl_map_item_t * p_item)
{
	cl_map_item_t *p_grand_uncle;

	assert(p_map);
	assert(p_item);
	assert(p_item != &p_map->root);

	while (p_item->p_up->color == CL_MAP_RED) {
		if (__cl_map_is_left_child(p_item->p_up)) {
			p_grand_uncle = p_item->p_up->p_up->p_right;
			assert(p_grand_uncle);
			if (p_grand_uncle->color == CL_MAP_RED) {
				p_grand_uncle->color = CL_MAP_BLACK;
				p_item->p_up->color = CL_MAP_BLACK;
				p_item->p_up->p_up->color = CL_MAP_RED;
				p_item = p_item->p_up->p_up;
				continue;
			}

			if (!__cl_map_is_left_child(p_item)) {
				p_item = p_item->p_up;
				__cl_map_rot_left(p_map, p_item);
			}
			p_item->p_up->color = CL_MAP_BLACK;
			p_item->p_up->p_up->color = CL_MAP_RED;
			__cl_map_rot_right(p_map, p_item->p_up->p_up);
		} else {
			p_grand_uncle = p_item->p_up->p_up->p_left;
			assert(p_grand_uncle);
			if (p_grand_uncle->color == CL_MAP_RED) {
				p_grand_uncle->color = CL_MAP_BLACK;
				p_item->p_up->color = CL_MAP_BLACK;
				p_item->p_up->p_up->color = CL_MAP_RED;
				p_item = p_item->p_up->p_up;
				continue;
			}

			if (__cl_map_is_left_child(p_item)) {
				p_item = p_item->p_up;
				__cl_map_rot_right(p_map, p_item);
			}
			p_item->p_up->color = CL_MAP_BLACK;
			p_item->p_up->p_up->color = CL_MAP_RED;
			__cl_map_rot_left(p_map, p_item->p_up->p_up);
		}
	}
}

cl_map_item_t *cl_qmap_insert(cl_qmap_t * const p_map,
			      const uint64_t key,
			      cl_map_item_t * const p_item)
{
	cl_map_item_t *p_insert_at, *p_comp_item;

	assert(p_map);
	assert(p_item);
	assert(p_map->root.p_up == &p_map->root);
	assert(p_map->root.color != CL_MAP_RED);
	assert(p_map->nil.color != CL_MAP_RED);

	p_item->p_left = &p_map->nil;
	p_item->p_right = &p_map->nil;
	p_item->key = key;
	p_item->color = CL_MAP_RED;

	/* Find the insertion location. */
	p_insert_at = &p_map->root;
	p_comp_item = __cl_map_root(p_map);

	while (p_comp_item != &p_map->nil) {
		p_insert_at = p_comp_item;

		if (key == p_insert_at->key)
			return (p_insert_at);

		/* Traverse the tree until the correct insertion point is found. */
		if (key < p_insert_at->key)
			p_comp_item = p_insert_at->p_left;
		else
			p_comp_item = p_insert_at->p_right;
	}

	assert(p_insert_at != &p_map->nil);
	assert(p_comp_item == &p_map->nil);
	/* Insert the item. */
	if (p_insert_at == &p_map->root) {
		p_insert_at->p_left = p_item;
		/*
		 * Primitive insert places the new item in front of
		 * the existing item.
		 */
		__cl_primitive_insert(&p_map->nil.pool_item.list_item,
				      &p_item->pool_item.list_item);
	} else if (key < p_insert_at->key) {
		p_insert_at->p_left = p_item;
		/*
		 * Primitive insert places the new item in front of
		 * the existing item.
		 */
		__cl_primitive_insert(&p_insert_at->pool_item.list_item,
				      &p_item->pool_item.list_item);
	} else {
		p_insert_at->p_right = p_item;
		/*
		 * Primitive insert places the new item in front of
		 * the existing item.
		 */
		__cl_primitive_insert(p_insert_at->pool_item.list_item.p_next,
				      &p_item->pool_item.list_item);
	}
	/* Increase the count. */
	p_map->count++;

	p_item->p_up = p_insert_at;

	/*
	 * We have added depth to this section of the tree.
	 * Rebalance as necessary as we retrace our path through the tree
	 * and update colors.
	 */
	__cl_map_ins_bal(p_map, p_item);

	__cl_map_root(p_map)->color = CL_MAP_BLACK;

	/*
	 * Note that it is not necessary to re-color the nil node black because all
	 * red color assignments are made via the p_up pointer, and nil is never
	 * set as the value of a p_up pointer.
	 */

#ifdef _DEBUG_
	/* Set the pointer to the map in the map item for consistency checking. */
	p_item->p_map = p_map;
#endif

	return (p_item);
}

static void __cl_map_del_bal(cl_qmap_t * const p_map,
			     cl_map_item_t * p_item)
{
	cl_map_item_t *p_uncle;

	while ((p_item->color != CL_MAP_RED) && (p_item->p_up != &p_map->root)) {
		if (__cl_map_is_left_child(p_item)) {
			p_uncle = p_item->p_up->p_right;

			if (p_uncle->color == CL_MAP_RED) {
				p_uncle->color = CL_MAP_BLACK;
				p_item->p_up->color = CL_MAP_RED;
				__cl_map_rot_left(p_map, p_item->p_up);
				p_uncle = p_item->p_up->p_right;
			}

			if (p_uncle->p_right->color != CL_MAP_RED) {
				if (p_uncle->p_left->color != CL_MAP_RED) {
					p_uncle->color = CL_MAP_RED;
					p_item = p_item->p_up;
					continue;
				}

				p_uncle->p_left->color = CL_MAP_BLACK;
				p_uncle->color = CL_MAP_RED;
				__cl_map_rot_right(p_map, p_uncle);
				p_uncle = p_item->p_up->p_right;
			}
			p_uncle->color = p_item->p_up->color;
			p_item->p_up->color = CL_MAP_BLACK;
			p_uncle->p_right->color = CL_MAP_BLACK;
			__cl_map_rot_left(p_map, p_item->p_up);
			break;
		} else {
			p_uncle = p_item->p_up->p_left;

			if (p_uncle->color == CL_MAP_RED) {
				p_uncle->color = CL_MAP_BLACK;
				p_item->p_up->color = CL_MAP_RED;
				__cl_map_rot_right(p_map, p_item->p_up);
				p_uncle = p_item->p_up->p_left;
			}

			if (p_uncle->p_left->color != CL_MAP_RED) {
				if (p_uncle->p_right->color != CL_MAP_RED) {
					p_uncle->color = CL_MAP_RED;
					p_item = p_item->p_up;
					continue;
				}

				p_uncle->p_right->color = CL_MAP_BLACK;
				p_uncle->color = CL_MAP_RED;
				__cl_map_rot_left(p_map, p_uncle);
				p_uncle = p_item->p_up->p_left;
			}
			p_uncle->color = p_item->p_up->color;
			p_item->p_up->color = CL_MAP_BLACK;
			p_uncle->p_left->color = CL_MAP_BLACK;
			__cl_map_rot_right(p_map, p_item->p_up);
			break;
		}
	}
	p_item->color = CL_MAP_BLACK;
}

void cl_qmap_remove_item(cl_qmap_t * const p_map,
			 cl_map_item_t * const p_item)
{
	cl_map_item_t *p_child, *p_del_item;

	assert(p_map);
	assert(p_item);

	if (p_item == cl_qmap_end(p_map))
		return;

	if ((p_item->p_right == &p_map->nil) || (p_item->p_left == &p_map->nil)) {
		/* The item being removed has children on at most on side. */
		p_del_item = p_item;
	} else {
		/*
		 * The item being removed has children on both side.
		 * We select the item that will replace it.  After removing
		 * the substitute item and rebalancing, the tree will have the
		 * correct topology.  Exchanging the substitute for the item
		 * will finalize the removal.
		 */
		p_del_item = cl_qmap_next(p_item);
		assert(p_del_item != &p_map->nil);
	}

	/* Remove the item from the list. */
	__cl_primitive_remove(&p_item->pool_item.list_item);
	/* Decrement the item count. */
	p_map->count--;

	/* Get the pointer to the new root's child, if any. */
	if (p_del_item->p_left != &p_map->nil)
		p_child = p_del_item->p_left;
	else
		p_child = p_del_item->p_right;

	/*
	 * This assignment may modify the parent pointer of the nil node.
	 * This is inconsequential.
	 */
	p_child->p_up = p_del_item->p_up;
	(*__cl_map_get_parent_ptr_to_item(p_del_item)) = p_child;

	if (p_del_item->color != CL_MAP_RED)
		__cl_map_del_bal(p_map, p_child);

	/*
	 * Note that the splicing done below does not need to occur before
	 * the tree is balanced, since the actual topology changes are made by the
	 * preceding code.  The topology is preserved by the color assignment made
	 * below (reader should be reminded that p_del_item == p_item in some cases).
	 */
	if (p_del_item != p_item) {
		/*
		 * Finalize the removal of the specified item by exchanging it with
		 * the substitute which we removed above.
		 */
		p_del_item->p_up = p_item->p_up;
		p_del_item->p_left = p_item->p_left;
		p_del_item->p_right = p_item->p_right;
		(*__cl_map_get_parent_ptr_to_item(p_item)) = p_del_item;
		p_item->p_right->p_up = p_del_item;
		p_item->p_left->p_up = p_del_item;
		p_del_item->color = p_item->color;
	}

	assert(p_map->nil.color != CL_MAP_RED);

#ifdef _DEBUG_
	/* Clear the pointer to the map since the item has been removed. */
	p_item->p_map = NULL;
#endif
}

cl_map_item_t *cl_qmap_remove(cl_qmap_t * const p_map, const uint64_t key)
{
	cl_map_item_t *p_item;

	assert(p_map);

	/* Seek the node with the specified key */
	p_item = cl_qmap_get(p_map, key);

	cl_qmap_remove_item(p_map, p_item);

	return (p_item);
}

void cl_qmap_merge(cl_qmap_t * const p_dest_map,
		   cl_qmap_t * const p_src_map)
{
	cl_map_item_t *p_item, *p_item2, *p_next;

	assert(p_dest_map);
	assert(p_src_map);

	p_item = cl_qmap_head(p_src_map);

	while (p_item != cl_qmap_end(p_src_map)) {
		p_next = cl_qmap_next(p_item);

		/* Remove the item from its current map. */
		cl_qmap_remove_item(p_src_map, p_item);
		/* Insert the item into the destination map. */
		p_item2 =
		    cl_qmap_insert(p_dest_map, cl_qmap_key(p_item), p_item);
		/* Check that the item was successfully inserted. */
		if (p_item2 != p_item) {
			/* Put the item in back in the source map. */
			p_item2 =
			    cl_qmap_insert(p_src_map, cl_qmap_key(p_item),
					   p_item);
			assert(p_item2 == p_item);
		}
		p_item = p_next;
	}
}

static void __cl_qmap_delta_move(cl_qmap_t * const p_dest,
				 cl_qmap_t * const p_src,
				 cl_map_item_t ** const pp_item)
{
	cl_map_item_t __attribute__((__unused__)) *p_temp;
	cl_map_item_t *p_next;

	/*
	 * Get the next item so that we can ensure that pp_item points to
	 * a valid item upon return from the function.
	 */
	p_next = cl_qmap_next(*pp_item);
	/* Move the old item from its current map the the old map. */
	cl_qmap_remove_item(p_src, *pp_item);
	p_temp = cl_qmap_insert(p_dest, cl_qmap_key(*pp_item), *pp_item);
	/* We should never have duplicates. */
	assert(p_temp == *pp_item);
	/* Point pp_item to a valid item in the source map. */
	(*pp_item) = p_next;
}

void cl_qmap_delta(cl_qmap_t * const p_map1,
		   cl_qmap_t * const p_map2,
		   cl_qmap_t * const p_new, cl_qmap_t * const p_old)
{
	cl_map_item_t *p_item1, *p_item2;
	uint64_t key1, key2;

	assert(p_map1);
	assert(p_map2);
	assert(p_new);
	assert(p_old);
	assert(cl_is_qmap_empty(p_new));
	assert(cl_is_qmap_empty(p_old));

	p_item1 = cl_qmap_head(p_map1);
	p_item2 = cl_qmap_head(p_map2);

	while (p_item1 != cl_qmap_end(p_map1) && p_item2 != cl_qmap_end(p_map2)) {
		key1 = cl_qmap_key(p_item1);
		key2 = cl_qmap_key(p_item2);
		if (key1 < key2) {
			/* We found an old item. */
			__cl_qmap_delta_move(p_old, p_map1, &p_item1);
		} else if (key1 > key2) {
			/* We found a new item. */
			__cl_qmap_delta_move(p_new, p_map2, &p_item2);
		} else {
			/* Move both forward since they have the same key. */
			p_item1 = cl_qmap_next(p_item1);
			p_item2 = cl_qmap_next(p_item2);
		}
	}

	/* Process the remainder if the end of either source map was reached. */
	while (p_item2 != cl_qmap_end(p_map2))
		__cl_qmap_delta_move(p_new, p_map2, &p_item2);

	while (p_item1 != cl_qmap_end(p_map1))
		__cl_qmap_delta_move(p_old, p_map1, &p_item1);
}
