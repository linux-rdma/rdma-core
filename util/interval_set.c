/* GPLv2 or OpenIB.org BSD (MIT) See COPYING file */

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>

#include <ccan/list.h>
#include <util/interval_set.h>
#include <util/util.h>

struct iset {
	struct list_head head;
	pthread_mutex_t lock;
};

struct iset_range {
	struct list_node entry;
	uint64_t start;
	uint64_t length;
};

struct iset *iset_create(void)
{
	struct iset *iset;

	iset = calloc(1, sizeof(*iset));
	if (!iset) {
		errno = ENOMEM;
		return NULL;
	}

	pthread_mutex_init(&iset->lock, NULL);
	list_head_init(&iset->head);
	return iset;
}

void iset_destroy(struct iset *iset)
{
	struct iset_range *range, *tmp;

	list_for_each_safe(&iset->head, range, tmp, entry)
		free(range);

	free(iset);
}

static int
range_overlap(uint64_t s1, uint64_t len1, uint64_t s2, uint64_t len2)
{
	if (((s1 < s2) && (s1 + len1 - 1 < s2)) ||
	    ((s1 > s2) && (s1 > s2 + len2 - 1)))
		return 0;

	return 1;
}

static struct iset_range *create_range(uint64_t start, uint64_t length)
{
	struct iset_range *range;

	range = calloc(1, sizeof(*range));
	if (!range) {
		errno = ENOMEM;
		return NULL;
	}

	range->start = start;
	range->length = length;
	return range;
}

static void delete_range(struct iset_range *r)
{
	list_del(&r->entry);
	free(r);
}

static bool check_do_combine(struct iset *iset,
			     struct iset_range *p, struct iset_range *n,
			     uint64_t start, uint64_t length)
{
	bool combined2prev = false, combined2next = false;

	if (p && (p->start + p->length == start)) {
		p->length += length;
		combined2prev = true;
	}

	if (n && (start + length == n->start)) {
		if (combined2prev) {
			p->length += n->length;
			delete_range(n);
		} else {
			n->start = start;
			n->length += length;
		}
		combined2next = true;
	}

	return combined2prev || combined2next;
}

int iset_insert_range(struct iset *iset, uint64_t start, uint64_t length)
{
	struct iset_range *prev = NULL, *r, *rnew;
	bool found = false, combined;
	int ret = 0;

	if (!length || (start + length - 1 < start)) {
		errno = EINVAL;
		return errno;
	}

	pthread_mutex_lock(&iset->lock);
	list_for_each(&iset->head, r, entry) {
		if (range_overlap(r->start, r->length, start, length)) {
			errno = EINVAL;
			ret = errno;
			goto out;
		}

		if (r->start > start) {
			found = true;
			break;
		}

		prev = r;
	}

	combined = check_do_combine(iset, prev, found ? r : NULL,
				    start, length);
	if (!combined) {
		rnew = create_range(start, length);
		if (!rnew) {
			ret = errno;
			goto out;
		}

		if (!found)
			list_add_tail(&iset->head, &rnew->entry);
		else
			list_add_before(&iset->head, &r->entry, &rnew->entry);
	}

out:
	pthread_mutex_unlock(&iset->lock);
	return ret;
}

static int power_of_two(uint64_t x)
{
	return ((x != 0) && !(x & (x - 1)));
}

int iset_alloc_range(struct iset *iset, uint64_t length, uint64_t *start)
{
	struct iset_range *r, *rnew;
	uint64_t astart, rend;
	bool found = false;
	int ret = 0;

	if (!power_of_two(length)) {
		errno = EINVAL;
		return errno;
	}

	pthread_mutex_lock(&iset->lock);
	list_for_each(&iset->head, r, entry) {
		astart = align(r->start, length);
		/* Check for wrap around */
		if ((astart + length - 1 >= astart) &&
		    (astart + length - 1 <= r->start + r->length - 1)) {
			found = true;
			break;
		}
	}
	if (!found) {
		errno = ENOSPC;
		ret = errno;
		goto out;
	}

	if (r->start == astart) {
		if (r->length == length) { /* Case #1 */
			delete_range(r);
		} else {	/* Case #2 */
			r->start += length;
			r->length -= length;
		}
	} else {
		rend = r->start + r->length;
		if (astart + length != rend) { /* Case #4 */
			rnew = create_range(astart + length,
					    rend - astart - length);
			if (!rnew) {
				ret = errno;
				goto out;
			}
			list_add_after(&iset->head, &r->entry, &rnew->entry);
		}
		r->length = astart - r->start; /* Case #3 & #4 */
	}

	*start = astart;
out:
	pthread_mutex_unlock(&iset->lock);
	return ret;
}
