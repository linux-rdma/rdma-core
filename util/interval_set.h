/* GPLv2 or OpenIB.org BSD (MIT) See COPYING file */

#include <stdint.h>

struct iset;

/**
 * iset_create - Create an interval set
 *
 * Return the created iset if succeeded, NULL otherwise, with errno set
 */
struct iset *iset_create(void);

/**
 * iset_destroy - Destroy an interval set
 * @iset: The set to be destroyed
 */
void iset_destroy(struct iset *iset);

/**
 * iset_insert_range - Insert a range to the set
 * @iset: The set to be operated
 * @start: The start address of the range
 * @length: The length of the range
 *
 * If this range is continuous to the adjacent ranges (before and/or after),
 * then they will be combined to a larger one.
 *
 * Return 0 if succeeded, errno otherwise
 */
int iset_insert_range(struct iset *iset, uint64_t start, uint64_t length);

/**
 * iset_alloc_range - Allocate a range from the set
 *
 * @iset: The set to be operated
 * @length: The length of the range, must be power of two
 * @start: The start address of the allocated range, aligned with @length
 *
 * Return 0 if succeeded, errno otherwise
 *
 * Note: There are these cases:
 *
Case 1: Original range is fully taken
+------------------+
|XXXXXXXXXXXXXXXXXX|
+------------------+
=>  (NULL)

Case 2: Original range shrunk
+------------------+
|XXXXX             |
+------------------+
=>
      +------------+
      |            |
      +------------+

Case 3: Original range shrunk
+------------------+
|             XXXXX|
+------------------+
=>
+------------+
|            |
+------------+

Case 4: Original range splited
+------------------+
|      XXXXX       |
+------------------+
=>
+-----+     +------+
|     |     |      |
+-----+     +------+
*/
int iset_alloc_range(struct iset *iset, uint64_t length, uint64_t *start);
