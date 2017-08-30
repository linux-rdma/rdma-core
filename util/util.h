/* GPLv2 or OpenIB.org BSD (MIT) See COPYING file */
#ifndef UTIL_UTIL_H
#define UTIL_UTIL_H

#include <stdbool.h>

/* Return true if the snprintf succeeded, false if there was truncation or
 * error */
#define check_snprintf(buf, len, fmt, ...)                                     \
	({                                                                     \
		int rc = snprintf(buf, len, fmt, ##__VA_ARGS__);               \
		(rc < len && rc >= 0);                                         \
	})

/* a CMP b. See also the BSD macro timercmp(). */
#define ts_cmp(a, b, CMP)			\
	(((a)->tv_sec == (b)->tv_sec) ?		\
	 ((a)->tv_nsec CMP (b)->tv_nsec) :	\
	 ((a)->tv_sec CMP (b)->tv_sec))

int set_fd_nonblock(int fd, bool nonblock);

#endif
