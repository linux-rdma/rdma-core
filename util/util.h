/* GPLv2 or OpenIB.org BSD (MIT) See COPYING file */
#ifndef UTIL_UTIL_H
#define UTIL_UTIL_H

/* Return true if the snprintf succeeded, false if there was truncation or
 * error */
#define check_snprintf(buf, len, fmt, ...)                                     \
	({                                                                     \
		int rc = snprintf(buf, len, fmt, ##__VA_ARGS__);               \
		(rc < len && rc >= 0);                                         \
	})

#endif
