#ifndef _FIXUP_SYS_RANDOM_H
#define _FIXUP_SYS_RANDOM_H

#include <sys/types.h>

/* Flags for use with getrandom. */
#define GRND_NONBLOCK 0x01

static inline ssize_t getrandom(void *buf, size_t buflen, unsigned int flags)
{
	return -1;
}
#endif
