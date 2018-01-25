/* COPYRIGHT (c) 2017 Obsidian Research Corporation.
   Licensed under BSD (MIT variant) or GPLv2. See COPYING. */

#ifndef _SPARSE_PTHREAD_H_
#define _SPARSE_PTHREAD_H_

#include_next <pthread.h>

/* Sparse complains that the glibc version of this has 0 instead of NULL */
#undef PTHREAD_MUTEX_INITIALIZER
#define PTHREAD_MUTEX_INITIALIZER {}

#endif
