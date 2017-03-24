/* COPYRIGHT (c) 2017 Obsidian Research Corporation. See COPYING file */

#ifndef _SPARSE_PTHREAD_H_
#define _SPARSE_PTHREAD_H_

#include_next <pthread.h>

/* Sparse complains that the glibc version of this has 0 instead of NULL */
#undef PTHREAD_MUTEX_INITIALIZER
#define PTHREAD_MUTEX_INITIALIZER {}

#endif
