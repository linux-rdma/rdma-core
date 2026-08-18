#ifndef	__FREEBSD_SYS_MMAN_H__
#define	__FREEBSD_SYS_MMAN_H__

#include_next <sys/mman.h>

/* use minherit(2) as needed */
#define	MADV_DOFORK	0x10000001
#define	MADV_DONTFORK	0x10000002

#define	MAP_LOCKED	0	/* XXXKIB implement ? */
#define	MAP_HUGETLB	0
#define	MAP_POPULATE	0
#define	MAP_NORESERVE	0
#define	MAP_GROWSDOWN	0

#endif
