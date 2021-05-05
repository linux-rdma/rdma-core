#ifndef _FIXUP_SYS_STAT_H
#define _FIXUP_SYS_STAT_H

#include_next <sys/stat.h>

extern int __fxstat(int __ver, int __fildes, struct stat *__stat_buf);
#endif
