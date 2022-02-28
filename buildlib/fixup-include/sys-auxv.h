#ifndef _FIXUP_SYS_AUXV_H
#define _FIXUP_SYS_AUXV_H
#if defined(__s390x__)

#include_next <sys/auxv.h>

#define HWCAP_S390_PCI_MIO 2097152

#endif
#endif
