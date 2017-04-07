/* Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md
 */
#ifndef MMIO_H
#define MMIO_H

#include <unistd.h>
#include <sys/syscall.h>
#ifdef __s390x__

static inline long mmio_write(const unsigned long mmio_addr,
			      const void *val,
			      const size_t length)
{
	return syscall(__NR_s390_pci_mmio_write, mmio_addr, val, length);
}

static inline void mlx4_bf_copy(unsigned long *dst,
				unsigned long *src,
				unsigned bytecnt)
{
	mmio_write((unsigned long)dst, src, bytecnt);
}

#else

/*
 * Avoid using memcpy() to copy to BlueFlame page, since memcpy()
 * implementations may use move-string-buffer assembler instructions,
 * which do not guarantee order of copying.
 */
static inline void mlx4_bf_copy(unsigned long *dst,
				unsigned long *src,
				unsigned bytecnt)
{
	while (bytecnt > 0) {
		*dst++ = *src++;
		*dst++ = *src++;
		bytecnt -= 2 * sizeof(long);
	}
}
#endif

#endif
