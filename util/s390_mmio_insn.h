/* GPLv2 or OpenIB.org BSD (MIT) See COPYING file */
#ifndef __S390_UTIL_MMIO_H
#define __S390_UTIL_MMIO_H
#ifdef __s390x__
#include <stdbool.h>
#include <stdint.h>
#include <endian.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/auxv.h>

#include <util/compiler.h>

/* s390 requires special instructions to access IO memory. Originally there
   were only privileged IO instructions that are exposed via special syscalls.
   Starting with z15 there are also non-privileged memory IO (MIO) instructions
   we can execute in user-space. Despite the hardware support this requires
   support in the kernel. If MIO instructions are available is indicated in an
   ELF hardware capability.
 */
extern bool s390_is_mio_supported;

union register_pair {
	unsigned __int128 pair;
	struct {
		uint64_t even;
		uint64_t odd;
	};
};

/* The following pcilgi and pcistgi instructions allow IO memory access from
   user-space but are only available on z15 and newer.
*/
static inline uint64_t s390_pcilgi(const void *ioaddr, size_t len)
{
	union register_pair ioaddr_len = {.even = (uint64_t)ioaddr, .odd = len};
	uint64_t val;
	int cc;

	asm volatile (
		/* pcilgi */
		".insn   rre,0xb9d60000,%[val],%[ioaddr_len]\n"
		"ipm     %[cc]\n"
		"srl     %[cc],28\n"
		: [cc] "=d" (cc), [val] "=d" (val),
		  [ioaddr_len] "+&d" (ioaddr_len.pair) :: "cc");
	if (unlikely(cc))
		val = -1ULL;

	return val;
}

static inline void s390_pcistgi(void *ioaddr, uint64_t val, size_t len)
{
	union register_pair ioaddr_len = {.even = (uint64_t)ioaddr, .odd = len};

	asm volatile (
		/* pcistgi */
		".insn   rre,0xb9d40000,%[val],%[ioaddr_len]\n"
		: [ioaddr_len] "+&d" (ioaddr_len.pair)
		: [val] "d" (val)
		: "cc", "memory");
}

/* This is the block store variant of unprivileged IO access instructions */
static inline void s390_pcistbi(void *ioaddr, const void *data, size_t len)
{
	const uint8_t *src = data;

	asm volatile (
		/* pcistbi */
		".insn   rsy,0xeb00000000d4,%[len],%[ioaddr],%[src]\n"
		: [len] "+d" (len)
		: [ioaddr] "d" ((uint64_t *)ioaddr),
		  [src] "Q" (*src)
		: "cc");
}

static inline void s390_pciwb(void)
{
	if (s390_is_mio_supported)
		asm volatile (".insn rre,0xb9d50000,0,0\n"); /* pciwb */
	else
		asm volatile("" ::: "memory");
}

static inline void s390_mmio_write_syscall(void *mmio_addr, const void *val,
					   size_t length)
{
	syscall(__NR_s390_pci_mmio_write, mmio_addr, val, length);
}

static inline void s390_mmio_read_syscall(const void *mmio_addr, void *val,
					  size_t length)
{
	syscall(__NR_s390_pci_mmio_read, mmio_addr, val, length);
}

#endif  /* __s390x__ */
#endif /* __S390_UTIL_MMIO_H */
