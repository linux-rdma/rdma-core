/* GPLv2 or OpenIB.org BSD (MIT) See COPYING file

   These accessors always map to PCI-E TLPs in predictable ways. Translation
   to other buses should follow similar definitions.

   write32(mem, 1)
      Produce a 4 byte MemWr TLP with bit 0 of DW byte offset 0 set
   write32_be(mem, htobe32(1))
      Produce a 4 byte MemWr TLP with bit 0 of DW byte offset 3 set
   write32_le(mem, htole32(1))
      Produce a 4 byte MemWr TLP with bit 0 of DW byte offset 0 set

   For ordering these accessors are similar to the Kernel's concept of
   writel_relaxed(). When working with UC memory the following hold:

   1) Strong ordering is required when talking to the same device (eg BAR),
      and combining is not permitted:

       write32(mem, 1);
       write32(mem + 4, 1);
       write32(mem, 1);

      Must produce three TLPs, in order.

   2) Ordering ignores all pthread locking:

       pthread_spin_lock(&lock);
       write32(mem, global++);
       pthread_spin_unlock(&lock);

      When run concurrently on all CPUs the device must observe all stores,
      but the data value will not be strictly increasing.

   3) Interaction with DMA is not ordered. Explicit use of a barrier from
      udma_barriers is required:

	*dma_mem = 1;
	udma_to_device_barrier();
	write32(mem, GO_DMA);

   4) Access out of program order (eg speculation), either by the CPU or
      compiler is not permitted:

	if (cond)
	   read32();

      Must not issue a read TLP if cond is false.

   If these are used with WC memory then #1 and #4 do not apply, and all WC
   accesses must be bracketed with mmio_wc_start() // mmio_flush_writes()
*/

#ifndef __UTIL_MMIO_H
#define __UTIL_MMIO_H

#include <linux/types.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stddef.h>
#include <endian.h>

#include <config.h>
#include <util/compiler.h>

/* The first step is to define the 'raw' accessors. To make this very safe
   with sparse we define two versions of each, a le and a be - however the
   code is always identical.
*/
#ifdef __s390x__
#include <unistd.h>
#include <sys/syscall.h>

/* s390 requires a privileged instruction to access IO memory, these syscalls
   perform that instruction using a memory buffer copy semantic.
*/
static inline void s390_mmio_write(void *mmio_addr, const void *val,
				   size_t length)
{
	// FIXME: Check for error and call abort?
	syscall(__NR_s390_pci_mmio_write, mmio_addr, val, length);
}

static inline void s390_mmio_read(const void *mmio_addr, void *val,
				  size_t length)
{
	// FIXME: Check for error and call abort?
	syscall(__NR_s390_pci_mmio_read, mmio_addr, val, length);
}

#define MAKE_WRITE(_NAME_, _SZ_)                                               \
	static inline void _NAME_##_be(void *addr, __be##_SZ_ value)           \
	{                                                                      \
		s390_mmio_write(addr, &value, sizeof(value));                  \
	}                                                                      \
	static inline void _NAME_##_le(void *addr, __le##_SZ_ value)           \
	{                                                                      \
		s390_mmio_write(addr, &value, sizeof(value));                  \
	}
#define MAKE_READ(_NAME_, _SZ_)                                                \
	static inline __be##_SZ_ _NAME_##_be(const void *addr)                 \
	{                                                                      \
		__be##_SZ_ res;                                                \
		s390_mmio_read(addr, &res, sizeof(res));                       \
		return res;                                                    \
	}                                                                      \
	static inline __le##_SZ_ _NAME_##_le(const void *addr)                 \
	{                                                                      \
		__le##_SZ_ res;                                                \
		s390_mmio_read(addr, &res, sizeof(res));                       \
		return res;                                                    \
	}

static inline void mmio_write8(void *addr, uint8_t value)
{
	s390_mmio_write(addr, &value, sizeof(value));
}

static inline uint8_t mmio_read8(const void *addr)
{
	uint8_t res;
	s390_mmio_read(addr, &res, sizeof(res));
	return res;
}

#else /* __s390x__ */

#define MAKE_WRITE(_NAME_, _SZ_)                                               \
	static inline void _NAME_##_be(void *addr, __be##_SZ_ value)           \
	{                                                                      \
		atomic_store_explicit((_Atomic(uint##_SZ_##_t) *)addr,         \
				      (__force uint##_SZ_##_t)value,           \
				      memory_order_relaxed);                   \
	}                                                                      \
	static inline void _NAME_##_le(void *addr, __le##_SZ_ value)           \
	{                                                                      \
		atomic_store_explicit((_Atomic(uint##_SZ_##_t) *)addr,         \
				      (__force uint##_SZ_##_t)value,           \
				      memory_order_relaxed);                   \
	}
#define MAKE_READ(_NAME_, _SZ_)                                                \
	static inline __be##_SZ_ _NAME_##_be(const void *addr)                 \
	{                                                                      \
		return (__force __be##_SZ_)atomic_load_explicit(               \
		    (_Atomic(uint##_SZ_##_t) *)addr, memory_order_relaxed);    \
	}                                                                      \
	static inline __le##_SZ_ _NAME_##_le(const void *addr)                 \
	{                                                                      \
		return (__force __le##_SZ_)atomic_load_explicit(               \
		    (_Atomic(uint##_SZ_##_t) *)addr, memory_order_relaxed);    \
	}

static inline void mmio_write8(void *addr, uint8_t value)
{
	atomic_store_explicit((_Atomic(uint8_t) *)addr, value,
			      memory_order_relaxed);
}
static inline uint8_t mmio_read8(const void *addr)
{
	return atomic_load_explicit((_Atomic(uint32_t) *)addr,
				    memory_order_relaxed);
}
#endif /* __s390x__ */

MAKE_WRITE(mmio_write16, 16)
MAKE_WRITE(mmio_write32, 32)

MAKE_READ(mmio_read16, 16)
MAKE_READ(mmio_read32, 32)

#if SIZEOF_LONG == 8
MAKE_WRITE(mmio_write64, 64)
MAKE_READ(mmio_read64, 64)
#else
void mmio_write64_be(void *addr, __be64 val);
static inline void mmio_write64_le(void *addr, __le64 val)
{
	mmio_write64_be(addr, (__be64 __force)val);
}

/* There is no way to do read64 atomically, rather than provide some sketchy
   implementation we leave these functions undefined, users should not call
   them if SIZEOF_LONG != 8, but instead implement an appropriate version.
*/
__be64 mmio_read64_be(const void *addr);
__le64 mmio_read64_le(const void *addr);
#endif /* SIZEOF_LONG == 8 */

#undef MAKE_WRITE
#undef MAKE_READ

/* Now we can define the host endian versions of the operator, this just includes
   a call to htole.
*/
#define MAKE_WRITE(_NAME_, _SZ_)                                               \
	static inline void _NAME_(void *addr, uint##_SZ_##_t value)            \
	{                                                                      \
		_NAME_##_le(addr, htole##_SZ_(value));                         \
	}
#define MAKE_READ(_NAME_, _SZ_)                                                \
	static inline uint##_SZ_##_t _NAME_(const void *addr)                  \
	{                                                                      \
		return le##_SZ_##toh(_NAME_##_le(addr));                       \
	}

/* This strictly guarantees the order of TLP generation for the memory copy to
   be in ascending address order.
*/
#ifdef __s390x__
static inline void mmio_memcpy_x64(void *dest, const void *src, size_t bytecnt)
{
	s390_mmio_write(dest, src, bytecnt);
}
#else

/* Transfer is some multiple of 64 bytes */
static inline void mmio_memcpy_x64(void *dest, const void *src, size_t bytecnt)
{
	uintptr_t *dst_p = dest;

	/* Caller must guarantee:
	    assert(bytecnt != 0);
	    assert((bytecnt % 64) == 0);
	    assert(((uintptr_t)dest) % __alignof__(*dst) == 0);
	    assert(((uintptr_t)src) % __alignof__(*dst) == 0);
	*/

	/* Use the native word size for the copy */
	if (sizeof(*dst_p) == 8) {
		const __be64 *src_p = src;

		do {
			/* Do 64 bytes at a time */
			mmio_write64_be(dst_p++, *src_p++);
			mmio_write64_be(dst_p++, *src_p++);
			mmio_write64_be(dst_p++, *src_p++);
			mmio_write64_be(dst_p++, *src_p++);
			mmio_write64_be(dst_p++, *src_p++);
			mmio_write64_be(dst_p++, *src_p++);
			mmio_write64_be(dst_p++, *src_p++);
			mmio_write64_be(dst_p++, *src_p++);

			bytecnt -= 8 * sizeof(*dst_p);
		} while (bytecnt > 0);
	} else if (sizeof(*dst_p) == 4) {
		const __be32 *src_p = src;

		do {
			mmio_write32_be(dst_p++, *src_p++);
			mmio_write32_be(dst_p++, *src_p++);
			bytecnt -= 2 * sizeof(*dst_p);
		} while (bytecnt > 0);
	}
}
#endif

MAKE_WRITE(mmio_write16, 16)
MAKE_WRITE(mmio_write32, 32)
MAKE_WRITE(mmio_write64, 64)

MAKE_READ(mmio_read16, 16)
MAKE_READ(mmio_read32, 32)
MAKE_READ(mmio_read64, 64)

#undef MAKE_WRITE
#undef MAKE_READ

#endif
