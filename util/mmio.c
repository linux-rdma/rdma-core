/* GPLv2 or OpenIB.org BSD (MIT) See COPYING file */
#include <util/mmio.h>
#include <util/udma_barrier.h>
#include <config.h>

#include <pthread.h>
#include <stdbool.h>

#ifdef __s390x__
#include <sys/auxv.h>
#include <ccan/minmax.h>

bool s390_is_mio_supported;

static __attribute__((constructor)) void check_mio_supported(void)
{
	s390_is_mio_supported = !!(getauxval(AT_HWCAP) & HWCAP_S390_PCI_MIO);
}

typedef void (*mmio_memcpy_x64_fn_t)(void *, const void *, size_t);
/* This uses the STT_GNU_IFUNC extension to have the dynamic linker select the
   best above implementations at runtime. */
#if HAVE_FUNC_ATTRIBUTE_IFUNC
void mmio_memcpy_x64(void *, const void *, size_t)
	__attribute__((ifunc("resolve_mmio_memcpy_x64")));
static mmio_memcpy_x64_fn_t resolve_mmio_memcpy_x64(uint64_t);
#else
__asm__(".type mmio_memcpy_x64, %gnu_indirect_function");
write64_fn_t resolve_mmio_memcpy_64(uint64_t)
	__asm__("mmio_memcpy_x64");
#endif

#define S390_MAX_WRITE_SIZE 128
#define S390_BOUNDARY_SIZE (1 << 12)
#define S390_BOUNDARY_MASK (S390_BOUNDARY_SIZE - 1)

static uint8_t get_max_write_size(void *dst, size_t len)
{
	size_t offset = ((uint64_t __force)dst) & S390_BOUNDARY_MASK;
	size_t size = min_t(int, len, S390_MAX_WRITE_SIZE);

	if (likely(offset + size <= S390_BOUNDARY_SIZE))
		return size;

	return S390_BOUNDARY_SIZE - offset;
}

static void mmio_memcpy_x64_mio(void *dst, const void *src, size_t bytecnt)
{
	size_t size;

	/* Input is 8 byte aligned 64 byte chunks. The alignment matches the
	 * requirements of pcistbi but we must not cross a 4K byte boundary.
	 */
	while (bytecnt > 0) {
		size = get_max_write_size(dst, bytecnt);
		if (size > 8)
			s390_pcistbi(dst, src, size);
		else
			s390_pcistgi(dst, *(uint64_t *)src, 8);
		src += size;
		dst += size;
		bytecnt -= size;
	}
}

mmio_memcpy_x64_fn_t resolve_mmio_memcpy_x64(uint64_t hwcap)
{
	if (hwcap & HWCAP_S390_PCI_MIO)
		return &mmio_memcpy_x64_mio;
	else
		return &s390_mmio_write_syscall;
}
#endif /* __s390x__ */

#if SIZEOF_LONG != 8

static pthread_spinlock_t mmio_spinlock;

static __attribute__((constructor)) void lock_constructor(void)
{
	pthread_spin_init(&mmio_spinlock, PTHREAD_PROCESS_PRIVATE);
}

/* When the arch does not have a 64 bit store we provide an emulation that
   does two stores in address ascending order while holding a global
   spinlock. */
static void pthread_mmio_write64_be(void *addr, __be64 val)
{
	__be32 first_dword = htobe32(be64toh(val) >> 32);
	__be32 second_dword = htobe32(be64toh(val));

	/* The WC spinlock, by definition, provides global ordering for all UC
	   and WC stores within the critical region. */
	mmio_wc_spinlock(&mmio_spinlock);

	mmio_write32_be(addr, first_dword);
	mmio_write32_be(addr + 4, second_dword);

	mmio_wc_spinunlock(&mmio_spinlock);
}

#if defined(__i386__)
#include <xmmintrin.h>
#include <cpuid.h>

/* For ia32 we have historically emitted movlps SSE instructions to do the 64
   bit operations. */
static void __attribute__((target("sse")))
sse_mmio_write64_be(void *addr, __be64 val)
{
	__m128 tmp = {};
	tmp = _mm_loadl_pi(tmp, (__force __m64 *)&val);
	_mm_storel_pi((__m64 *)addr,tmp);
}

static bool have_sse(void)
{
	unsigned int ax,bx,cx,dx;

	if (!__get_cpuid(1,&ax,&bx,&cx,&dx))
		return false;
	return dx & bit_SSE;
}

typedef void (*write64_fn_t)(void *, __be64);

/* This uses the STT_GNU_IFUNC extension to have the dynamic linker select the
   best above implementations at runtime. */
#if HAVE_FUNC_ATTRIBUTE_IFUNC
void mmio_write64_be(void *addr, __be64 val)
    __attribute__((ifunc("resolve_mmio_write64_be")));
static write64_fn_t resolve_mmio_write64_be(void);
#else
__asm__(".type mmio_write64_be, %gnu_indirect_function");
write64_fn_t resolve_mmio_write64_be(void) __asm__("mmio_write64_be");
#endif

write64_fn_t resolve_mmio_write64_be(void)
{
	if (have_sse())
		return &sse_mmio_write64_be;
	return &pthread_mmio_write64_be;
}

#else

void mmio_write64_be(void *addr, __be64 val)
{
	return pthread_mmio_write64_be(addr, val);
}

#endif /* defined(__i386__) */

#endif /* SIZEOF_LONG != 8 */
