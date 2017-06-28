/* GPLv2 or OpenIB.org BSD (MIT) See COPYING file */
#include <util/mmio.h>
#include <util/udma_barrier.h>
#include <config.h>

#include <pthread.h>
#include <stdbool.h>

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

#endif /* defined(__i386__) */

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
#if defined(__i386__)
	if (have_sse())
		return &sse_mmio_write64_be;
#endif
	return &pthread_mmio_write64_be;
}

#endif /* SIZEOF_LONG != 8 */
