/* COPYRIGHT (c) 2017 Obsidian Research Corporation.
 * Licensed under BSD (MIT variant) or GPLv2. See COPYING.
 *
 * A version of C11 stdatomic.h that doesn't make spare angry. This doesn't
 * actually work.
 */

#ifndef _SPARSE_STDATOMIC_H_
#define _SPARSE_STDATOMIC_H_

#include <stddef.h>
#include <stdint.h>

#define _Atomic(T) struct {volatile __typeof__(T) __val; }

#define ATOMIC_VAR_INIT(value)                                                 \
	{                                                                      \
		.__val = (value)                                               \
	}
#define atomic_init(obj, value)                                                \
	do {                                                                   \
		(obj)->__val = (value);                                        \
	} while (0)

enum memory_order {
	memory_order_relaxed,
	memory_order_consume,
	memory_order_acquire,
	memory_order_release,
	memory_order_acq_rel,
	memory_order_seq_cst,
};

typedef enum memory_order memory_order;

#define atomic_thread_fence(order) __asm volatile("" : : : "memory")
#define atomic_signal_fence(order) __asm volatile("" : : : "memory")

#define atomic_is_lock_free(obj) (sizeof((obj)->__val) <= sizeof(void *))

typedef _Atomic(_Bool) atomic_bool;
typedef _Atomic(char) atomic_char;
typedef _Atomic(signed char) atomic_schar;
typedef _Atomic(unsigned char) atomic_uchar;
typedef _Atomic(short) atomic_short;
typedef _Atomic(unsigned short) atomic_ushort;
typedef _Atomic(int) atomic_int;
typedef _Atomic(unsigned int) atomic_uint;
typedef _Atomic(long) atomic_long;
typedef _Atomic(unsigned long) atomic_ulong;
typedef _Atomic(long long) atomic_llong;
typedef _Atomic(unsigned long long) atomic_ullong;
typedef _Atomic(wchar_t) atomic_wchar_t;
typedef _Atomic(int_least8_t) atomic_int_least8_t;
typedef _Atomic(uint_least8_t) atomic_uint_least8_t;
typedef _Atomic(int_least16_t) atomic_int_least16_t;
typedef _Atomic(uint_least16_t) atomic_uint_least16_t;
typedef _Atomic(int_least32_t) atomic_int_least32_t;
typedef _Atomic(uint_least32_t) atomic_uint_least32_t;
typedef _Atomic(int_least64_t) atomic_int_least64_t;
typedef _Atomic(uint_least64_t) atomic_uint_least64_t;
typedef _Atomic(int_fast8_t) atomic_int_fast8_t;
typedef _Atomic(uint_fast8_t) atomic_uint_fast8_t;
typedef _Atomic(int_fast16_t) atomic_int_fast16_t;
typedef _Atomic(uint_fast16_t) atomic_uint_fast16_t;
typedef _Atomic(int_fast32_t) atomic_int_fast32_t;
typedef _Atomic(uint_fast32_t) atomic_uint_fast32_t;
typedef _Atomic(int_fast64_t) atomic_int_fast64_t;
typedef _Atomic(uint_fast64_t) atomic_uint_fast64_t;
typedef _Atomic(intptr_t) atomic_intptr_t;
typedef _Atomic(uintptr_t) atomic_uintptr_t;
typedef _Atomic(size_t) atomic_size_t;
typedef _Atomic(ptrdiff_t) atomic_ptrdiff_t;
typedef _Atomic(intmax_t) atomic_intmax_t;
typedef _Atomic(uintmax_t) atomic_uintmax_t;

#define atomic_compare_exchange_strong_explicit(object, expected, desired, \
						success, failure)              \
	({                                                                     \
		__typeof__((object)->__val) __v = (object)->__val;             \
		bool __r;                                                      \
		if (__v == *(expected)) {                                      \
			r = true;                                              \
			(object)->__val = (desired);                           \
		} else {                                                       \
			r = false;                                             \
			*(expected) = __val;                                   \
		}                                                              \
		__r;                                                           \
	})

#define atomic_compare_exchange_weak_explicit(object, expected, desired,       \
					      success, failure)                \
	atomic_compare_exchange_strong_explicit(object, expected, desired,     \
						success, failure)

#define atomic_exchange_explicit(object, desired, order)		\
	({                                                                     \
		__typeof__((object)->__val) __v = (object)->__val;             \
		(object)->__val = (operand);                                   \
		__v;                                                           \
	})
#define atomic_fetch_add_explicit(object, operand, order)                      \
	({                                                                     \
		__typeof__((object)->__val) __v = (object)->__val;             \
		(object)->__val += (operand);                                  \
		__v;                                                           \
	})
#define atomic_fetch_and_explicit(object, operand, order)                      \
	({                                                                     \
		__typeof__((object)->__val) __v = (object)->__val;             \
		(object)->__val &= (operand);                                  \
		__v;                                                           \
	})
#define atomic_fetch_or_explicit(object, operand, order)                       \
	({                                                                     \
		__typeof__((object)->__val) __v = (object)->__val;             \
		(object)->__val |= (operand);                                  \
		__v;                                                           \
	})
#define atomic_fetch_sub_explicit(object, operand, order)                      \
	({                                                                     \
		__typeof__((object)->__val) __v = (object)->__val;             \
		(object)->__val -= (operand);                                  \
		__v;                                                           \
	})
#define atomic_fetch_xor_explicit(object, operand, order)                      \
	({                                                                     \
		__typeof__((object)->__val) __v = (object)->__val;             \
		(object)->__val ^= (operand);                                  \
		__v;                                                           \
	})

#define atomic_load_explicit(object, order) ((object)->__val)
#define atomic_store_explicit(object, desired, order)                          \
	({ (object)->__val = (desired); })

#define atomic_compare_exchange_strong(object, expected, desired)              \
	atomic_compare_exchange_strong_explicit(object, expected, desired,     \
						memory_order_seq_cst,          \
						memory_order_seq_cst)
#define atomic_compare_exchange_weak(object, expected, desired)                \
	atomic_compare_exchange_weak_explicit(object, expected, desired,       \
					      memory_order_seq_cst,            \
					      memory_order_seq_cst)
#define atomic_exchange(object, desired)                                       \
	atomic_exchange_explicit(object, desired, memory_order_seq_cst)
#define atomic_fetch_add(object, operand)                                      \
	atomic_fetch_add_explicit(object, operand, memory_order_seq_cst)
#define atomic_fetch_and(object, operand)                                      \
	atomic_fetch_and_explicit(object, operand, memory_order_seq_cst)
#define atomic_fetch_or(object, operand)                                       \
	atomic_fetch_or_explicit(object, operand, memory_order_seq_cst)
#define atomic_fetch_sub(object, operand)                                      \
	atomic_fetch_sub_explicit(object, operand, memory_order_seq_cst)
#define atomic_fetch_xor(object, operand)                                      \
	atomic_fetch_xor_explicit(object, operand, memory_order_seq_cst)
#define atomic_load(object) atomic_load_explicit(object, memory_order_seq_cst)
#define atomic_store(object, desired)                                          \
	atomic_store_explicit(object, desired, memory_order_seq_cst)

typedef atomic_bool			atomic_flag;

#define ATOMIC_FLAG_INIT ATOMIC_VAR_INIT(0)

#define atomic_flag_clear_explicit(object, order)                              \
	atomic_store_explicit(object, 0, order)
#define atomic_flag_test_and_set_explicit(object, order)                       \
	atomic_compare_exchange_strong_explicit(object, 0, 1, order, order)

#define atomic_flag_clear(object)                                              \
	atomic_flag_clear_explicit(object, memory_order_seq_cst)
#define atomic_flag_test_and_set(object)                                       \
	atomic_flag_test_and_set_explicit(object, memory_order_seq_cst)

#endif
