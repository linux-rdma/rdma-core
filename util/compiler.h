/* GPLv2 or OpenIB.org BSD (MIT) See COPYING file */
#ifndef UTIL_COMPILER_H
#define UTIL_COMPILER_H

/* Use to tag a variable that causes compiler warnings. Use as:
    int uninitialized_var(sz)

   This is only enabled for old compilers. gcc 6.x and beyond have excellent
   static flow analysis. If code solicits a warning from 6.x it is almost
   certainly too complex for a human to understand. For some reason powerpc
   uses a different scheme than gcc for flow analysis.
*/
#if (__GNUC__ >= 6 && !defined(__powerpc__)) || defined(__clang__)
#define uninitialized_var(x) x
#else
#define uninitialized_var(x) x = x
#endif

#ifndef likely
#ifdef __GNUC__
#define likely(x)       __builtin_expect(!!(x), 1)
#else
#define likely(x)      (x)
#endif
#endif

#ifndef unlikely
#ifdef __GNUC__
#define unlikely(x)      __builtin_expect(!!(x), 0)
#else
#define unlikely(x)    (x)
#endif
#endif

#ifdef HAVE_FUNC_ATTRIBUTE_ALWAYS_INLINE
#define ALWAYS_INLINE __attribute__((always_inline))
#else
#define ALWAYS_INLINE
#endif

/* Use to mark fall through on switch statements as desired. */
#if __GNUC__ >= 7
#define SWITCH_FALLTHROUGH __attribute__ ((fallthrough))
#else
#define SWITCH_FALLTHROUGH
#endif

#ifdef __CHECKER__
# define __force __attribute__((force))
#else
# define __force
#endif

#endif
