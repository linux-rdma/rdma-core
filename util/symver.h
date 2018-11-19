/* GPLv2 or OpenIB.org BSD (MIT) See COPYING file

   These definitions help using the ELF symbol version feature, and must be
   used in conjunction with the library's map file.
 */

#ifndef __UTIL_SYMVER_H
#define __UTIL_SYMVER_H

#include <config.h>
#include <ccan/str.h>

/*
  These macros should only be used if the library is defining compatibility
  symbols, eg:

    213: 000000000000a650   315 FUNC    GLOBAL DEFAULT   13 ibv_get_device_list@IBVERBS_1.0
    214: 000000000000b020   304 FUNC    GLOBAL DEFAULT   13 ibv_get_device_list@@IBVERBS_1.1

  Symbols which have only a single implementation should use a normal extern
  function and be placed in the correct stanza in the linker map file.

  Follow this pattern to use this feature:
    public.h:
      struct ibv_device **ibv_get_device_list(int *num_devices);
    foo.c:
      // Implement the latest version
      LATEST_SYMVER_FUNC(ibv_get_device_list, 1_1, "IBVERBS_1.1",
			 struct ibv_device **,
			 int *num_devices)
      {
       ...
      }

      // Implement the compat version
      COMPAT_SYMVER_FUNC(ibv_get_device_list, 1_0, "IBVERBS_1.0",
			 struct ibv_device_1_0 **,
			 int *num_devices)
      {
       ...
      }

  As well as matching information in the map file.

  These macros deal with the various uglyness in gcc surrounding symbol
  versions

    - The internal name __public_1_x is synthesized by the macro
    - A prototype for the internal name is created by the macro
    - If statically linking the latest symbol expands into a normal function
      definition
    - If statically linking the compat symbols expand into unused static
      functions are are discarded by the compiler.
    - The prototype of the latest symbol is checked against the public
      prototype (only when compiling statically)

  The extra prototypes are included only to avoid -Wmissing-prototypes
  warnings.  See also Documentation/versioning.md
*/

#define _MAKE_SYMVER(_local_sym, _public_sym, _ver_str)                        \
	asm(".symver " #_local_sym "," #_public_sym "@" _ver_str)
#define _MAKE_SYMVER_FUNC(_public_sym, _uniq, _ver_str, _ret, ...)             \
	_ret __##_public_sym##_##_uniq(__VA_ARGS__);                           \
	_MAKE_SYMVER(__##_public_sym##_##_uniq, _public_sym, _ver_str);        \
	_ret __##_public_sym##_##_uniq(__VA_ARGS__)

#if defined(HAVE_FULL_SYMBOL_VERSIONS) && !defined(_STATIC_LIBRARY_BUILD_)

    // Produce all symbol versions for dynamic linking

#   define COMPAT_SYMVER_FUNC(_public_sym, _uniq, _ver_str, _ret, ...)         \
	_MAKE_SYMVER_FUNC(_public_sym, _uniq, _ver_str, _ret, __VA_ARGS__)
#   define LATEST_SYMVER_FUNC(_public_sym, _uniq, _ver_str, _ret, ...)         \
	_MAKE_SYMVER_FUNC(_public_sym, _uniq, "@" _ver_str, _ret, __VA_ARGS__)

#elif defined(HAVE_LIMITED_SYMBOL_VERSIONS) && !defined(_STATIC_LIBRARY_BUILD_)

    /* Produce only implemenations for the latest symbol and tag it with the
     * correct symbol versions. This supports dynamic linkers that do not
     * understand symbol versions
     */
#    define COMPAT_SYMVER_FUNC(_public_sym, _uniq, _ver_str, _ret, ...)        \
	static inline _ret __##_public_sym##_##_uniq(__VA_ARGS__)
#    define LATEST_SYMVER_FUNC(_public_sym, _uniq, _ver_str, _ret, ...)        \
	_MAKE_SYMVER_FUNC(_public_sym, _uniq, "@" _ver_str, _ret, __VA_ARGS__)

#else

    // Static linking, or linker does not support symbol versions
#define COMPAT_SYMVER_FUNC(_public_sym, _uniq, _ver_str, _ret, ...)            \
	static inline __attribute__((unused))                                  \
		_ret __##_public_sym##_##_uniq(__VA_ARGS__)
#define LATEST_SYMVER_FUNC(_public_sym, _uniq, _ver_str, _ret, ...)            \
	static __attribute__((unused))                                         \
		_ret __##_public_sym##_##_uniq(__VA_ARGS__)                    \
			__attribute__((alias(stringify(_public_sym))));        \
	extern _ret _public_sym(__VA_ARGS__)

#endif

#endif
