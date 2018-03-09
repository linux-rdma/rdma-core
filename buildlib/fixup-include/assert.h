#ifndef _FIXUP_ASSERT_H
#define _FIXUP_ASSERT_H

#include_next <assert.h>

/* Without C11 compiler support it is not possible to implement static_assert */
#undef static_assert
#define static_assert(_cond, msg)

#endif
