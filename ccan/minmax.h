/* CC0 (Public domain) - see LICENSE.CC0 file for details */
#ifndef CCAN_MINMAX_H
#define CCAN_MINMAX_H

#include "config.h"

#include <ccan/build_assert.h>

#if !HAVE_STATEMENT_EXPR || !HAVE_TYPEOF
/*
 * Without these, there's no way to avoid unsafe double evaluation of
 * the arguments
 */
#error Sorry, minmax module requires statement expressions and typeof
#endif

#if HAVE_BUILTIN_TYPES_COMPATIBLE_P
#define MINMAX_ASSERT_COMPATIBLE(a, b) \
	BUILD_ASSERT(__builtin_types_compatible_p(a, b))
#else
#define MINMAX_ASSERT_COMPATIBLE(a, b) \
	do { } while (0)
#endif

#define min(a, b) \
	({ \
		typeof(a) _a = (a); \
		typeof(b) _b = (b); \
		MINMAX_ASSERT_COMPATIBLE(typeof(_a), typeof(_b)); \
		_a < _b ? _a : _b; \
	})

#define max(a, b) \
	({ \
		typeof(a) _a = (a); \
		typeof(b) _b = (b); \
		MINMAX_ASSERT_COMPATIBLE(typeof(_a), typeof(_b)); \
		_a > _b ? _a : _b; \
	})

#define clamp(v, f, c)	(max(min((v), (c)), (f)))


#define min_t(t, a, b) \
	({ \
		t _ta = (a); \
		t _tb = (b); \
		min(_ta, _tb); \
	})
#define max_t(t, a, b) \
	({ \
		t _ta = (a); \
		t _tb = (b); \
		max(_ta, _tb); \
	})

#define clamp_t(t, v, f, c) \
	({ \
		t _tv = (v); \
		t _tf = (f); \
		t _tc = (c); \
		clamp(_tv, _tf, _tc); \
	})

#endif /* CCAN_MINMAX_H */
