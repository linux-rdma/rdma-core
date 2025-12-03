#ifndef __FREEBSD_STRING_H__
#define __FREEBSD_STRING_H__

#include_next <string.h>

#ifndef strdupa
#define	strdupa(_Str) (__extension__({				\
	const char *_Str1;					\
	size_t _Len;						\
	char *_Copy;						\
								\
	_Str1 = (_Str);						\
	_Len = strlen(_Str1) + 1;				\
	_Copy = (char *)__builtin_alloca(_Len);			\
	memcpy(_Copy, _Str1, _Len);				\
	_Copy;							\
}))
#endif

#ifndef strndupa
#define	strndupa(_Str, _Maxlen) (__extension__({		\
	const char *_Str1;					\
	char *_Copy;						\
	size_t _Len;						\
								\
	_Str1 = (_Str);						\
	_Len = strnlen((_Str1), (_Maxlen));			\
	_Copy = __builtin_alloca(_Len + 1);			\
	(void)memcpy(_Copy, _Str1, _Len);			\
	_Copy[_Len] = '\0';					\
	_Copy;							\
}))
#endif

#endif
