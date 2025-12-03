#ifndef __FREEBSD_LINUX_STDDEF_H__
#define __FREEBSD_LINUX_STDDEF_H__

#ifndef __cplusplus
#define __struct_group_tag(TAG)         TAG
#else
#define __struct_group_tag(TAG)
#endif

#define __struct_group(TAG, NAME, ATTRS, MEMBERS...) \
	union { \
		struct { MEMBERS } ATTRS; \
		struct __struct_group_tag(TAG) { MEMBERS } ATTRS NAME; \
	} ATTRS

#ifdef __cplusplus
#define __DECLARE_FLEX_ARRAY(T, member) \
	T member[0]
#else
#define __DECLARE_FLEX_ARRAY(TYPE, NAME)        \
	struct { \
		struct { } __empty_ ## NAME; \
		TYPE NAME[]; \
	}
#endif

#endif
