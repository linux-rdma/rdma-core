static inline void VALGRIND_MAKE_MEM_DEFINED(const void *mem,size_t len) {}
#define VALGRIND_MAKE_MEM_DEFINED VALGRIND_MAKE_MEM_DEFINED

static inline void VALGRIND_MAKE_MEM_UNDEFINED(const void *mem,size_t len) {}
#define VALGRIND_MAKE_MEM_UNDEFINED VALGRIND_MAKE_MEM_UNDEFINED
