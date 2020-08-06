publish_internal_headers(ccan
  array_size.h
  bitmap.h
  build_assert.h
  check_type.h
  compiler.h
  container_of.h
  ilog.h
  list.h
  minmax.h
  str.h
  str_debug.h
  )

set(C_FILES
  bitmap.c
  ilog.c
  list.c
  str.c
  )
add_library(ccan STATIC ${C_FILES})
add_library(ccan_pic STATIC ${C_FILES})
set_property(TARGET ccan_pic PROPERTY POSITION_INDEPENDENT_CODE TRUE)
