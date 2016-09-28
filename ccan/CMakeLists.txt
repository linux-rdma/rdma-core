publish_internal_headers(ccan
  minmax.h
  build_assert.h
  config.h
  list.h
  str.h
  str_debug.h
  check_type.h
  container_of.h
  )

set(C_FILES
  str.c
  )
add_library(ccan STATIC ${C_FILES})
add_library(ccan_pic STATIC ${C_FILES})
set_property(TARGET ccan_pic PROPERTY POSITION_INDEPENDENT_CODE TRUE)
