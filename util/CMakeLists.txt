publish_internal_headers(util
  compiler.h
  symver.h
  util.h
  )

set(C_FILES
  util.c)

if (HAVE_COHERENT_DMA)
  publish_internal_headers(util
    mmio.h
    udma_barrier.h
    )

  set(C_FILES ${C_FILES}
    mmio.c
    )
  set_source_files_properties(mmio.c PROPERTIES COMPILE_FLAGS "${SSE_FLAGS}")
endif()

add_library(rdma_util STATIC ${C_FILES})
add_library(rdma_util_pic STATIC ${C_FILES})
set_property(TARGET rdma_util_pic PROPERTY POSITION_INDEPENDENT_CODE TRUE)
