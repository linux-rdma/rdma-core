publish_internal_headers(util
  cl_qmap.h
  compiler.h
  node_name_map.h
  rdma_nl.h
  symver.h
  util.h
  )

set(C_FILES
  cl_map.c
  node_name_map.c
  open_cdev.c
  rdma_nl.c
  util.c
  )

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
