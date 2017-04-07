publish_internal_headers(util
  compiler.h
  util.h
  )

# The empty dummy.c is only needed so that cmake always has something to build
# into the library.
set(C_FILES dummy.c)

if (HAVE_COHERENT_DMA)
  publish_internal_headers(util
    mmio.h
    udma_barrier.h
    )

  set(C_FILES ${C_FILES}
    mmio.c
    )
endif()

add_library(rdma_util STATIC ${C_FILES})
add_library(rdma_util_pic STATIC ${C_FILES})
set_property(TARGET rdma_util_pic PROPERTY POSITION_INDEPENDENT_CODE TRUE)
