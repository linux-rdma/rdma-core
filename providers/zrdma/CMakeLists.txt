# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2024 ZTE Corporation.

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
rdma_provider(zrdma
  zxdh_hw.c
  zxdh_zrdma.c
  zxdh_verbs.c
  private_verbs_cmd.c
)

include_directories(${NL_INCLUDE_DIRS})

publish_headers(infiniband
  zxdh_dv.h
  zxdh_devids.h
)

if(TARGET zrdma)
  target_link_libraries(zrdma PRIVATE nl-3)
  rdma_pkg_config("zrdma" "libibverbs" "${CMAKE_THREAD_LIBS_INIT}")
endif()
if(TARGET zrdma-rdmav${IBVERBS_PABI_VERSION})
  target_link_libraries(zrdma-rdmav${IBVERBS_PABI_VERSION} PRIVATE nl-3)
  rdma_pkg_config("zrdma-rdmav${IBVERBS_PABI_VERSION}" "libibverbs" "${CMAKE_THREAD_LIBS_INIT}")
endif()

