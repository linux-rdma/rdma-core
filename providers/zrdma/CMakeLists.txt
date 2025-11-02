# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2024 ZTE Corporation.

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
rdma_shared_provider(zrdma libzrdma.map
  1 1.1.${PACKAGE_VERSION}
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

rdma_pkg_config("zrdma" "libibverbs" "${CMAKE_THREAD_LIBS_INIT}")

