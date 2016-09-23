publish_headers(infiniband
  include/infiniband/acm.h
  include/infiniband/acm_prov.h
  )

# FIXME: Fixup the include scheme to not require all these -Is
include_directories("include")
include_directories("src")
include_directories("linux")

# NOTE: ibacm exports symbols from its own binary for use by ibacm
rdma_sbin_executable(ibacm
  src/acm.c
  src/acm_util.c
  )
target_link_libraries(ibacm
  ibverbs
  ibumad
  ${CMAKE_THREAD_LIBS_INIT}
  ${CMAKE_DL_LIBS}
  )
# FIXME: We should probably list the symbols we want to export..
set_target_properties(ibacm PROPERTIES ENABLE_EXPORTS TRUE)

# This is a plugin module that dynamically links to ibacm
add_library(ibacmp MODULE
  prov/acmp/src/acmp.c
  )
rdma_set_library_map(ibacmp "prov/acmp/src/libibacmp.map")
target_link_libraries(ibacmp
  ibacm
  ibverbs
  ibumad
  ${CMAKE_THREAD_LIBS_INIT}
  )
set_target_properties(ibacmp PROPERTIES
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_LIB}")
install(TARGETS ibacmp DESTINATION "${ACM_PROVIDER_DIR}")

rdma_executable(ib_acme
  linux/libacm_linux.c
  src/acme.c
  src/libacm.c
  src/parse.c
  )
target_link_libraries(ib_acme
  ibverbs
  )
target_compile_definitions(ib_acme PRIVATE "-DACME_PRINTS")

rdma_man_pages(
  man/ib_acme.1
  man/ibacm.1
  man/ibacm.7
  man/ibacm_prov.7.in
  )

# FIXME: update the .init.in
set(rdmascript "openibd")
set(prefix "${CMAKE_INSTALL_PREFIX}")
rdma_subst_install(FILES "ibacm.init.in"
  DESTINATION "${CMAKE_INSTALL_INITDDIR}"
  RENAME "ibacm"
  PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ OWNER_EXECUTE GROUP_EXECUTE WORLD_EXECUTE)
