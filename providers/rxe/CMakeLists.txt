
# Shadow kernel headers to avoid multiple symbol definitions with rxe.h
RDMA_DoFixup("${RXE_COMPILES}" "rdma/rdma_user_rxe.h")

rdma_provider(rxe
  rxe.c
  )
rdma_subst_install(FILES "rxe_cfg.in"
  RENAME "rxe_cfg"
  DESTINATION "${CMAKE_INSTALL_BINDIR}"
  PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ OWNER_EXECUTE GROUP_EXECUTE WORLD_EXECUTE
  )
