rdma_provider(ipathverbs
  ipathverbs.c
  verbs.c
  )

rdma_subst_install(FILES "truescale.conf.in"
  DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/modprobe.d/"
  RENAME "truescale.conf")
install(FILES truescale-serdes.cmds
  DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}"
  PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ OWNER_EXECUTE GROUP_EXECUTE WORLD_EXECUTE)
