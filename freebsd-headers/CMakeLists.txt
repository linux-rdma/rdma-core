# Like publish_headers(), but installs under $DEST/linuxapi
function(publish_freebsd_headers DEST)
  publish_internal_headers("${DEST}" ${ARGN})

  foreach(SFIL ${ARGN})
    get_filename_component(FIL ${SFIL} NAME)
    install(FILES "${SFIL}" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/linuxapi/${DEST}/" RENAME "${FIL}")
  endforeach()
endfunction()

publish_freebsd_headers(""
  alloca.h
  errno.h
  limits.h
  string.h
  )

publish_freebsd_headers(netinet
  netinet/in.h
  netinet/tcp.h
  )

publish_freebsd_headers(sys
  sys/mman.h
  sys/sendfile.h
  sys/shm.h
  sys/socket.h
  sys/sysmacros.h
  )

publish_freebsd_headers(linux
  linux/if_ether.h
  linux/in.h
  linux/in6.h
  linux/ioctl.h
  linux/ip.h
  linux/netlink.h
  linux/rtnetlink.h
  linux/socket.h
  linux/types.h
  )
