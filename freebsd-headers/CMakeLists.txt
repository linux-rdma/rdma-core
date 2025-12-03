publish_internal_headers(""
  alloca.h
  errno.h
  limits.h
  string.h
  )

publish_internal_headers(netinet
  netinet/in.h
  netinet/tcp.h
  )

publish_internal_headers(sys
  sys/mman.h
  sys/sendfile.h
  sys/shm.h
  sys/socket.h
  sys/sysmacros.h
  )

publish_internal_headers(linux
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
