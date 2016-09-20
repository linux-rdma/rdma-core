AM_CPPFLAGS = -I$(srcdir)/include

rslibdir = $(libdir)/rsocket
lib_LTLIBRARIES = src/librdmacm.la
rslib_LTLIBRARIES = src/librspreload.la

ACLOCAL_AMFLAGS = -I config
AM_CFLAGS = -g -Wall -D_GNU_SOURCE -DSYSCONFDIR=\"$(sysconfdir)\" -DRDMADIR=\"@rdmadir@\"

src_librdmacm_la_CFLAGS = $(AM_CFLAGS)
src_librspreload_la_CFLAGS = $(AM_CFLAGS)

if HAVE_LD_VERSION_SCRIPT
    librdmacm_version_script = -Wl,--version-script=$(srcdir)/src/librdmacm.map
else
    librdmacm_version_script =
endif

src_librdmacm_la_SOURCES = src/cma.c src/addrinfo.c src/acm.c \
		src/rsocket.c src/indexer.c
src_librdmacm_la_LDFLAGS = -version-info 1 -export-dynamic \
			   $(librdmacm_version_script)
src_librdmacm_la_DEPENDENCIES =  $(srcdir)/src/librdmacm.map

src_librspreload_la_SOURCES = src/preload.c src/indexer.c
src_librspreload_la_LDFLAGS = -version-info 1 -export-dynamic
src_librspreload_la_LIBADD = $(top_builddir)/src/librdmacm.la

bin_PROGRAMS = examples/ucmatose examples/rping examples/udaddy examples/mckey \
	       examples/rdma_client examples/rdma_server examples/rdma_xclient \
	       examples/rdma_xserver examples/rstream examples/rcopy \
	       examples/riostream examples/udpong examples/cmtime
examples_ucmatose_SOURCES = examples/cmatose.c examples/common.c
examples_ucmatose_LDADD = $(top_builddir)/src/librdmacm.la
examples_rping_SOURCES = examples/rping.c
examples_rping_LDADD = $(top_builddir)/src/librdmacm.la
examples_udaddy_SOURCES = examples/udaddy.c examples/common.c
examples_udaddy_LDADD = $(top_builddir)/src/librdmacm.la
examples_mckey_SOURCES = examples/mckey.c
examples_mckey_LDADD = $(top_builddir)/src/librdmacm.la
examples_rdma_client_SOURCES = examples/rdma_client.c
examples_rdma_client_LDADD = $(top_builddir)/src/librdmacm.la
examples_rdma_server_SOURCES = examples/rdma_server.c
examples_rdma_server_LDADD = $(top_builddir)/src/librdmacm.la
examples_rdma_xclient_SOURCES = examples/rdma_xclient.c
examples_rdma_xclient_LDADD = $(top_builddir)/src/librdmacm.la
examples_rdma_xserver_SOURCES = examples/rdma_xserver.c
examples_rdma_xserver_LDADD = $(top_builddir)/src/librdmacm.la
examples_rstream_SOURCES = examples/rstream.c examples/common.c
examples_rstream_LDADD = $(top_builddir)/src/librdmacm.la
examples_riostream_SOURCES = examples/riostream.c examples/common.c
examples_riostream_LDADD = $(top_builddir)/src/librdmacm.la
examples_rcopy_SOURCES = examples/rcopy.c
examples_rcopy_LDADD = $(top_builddir)/src/librdmacm.la
examples_udpong_SOURCES = examples/udpong.c examples/common.c
examples_udpong_LDADD = $(top_builddir)/src/librdmacm.la
examples_cmtime_SOURCES = examples/cmtime.c examples/common.c
examples_cmtime_LDADD = $(top_builddir)/src/librdmacm.la

librdmacmincludedir = $(includedir)/rdma
infinibandincludedir = $(includedir)/infiniband

librdmacminclude_HEADERS = $(top_srcdir)/include/rdma/rdma_cma_abi.h \
			   $(top_srcdir)/include/rdma/rdma_cma.h \
			   $(top_srcdir)/include/rdma/rdma_verbs.h \
			   $(top_srcdir)/include/rdma/rsocket.h

infinibandinclude_HEADERS = $(top_srcdir)/include/infiniband/ib.h

man_MANS = \
	man/rdma_accept.3 \
	man/rdma_ack_cm_event.3 \
	man/rdma_bind_addr.3 \
	man/rdma_connect.3 \
	man/rdma_create_event_channel.3 \
	man/rdma_create_id.3 \
	man/rdma_create_qp.3 \
	man/rdma_create_srq.3 \
	man/rdma_destroy_event_channel.3 \
	man/rdma_destroy_id.3 \
	man/rdma_destroy_qp.3 \
	man/rdma_destroy_srq.3 \
	man/rdma_disconnect.3 \
	man/rdma_free_devices.3 \
	man/rdma_get_cm_event.3 \
	man/rdma_get_devices.3 \
	man/rdma_get_src_port.3 \
	man/rdma_get_dst_port.3 \
	man/rdma_get_local_addr.3 \
	man/rdma_get_peer_addr.3 \
	man/rdma_join_multicast.3 \
	man/rdma_leave_multicast.3 \
	man/rdma_listen.3 \
	man/rdma_migrate_id.3 \
	man/rdma_notify.3 \
	man/rdma_reject.3 \
	man/rdma_resolve_addr.3 \
	man/rdma_resolve_route.3 \
	man/rdma_event_str.3 \
	man/rdma_set_option.3 \
	man/rdma_get_request.3 \
	man/rdma_create_ep.3 \
	man/rdma_destroy_ep.3 \
	man/rdma_getaddrinfo.3 \
	man/rdma_dereg_mr.3 \
	man/rdma_get_recv_comp.3 \
	man/rdma_get_send_comp.3 \
	man/rdma_post_read.3 \
	man/rdma_post_readv.3 \
	man/rdma_post_recv.3 \
	man/rdma_post_recvv.3 \
	man/rdma_post_send.3 \
	man/rdma_post_sendv.3 \
	man/rdma_post_ud_send.3 \
	man/rdma_post_write.3 \
	man/rdma_post_writev.3 \
	man/rdma_reg_msgs.3 \
	man/rdma_reg_read.3 \
	man/rdma_reg_write.3 \
	man/ucmatose.1 \
	man/udaddy.1 \
	man/mckey.1 \
	man/rping.1 \
	man/rdma_server.1 \
	man/rdma_client.1 \
	man/rdma_xserver.1 \
	man/rdma_xclient.1 \
	man/riostream.1 \
	man/rstream.1 \
	man/rcopy.1 \
	man/rdma_cm.7 \
	man/rsocket.7

EXTRA_DIST = src/cma.h src/indexer.h src/librdmacm.map \
	examples/common.h librdmacm.spec.in $(man_MANS)

dist-hook: librdmacm.spec
	cp librdmacm.spec $(distdir)
