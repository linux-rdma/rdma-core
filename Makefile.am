AM_CFLAGS = -g -Wall -D_GNU_SOURCE
ACLOCAL_AMFLAGS = -I m4

mlx5_version_script = @MLX5_VERSION_SCRIPT@

MLX5_SOURCES = src/buf.c src/cq.c src/dbrec.c src/mlx5.c src/qp.c src/srq.c src/verbs.c
noinst_HEADERS = src/bitmap.h src/doorbell.h src/list.h src/mlx5-abi.h src/mlx5.h src/wqe.h


if HAVE_IBV_DEVICE_LIBRARY_EXTENSION
    lib_LTLIBRARIES = src/libmlx5.la
    src_libmlx5_la_SOURCES = $(MLX5_SOURCES)
    src_libmlx5_la_LDFLAGS = -avoid-version -release @IBV_DEVICE_LIBRARY_EXTENSION@ \
        $(mlx5_version_script)
    mlx5confdir = $(sysconfdir)/libibverbs.d
    mlx5conf_DATA = mlx5.driver
else
    mlx5libdir = $(libdir)/infiniband
    mlx5lib_LTLIBRARIES = src/mlx5.la
    src_mlx5_la_SOURCES = $(MLX5_SOURCES)
    src_mlx5_la_LDFLAGS = -avoid-version -module $(mlx5_version_script)
endif

EXTRA_DIST = src/mlx5.map libmlx5.spec.in mlx5.driver

dist-hook: libmlx5.spec
	cp libmlx5.spec $(distdir)
