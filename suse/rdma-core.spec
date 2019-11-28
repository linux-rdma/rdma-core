#
# spec file for package rdma-core
#
# Copyright (c) 2019 SUSE LINUX GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via https://bugs.opensuse.org/
#


%bcond_without  systemd
# Do not build static libs by default.
%define with_static %{?_with_static: 1} %{?!_with_static: 0}
%define with_pyverbs %{?_with_pyverbs: 1} %{?!_with_pyverbs: 0}

%define         git_ver %{nil}
Name:           rdma-core
Version:        23.3
Release:        0
Summary:        RDMA core userspace libraries and daemons
License:        GPL-2.0-only OR BSD-2-Clause
Group:          Productivity/Networking/Other

%define verbs_so_major  1
%define rdmacm_so_major 1
%define umad_so_major   3
%define mlx4_so_major   1
%define mlx5_so_major   1

%define  verbs_lname  libibverbs%{verbs_so_major}
%define  rdmacm_lname librdmacm%{rdmacm_so_major}
%define  umad_lname   libibumad%{umad_so_major}
%define  mlx4_lname   libmlx4-%{mlx4_so_major}
%define  mlx5_lname   libmlx5-%{mlx5_so_major}

%ifnarch s390 %arm
%define dma_coherent 1
%endif

# Almost everything is licensed under the OFA dual GPLv2, 2 Clause BSD license
#  providers/ipathverbs/ Dual licensed using a BSD license with an extra patent clause
#  providers/rxe/ Incorporates code from ipathverbs and contains the patent clause
#  providers/hfi1verbs Uses the 3 Clause BSD license
Url:            https://github.com/linux-rdma/rdma-core
Source:         rdma-core-%{version}%{git_ver}.tar.gz
Source1:        baselibs.conf
BuildRequires:  binutils
BuildRequires:  cmake >= 2.8.11
BuildRequires:  gcc
BuildRequires:  pandoc
BuildRequires:  pkgconfig
BuildRequires:  python3-base
BuildRequires:  pkgconfig(libsystemd)
BuildRequires:  pkgconfig(libudev)
BuildRequires:  pkgconfig(systemd)
BuildRequires:  pkgconfig(udev)
%if %{with_pyverbs}
BuildRequires:  python3-Cython
BuildRequires:  python3-devel
%endif
%ifnarch s390 s390x
BuildRequires:  valgrind-devel
%endif
BuildRequires:  systemd-rpm-macros
BuildRequires:  pkgconfig(libnl-3.0)
BuildRequires:  pkgconfig(libnl-route-3.0)
BuildRequires:  pkgconfig(systemd)
Requires:       kmod
Requires:       systemd
Requires:       udev

# SUSE previously shipped rdma as a stand-alone
# package which we're supplanting here.

Provides:       rdma = %{version}
Obsoletes:      rdma < %{version}
Provides:       ofed = %{version}
Obsoletes:      ofed < %{version}

# Trickery to handle both SUSE OpenBuild System and Manual build
# In OBS, rdma-core must use curl-mini instead of curl to avoid
# a build dependency loop:
# rdma-core -> cmake -> curl -> ... -> boost -> rdma-core
# Thus we force a BuildRequires to curl-mini which as no impact
# as it is not used during the build.
# However curl-mini is not a published RPM. This would prevent any build
# outside of OBS. Thus we add a bcond to allow manual build.
# To force build without the use of curl-mini, --without=curlmini
# should be passed to rpmbuild
%bcond_without curlmini
%if 0%{?suse_version} >= 1330
%if %{with curlmini}
BuildRequires:  curl-mini
%endif
%endif

# Tumbleweed's cmake RPM macro adds -Wl,--no-undefined to the module flags
# which is totally inappropriate and breaks building 'ENABLE_EXPORTS' style
# module libraries (eg ibacmp).
#%%define CMAKE_FLAGS -DCMAKE_MODULE_LINKER_FLAGS=""

# Since we recommend developers use Ninja, so should packagers, for consistency.
%define CMAKE_FLAGS %{nil}
%if 0%{?suse_version} >= 1300
BuildRequires:  ninja
%define CMAKE_FLAGS -GNinja
%define make_jobs ninja -v %{?_smp_mflags}
%define cmake_install DESTDIR=%{buildroot} ninja install
%else
# Fallback to make otherwise
BuildRequires:  make
%define make_jobs make -v %{?_smp_mflags}
%define cmake_install DESTDIR=%{buildroot} make install
%endif

%description
RDMA core userspace infrastructure and documentation, including initialization
scripts, kernel driver-specific modprobe override configs, IPoIB network
scripts, dracut rules, and the rdma-ndd utility.

%package devel
Summary:        RDMA core development libraries and headers
Group:          Development/Libraries/C and C++
Requires:       %{name}%{?_isa} = %{version}-%{release}

Requires:       %{rdmacm_lname} = %{version}-%{release}
Requires:       %{umad_lname} = %{version}-%{release}
Requires:       %{verbs_lname} = %{version}-%{release}
%if 0%{?dma_coherent}
Requires:       %{mlx4_lname} = %{version}-%{release}
Requires:       %{mlx5_lname} = %{version}-%{release}
%endif
Requires:       rsocket = %{version}-%{release}

Provides:       libibverbs-devel = %{version}-%{release}
Obsoletes:      libibverbs-devel < %{version}-%{release}

Provides:       libibumad-devel = %{version}-%{release}
Obsoletes:      libibumad-devel < %{version}-%{release}
Provides:       librdmacm-devel = %{version}-%{release}

Obsoletes:      librdmacm-devel < %{version}-%{release}
#Requires:       ibacm = %%{version}-%%{release}
Provides:       ibacm-devel = %{version}-%{release}
Obsoletes:      ibacm-devel < %{version}-%{release}
%if %{with_static}
# Since our pkg-config files include private references to these packages they
# need to have their .pc files installed too, even for dynamic linking, or
# pkg-config breaks.
BuildRequires:  pkgconfig(libnl-3.0)
BuildRequires:  pkgconfig(libnl-route-3.0)
%endif

%description devel
RDMA core development libraries and headers.

%package -n     libibverbs
Summary:        Library & drivers for direct userspace use of InfiniBand/iWARP/RoCE hardware
Group:          System/Libraries
Requires:       %{name}%{?_isa} = %{version}-%{release}
Obsoletes:      libcxgb3-rdmav2 < %{version}-%{release}
Obsoletes:      libcxgb4-rdmav2 < %{version}-%{release}
Obsoletes:      libhfi1verbs-rdmav2 < %{version}-%{release}
Obsoletes:      libi40iw-rdmav2 < %{version}-%{release}
Obsoletes:      libipathverbs-rdmav2 < %{version}-%{release}
Obsoletes:      libmlx4-rdmav2 < %{version}-%{release}
Obsoletes:      libmlx5-rdmav2 < %{version}-%{release}
Obsoletes:      libmthca-rdmav2 < %{version}-%{release}
Obsoletes:      libnes-rdmav2 < %{version}-%{release}
Obsoletes:      libocrdma-rdmav2 < %{version}-%{release}
Obsoletes:      librxe-rdmav2 < %{version}-%{release}
%if 0%{?dma_coherent}
Requires:       %{mlx4_lname} = %{version}-%{release}
Requires:       %{mlx5_lname} = %{version}-%{release}
%endif
# Recommended packages for rxe_cfg
Recommends:     ethtool
Recommends:     iproute2

%description -n libibverbs
libibverbs is a library that allows userspace processes to use RDMA
"verbs" as described in the InfiniBand Architecture Specification and
the RDMA Protocol Verbs Specification.  This includes direct hardware
access from userspace to InfiniBand/iWARP adapters (kernel bypass) for
fast path operations.

Device-specific plug-in ibverbs userspace drivers are included:

- libcxgb3: Chelsio T3 iWARP HCA
- libcxgb4: Chelsio T4 iWARP HCA
- libhfi1: Intel Omni-Path HFI
- libhns: HiSilicon Hip06 SoC
- libi40iw: Intel Ethernet Connection X722 RDMA
- libipathverbs: QLogic InfiniPath HCA
- libmlx4: Mellanox ConnectX-3 InfiniBand HCA
- libmlx5: Mellanox Connect-IB/X-4+ InfiniBand HCA
- libmthca: Mellanox InfiniBand HCA
- libnes: NetEffect RNIC
- libocrdma: Emulex OneConnect RDMA/RoCE Device
- libqedr: QLogic QL4xxx RoCE HCA
- librxe: A software implementation of the RoCE protocol
- libvmw_pvrdma: VMware paravirtual RDMA device

%package -n %verbs_lname
Summary:        Ibverbs runtime library
Group:          System/Libraries
Requires:       libibverbs = %{version}

%description -n %verbs_lname
This package contains the ibverbs runtime library.

%package -n %mlx4_lname
Summary:        MLX4 runtime library
Group:          System/Libraries

%description -n %mlx4_lname
This package contains the mlx4 runtime library.

%package -n %mlx5_lname
Summary:        MLX5 runtime library
Group:          System/Libraries

%description -n %mlx5_lname
This package contains the mlx5 runtime library.

%package -n     libibverbs-utils
Summary:        Examples for the libibverbs library
Group:          Productivity/Networking/Other
Requires:       libibverbs%{?_isa} = %{version}

%description -n libibverbs-utils
Useful libibverbs example programs such as ibv_devinfo, which
displays information about RDMA devices.

%package -n     ibacm
Summary:        InfiniBand Communication Manager Assistant
Group:          Productivity/Networking/Other
%{?systemd_requires}
Requires:       %{name}%{?_isa} = %{version}
Obsoletes:      libibacmp1 < %{version}
Provides:       libibacmp1 = %{version}

%description -n ibacm
The ibacm daemon helps reduce the load of managing path record lookups on
large InfiniBand fabrics by providing a user space implementation of what
is functionally similar to an ARP cache.  The use of ibacm, when properly
configured, can reduce the SA packet load of a large IB cluster from O(n^2)
to O(n).  The ibacm daemon is started and normally runs in the background,
user applications need not know about this daemon as long as their app
uses librdmacm to handle connection bring up/tear down.  The librdmacm
library knows how to talk directly to the ibacm daemon to retrieve data.

%package -n iwpmd
Summary:        Userspace iWarp Port Mapper daemon
Group:          Development/Libraries/C and C++
Requires:       %{name}%{?_isa} = %{version}
%{?systemd_requires}

%description -n iwpmd
iwpmd provides a userspace service for iWarp drivers to claim
tcp ports through the standard socket interface.

%package -n %umad_lname
Summary:        OpenFabrics Alliance InfiniBand Userspace Management Datagram library
Group:          System/Libraries

%description -n %umad_lname
libibumad provides the userspace management datagram (umad) library
functions, which sit on top of the umad modules in the kernel. These
are used by the IB diagnostic and management tools, including OpenSM.

%package -n     %rdmacm_lname
Summary:        Userspace RDMA Connection Manager
Group:          System/Libraries
Requires:       %{name} = %{version}
Provides:       librdmacm = %{version}
Obsoletes:      librdmacm < %{version}

%description -n %rdmacm_lname
librdmacm provides a userspace RDMA Communication Management API.

%package -n rsocket
Summary:        Preloadable library to turn the socket API RDMA-aware
Group:          System/Libraries

%description -n rsocket
Existing applications can make use of rsockets through the use this
preloadable library. See the documentation in the packaged rsocket(7)
manpage for details.

%package -n librdmacm-utils
Summary:        Examples for the librdmacm library
Group:          Productivity/Networking/Other

%description -n librdmacm-utils
Example test programs for the librdmacm library.

%package -n srp_daemon
Summary:        Tools for using the InfiniBand SRP protocol devices
Group:          Development/Libraries/C and C++
Requires:       %{name} = %{version}
Obsoletes:      srptools <= 1.0.3
Provides:       srptools = %{version}
%{?systemd_requires}

%description -n srp_daemon
In conjunction with the kernel ib_srp driver, srp_daemon allows you to
discover and use SCSI devices via the SCSI RDMA Protocol over InfiniBand.

%package     -n rdma-ndd
Summary:        Daemon to manage RDMA Node Description
Group:          System/Daemons
Requires:       %{name} = %{version}
# The udev rules in rdma need to be aware of rdma-ndd:
Conflicts:      rdma < 2.1
%{?systemd_requires}

%description -n rdma-ndd
rdma-ndd is a system daemon which watches for rdma device changes and/or
hostname changes and updates the Node Description of the rdma devices based
on those changes.

%package -n python3-pyverbs
Summary:        Python3 API over IB verbs
Group:          Development/Languages/Python

%description -n python3-pyverbs
Pyverbs is a Cython-based Python API over libibverbs, providing an
easy, object-oriented access to IB verbs.

%prep
# Make sure LTO is disable as rdma-core fails to compile with LTO enabled
%define _lto_cflags %{nil}
%setup -q -n  %{name}-%{version}%{git_ver}

%build

# New RPM defines _rundir, usually as /run
%if 0%{?_rundir:1}
%else
%define _rundir /var/run
%endif

%{!?EXTRA_CMAKE_FLAGS: %define EXTRA_CMAKE_FLAGS %{nil}}

# Pass all of the rpm paths directly to GNUInstallDirs and our other defines.
%cmake %{CMAKE_FLAGS} \
	 -DCMAKE_MODULE_LINKER_FLAGS="-Wl,--as-needed -Wl,-z,now" \
         -DCMAKE_BUILD_TYPE=Release \
         -DCMAKE_INSTALL_BINDIR:PATH=%{_bindir} \
         -DCMAKE_INSTALL_SBINDIR:PATH=%{_sbindir} \
         -DCMAKE_INSTALL_LIBDIR:PATH=%{_libdir} \
         -DCMAKE_INSTALL_LIBEXECDIR:PATH=%{_libexecdir} \
         -DCMAKE_INSTALL_LOCALSTATEDIR:PATH=%{_localstatedir} \
         -DCMAKE_INSTALL_SHAREDSTATEDIR:PATH=%{_sharedstatedir} \
         -DCMAKE_INSTALL_INCLUDEDIR:PATH=%{_includedir} \
         -DCMAKE_INSTALL_INFODIR:PATH=%{_infodir} \
         -DCMAKE_INSTALL_MANDIR:PATH=%{_mandir} \
         -DCMAKE_INSTALL_SYSCONFDIR:PATH=%{_sysconfdir} \
         -DCMAKE_INSTALL_SYSTEMD_SERVICEDIR:PATH=%{_unitdir} \
         -DCMAKE_INSTALL_SYSTEMD_BINDIR:PATH=%{_libexecdir}/systemd \
         -DCMAKE_INSTALL_INITDDIR:PATH=%{_initddir} \
         -DCMAKE_INSTALL_RUNDIR:PATH=%{_rundir} \
         -DCMAKE_INSTALL_DOCDIR:PATH=%{_docdir}/%{name}-%{version} \
         -DCMAKE_INSTALL_UDEV_RULESDIR:PATH=%{_udevrulesdir} \
%if %{with_static}
         -DENABLE_STATIC=1 \
%endif
         %{EXTRA_CMAKE_FLAGS} \
%if %{defined __python3}
         -DPYTHON_EXECUTABLE:PATH=%{__python3} \
         -DCMAKE_INSTALL_PYTHON_ARCH_LIB:PATH=%{python3_sitearch} \
%endif
%if %{with_pyverbs}
         -DNO_PYVERBS=0
%else
	 -DNO_PYVERBS=1
%endif
%make_jobs

%install
cd build
%cmake_install
cd ..
mkdir -p %{buildroot}/%{_sysconfdir}/rdma

%global dracutlibdir %%{_libexecdir}/dracut/
%global sysmodprobedir %%{_sysconfdir}/modprobe.d

mkdir -p %{buildroot}%{_udevrulesdir}
mkdir -p %{buildroot}%{dracutlibdir}/modules.d/05rdma
mkdir -p %{buildroot}%{sysmodprobedir}
mkdir -p %{buildroot}%{_unitdir}

# SRIOV service
install -D -m0644 redhat/rdma.sriov-vfs %{buildroot}/%{_sysconfdir}/rdma/sriov-vfs
install -D -m0755 redhat/rdma.sriov-init %{buildroot}%{_libexecdir}/rdma-set-sriov-vf
install -D -m0644 suse/rdma.sriov-rules %{buildroot}%{_udevrulesdir}/98-rdma-sriov.rules
install -D -m0644 suse/rdma.sriov-service %{buildroot}%{_unitdir}/rdma-sriov.service

# Port type setup for mlx4 dual port cards
install -D -m0644 redhat/rdma.mlx4.conf %{buildroot}/%{_sysconfdir}/rdma/mlx4.conf
sed 's%/usr/libexec%/usr/lib%g' redhat/rdma.mlx4.sys.modprobe > %{buildroot}%{sysmodprobedir}/50-libmlx4.conf
chmod 0644 %{buildroot}%{sysmodprobedir}/50-libmlx4.conf
install -D -m0755 redhat/rdma.mlx4-setup.sh %{buildroot}%{_libexecdir}/mlx4-setup.sh

# Dracut file for IB support during boot
install -D -m0644 suse/module-setup.sh %{buildroot}%{dracutlibdir}/modules.d/05rdma/module-setup.sh

# ibacm
cd build
LD_LIBRARY_PATH=./lib bin/ib_acme -D . -O
install -D -m0644 ibacm_opts.cfg %{buildroot}%{_sysconfdir}/rdma/

for service in rdma rdma-ndd ibacm iwpmd srp_daemon; do ln -sf %{_sbindir}/service %{buildroot}%{_sbindir}/rc${service}; done

# Delete the package's init.d scripts
rm -rf %{buildroot}/%{_initddir}/
rm -rf %{buildroot}/%{_sbindir}/srp_daemon.sh

%post -n %verbs_lname -p /sbin/ldconfig
%postun -n %verbs_lname -p /sbin/ldconfig

%post -n %mlx4_lname -p /sbin/ldconfig
%postun -n %mlx4_lname -p /sbin/ldconfig

%post -n %mlx5_lname -p /sbin/ldconfig
%postun -n %mlx5_lname -p /sbin/ldconfig

%post -n %umad_lname -p /sbin/ldconfig
%postun -n %umad_lname -p /sbin/ldconfig

%post -n %rdmacm_lname -p /sbin/ldconfig
%postun -n %rdmacm_lname -p /sbin/ldconfig

%post
# we ship udev rules, so trigger an update.
/sbin/udevadm trigger --subsystem-match=infiniband --action=change || true
/sbin/udevadm trigger --subsystem-match=infiniband_mad --action=change || true

#
# ibacm
#
%pre -n ibacm
%service_add_pre ibacm.service ibacm.socket

%post -n ibacm
%service_add_post ibacm.service ibacm.socket

%preun -n ibacm
%service_del_preun ibacm.service ibacm.socket

%postun -n ibacm
%service_del_postun ibacm.service ibacm.socket

#
# srp daemon
#
%pre -n srp_daemon
%service_add_pre srp_daemon.service

%post -n srp_daemon
%service_add_post srp_daemon.service
# we ship udev rules, so trigger an update.
/sbin/udevadm trigger --subsystem-match=infiniband_mad --action=change

%preun -n srp_daemon
%service_del_preun srp_daemon.service

%postun -n srp_daemon
%service_del_postun srp_daemon.service

#
# iwpmd
#
%pre -n iwpmd
%service_add_pre ibiwpmd.service

%post -n iwpmd
%service_add_post iwpmd.service

%preun -n iwpmd
%service_del_preun iwpmd.service

%postun -n iwpmd
%service_del_postun iwpmd.service

#
# rdma-ndd
#
%pre -n rdma-ndd
%service_add_pre rdma-ndd.service

%preun -n rdma-ndd
%service_del_preun rdma-ndd.service

%post -n rdma-ndd
%service_add_post rdma-ndd.service

%postun -n rdma-ndd
%service_del_postun rdma-ndd.service

%files
%defattr(-,root,root)
%dir %{_sysconfdir}/rdma
%dir %{_sysconfdir}/rdma/modules
%dir %{_docdir}/%{name}-%{version}
%dir %{_udevrulesdir}
%dir %{_sysconfdir}/udev
%dir %{_sysconfdir}/udev/rules.d
%dir %{_sysconfdir}/modprobe.d
%doc %{_docdir}/%{name}-%{version}/README.md
%doc %{_docdir}/%{name}-%{version}/udev.md
%config(noreplace) %{_sysconfdir}/rdma/mlx4.conf
%config(noreplace) %{_sysconfdir}/rdma/modules/infiniband.conf
%config(noreplace) %{_sysconfdir}/rdma/modules/iwarp.conf
%config(noreplace) %{_sysconfdir}/rdma/modules/opa.conf
%config(noreplace) %{_sysconfdir}/rdma/modules/rdma.conf
%config(noreplace) %{_sysconfdir}/rdma/modules/roce.conf
%config(noreplace) %{_sysconfdir}/rdma/sriov-vfs
%if 0%{?dma_coherent}
%config(noreplace) %{_sysconfdir}/modprobe.d/mlx4.conf
%endif
%config(noreplace) %{_sysconfdir}/modprobe.d/truescale.conf
%config(noreplace) %{_sysconfdir}/udev/rules.d/70-persistent-ipoib.rules
%{_unitdir}/rdma-hw.target
%{_unitdir}/rdma-load-modules@.service
%{_unitdir}/rdma-sriov.service
%dir %{dracutlibdir}
%dir %{dracutlibdir}/modules.d
%dir %{dracutlibdir}/modules.d/05rdma
%{dracutlibdir}/modules.d/05rdma/module-setup.sh
%{_udevrulesdir}/75-rdma-description.rules
%{_udevrulesdir}/90-rdma-hw-modules.rules
%{_udevrulesdir}/90-rdma-ulp-modules.rules
%{_udevrulesdir}/90-rdma-umad.rules
%{_udevrulesdir}/98-rdma-sriov.rules
%{sysmodprobedir}/50-libmlx4.conf
%{_libexecdir}/rdma-set-sriov-vf
%{_libexecdir}/mlx4-setup.sh
%{_libexecdir}/truescale-serdes.cmds
%license COPYING.*
%{_sbindir}/rcrdma

%files devel
%defattr(-,root,root)
%doc %{_docdir}/%{name}-%{version}/MAINTAINERS
%dir %{_includedir}/infiniband
%dir %{_includedir}/rdma
%{_includedir}/infiniband/*
%{_includedir}/rdma/*
%if %{with_static}
%{_libdir}/lib*.a
%endif
%{_libdir}/lib*.so
%{_libdir}/pkgconfig/*.pc
%{_mandir}/man3/ibv_*
%{_mandir}/man3/rdma*
%{_mandir}/man3/umad*
%{_mandir}/man3/*_to_ibv_rate.*
%{_mandir}/man7/rdma_cm.*
%if 0%{?dma_coherent}
%{_mandir}/man3/mlx5dv*
%{_mandir}/man3/mlx4dv*
%{_mandir}/man7/mlx5dv*
%{_mandir}/man7/mlx4dv*
%endif

%files -n libibverbs
%defattr(-,root,root)
%dir %{_sysconfdir}/libibverbs.d
%dir %{_libdir}/libibverbs
%{_libdir}/libibverbs/*.so
%config(noreplace) %{_sysconfdir}/libibverbs.d/*.driver
%doc %{_docdir}/%{name}-%{version}/libibverbs.md
%doc %{_docdir}/%{name}-%{version}/rxe.md
%doc %{_docdir}/%{name}-%{version}/tag_matching.md
%{_bindir}/rxe_cfg
%{_mandir}/man7/rxe*
%{_mandir}/man8/rxe*

%files -n %verbs_lname
%defattr(-,root,root)
%{_libdir}/libibverbs*.so.*

%if 0%{?dma_coherent}
%files -n %mlx4_lname
%defattr(-,root,root)
%{_libdir}/libmlx4*.so.*

%files -n %mlx5_lname
%defattr(-,root,root)
%{_libdir}/libmlx5*.so.*
%endif

%files -n libibverbs-utils
%defattr(-,root,root)
%{_bindir}/ibv_*
%{_mandir}/man1/ibv_*

%files -n ibacm
%defattr(-,root,root)
%config(noreplace) %{_sysconfdir}/rdma/ibacm_opts.cfg
%{_bindir}/ib_acme
%{_sbindir}/ibacm
%{_mandir}/man1/ibacm.*
%{_mandir}/man1/ib_acme.*
%{_mandir}/man7/ibacm.*
%{_mandir}/man7/ibacm_prov.*
%{_unitdir}/ibacm.service
%{_unitdir}/ibacm.socket
%dir %{_libdir}/ibacm
%{_libdir}/ibacm/*
%{_sbindir}/rcibacm
%doc %{_docdir}/%{name}-%{version}/ibacm.md

%files -n iwpmd
%defattr(-,root,root)
%dir %{_sysconfdir}/rdma
%dir %{_sysconfdir}/rdma/modules
%{_sbindir}/iwpmd
%{_sbindir}/rciwpmd
%{_unitdir}/iwpmd.service
%config(noreplace) %{_sysconfdir}/rdma/modules/iwpmd.conf
%config(noreplace) %{_sysconfdir}/iwpmd.conf
%{_udevrulesdir}/90-iwpmd.rules
%{_mandir}/man8/iwpmd.*
%{_mandir}/man5/iwpmd.*

%files -n %umad_lname
%defattr(-,root,root)
%{_libdir}/libibumad*.so.*

%files -n %rdmacm_lname
%defattr(-,root,root)
%{_libdir}/librdmacm*.so.*
%doc %{_docdir}/%{name}-%{version}/librdmacm.md

%files -n rsocket
%defattr(-,root,root)
%dir %{_libdir}/rsocket
%{_libdir}/rsocket/*.so*
%{_mandir}/man7/rsocket.*

%files -n librdmacm-utils
%defattr(-,root,root)
%{_bindir}/cmtime
%{_bindir}/mckey
%{_bindir}/rcopy
%{_bindir}/rdma_client
%{_bindir}/rdma_server
%{_bindir}/rdma_xclient
%{_bindir}/rdma_xserver
%{_bindir}/riostream
%{_bindir}/rping
%{_bindir}/rstream
%{_bindir}/ucmatose
%{_bindir}/udaddy
%{_bindir}/udpong
%{_mandir}/man1/cmtime.*
%{_mandir}/man1/mckey.*
%{_mandir}/man1/rcopy.*
%{_mandir}/man1/rdma_client.*
%{_mandir}/man1/rdma_server.*
%{_mandir}/man1/rdma_xclient.*
%{_mandir}/man1/rdma_xserver.*
%{_mandir}/man1/riostream.*
%{_mandir}/man1/rping.*
%{_mandir}/man1/rstream.*
%{_mandir}/man1/ucmatose.*
%{_mandir}/man1/udaddy.*
%{_mandir}/man1/udpong.*

%files -n srp_daemon
%defattr(-,root,root)
%dir %{_libexecdir}/srp_daemon
%dir %{_sysconfdir}/rdma
%dir %{_sysconfdir}/rdma/modules
%config(noreplace) %{_sysconfdir}/srp_daemon.conf
%config(noreplace) %{_sysconfdir}/rdma/modules/srp_daemon.conf
%{_udevrulesdir}/60-srp_daemon.rules
%{_libexecdir}/srp_daemon/start_on_all_ports
%{_unitdir}/srp_daemon.service
%{_unitdir}/srp_daemon_port@.service
%{_sbindir}/ibsrpdm
%{_sbindir}/srp_daemon
%{_sbindir}/run_srp_daemon
%{_sbindir}/rcsrp_daemon
%{_mandir}/man1/ibsrpdm.1*
%{_mandir}/man1/srp_daemon.1*
%{_mandir}/man5/srp_daemon.service.5*
%{_mandir}/man5/srp_daemon_port@.service.5*
%doc %{_docdir}/%{name}-%{version}/ibsrpdm.md

%files -n rdma-ndd
%defattr(-, root, root)
%{_sbindir}/rdma-ndd
%{_sbindir}/rcrdma-ndd
%{_unitdir}/rdma-ndd.service
%{_mandir}/man8/rdma-ndd.8*
%{_udevrulesdir}/60-rdma-ndd.rules

%if %{with_pyverbs}
%files -n python3-pyverbs
%{python3_sitearch}/pyverbs
%endif

%changelog
