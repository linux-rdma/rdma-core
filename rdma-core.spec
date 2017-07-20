Name: rdma-core
Version: 15
Release: 1%{?dist}
Summary: RDMA core userspace libraries and daemons

# Almost everything is licensed under the OFA dual GPLv2, 2 Clause BSD license
#  providers/ipathverbs/ Dual licensed using a BSD license with an extra patent clause
#  providers/rxe/ Incorporates code from ipathverbs and contains the patent clause
#  providers/hfi1verbs Uses the 3 Clause BSD license
License: (GPLv2 or BSD) and (GPLv2 or PathScale-BSD)
Url: https://github.com/linux-rdma/rdma-core
Source: rdma-core-%{version}.tgz

BuildRequires: binutils
BuildRequires: cmake >= 2.8.11
BuildRequires: gcc
BuildRequires: libudev-devel
BuildRequires: pkgconfig
BuildRequires: pkgconfig(libnl-3.0)
BuildRequires: pkgconfig(libnl-route-3.0)
BuildRequires: valgrind-devel
BuildRequires: python
%if 0%{?_unitdir:1}
BuildRequires: systemd-devel
%endif

# Since we recommend developers use Ninja, so should packagers, for consistency.
%define CMAKE_FLAGS %{nil}
%if 0%{?suse_version}
# SuSE releases have it, and sometime around cmake 3.3.2-1.2 the macros learned to use it.
BuildRequires: ninja,make
%define __builder ninja
# cmake_install is specified by opensuse. It also specifies make_jobs, but it
# doesn't work with __builder as other rpm macro packages define it too.
%define make_jobs ninja -v %{?_smp_mflags}

# Tumbleweed's cmake RPM macro adds -Wl,--no-undefined to the module flags
# which is totally inappropriate and breaks building 'ENABLE_EXPORTS' style
# module libraries (eg ibacmp).
%define CMAKE_FLAGS -DCMAKE_MODULE_LINKER_FLAGS=""
%else
%if 0%{?fedora} >= 23
# Ninja was introduced in FC23
BuildRequires: ninja-build
%define CMAKE_FLAGS -GNinja
%define make_jobs ninja-build -v %{?_smp_mflags}
%define cmake_install DESTDIR=%{buildroot} ninja-build install
%else
# Fallback to make otherwise
BuildRequires: make
%define make_jobs make -v %{?_smp_mflags}
%define cmake_install DESTDIR=%{buildroot} make install
%endif
%endif

# Detect if systemd is supported on this system
%if 0%{?_unitdir:1}
Requires(post): systemd-units
Requires(preun): systemd-units
Requires(postun): systemd-units
%endif

%description
Temporary packaging

This is a simple example without the split sub packages to get things started.

%prep
%setup

%build

# Detect if systemd is supported on this system
%if 0%{?_unitdir:1}
%define my_unitdir %{_unitdir}
%else
%define my_unitdir /tmp/
%endif

# New RPM defines _rundir, usually as /run
%if 0%{?_rundir:1}
%else
%define _rundir /var/run
%endif

# New RPM defines _udevrulesdir, usually as /usr/lib/udev/rules.d
%if 0%{?_udevrulesdir:1}
%else
# This is the old path (eg for C6)
%define _udevrulesdir /lib/udev/rules.d
%endif

# Pass all of the rpm paths directly to GNUInstallDirs and our other defines.
%cmake %{CMAKE_FLAGS} \
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
	 -DCMAKE_INSTALL_SYSTEMD_SERVICEDIR:PATH=%{my_unitdir} \
	 -DCMAKE_INSTALL_INITDDIR:PATH=%{_initrddir} \
	 -DCMAKE_INSTALL_RUNDIR:PATH=%{_rundir} \
	 -DCMAKE_INSTALL_DOCDIR:PATH=%{_docdir}/%{name}-%{version} \
	 -DCMAKE_INSTALL_UDEV_RULESDIR:PATH=%{_udevrulesdir}
%make_jobs

%install
%cmake_install

%if 0%{?_unitdir:1}
rm -rf %{buildroot}/%{_initrddir}/
%else
rm -rf %{buildroot}/%{my_unitdir}/
%endif

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%files
%doc %{_mandir}/man*/*
%{_bindir}/*
%{_includedir}/*
%{_libdir}/lib*.so*
%{_libdir}/libibverbs/*
%{_libdir}/ibacm/*
%{_libdir}/rsocket/*
%{_sbindir}/*
%{_libexecdir}/*
%{_udevrulesdir}/*
%doc %{_docdir}/%{name}-%{version}/*
%if 0%{?_unitdir:1}
%{_unitdir}/*
%else
%config %{_initrddir}/*
%endif
%config %{_sysconfdir}/iwpmd.conf
%config %{_sysconfdir}/srp_daemon.conf
%config %{_sysconfdir}/libibverbs.d/*
%config %{_sysconfdir}/rdma/modules/*
%{_sysconfdir}/modprobe.d/*
