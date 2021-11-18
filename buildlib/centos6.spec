Name: rdma-core
Version: 39.0
Release: 1%{?dist}
Summary: RDMA core userspace libraries and daemons

# Almost everything is licensed under the OFA dual GPLv2, 2 Clause BSD license
#  providers/ipathverbs/ Dual licensed using a BSD license with an extra patent clause
#  providers/rxe/ Incorporates code from ipathverbs and contains the patent clause
#  providers/hfi1verbs Uses the 3 Clause BSD license
License: (GPLv2 or BSD) and (GPLv2 or PathScale-BSD)
Url: https://github.com/linux-rdma/rdma-core
Source: rdma-core.tgz

BuildRequires: binutils
BuildRequires: cmake >= 2.8.11
BuildRequires: gcc
BuildRequires: libudev-devel
BuildRequires: pkgconfig
BuildRequires: pkgconfig(libnl-3.0)
BuildRequires: pkgconfig(libnl-route-3.0)
BuildRequires: valgrind-devel
BuildRequires: python

%define CMAKE_FLAGS %{nil}
BuildRequires: make

%description
Temporary packaging

This is a simple example without the split sub packages to get things started.

%prep
%setup

%build

%define my_unitdir /tmp/

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
	 -DCMAKE_INSTALL_UDEV_RULESDIR:PATH=%{_udevrulesdir} \
         -DCMAKE_INSTALL_PERLDIR:PATH=%{perl_vendorlib}
make -s %{?_smp_mflags}

%install
DESTDIR=%{buildroot} make install

%if 0%{?_unitdir:1}
rm -rf %{buildroot}/%{_initrddir}/
%else
rm -rf %{buildroot}/%{my_unitdir}/
%endif

%files
%doc %{_mandir}/man*/*
%{_bindir}/*
%{_includedir}/*
%{_libdir}/lib*.so*
%{_libdir}/libibverbs/*
%{_libdir}/ibacm/*
%{_libdir}/rsocket/*
%{_libdir}/pkgconfig/*.pc
%{_sbindir}/*
%{_libexecdir}/*
%{_udevrulesdir}/*
%{_udevrulesdir}/../rdma_rename
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
%{perl_vendorlib}/IBswcountlimits.pm
%config(noreplace) %{_sysconfdir}/udev/rules.d/*
%config(noreplace) %{_sysconfdir}/infiniband-diags/error_thresholds
%config(noreplace) %{_sysconfdir}/infiniband-diags/ibdiag.conf
%{_sysconfdir}/modprobe.d/*
