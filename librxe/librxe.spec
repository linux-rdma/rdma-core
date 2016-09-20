Name: librxe
Version: 1.0.0
Release: 1
Summary: RDMA over Converging Enhanced Ethernet (RoCE) user library 

Group: System Environment/Libraries
License: GPLv2 or BSD
Url: http://openfabrics.org/
Source: librxe-%{version}.tar.gz
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires: libibverbs-devel >= 1.1-0.1.rc2

%description
librxe provides a device-specific userspace driver RDMA
over Converging Enhanced Ethernet for use with the libibverbs library.

%package devel-static
Summary: Development files for the librxe driver
Group: System Environment/Libraries
Requires: %{name} = %{version}-%{release}

%description devel-static
Static version of librxe that may be linked directly to an
application, which may be useful for debugging.

%prep
%setup -q -n %{name}-1.0.0

%build
%configure
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make DESTDIR=%{buildroot} install
# remove unpackaged files from the buildroot
rm -f $RPM_BUILD_ROOT%{_libdir}/*.la $RPM_BUILD_ROOT%{_libdir}/librxe.so

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_libdir}/librxe-rdmav2.so
%{_sysconfdir}/libibverbs.d/rxe.driver
%{_mandir}/man7/*
%{_mandir}/man8/*
%doc AUTHORS COPYING ChangeLog README

%files devel-static
%defattr(-,root,root,-)
%{_libdir}/librxe.a

%changelog
