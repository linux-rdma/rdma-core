Name: libiwpm
Version: 1.0.0
Release: 1
Summary: iWarp Port Mapper userspace daemon

Group: System Environment/Daemons
License: GPL/BSD
Url: http://www.openfabrics.org/
Source: http://www.openfabrics.org/downloads/%{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%description
libiwpm provides a userspace service for NetEffect Ethernet Server Cluster 
Adaper for reserving tcp ports through the socket interface

%prep
%setup -q -n %{name}-1.0.0

%build
%configure
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make DESTDIR=%{buildroot} install
install -d $RPM_BUILD_ROOT/etc/init.d
cp -p $RPM_BUILD_DIR/%{name}-1.0.0/iwpmd_init $RPM_BUILD_ROOT/etc/init.d/iwpmd

%clean
rm -rf $RPM_BUILD_ROOT

%post
if [[ -f /etc/redhat-release ]]; then 
	/sbin/chkconfig --add iwpmd > /dev/null
	/etc/init.d/iwpmd start || exit 0
fi

%preun
if [[ -f /etc/redhat-release ]]; then 
	/etc/init.d/iwpmd stop || exit 0
        /sbin/chkconfig --del iwpmd > /dev/null
fi

%files
%defattr(-,root,root,-)
/etc/init.d/iwpmd
%_includedir/rdma/iwpm/iwpm_netlink.h
%_includedir/rdma/iwpm/iwarp_pm.h
%_bindir/*
%doc AUTHORS COPYING README


%changelog
*Fri Jun 11 2013 Tatyana Nikolova <tatyana.e.nikolova@intel.com> - 1.0.0
- Releasing iWarp Port Mapper Version 1.0.0 
