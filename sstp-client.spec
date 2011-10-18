%define ppp_version 2.4.5
%define event_version 2.0.10

Name:		sstp-client
Version:	1.0.2
Release:	1%{?dist}
Summary:	Secure Socket Tunneling Protocol (SSTP) Client
Group:		Applications/Internet
License:	GPLv2+
Packager:	Eivind Naess <eivnaes@yahoo.com>
Provides:	sstp-client
URL:		http://sstp-client.sourceforge.net/
Source0:	http://downloads.sf.net/sstp-client/sstp-client-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Requires:	ppp >= %ppp_version
Requires:	libevent >= %event_version
Requires(pre):      /usr/sbin/useradd, /usr/bin/getent
Requires(postun):   /usr/sbin/userdel

%package devel
Summary:	Provide development headers for sstp-client
Group: 		Applications/Internet
Provides:	sstp-client-devel

%description devel
This package contains the necessary header files for sstp-client development

This package is required to compile plugin's for sstp-client.

%description
Client for the proprietary Microsoft Secure Socket Tunneling Protocol, SSTP.
Allows connection to a SSTP based VPN as used by employers and some cable 
and ADSL service providers.

%prep
%setup -q

%build
CFLAGS="-Wall %{optflags}" 		\
	./configure 			\
		--disable-static	\
		--prefix=/usr 		\
		--with-libevent=2 	\
		--with-pppd-plugin-dir=%_libdir/pppd/%ppp_version \
		--with-runtime-dir="/var/run/sstpc"
%{__make} %{?_smp_mflags}

%pre
/usr/bin/getent group sstpc || /usr/sbin/groupadd -r \
    sstpc

/usr/bin/getent passwd sstpc || /usr/sbin/useradd -r \
    -c "Secure Socket Tunneling Protocol (SSTP) Client" \
    -g sstpc \
    -d /var/run/sstpc \
    -s /bin/false \
    sstpc

%postun
rm -rf /var/run/sstpc
/usr/sbin/userdel sstpc

%install
%{__rm} -rf %{buildroot}
%{__make} DESTDIR=%{buildroot} install
%{__install} -c -d -m 755 %{buildroot}/%{_mandir}/man8
%{__install} -c -m 755 sstpc.8 %{buildroot}/%{_mandir}/man8

%clean
%{__rm} -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc AUTHORS COPYING DEVELOPERS NEWS README TODO USING
%doc ChangeLog 
%{_sbindir}/sstpc
%{_mandir}/man8/sstpc.8*
%{_libdir}/libsstp_api*.so*
%{_libdir}/pppd/%ppp_version/sstp-pppd-plugin*.so*
%{_libdir}/pkgconfig/sstp-client*.pc

%exclude %{_libdir}/*.la
%exclude %{_libdir}/pppd/%ppp_version/*.la


%files devel
/usr/include/sstp-client/sstp-api.h

%changelog
* Sun Oct 02 2011 Eivind Naess <eivnaes@yahoo.com> - 1.0-1
- Initial packaging release
