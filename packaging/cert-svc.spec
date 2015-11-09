%define certsvc_test_build 0

Name:    cert-svc
Summary: Certification service
Version: 1.0.1
Release: 45
Group:   Security/Libraries
License: Apache-2.0
Source0: %{name}-%{version}.tar.gz
Source1001: %{name}.manifest
BuildRequires: cmake
BuildRequires: findutils
BuildRequires: openssl
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(openssl)
BuildRequires: pkgconfig(libpcrecpp)
BuildRequires: pkgconfig(xmlsec1)
BuildRequires: pkgconfig(libxml-2.0)
BuildRequires: pkgconfig(libxslt)
BuildRequires: pkgconfig(db-util)
BuildRequires: pkgconfig(libsystemd-daemon)
BuildRequires: pkgconfig(key-manager)
BuildRequires: pkgconfig(libtzplatform-config)
BuildRequires: pkgconfig(libsystemd-journal)
BuildRequires: pkgconfig(sqlite3)
BuildRequires: ca-certificates-tizen
BuildRequires: ca-certificates-mozilla

%description
Certification service

%package devel
Summary:    Certification service (development files)
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
Certification service (development files)

%if 0%{?certsvc_test_build}
%package test
Summary:  Certification service (tests)
Group:    Security/Testing
Requires: ca-certificates-tizen
Requires: %{name} = %{version}-%{release}

%description test
Certification service (tests)
%endif

%prep
%setup -q
cp -a %{SOURCE1001} .

%build
export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"

export CFLAGS="$CFLAGS -DTIZEN_ENGINEER_MODE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_ENGINEER_MODE"
export FFLAGS="$FFLAGS -DTIZEN_ENGINEER_MODE"

%ifarch %{ix86}
export CFLAGS="$CFLAGS -DTIZEN_EMULATOR_MODE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_EMULATOR_MODE"
export FFLAGS="$FFLAGS -DTIZEN_EMULATOR_MODE"
%endif

%{!?build_type:%define build_type "Release"}
%cmake . -DPREFIX=%{_prefix} \
        -DEXEC_PREFIX=%{_exec_prefix} \
        -DLIBDIR=%{_libdir} \
        -DINCLUDEDIR=%{_includedir} \
        -DTZ_SYS_SHARE=%TZ_SYS_SHARE \
        -DTZ_SYS_BIN=%TZ_SYS_BIN \
        -DTZ_SYS_ETC=%TZ_SYS_ETC \
        -DTZ_SYS_RO_WRT_ENGINE=%TZ_SYS_RO_WRT_ENGINE \
%if 0%{?certsvc_test_build}
        -DCERTSVC_TEST_BUILD=1 \
        -DTZ_SYS_RO_APP=%TZ_SYS_RO_APP \
%endif
        -DCMAKE_BUILD_TYPE=%{build_type} \
        -DSYSTEMD_UNIT_DIR=%{_unitdir}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{TZ_SYS_SHARE}/license
cp LICENSE %{buildroot}%{TZ_SYS_SHARE}/license/%{name}

mkdir -p %{buildroot}%{TZ_SYS_SHARE}/cert-svc/pkcs12
mkdir -p %{buildroot}%{TZ_SYS_SHARE}/cert-svc/dbspace

%make_install
mkdir -p %{buildroot}%{_unitdir}/multi-user.target.wants
mkdir -p %{buildroot}%{_unitdir}/sockets.target.wants
ln -s ../cert-server.service %{buildroot}%{_unitdir}/multi-user.target.wants/
ln -s ../cert-server.socket %{buildroot}%{_unitdir}/sockets.target.wants/

%clean
rm -rf %{buildroot}

%preun
if [ $1 == 0 ]; then
    systemctl stop cert-server.service
fi

%post
/sbin/ldconfig
systemctl daemon-reload
if [ $1 == 1 ]; then
    systemctl restart cert-server.service
fi

%postun
/sbin/ldconfig

%files
%defattr(644,system,system,755)
%manifest %{name}.manifest
# Read only files install as root
%attr(755,root,root) %{TZ_SYS_BIN}/cert-server
%attr(644,root,root) %{_unitdir}/cert-server.service
%attr(644,root,root) %{_unitdir}/cert-server.socket
%attr(777,root,root) %{_unitdir}/multi-user.target.wants/cert-server.service
%attr(777,root,root) %{_unitdir}/sockets.target.wants/cert-server.socket
%attr(755,root,root) %{_libdir}/libcert-svc-vcore.so.*
%attr(644,root,root) %{TZ_SYS_SHARE}/license/%{name}
%attr(644,root,root) %{TZ_SYS_RO_WRT_ENGINE}/schema.xsd

# Resource files install as system
%{TZ_SYS_SHARE}/cert-svc/pkcs12
%{TZ_SYS_SHARE}/cert-svc/dbspace/certs-meta.db*
%{TZ_SYS_SHARE}/cert-svc/ca-certificate.crt

%files devel
%defattr(-,root,root,-)
%{_includedir}/*
%{_libdir}/pkgconfig/*
%{_libdir}/libcert-svc-vcore.so


%if 0%{?certsvc_test_build}
%post test
ln -sf %{TZ_SYS_SHARE}/ca-certificates/tizen/root_cacert0.pem %{TZ_SYS_ETC}/ssl/certs/
ln -sf %{TZ_SYS_ETC}/ssl/certs/root_cacert0.pem %{TZ_SYS_ETC}/ssl/certs/ba70bb69.0

%postun test
rm %{TZ_SYS_ETC}/ssl/certs/root_cacert0.pem
rm %{TZ_SYS_ETC}/ssl/certs/ba70bb69.0

%files test
%defattr(644,system,system,755)
%attr(755,root,root) %{TZ_SYS_BIN}/cert-svc-test*
%{TZ_SYS_RO_APP}/widget/tests/*
%{TZ_SYS_ETC}/ssl/certs/8956b9bc.0
%{TZ_SYS_SHARE}/ca-certificates/tizen/*
%{TZ_SYS_SHARE}/cert-svc/cert-type/*
%{TZ_SYS_SHARE}/cert-svc/tests/*
%{_libdir}/libcert-svc-validator-plugin.so
%endif
