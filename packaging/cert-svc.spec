%define certsvc_test_build 0

Name:    cert-svc
Summary: Certification service
Version: 2.0.5
Release: 0
Group:   Security/Certificate Management
License: Apache-2.0
Source0: %{name}-%{version}.tar.gz
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
BuildRequires: ca-certificates
BuildRequires: ca-certificates-devel
Requires: ca-certificates
Requires: ca-certificates-tizen

%global TZ_SYS_BIN      %{?TZ_SYS_BIN:%TZ_SYS_BIN}%{!?TZ_SYS_BIN:%_bindir}
%global TZ_SYS_SHARE    %{?TZ_SYS_SHARE:%TZ_SYS_SHARE}%{!?TZ_SYS_SHARE:/opt/share}
%global TZ_SYS_RO_SHARE %{?TZ_SYS_RO_SHARE:%TZ_SYS_RO_SHARE}%{!?TZ_SYS_RO_SHARE:%_datadir}
%global TZ_SYS_RO_APP   %{?TZ_SYS_RO_APP:%TZ_SYS_RO_APP}%!?TZ_SYS_RO_APP:/usr/apps}
%global TZ_SYS_CA_CERTS %{?TZ_SYS_CA_CERTS:%TZ_SYS_CA_CERTS}%{!?TZ_SYS_CA_CERTS:/etc/ssl/certs}
%global TZ_SYS_CA_CERTS_ORIG %{?TZ_SYS_CA_CERTS_ORIG:%TZ_SYS_CA_CERTS_ORIG}%{!?TZ_SYS_CA_CERTS_ORGIN:%TZ_SYS_RO_SHARE/ca-certificates/certs}
%global TZ_SYS_CA_BUNDLE_RW  %{?TZ_SYS_CA_BUNDLE_RW:%TZ_SYS_CA_BUNDLE_RW}%{!?TZ_SYS_CA_BUNDLE_RW:/var/lib/ca-certificates/ca-bundle.pem}

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
%cmake . -DVERSION=%version \
        -DINCLUDEDIR=%_includedir \
        -DTZ_SYS_SHARE=%TZ_SYS_SHARE \
        -DTZ_SYS_RO_SHARE=%TZ_SYS_RO_SHARE \
        -DTZ_SYS_BIN=%TZ_SYS_BIN \
        -DTZ_SYS_CA_CERTS=%TZ_SYS_CA_CERTS \
        -DTZ_SYS_CA_CERTS_ORIG=%TZ_SYS_CA_CERTS_ORIG \
        -DTZ_SYS_CA_BUNDLE_RW=%TZ_SYS_CA_BUNDLE_RW \
%if 0%{?certsvc_test_build}
        -DCERTSVC_TEST_BUILD=1 \
        -DTZ_SYS_RO_APP=%TZ_SYS_RO_APP \
%endif
        -DCMAKE_BUILD_TYPE=%build_type \
        -DSYSTEMD_UNIT_DIR=%_unitdir

make %{?_smp_mflags}

%install
%make_install
%install_service multi-user.target.wants cert-server.service
%install_service sockets.target.wants cert-server.socket

mkdir -p %buildroot%TZ_SYS_RO_SHARE/cert-svc/pkcs12
mkdir -p %buildroot%TZ_SYS_SHARE/cert-svc/dbspace
ln -s %TZ_SYS_CA_BUNDLE_RW %buildroot%TZ_SYS_RO_SHARE/cert-svc/ca-certificate.crt

%preun
# erase
if [ $1 = 0 ]; then
    systemctl stop cert-server.service
fi

%post
/sbin/ldconfig
systemctl daemon-reload
# install
if [ $1 = 1 ]; then
    systemctl start cert-server.service
fi
# upgrade / reinstall
if [ $1 = 2 ]; then
    systemctl restart cert-server.service
fi

%postun -p /sbin/ldconfig

%files
%manifest %name.manifest
%license LICENSE
%_unitdir/cert-server.service
%_unitdir/cert-server.socket
%_unitdir/multi-user.target.wants/cert-server.service
%_unitdir/sockets.target.wants/cert-server.socket
%_libdir/libcert-svc-vcore.so.*
%TZ_SYS_BIN/cert-server
%attr(-, system, system) %TZ_SYS_RO_SHARE/cert-svc

%files devel
%_includedir/*
%_libdir/pkgconfig/*
%_libdir/libcert-svc-vcore.so

%if 0%{?certsvc_test_build}
%files test
%TZ_SYS_BIN/cert-svc-test*
%TZ_SYS_RO_APP/cert-svc-tests
%_libdir/libcert-svc-validator-plugin.so
%endif
