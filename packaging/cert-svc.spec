%define certsvc_feature_ocsp_crl     0
%define certsvc_test_build           0

Name:    cert-svc
Summary: Certification service
Version: 1.0.1
Release: 45
Group:   Security/Libraries
License: Apache-2.0
Source0: %{name}-%{version}.tar.gz
Source1001: %{name}.manifest
Requires(post): findutils
BuildRequires: cmake
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(openssl)
BuildRequires: pkgconfig(libpcrecpp)
BuildRequires: pkgconfig(xmlsec1)
BuildRequires: pkgconfig(glib-2.0)
BuildRequires: pkgconfig(libxml-2.0)
BuildRequires: pkgconfig(libxslt)
BuildRequires: pkgconfig(icu-i18n)
BuildRequires: pkgconfig(libsoup-2.4)
BuildRequires: pkgconfig(db-util)
BuildRequires: pkgconfig(libsystemd-daemon)
BuildRequires: pkgconfig(key-manager)
BuildRequires: pkgconfig(secure-storage)
BuildRequires: pkgconfig(libtzplatform-config)
BuildRequires: boost-devel
%if 0%{?certsvc_feature_ocsp_crl}
BuildRequires: pkgconfig(vconf)
BuildRequires: pkgconfig(sqlite3)
%endif
Requires: pkgconfig(libtzplatform-config)
Requires: ca-certificates-tizen
Requires: ca-certificates-mozilla
Requires: ca-certificates
Requires: openssl

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
BuildRequires: pkgconfig(dpl-test-efl)
Requires: boost-devel
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
cmake . -DPREFIX=%{_prefix} \
        -DEXEC_PREFIX=%{_exec_prefix} \
        -DLIBDIR=%{_libdir} \
        -DBINDIR=%{_bindir} \
        -DINCLUDEDIR=%{_includedir} \
        -DTZ_SYS_SHARE=%TZ_SYS_SHARE \
        -DTZ_SYS_BIN=%TZ_SYS_BIN \
        -DTZ_SYS_ETC=%TZ_SYS_ETC \
        -DTZ_SYS_RO_WRT_ENGINE=%TZ_SYS_RO_WRT_ENGINE \
        -DTZ_SYS_DB=%TZ_SYS_DB \
%if 0%{?certsvc_feature_ocsp_crl}
        -DTIZEN_FEAT_CERTSVC_OCSP_CRL=1 \
%endif
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

mkdir -p %{buildroot}%{TZ_SYS_SHARE}/cert-svc/certs/user
mkdir -p %{buildroot}%{TZ_SYS_SHARE}/cert-svc/certs/trusteduser
mkdir -p %{buildroot}%{TZ_SYS_SHARE}/cert-svc/pkcs12
mkdir -p %{buildroot}%{TZ_SYS_SHARE}/cert-svc/dbspace

%make_install
mkdir -p %{buildroot}%{_unitdir}/multi-user.target.wants
mkdir -p %{buildroot}%{_unitdir}/sockets.target.wants
ln -s ../cert-server.service %{buildroot}%{_unitdir}/multi-user.target.wants/
ln -s ../cert-server.socket %{buildroot}%{_unitdir}/sockets.target.wants/

ln -sf %{TZ_SYS_ETC}/ssl/certs %{buildroot}%{TZ_SYS_SHARE}/cert-svc/certs/ssl

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

echo "make ca-certificate.crt"
%{TZ_SYS_BIN}/make-ca-certificate.sh
rm %{TZ_SYS_BIN}/make-ca-certificate.sh

echo "create .cert_svc_vcore.db"
%if 0%{?certsvc_feature_ocsp_crl}
if [ -z ${2} ]; then
    echo "This is new install of cert-svc"
    %{TZ_SYS_BIN}/cert_svc_create_clean_db.sh
else
    echo "Find out old and new version of databases"
    VCORE_OLD_DB_VERSION=`sqlite3 %{TZ_SYS_DB}/.cert_svc_vcore.db ".tables" | grep "DB_VERSION_"`
    VCORE_NEW_DB_VERSION=`cat %{TZ_SYS_SHARE}/cert-svc/cert_svc_vcore_db.sql | tr '[:blank:]' '\n' | grep DB_VERSION_`
    echo "OLD vcore database version ${VCORE_OLD_DB_VERSION}"
    echo "NEW vcore database version ${VCORE_NEW_DB_VERSION}"

    if [ ${VCORE_OLD_DB_VERSION} -a ${VCORE_NEW_DB_VERSION} ]; then
        if [ ${VCORE_OLD_DB_VERSION} = ${VCORE_NEW_DB_VERSION} ]; then
            echo "Equal database detected so db installation ignored"
        else
            echo "Calling /usr/bin/cert_svc_create_clean_db.sh"
            %{TZ_SYS_BIN}/cert_svc_create_clean_db.sh
        fi
    else
        echo "Calling /usr/bin/cert_svc_create_clean_db.sh"
        %{TZ_SYS_BIN}/cert_svc_create_clean_db.sh
    fi
fi
rm %{TZ_SYS_SHARE}/cert-svc/cert_svc_vcore_db.sql
rm %{TZ_SYS_BIN}/cert_svc_create_clean_db.sh
%endif

echo "create certs-meta.db"
rm -rf %{TZ_SYS_SHARE}/cert-svc/dbspace/certs-meta.db
%{TZ_SYS_BIN}/cert_svc_create_clean_store_db.sh %{TZ_SYS_SHARE}/cert-svc/cert_svc_store_db.sql
%{TZ_SYS_BIN}/initialize_store_db.sh
if [[ -e %{TZ_SYS_SHARE}/cert-svc/dbspace/certs-meta.db ]]; then
    cat %{TZ_SYS_SHARE}/cert-svc/root-cert.sql | sqlite3 %{TZ_SYS_SHARE}/cert-svc/dbspace/certs-meta.db
fi
rm %{TZ_SYS_SHARE}/cert-svc/cert_svc_store_db.sql
rm %{TZ_SYS_SHARE}/cert-svc/root-cert.sql
rm %{TZ_SYS_BIN}/cert_svc_create_clean_store_db.sh
rm %{TZ_SYS_BIN}/initialize_store_db.sh

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
%attr(755,root,root) %{_libdir}/libcert-svc.so.*
%attr(755,root,root) %{_libdir}/libcert-svc-vcore.so.*
%attr(644,root,root) %{TZ_SYS_SHARE}/license/%{name}
%attr(644,root,root) %{TZ_SYS_RO_WRT_ENGINE}/schema.xsd
%attr(644,root,root) %{TZ_SYS_SHARE}/cert-svc/cert_svc_store_db.sql
%attr(755,root,root) %{TZ_SYS_BIN}/cert_svc_create_clean_store_db.sh
%attr(755,root,root) %{TZ_SYS_BIN}/make-ca-certificate.sh
%attr(755,root,root) %{TZ_SYS_BIN}/initialize_store_db.sh

%if 0%{?certsvc_feature_ocsp_crl}
%attr(644,root,root) %{TZ_SYS_SHARE}/cert-svc/cert_svc_vcore_db.sql
%attr(755,root,root) %{TZ_SYS_BIN}/cert_svc_create_clean_db.sh
%endif

# Resource files install as system
%{TZ_SYS_SHARE}/cert-svc/certs/user
%{TZ_SYS_SHARE}/cert-svc/certs/trusteduser
%{TZ_SYS_SHARE}/cert-svc/pkcs12
%{TZ_SYS_SHARE}/cert-svc/dbspace
%{TZ_SYS_SHARE}/cert-svc/certs/ssl


%files devel
%defattr(-,root,root,-)
%{_includedir}/*
%{_libdir}/pkgconfig/*
%{_libdir}/libcert-svc.so
%{_libdir}/libcert-svc-vcore.so

%if 0%{?certsvc_test_build}
%files test
%defattr(644,system,system,755)
%attr(755,root,root) %{TZ_SYS_BIN}/cert-svc-test*
%{TZ_SYS_RO_APP}/widget/tests/vcore_widget_uncompressed/*
%{TZ_SYS_RO_APP}/widget/tests/vcore_widget_uncompressed_negative_hash/*
%{TZ_SYS_RO_APP}/widget/tests/vcore_widget_uncompressed_negative_signature/*
%{TZ_SYS_RO_APP}/widget/tests/vcore_widget_uncompressed_negative_certificate/*
%{TZ_SYS_RO_APP}/widget/tests/vcore_widget_uncompressed_partner/*
%{TZ_SYS_RO_APP}/widget/tests/vcore_widget_uncompressed_partner_operator/*
%{TZ_SYS_RO_APP}/widget/tests/vcore_keys/*
%{TZ_SYS_RO_APP}/widget/tests/vcore_certs/*
%{TZ_SYS_RO_APP}/widget/tests/vcore_config/*
%{TZ_SYS_RO_APP}/widget/tests/pkcs12/*
%{TZ_SYS_RO_APP}/widget/tests/reference/*
%{TZ_SYS_ETC}/ssl/certs/8956b9bc.0
%{TZ_SYS_SHARE}/ca-certificates/wac/root_cacert0.pem
%{TZ_SYS_SHARE}/cert-svc/pkcs12/*
%{TZ_SYS_SHARE}/cert-svc/cert-type/*
%{TZ_SYS_SHARE}/cert-svc/tests/orig_c/data/caflag/*
%{TZ_SYS_SHARE}/cert-svc/certs/root_ca*.der
%{TZ_SYS_SHARE}/cert-svc/certs/second_ca*.der
%{TZ_SYS_SHARE}/cert-svc/tests/*
%endif
