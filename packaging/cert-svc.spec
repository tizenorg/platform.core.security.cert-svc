#sbs-git:slp/pkgs/c/cert-svc cert-svc 1.0.1 ad7eb7efcefb37b06017c69cb2fc44e6f7b6cab7
Name:    cert-svc
Summary: Certification service
Version: 1.0.1
Release: 45
Group:   System/Libraries
License: Apache-2.0
Source0: %{name}-%{version}.tar.gz
Source1001: %{name}.manifest
BuildRequires: cmake
BuildRequires: boost-devel
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(openssl)
BuildRequires: pkgconfig(evas)
BuildRequires: pkgconfig(dpl-efl)
BuildRequires: pkgconfig(libsoup-2.4)
BuildRequires: pkgconfig(libpcre)
BuildRequires: pkgconfig(libpcrecpp)
BuildRequires: pkgconfig(xmlsec1)
BuildRequires: pkgconfig(secure-storage)
BuildRequires: pkgconfig(glib-2.0)
BuildRequires: pkgconfig(libxml-2.0)
BuildRequires: pkgconfig(libxslt)
BuildRequires: pkgconfig(libtzplatform-config)
Requires(post):   /sbin/ldconfig
Requires(postun): /sbin/ldconfig
Requires: libtzplatform-config
Provides: libcert-svc-vcore.so.1

%description
Certification service

%package devel
Summary:    Certification service (development files)
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
Certification service (developement files)

%prep
%setup -q
cp %{SOURCE1001} .

%build
%{!?build_type:%define build_type "Release"}
%cmake . -DPREFIX=%{_prefix} \
         -DEXEC_PREFIX=%{_exec_prefix} \
         -DBINDIR=%{_bindir} \
         -DINCLUDEDIR=%{_includedir} \
         -DCMAKE_BUILD_TYPE=%{build_type} \
	 -DTZ_SYS_SHARE=%TZ_SYS_SHARE \
	 -DTZ_SYS_BIN=%TZ_SYS_BIN

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{TZ_SYS_SHARE}/license
cp LICENSE.APLv2 %{buildroot}%{TZ_SYS_SHARE}/license/%{name}
%make_install
ln -sf %{TZ_SYS_ETC}/ssl/certs %{buildroot}%{TZ_SYS_SHARE}/cert-svc/certs/ssl
touch %{buildroot}%{TZ_SYS_SHARE}/cert-svc/pkcs12/storage
chmod 766 %{buildroot}%{TZ_SYS_SHARE}/cert-svc/pkcs12/storage

%clean
rm -rf %{buildroot}

%post
/sbin/ldconfig
%if 0%{?tizen_feature_certsvc_ocsp_crl}
if [ -z ${2} ]; then
    echo "This is new install of wrt-security"
    echo "Calling %{TZ_SYS_BIN}/cert_svc_create_clean_db.sh"
    %{TZ_SYS_BIN}/cert_svc_create_clean_db.sh
else
    # Find out old and new version of databases
    VCORE_OLD_DB_VERSION=`sqlite3 %{TZ_SYS_DB}/.cert_svc_vcore.db ".tables" | grep "DB_VERSION_"`
    VCORE_NEW_DB_VERSION=`cat %{TZ_SYS_SHARE}/cert-svc/cert_svc_vcore_db.sql | tr '[:blank:]' '\n' | grep DB_VERSION_`
    echo "OLD vcore database version ${VCORE_OLD_DB_VERSION}"
    echo "NEW vcore database version ${VCORE_NEW_DB_VERSION}"

    if [ ${VCORE_OLD_DB_VERSION} -a ${VCORE_NEW_DB_VERSION} ]; then
        if [ ${VCORE_OLD_DB_VERSION} = ${VCORE_NEW_DB_VERSION} ]; then
            echo "Equal database detected so db installation ignored"
        else
            echo "Calling %{TZ_SYS_BIN}/cert_svc_create_clean_db.sh"
            %{TZ_SYS_BIN}/cert_svc_create_clean_db.sh
        fi
    else
        echo "Calling %{TZ_SYS_BIN}/cert_svc_create_clean_db.sh"
        %{TZ_SYS_BIN}/cert_svc_create_clean_db.sh
    fi
fi

chsmack -a 'User' %TZ_SYS_DB/.cert_svc_vcore.db*
%endif #tizen_feature_certsvc_ocsp_crl
%postun
/sbin/ldconfig

%files

%defattr(-,root,root,-)
%manifest %{name}.manifest
%attr(0755,root,root) %{_bindir}/cert_svc_create_clean_db.sh
%{_libdir}/*.so.*
#%{_bindir}/dpkg-pki-sig
%{TZ_SYS_SHARE}/cert-svc/targetinfo
%if 0%{?tizen_feature_certsvc_ocsp_crl}
%{_datadir}/cert-svc/cert_svc_vcore_db.sql
%endif
%{_datadir}/license/%{name}
%dir %attr(0755,root,use_cert) %{TZ_SYS_SHARE}/cert-svc
#%dir %attr(0755,root,use_cert) %{TZ_SYS_SHARE}/cert-svc/ca-certs
#%dir %attr(0755,root,use_cert) %{TZ_SYS_SHARE}/cert-svc/ca-certs/code-signing
#%dir %attr(0755,root,use_cert) %{TZ_SYS_SHARE}/cert-svc/ca-certs/code-signing/native
#%dir %attr(0755,root,use_cert) %{TZ_SYS_SHARE}/cert-svc/ca-certs/code-signing/wac

#%dir %attr(0775,root,use_cert) %{TZ_SYS_SHARE}/cert-svc/certs/code-signing
#%dir %attr(0775,root,use_cert) %{TZ_SYS_SHARE}/cert-svc/certs/code-signing/wac
#%dir %attr(0775,root,use_cert) %{TZ_SYS_SHARE}/cert-svc/certs/code-signing/tizen
%dir %attr(0775,root,use_cert) %{TZ_SYS_SHARE}/cert-svc
%dir %attr(0775,root,use_cert) %{TZ_SYS_SHARE}/cert-svc/certs
%dir %attr(0775,root,use_cert) %{TZ_SYS_SHARE}/cert-svc/certs/sim
%dir %attr(0775,root,use_cert) %{TZ_SYS_SHARE}/cert-svc/certs/sim/operator
%dir %attr(0775,root,use_cert) %{TZ_SYS_SHARE}/cert-svc/certs/sim/thirdparty
%dir %attr(0777,root,use_cert) %{TZ_SYS_SHARE}/cert-svc/certs/user
%dir %attr(0777,root,use_cert) %{TZ_SYS_SHARE}/cert-svc/certs/trusteduser
%dir %attr(0775,root,use_cert) %{TZ_SYS_SHARE}/cert-svc/certs/mdm
%dir %attr(0775,root,use_cert) %{TZ_SYS_SHARE}/cert-svc/certs/mdm/security
%dir %attr(0775,root,use_cert) %{TZ_SYS_SHARE}/cert-svc/certs/mdm/security/cert
%dir %attr(0777,root,use_cert) %{TZ_SYS_SHARE}/cert-svc/pkcs12
#%{TZ_SYS_SHARE}/cert-svc/pin/.pin
%{TZ_SYS_SHARE}/cert-svc/certs/ssl
%{TZ_SYS_SHARE}/cert-svc/pkcs12/storage
#%dir %attr(0700, root, root) %{TZ_SYS_SHARE}/cert-svc/pin
%if 0%{?tizen_feature_certsvc_ocsp_crl}
%attr(0755,root,use_cert) %{TZ_SYS_SHARE}/cert-svc/certs/fota/*
%endif
#%{TZ_SYS_SHARE}/cert-svc/pin/.pin
%{TZ_SYS_SHARE}/cert-svc/certs/ssl
%{TZ_SYS_SHARE}/cert-svc/pkcs12/storage

%files devel
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_includedir}/*
%{_libdir}/pkgconfig/*
%{_libdir}/*.so
