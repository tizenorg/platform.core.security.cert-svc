Name:    cert-svc
Summary: Certification service
Version: 1.0.1
Release: 45
Group:   System/Libraries
License: Apache-2.0
Source0: %{name}-%{version}.tar.gz

Requires(post):   /sbin/ldconfig
Requires(postun): /sbin/ldconfig

BuildRequires: cmake
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(openssl)
BuildRequires: pkgconfig(dpl-efl)
BuildRequires: pkgconfig(libsoup-2.4)
BuildRequires: pkgconfig(xmlsec1)
BuildRequires: pkgconfig(secure-storage)
BuildRequires: pkgconfig(cryptsvc)
BuildRequires: ca-certificates
Provides: libcert-svc-vcore.so.1
# ca-certificates build dependency is added for ca-certificate.crt file and /opt/share/cert-svc directory

%description
Certification service


%package devel
Summary:    Certification service (development files)
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
Certification service (developement files)

%package test
Summary:  Certification service (tests)
Group:    System/Misc
Requires: %{name} = %{version}-%{release}

%description test
Certification service (tests)

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

%define tizen_feature_osp_disable 1

%{!?build_type:%define build_type "Release"}
cmake . -DPREFIX=%{_prefix} \
        -DEXEC_PREFIX=%{_exec_prefix} \
        -DLIBDIR=%{_libdir} \
        -DBINDIR=%{_bindir} \
        -DINCLUDEDIR=%{_includedir} \
	-DTIZEN_ENGINEER_MODE=1 \
%if 0%{?tizen_feature_osp_disable}
	-DTIZEN_FEAT_OSP_DISABLE=1 \
%else
	-DTIZEN_FEAT_OSP_DISABLE=0 \
%endif
%if 0%{?tizen_feature_certsvc_ocsp_crl}
	-DCMAKE_BUILD_TYPE=%{build_type} \
	-DTIZEN_FEAT_PROFILE_CERT_SVC_OCSP_CRL=1 \
%else
	-DCMAKE_BUILD_TYPE=%{build_type} \
	-DTIZEN_FEAT_PROFILE_CERT_SVC_OCSP_CRL=0
%endif
make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
mkdir -p %{buildroot}/opt/share/cert-svc
cp LICENSE.APLv2 %{buildroot}/usr/share/license/%{name}
%make_install
ln -sf /opt/etc/ssl/certs %{buildroot}/opt/share/cert-svc/certs/ssl
touch %{buildroot}/opt/share/cert-svc/pkcs12/storage
chmod 766 %{buildroot}/opt/share/cert-svc/pkcs12/storage

%clean
rm -rf %{buildroot}

%post
/sbin/ldconfig
%if 0%{?tizen_feature_certsvc_ocsp_crl}
if [ -z ${2} ]; then
    echo "This is new install of wrt-security"
    echo "Calling /usr/bin/cert_svc_create_clean_db.sh"
    /usr/bin/cert_svc_create_clean_db.sh
else
    # Find out old and new version of databases
    VCORE_OLD_DB_VERSION=`sqlite3 /opt/dbspace/.cert_svc_vcore.db ".tables" | grep "DB_VERSION_"`
    VCORE_NEW_DB_VERSION=`cat /usr/share/cert-svc/cert_svc_vcore_db.sql | tr '[:blank:]' '\n' | grep DB_VERSION_`
    echo "OLD vcore database version ${VCORE_OLD_DB_VERSION}"
    echo "NEW vcore database version ${VCORE_NEW_DB_VERSION}"

    if [ ${VCORE_OLD_DB_VERSION} -a ${VCORE_NEW_DB_VERSION} ]; then
        if [ ${VCORE_OLD_DB_VERSION} = ${VCORE_NEW_DB_VERSION} ]; then
            echo "Equal database detected so db installation ignored"
        else
            echo "Calling /usr/bin/cert_svc_create_clean_db.sh"
            /usr/bin/cert_svc_create_clean_db.sh
        fi
    else
        echo "Calling /usr/bin/cert_svc_create_clean_db.sh"
        /usr/bin/cert_svc_create_clean_db.sh
    fi
fi
rm /usr/bin/cert_svc_create_clean_db.sh
%endif #tizen_feature_certsvc_ocsp_crl
%postun
/sbin/ldconfig

%files
%defattr(-,root,root,-)
%manifest %{name}.manifest
%attr(0755,root,root) %{_bindir}/cert_svc_create_clean_db.sh
%{_libdir}/*.so.*
#%{_bindir}/dpkg-pki-sig
/opt/share/cert-svc/targetinfo
%if 0%{?tizen_feature_certsvc_ocsp_crl}
%{_datadir}/cert-svc/cert_svc_vcore_db.sql
%endif
%{_datadir}/license/%{name}
%dir %attr(0755,root,use_cert) /usr/share/cert-svc
#%dir %attr(0755,root,use_cert) /usr/share/cert-svc/ca-certs
#%dir %attr(0755,root,use_cert) /usr/share/cert-svc/ca-certs/code-signing
#%dir %attr(0755,root,use_cert) /usr/share/cert-svc/ca-certs/code-signing/native
#%dir %attr(0755,root,use_cert) /usr/share/cert-svc/ca-certs/code-signing/wac
%dir %attr(0775,root,use_cert) /usr/share/cert-svc/certs/code-signing
%dir %attr(0775,root,use_cert) /usr/share/cert-svc/certs/code-signing/wac
%dir %attr(0775,root,use_cert) /usr/share/cert-svc/certs/code-signing/tizen
%dir %attr(0775,root,use_cert) /opt/share/cert-svc
%dir %attr(0775,root,use_cert) /opt/share/cert-svc/certs
#%dir %attr(0775,root,use_cert) /opt/share/cert-svc/certs/code-signing
#%dir %attr(0775,root,use_cert) /opt/share/cert-svc/certs/code-signing/wac
#%dir %attr(0775,root,use_cert) /opt/share/cert-svc/certs/code-signing/tizen
%dir %attr(0775,root,use_cert) /opt/share/cert-svc/certs/sim
%dir %attr(0775,root,use_cert) /opt/share/cert-svc/certs/sim/operator
%dir %attr(0775,root,use_cert) /opt/share/cert-svc/certs/sim/thirdparty
%dir %attr(0777,root,use_cert) /opt/share/cert-svc/certs/user
%dir %attr(0777,root,use_cert) /opt/share/cert-svc/certs/trusteduser
%dir %attr(0775,root,use_cert) /opt/share/cert-svc/certs/mdm
%dir %attr(0775,root,use_cert) /opt/share/cert-svc/certs/mdm/security
%dir %attr(0775,root,use_cert) /opt/share/cert-svc/certs/mdm/security/cert
%dir %attr(0777,root,use_cert) /opt/share/cert-svc/pkcs12
%dir %attr(0700, root, root) /opt/share/cert-svc/pin
%if 0%{?tizen_feature_certsvc_ocsp_crl}
%attr(0755,root,use_cert) /usr/share/cert-svc/certs/fota/*
%endif
/opt/share/cert-svc/pin/.pin
/opt/share/cert-svc/certs/ssl
/opt/share/cert-svc/pkcs12/storage


%files devel
%defattr(-,root,root,-)
%{_includedir}/*
%{_libdir}/pkgconfig/*
%{_libdir}/*.so

%pre test
rm -rf /usr/share/cert-svc/certs/code-signing/wac/root_cacert0.pem
#rm -rf /opt/share/cert-svc/certs/code-signing/wac/root_cacert0.pem

%files test
%defattr(-,root,root,-)
%manifest %{name}-test.manifest
%{_bindir}/cert-svc-test*
/opt/apps/widget/tests/vcore_widget_uncompressed/*
/opt/apps/widget/tests/vcore_widget_uncompressed_negative_hash/*
/opt/apps/widget/tests/vcore_widget_uncompressed_negative_signature/*
/opt/apps/widget/tests/vcore_widget_uncompressed_negative_certificate/*
/opt/apps/widget/tests/vcore_widget_uncompressed_partner/*
/opt/apps/widget/tests/vcore_widget_uncompressed_partner_operator/*
/opt/apps/widget/tests/vcore_keys/*
/opt/apps/widget/tests/vcore_certs/*
/opt/apps/widget/tests/vcore_config/*
/opt/apps/widget/tests/pkcs12/*
/opt/apps/widget/tests/reference/*
/usr/share/cert-svc/certs/code-signing/wac/root_cacert0.pem
#/opt/share/cert-svc/certs/code-signing/wac/root_cacert0.pem
/opt/share/cert-svc/pkcs12/*
/opt/share/cert-svc/cert-type/*
/opt/share/cert-svc/tests/orig_c/data/caflag/*
%if 0%{?tizen_feature_certsvc_ocsp_crl}
/opt/share/cert-svc/tests/orig_c/data/ocsp/*
%endif #tizen_feature_certsvc_ocsp_crl
/opt/share/cert-svc/certs/root_ca*.der
/opt/share/cert-svc/certs/second_ca*.der
