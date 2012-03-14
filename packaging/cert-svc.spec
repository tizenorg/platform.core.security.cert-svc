Name:	    cert-svc
Summary:    Certification service 
Version:    1.0.1
Release:    0
Group:      System/Libraries
License:    Apache2.0
Source0:    cert-svc-%{version}.tar.gz
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
Requires:   ca-certificates

BuildRequires: cmake

BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(openssl)


%description
Certification service 


%package devel
Summary:    Download agent
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
Certification service  (developement files)

%prep
%setup -q


%build
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix}
make %{?jobs:-j%jobs}

%install
%make_install

# make certificate store directory
mkdir -p %{buildroot}/usr/share/cert-svc/ca-certs/code-signing/java/operator
mkdir -p %{buildroot}/usr/share/cert-svc/ca-certs/code-signing/java/manufacture
mkdir -p %{buildroot}/usr/share/cert-svc/ca-certs/code-signing/java/thirdparty
mkdir -p %{buildroot}/usr/share/cert-svc/ca-certs/code-signing/debian
mkdir -p %{buildroot}/usr/share/cert-svc/ca-certs/code-signing/wac

mkdir -p %{buildroot}/opt/share/cert-svc/certs/code-signing/java/operator
mkdir -p %{buildroot}/opt/share/cert-svc/certs/code-signing/java/manufacture
mkdir -p %{buildroot}/opt/share/cert-svc/certs/code-signing/java/thirdparty
mkdir -p %{buildroot}/opt/share/cert-svc/certs/code-signing/wac
mkdir -p %{buildroot}/opt/share/cert-svc/certs/sim/operator
mkdir -p %{buildroot}/opt/share/cert-svc/certs/sim/thirdparty
mkdir -p %{buildroot}/opt/share/cert-svc/certs/ssl
mkdir -p %{buildroot}/opt/share/cert-svc/certs/user
mkdir -p %{buildroot}/opt/share/cert-svc/certs/trusteduser
mkdir -p %{buildroot}/opt/share/cert-svc/certs/mdm/security/cert

ln -s /opt/etc/ssl/certs/ %{buildroot}/usr/share/cert-svc/ca-certs/ssl
%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig


%files
/usr/share/cert-svc/ca-certs/code-signing/java/operator
/usr/share/cert-svc/ca-certs/code-signing/java/manufacture
/usr/share/cert-svc/ca-certs/code-signing/java/thirdparty
/usr/share/cert-svc/ca-certs/code-signing/debian
/usr/share/cert-svc/ca-certs/code-signing/wac
/usr/share/cert-svc/ca-certs/ssl

%dir %attr(0775,root,use_cert)/opt/share/cert-svc/certs/code-signing/java/operator
%dir %attr(0775,root,use_cert)/opt/share/cert-svc/certs/code-signing/java/manufacture
%dir %attr(0775,root,use_cert)/opt/share/cert-svc/certs/code-signing/java/thirdparty
%dir %attr(0775,root,use_cert)/opt/share/cert-svc/certs/code-signing/wac
%dir %attr(0775,root,use_cert)/opt/share/cert-svc/certs/sim/operator
%dir %attr(0775,root,use_cert)/opt/share/cert-svc/certs/sim/thirdparty
%dir %attr(0775,root,use_cert)/opt/share/cert-svc/certs/ssl
%dir %attr(0775,root,use_cert)/opt/share/cert-svc/certs/user
%dir %attr(0775,root,use_cert)/opt/share/cert-svc/certs/trusteduser
/opt/share/cert-svc/targetinfo
/usr/bin/dpkg-pki-sig
/usr/lib/libcert-svc.so.1
/usr/lib/libcert-svc.so.1.0.0

%files devel
/usr/lib/pkgconfig/cert-svc.pc
/usr/lib/libcert-svc.so
/usr/include/cert-service.h


