Name:	    cert-svc
Summary:    Certification service 
Version:    1.0.1
Release:    0
Group:      System/Libraries
License:    Apache2.0
Source0:    cert-svc-%{version}.tar.gz

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
rm -rf %{buildroot}
%make_install


%post
mkdir -p /usr/share/cert-svc/ca-certs/code-signing/java/operator
mkdir -p /usr/share/cert-svc/ca-certs/code-signing/java/manufacture
mkdir -p /usr/share/cert-svc/ca-certs/code-signing/java/thirdparty
mkdir -p /usr/share/cert-svc/ca-certs/code-signing/debian
mkdir -p /usr/share/cert-svc/ca-certs/code-signing/wac
 
mkdir -p /opt/share/cert-svc/certs/code-signing/java/operator
mkdir -p /opt/share/cert-svc/certs/code-signing/java/manufacture
mkdir -p /opt/share/cert-svc/certs/code-signing/java/thirdparty
mkdir -p /opt/share/cert-svc/certs/code-signing/wac
mkdir -p /opt/share/cert-svc/certs/sim/operator
mkdir -p /opt/share/cert-svc/certs/sim/thirdparty
mkdir -p /opt/share/cert-svc/certs/ssl
mkdir -p /opt/share/cert-svc/certs/user
mkdir -p /opt/share/cert-svc/certs/trusteduser
mkdir -p /opt/share/cert-svc/certs/mdm/security/cert

chown -R :6524 /opt/share/cert-svc/certs/
chmod -R 0775 /opt/share/cert-svc/certs/

ln -s /opt/etc/ssl/certs/ /usr/share/cert-svc/ca-certs/ssl


%postun


%files
%defattr(-,root,root,-)
/usr/bin/dpkg-pki-sig
/opt/share/cert-svc/targetinfo
/usr/lib/libcert-svc.so.1
/usr/lib/libcert-svc.so.1.0.0

%files devel
%defattr(-,root,root,-)
/usr/lib/pkgconfig/cert-svc.pc
/usr/lib/libcert-svc.so
/usr/include/cert-service.h


