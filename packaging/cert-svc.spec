Name:	    cert-svc
Summary:    Certification service 
Version:    1.0.1
Release:    0
Group:      System/Libraries
License:    Apache2.0
Source0:    cert-svc-%{version}.tar.gz
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

BuildRequires: cmake

BuildRequires: pkgconfig(dnet)
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


%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig


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


