Summary: SELinux library and simple utilities
Name: libselinux
Version: 1.16
Release: 1
License: Public domain (uncopyrighted)
Group: System Environment/Libraries
Source: http://www.nsa.gov/selinux/archives/libselinux-%{version}.tgz
Prefix: %{_prefix}
BuildRoot: %{_tmppath}/%{name}-buildroot
Provides: libselinux.so

%description
Security-enhanced Linux is a patch of the Linux® kernel and a number
of utilities with enhanced security functionality designed to add
mandatory access controls to Linux.  The Security-enhanced Linux
kernel contains new architectural components originally developed to
improve the security of the Flask operating system. These
architectural components provide general support for the enforcement
of many kinds of mandatory access control policies, including those
based on the concepts of Type Enforcement®, Role-based Access
Control, and Multi-level Security.

libselinux provides an API for SELinux applications to get and set
process and file security contexts and to obtain security policy
decisions.  Required for any applications that use the SELinux API.

%package devel
Summary: Header files and libraries used to build SELinux
Group: Development/Libraries
Requires: libselinux = %{version}

%description devel
The selinux-devel package contains the static libraries and header files
needed for developing SELinux applications. 

%prep
%setup -q

%build
make 

%install
rm -rf ${RPM_BUILD_ROOT}
mkdir -p ${RPM_BUILD_ROOT}/%{_lib} 
mkdir -p ${RPM_BUILD_ROOT}/%{_libdir} 
mkdir -p ${RPM_BUILD_ROOT}%{_includedir} 
mkdir -p ${RPM_BUILD_ROOT}%{_bindir} 
mkdir -p ${RPM_BUILD_ROOT}%{_mandir}/man3
mkdir -p ${RPM_BUILD_ROOT}%{_mandir}/man8
make DESTDIR="${RPM_BUILD_ROOT}" LIBDIR="${RPM_BUILD_ROOT}%{_libdir}" SHLIBDIR="${RPM_BUILD_ROOT}/%{_lib}" install

%clean
rm -rf ${RPM_BUILD_ROOT}

%post
# add libselinux to the cache
/sbin/ldconfig

%files devel
%defattr(-,root,root)
%{_libdir}/libselinux.a
%{_libdir}/libselinux.so
%{_includedir}/selinux/*.h
%{_mandir}/man3/*.3.gz

%files
%defattr(-,root,root)
/%{_lib}/libselinux.so.1
%{_bindir}/*
%{_mandir}/man8/*.8.gz

%changelog

* Wed Oct 21 2003 Dan Walsh <dwalsh@redhat.com> 1.3-1
- Latest tarball from NSA.

* Tue Oct 21 2003 Dan Walsh <dwalsh@redhat.com> 1.2-9
- Update with latest changes from NSA

* Mon Oct 20 2003 Dan Walsh <dwalsh@redhat.com> 1.2-8
- Change location of .so file

* Wed Oct 8 2003 Dan Walsh <dwalsh@redhat.com> 1.2-7
- Break out into development library

* Wed Oct  8 2003 Dan Walsh <dwalsh@redhat.com> 1.2-6
- Move location of libselinux.so to /lib

* Fri Oct  3 2003 Dan Walsh <dwalsh@redhat.com> 1.2-5
- Add selinuxenabled patch

* Wed Oct  1 2003 Dan Walsh <dwalsh@redhat.com> 1.2-4
- Update with final NSA 1.2 sources.

* Fri Sep  12 2003 Dan Walsh <dwalsh@redhat.com> 1.2-3
- Update with latest from NSA.

* Fri Aug  28 2003 Dan Walsh <dwalsh@redhat.com> 1.2-2
- Fix to build on x86_64

* Thu Aug  21 2003 Dan Walsh <dwalsh@redhat.com> 1.2-1
- update for version 1.2

* Wed May 27 2003 Dan Walsh <dwalsh@redhat.com> 1.0-1
- Initial version

